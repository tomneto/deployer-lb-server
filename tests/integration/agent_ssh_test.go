//go:build integration

// Package integration drives the real deployer-lb-agent flow over a real
// SSH connection against docker-compose.ssh-test.yaml's throwaway systemd
// host: SSH in as root, run the real `setup.sh agent` (no docker exec, no
// bypassing systemd), then assert the resulting agent actually posts valid
// reports to a fake intake — connections/disk_io/agent_version included,
// which is exactly what was missing when the frontend showed "não reporta
// conexões de rede" / "Aguardando amostras…".
//
// Run via scripts/test-agent-ssh.sh, which by default brings up the local
// docker-compose.ssh-test.yaml fixture and tears it down. To point this at
// any other reachable SSH host instead (e.g. a real VM, when nested
// virtualization can't create a real WireGuard interface), set
// SSH_TEST_HOST (and SKIP_FIXTURE=1 on the script) plus whichever of
// SSH_TEST_USER/SSH_TEST_PASSWORD/SSH_TEST_KEY/INTAKE_ADVERTISE_HOST don't
// match that host's defaults — see envOr() below for the full list. No need
// to pre-clone anything there either: unless REPO_REMOTE_PATH is set, this
// test tars up the exact local checkout (uncommitted changes included) and
// extracts it into a fresh remote temp dir over the same SSH connection,
// cleaned up automatically when the test ends (see copyRepoToRemoteTemp).
package integration

import (
	"archive/tar"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Every one of these defaults matches docker-compose.ssh-test.yaml, so
// running with no env vars at all still targets the local fixture exactly
// as before. Set SSH_TEST_HOST (and optionally SSH_TEST_USER/_PASSWORD/_KEY,
// REPO_REMOTE_PATH, INTAKE_ADVERTISE_HOST) to point the same test at any
// real reachable SSH box instead — useful when the local Docker Desktop
// VM can't create a real WireGuard interface (nested virtualization) but a
// real host/VM can.
const (
	agentToken = "smoke-test-token"
	agentID    = "agent-ssh-test"
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func sshHost() string { return envOr("SSH_TEST_HOST", "127.0.0.1") }
func sshPort() string { return envOr("SSH_TEST_PORT", "2222") }
func sshUser() string { return envOr("SSH_TEST_USER", "root") }

// resolveRepoRemotePath decides where setup.sh (and the rest of the
// checkout) lives on the target. Three cases:
//   - REPO_REMOTE_PATH set: use it verbatim — caller already put the repo
//     there (or wants a specific path re-used across test runs).
//   - Local docker fixture (SSH_TEST_HOST unset): "/repo", the read-only
//     bind mount docker-compose.ssh-test.yaml already sets up.
//   - Real external host (SSH_TEST_HOST set) with no REPO_REMOTE_PATH:
//     tar up *this exact local checkout* — including any uncommitted
//     changes, since that's usually the point of testing before a commit —
//     and extract it into a fresh remote temp dir over the same SSH
//     connection. No git clone/credentials on the remote host needed.
func resolveRepoRemotePath(t *testing.T, client *ssh.Client) string {
	t.Helper()
	if p := os.Getenv("REPO_REMOTE_PATH"); p != "" {
		return p
	}
	if os.Getenv("SSH_TEST_HOST") == "" {
		return "/repo"
	}
	return copyRepoToRemoteTemp(t, client)
}

// localRepoRoot walks up from this source file's own location to the repo
// root (tests/integration/ -> repo root), so this works regardless of the
// working directory `go test` happens to be invoked from.
func localRepoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("could not determine this source file's own path via runtime.Caller")
	}
	return filepath.Dir(filepath.Dir(filepath.Dir(thisFile)))
}

// skipFromRepoTar excludes paths with no business being shipped to a throw-
// away remote: .git (large, irrelevant to setup.sh) and any prebuilt bin/
// (shipping one would defeat the very version-check test this package
// exists to run — force download_or_build_binary() into its git-describe/
// go-build path every time, deterministically).
func skipFromRepoTar(relPath string) bool {
	first := strings.SplitN(relPath, string(filepath.Separator), 2)[0]
	return first == ".git" || first == "bin"
}

func copyRepoToRemoteTemp(t *testing.T, client *ssh.Client) string {
	t.Helper()
	localRoot := localRepoRoot(t)

	mkdirOut, err := runRemote(t, client, "mktemp -d /tmp/deployer-lb-server.XXXXXX")
	if err != nil {
		t.Fatalf("mktemp -d on remote host: %v (%s)", err, mkdirOut)
	}
	remoteDir := strings.TrimSpace(mkdirOut)
	t.Cleanup(func() {
		_, _ = runRemote(t, client, fmt.Sprintf("rm -rf %s", remoteDir))
	})

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("ssh new session for repo copy: %v", err)
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("ssh stdin pipe: %v", err)
	}
	var remoteOut strings.Builder
	session.Stdout = &remoteOut
	session.Stderr = &remoteOut

	if err := session.Start(fmt.Sprintf("tar -xzf - -C %s", remoteDir)); err != nil {
		t.Fatalf("start remote tar extract: %v", err)
	}

	gz := gzip.NewWriter(stdin)
	tw := tar.NewWriter(gz)
	walkErr := filepath.WalkDir(localRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(localRoot, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if skipFromRepoTar(rel) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if d.IsDir() {
			hdr.Name += "/"
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if d.IsDir() || !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	})
	closeErr1 := tw.Close()
	closeErr2 := gz.Close()
	closeErr3 := stdin.Close()
	for _, e := range []error{walkErr, closeErr1, closeErr2, closeErr3} {
		if e != nil {
			t.Fatalf("streaming repo tar to remote host: %v", e)
		}
	}

	if err := session.Wait(); err != nil {
		t.Fatalf("remote tar extract failed: %v (%s)", err, remoteOut.String())
	}
	return remoteDir
}

func sshAuthMethod() (ssh.AuthMethod, error) {
	if keyPath := os.Getenv("SSH_TEST_KEY"); keyPath != "" {
		key, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read SSH_TEST_KEY %q: %w", keyPath, err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("parse SSH_TEST_KEY %q: %w", keyPath, err)
		}
		return ssh.PublicKeys(signer), nil
	}
	return ssh.Password(envOr("SSH_TEST_PASSWORD", "testpass123")), nil
}

func dialSSH(t *testing.T) *ssh.Client {
	t.Helper()
	auth, err := sshAuthMethod()
	if err != nil {
		t.Fatalf("build SSH auth method: %v", err)
	}
	cfg := &ssh.ClientConfig{
		User:            sshUser(),
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	addr := net.JoinHostPort(sshHost(), sshPort())

	// The docker fixture's boot command apt-get installs systemd/sshd/
	// golang-go/git from scratch (docker-compose.ssh-test.yaml) before
	// systemd ever starts sshd — on a first pull with no apt cache this
	// alone can take several minutes, and docker's port-forwarding proxy
	// will happily accept a raw TCP connect (and then reset it) long before
	// anything real is listening behind it, so a short deadline here just
	// produces a misleading "connection reset" instead of a real timeout.
	// A real external target (SSH_TEST_HOST set) is normally ready
	// immediately, but the same generous deadline is harmless there too.
	var client *ssh.Client
	deadline := time.Now().Add(5 * time.Minute)
	for time.Now().Before(deadline) {
		client, err = ssh.Dial("tcp", addr, cfg)
		if err == nil {
			return client
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("could not SSH into %s after 5min: %v", addr, err)
	return nil
}

func runRemote(t *testing.T, client *ssh.Client, cmd string) (string, error) {
	t.Helper()
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("ssh new session: %v", err)
	}
	defer session.Close()

	out, err := session.CombinedOutput(cmd)
	return string(out), err
}

// intakeAdvertiseHost resolves the address the SSH target should use to
// reach back to this test process's fake intake (an httptest.Server running
// right here). For the docker fixture that's the container's default route
// gateway (the host, from the container's point of view) — auto-detected.
// A real external target can't be auto-detected the same way (its default
// route goes to a real router, not back to your machine), so set
// INTAKE_ADVERTISE_HOST to whatever address that target can use to reach
// this machine (a WireGuard/VPN IP, a LAN IP, etc).
func intakeAdvertiseHost(t *testing.T, client *ssh.Client) string {
	t.Helper()
	if h := os.Getenv("INTAKE_ADVERTISE_HOST"); h != "" {
		return h
	}
	out, err := runRemote(t, client, "ip route | awk '/default/ {print $3}'")
	if err != nil {
		t.Fatalf("resolve default-route gateway (set INTAKE_ADVERTISE_HOST to skip this auto-detection): %v (%s)", err, out)
	}
	gw := ""
	for _, line := range splitLines(out) {
		if line != "" {
			gw = line
		}
	}
	if gw == "" {
		t.Fatalf("could not resolve default-route gateway from route output (set INTAKE_ADVERTISE_HOST instead): %q", out)
	}
	return gw
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

type receivedReport struct {
	body      []byte
	agentID   string
	timestamp string
	signature string
}

// fakeIntake mimics selfApi's /infra/agent/report just enough to verify the
// agent's HMAC scheme end to end (Sign() in internal/agent/hmac.go: hex
// HMAC-SHA256 of timestamp+body, keyed by the agent token) without pulling
// in the internal/agent package (which is gated behind the "agent" build
// tag) — this is a deliberate reimplementation of the receiver contract,
// not a shortcut around it.
type fakeIntake struct {
	mu      sync.Mutex
	reports []receivedReport
	srv     *httptest.Server
}

func newFakeIntake() *fakeIntake {
	fi := &fakeIntake{}
	fi.srv = httptest.NewServer(http.HandlerFunc(fi.handle))
	return fi
}

func (fi *fakeIntake) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}
	rep := receivedReport{
		body:      body,
		agentID:   r.Header.Get("X-Agent-Id"),
		timestamp: r.Header.Get("X-Agent-Ts"),
		signature: r.Header.Get("X-Agent-Token"),
	}
	if !verifySignature(agentToken, rep.timestamp, body, rep.signature) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	fi.mu.Lock()
	fi.reports = append(fi.reports, rep)
	fi.mu.Unlock()
	w.WriteHeader(http.StatusOK)
}

func (fi *fakeIntake) count() int {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	return len(fi.reports)
}

func (fi *fakeIntake) snapshot() []receivedReport {
	fi.mu.Lock()
	defer fi.mu.Unlock()
	out := make([]receivedReport, len(fi.reports))
	copy(out, fi.reports)
	return out
}

func (fi *fakeIntake) close() { fi.srv.Close() }

// port returns the httptest server's listening port, so the caller can
// build a URL pointed at the docker bridge gateway instead of 127.0.0.1
// (which inside the container means the container itself, not the host).
func (fi *fakeIntake) port() string {
	_, port, _ := net.SplitHostPort(fi.srv.Listener.Addr().String())
	return port
}

func verifySignature(secret, timestamp string, body []byte, signature string) bool {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

func TestSetupAgent_RunsOverSSHAndReportsConnectionsAndDiskIO(t *testing.T) {
	client := dialSSH(t)
	defer client.Close()

	intake := newFakeIntake()
	defer intake.close()

	repoPath := resolveRepoRemotePath(t, client)
	gw := intakeAdvertiseHost(t, client)
	intakeURL := fmt.Sprintf("http://%s/infra/agent/report", net.JoinHostPort(gw, intake.port()))

	// Wrapped in `timeout` so a stalled network call inside setup.sh (its
	// curl calls now carry --max-time, but this is a second line of
	// defense) fails fast with a clear error instead of silently eating
	// the whole go test -timeout budget with no output to show why.
	cmd := fmt.Sprintf(
		"cd %s && timeout 240 env AGENT_INTERVAL=3 bash setup.sh agent --intake-url %s --agent-token %s --wg-ip 10.10.9.9",
		repoPath, intakeURL, agentToken,
	)
	out, err := runRemote(t, client, cmd)
	if err != nil {
		t.Fatalf("setup.sh agent failed: %v\n--- output ---\n%s", err, out)
	}

	active, err := runRemote(t, client, "systemctl is-active deployer-lb-agent")
	if err != nil {
		t.Fatalf("deployer-lb-agent unit is not active: %v (%s)", err, active)
	}

	deadline := time.Now().Add(45 * time.Second)
	for intake.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(1 * time.Second)
	}
	reports := intake.snapshot()
	if len(reports) < 2 {
		t.Fatalf("expected >=2 reports within 45s (frontend needs 2 samples to leave 'Aguardando amostras…'), got %d", len(reports))
	}

	var payload map[string]any
	if err := json.Unmarshal(reports[len(reports)-1].body, &payload); err != nil {
		t.Fatalf("report body is not valid JSON: %v", err)
	}
	if _, ok := payload["connections"]; !ok {
		t.Errorf("report missing 'connections' field — this is exactly the symptom that caused the 'não reporta conexões de rede' warning")
	}
	if _, ok := payload["disk_io"]; !ok {
		t.Errorf("report missing 'disk_io' field")
	}
	if v, _ := payload["agent_version"].(string); v == "" {
		t.Errorf("report missing/empty 'agent_version' field")
	}
	if reports[len(reports)-1].agentID != agentID {
		t.Errorf("X-Agent-Id = %q, want %q", reports[len(reports)-1].agentID, agentID)
	}
	// sanity: header timestamp must parse as a unix time close to now, or
	// verifySignature's construction would be trivially satisfiable by any
	// signature computed against garbage.
	if _, err := strconv.ParseInt(reports[len(reports)-1].timestamp, 10, 64); err != nil {
		t.Errorf("X-Agent-Ts %q does not parse as unix timestamp: %v", reports[len(reports)-1].timestamp, err)
	}
}

// TestSetupAgent_RejectsStalePrebuiltBinary re-runs the exact same unit
// test as scripts/test-download-or-build-binary.sh, but over real SSH
// against the fixture host instead of locally — proving the fix behaves
// the same way on a real remote target as it does in isolation. It
// deliberately does not re-implement the assertions: it drives the
// existing, already-reviewed test script and just checks its exit code.
func TestSetupAgent_RejectsStalePrebuiltBinary(t *testing.T) {
	client := dialSSH(t)
	defer client.Close()

	repoPath := resolveRepoRemotePath(t, client)
	// The docker fixture's /repo is read-only, and the script needs to
	// create a throwaway git repo under mktemp — that part works fine
	// against a read-only checkout since it only reads setup.sh out of it
	// and writes everything else under /tmp.
	out, err := runRemote(t, client, fmt.Sprintf("bash %s/scripts/test-download-or-build-binary.sh", repoPath))
	if err != nil {
		t.Fatalf("scripts/test-download-or-build-binary.sh failed over SSH: %v\n--- output ---\n%s", err, out)
	}
}
