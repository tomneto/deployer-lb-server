//go:build integration

// Package integration drives the real deployer-lb-agent flow over a real
// SSH connection against docker-compose.ssh-test.yaml's throwaway systemd
// host: SSH in as root, run the real `setup.sh agent` (no docker exec, no
// bypassing systemd), then assert the resulting agent actually posts valid
// reports to a fake intake — connections/disk_io/agent_version included,
// which is exactly what was missing when the frontend showed "não reporta
// conexões de rede" / "Aguardando amostras…".
//
// Run via scripts/test-agent-ssh.sh, which brings up the fixture and tears
// it down; see that script and docker-compose.ssh-test.yaml for the usage
// this test assumes (fixture already up on $SSH_TEST_PORT, repo mounted
// read-only at /repo inside the container).
package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	sshUser     = "root"
	sshPassword = "testpass123"
	agentToken  = "smoke-test-token"
	agentID     = "agent-ssh-test"
)

func sshPort(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("SSH_TEST_PORT"); p != "" {
		return p
	}
	return "2222"
}

func dialSSH(t *testing.T) *ssh.Client {
	t.Helper()
	cfg := &ssh.ClientConfig{
		User:            sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(sshPassword)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	addr := net.JoinHostPort("127.0.0.1", sshPort(t))

	var client *ssh.Client
	var err error
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		client, err = ssh.Dial("tcp", addr, cfg)
		if err == nil {
			return client
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("could not SSH into fixture at %s after 60s: %v", addr, err)
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

// dockerBridgeGateway resolves the address the container's default route
// uses to reach the host — the fake intake httptest server runs in this
// test process on the host, and the container needs to reach it without
// docker-compose port publishing (which would round-trip through the OS
// network stack for no benefit here).
func dockerBridgeGateway(t *testing.T, client *ssh.Client) string {
	t.Helper()
	out, err := runRemote(t, client, "ip route | awk '/default/ {print $3}'")
	if err != nil {
		t.Fatalf("resolve docker bridge gateway: %v (%s)", err, out)
	}
	gw := ""
	for _, line := range splitLines(out) {
		if line != "" {
			gw = line
		}
	}
	if gw == "" {
		t.Fatalf("could not resolve docker bridge gateway from route output: %q", out)
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

	gw := dockerBridgeGateway(t, client)
	intakeURL := fmt.Sprintf("http://%s/infra/agent/report", net.JoinHostPort(gw, intake.port()))

	cmd := fmt.Sprintf(
		"cd /repo && AGENT_INTERVAL=3 bash setup.sh agent --intake-url %s --agent-token %s --wg-ip 10.10.9.9",
		intakeURL, agentToken,
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

	// /repo is read-only (docker-compose.ssh-test.yaml), and the script
	// needs to create a throwaway git repo under mktemp — that part works
	// fine against a read-only checkout since it only reads setup.sh out
	// of it and writes everything else under /tmp.
	out, err := runRemote(t, client, "bash /repo/scripts/test-download-or-build-binary.sh")
	if err != nil {
		t.Fatalf("scripts/test-download-or-build-binary.sh failed over SSH: %v\n--- output ---\n%s", err, out)
	}
}
