// Package nginx wraps the shell-out surface the `lb` listener needs
// (`nginx -t`, `nginx -T`, `systemctl reload nginx`) behind a small
// injectable interface, plus atomic conf.d file writes and a minimal parser
// for detecting legacy (unmanaged) server_name collisions in `nginx -T`
// output. Everything here is designed to be testable without a real nginx
// installed (pipe-improves.md §5 B1: "Use um fake/mock ... para não
// depender de nginx instalado").
package nginx

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Runner is the seam between the listener's apply/rollback orchestration and
// the actual nginx/systemd commands. RealRunner implements it against the
// real host; FakeRunner (see fake.go) implements it in-memory for tests.
type Runner interface {
	// Test runs `nginx -t` against confDir (a directory containing *.conf
	// files to be validated as a self-contained overlay — see the wrapper
	// nginx.conf built by RealRunner.Test). Returns whether the config is
	// valid and the raw command output (for surfacing as `errors[]`).
	Test(confDir string) (ok bool, output string, err error)

	// Reload runs `systemctl reload nginx` against the live service.
	Reload() (output string, err error)

	// DumpConfig runs `nginx -T` against the live, active configuration
	// (never the overlay) — used for the legacy server_name collision
	// check.
	DumpConfig() (output string, err error)

	// IsActive reports whether the nginx service is currently active,
	// feeding GET /v1/status's `nginx.running` field.
	IsActive() (bool, error)
}

// RealRunner shells out to nginx/systemctl on the local host.
type RealRunner struct{}

// Test builds a minimal, self-contained wrapper nginx.conf that includes
// every *.conf file under confDir and runs `nginx -t -c <wrapper>` against
// it.
//
// Decision (implementation detail not fully specified by the plan): the
// plan says to validate "a árvore com staging incluído" before promoting a
// file. Since nginx only reads files matched by the real `include
// conf.d/*.conf;` directive in the live nginx.conf, a staged file with a
// different name/extension would be invisible to a straightforward
// `nginx -t`. To make "test the overlay" self-contained and independent of
// the live nginx.conf (so it works the same in CI/tests and in production,
// and doesn't require root to touch /etc/nginx/nginx.conf just to validate),
// this generates a throwaway wrapper config scoped to confDir. This does
// not include the production snippets (`cloudflare-real-ip.conf`,
// error-pages) that the real template `include`s — that wiring belongs to
// B3/B4 provisioning, which is expected to ship a `Test` override or extend
// this wrapper once the real template/snippet layout lands.
//
// `nginx -t` does not only parse. It opens the pidfile, both log destinations
// AND the five scratch directories it would use at runtime, checking it could
// write each one. Every default points outside confDir, and the unit runs
// under ProtectSystem=strict with /etc/nginx as the only writable path — so
// the probe kept dying on things that have nothing to do with the
// configuration being tested, one at a time:
//
//	[emerg] open() "/run/nginx.pid" failed (30: Read-only file system)
//	[emerg] open() "/var/log/nginx/access.log" failed (30: Read-only file system)
//	[emerg] chown("/var/lib/nginx/body", 65534) failed (30: Read-only file system)
//
// They are listed together because fixing them one at a time just moves the
// error to the next path — this was found three times before the whole set
// was enumerated and verified against the real host.
//
// The effect was a permanent `config_ok: false` in /v1/status on a host whose
// config is perfectly valid — the backoffice drew "config inválida" in red
// next to an nginx that was serving traffic.
//
// Note the access log default is NOT inherited from the live nginx.conf (this
// wrapper never includes it): it is the path nginx was COMPILED with, which on
// Debian/Ubuntu is /var/log/nginx/access.log. So the wrapper has to name its
// own, the same way it names its own pid.
//
// Everything the probe writes now lands inside confDir, which is writable by
// definition since the wrapper itself is written there. The test depends on the
// configuration alone, and nobody has to widen the unit's sandbox to make it
// pass — widening it would mean handing a validation probe write access to
// /run and /var/log just to read a boolean.
func (RealRunner) Test(confDir string) (bool, string, error) {
	wrapper := filepath.Join(confDir, ".nginx-test.conf")
	if err := os.WriteFile(wrapper, []byte(wrapperContent(confDir)), 0o600); err != nil {
		return false, "", err
	}
	defer os.Remove(wrapper)

	tmp := testTempDir(confDir)
	if err := os.MkdirAll(tmp, 0o700); err != nil {
		return false, "", err
	}
	defer os.RemoveAll(tmp)

	pid := testPidPath(confDir)
	defer os.Remove(pid)

	args := testArgs(wrapper, pid)
	cmd := exec.Command("nginx", args...)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out), err
}

// wrapperContent is the throwaway nginx.conf the probe validates against.
// Split out so the access_log override is covered by a test rather than living
// only inside a call the suite never reaches.
func wrapperContent(confDir string) string {
	tmp := testTempDir(confDir)
	return fmt.Sprintf(`events {}
http {
    access_log off;
    client_body_temp_path %[1]s/body;
    proxy_temp_path %[1]s/proxy;
    fastcgi_temp_path %[1]s/fastcgi;
    uwsgi_temp_path %[1]s/uwsgi;
    scgi_temp_path %[1]s/scgi;
    include %[2]s/*.conf;
}
`, tmp, confDir)
}

// testTempDir is where the probe points every scratch path nginx insists on
// being able to write. Inside confDir, which is writable by definition.
func testTempDir(confDir string) string {
	return filepath.Join(confDir, ".nginx-test-tmp")
}

// testPidPath keeps the throwaway pidfile next to the throwaway wrapper: that
// directory is writable by definition (the wrapper is written there), which is
// exactly the property /run does not have under the unit's sandbox. The name
// deliberately does not end in .conf, so the wrapper's own `include *.conf`
// cannot pick it up.
func testPidPath(confDir string) string {
	return filepath.Join(confDir, ".nginx-test.pid")
}

// testArgs is split out so the pid override is covered by a test instead of
// living only inside an exec call that the suite never reaches — it was the
// absence of that override that produced a permanent false `config_ok: false`.
func testArgs(wrapper, pid string) []string {
	// error_log is a main-context directive, so it rides in -g next to pid;
	// access_log is http-context and lives in the wrapper body above.
	return []string{"-t", "-c", wrapper, "-g", "pid " + pid + "; error_log stderr;"}
}

// Reload asks systemd to reload the nginx service (never `restart` — see
// §2.3 "SDLC da aplicação no LB").
func (RealRunner) Reload() (string, error) {
	cmd := exec.Command("systemctl", "reload", "nginx")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// DumpConfig runs `nginx -T` against the live, active configuration.
func (RealRunner) DumpConfig() (string, error) {
	cmd := exec.Command("nginx", "-T")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// IsActive shells out to `systemctl is-active nginx`.
func (RealRunner) IsActive() (bool, error) {
	cmd := exec.Command("systemctl", "is-active", "nginx")
	out, _ := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)) == "active", nil
}
