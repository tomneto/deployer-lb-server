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
func (RealRunner) Test(confDir string) (bool, string, error) {
	wrapper := filepath.Join(confDir, ".nginx-test.conf")
	content := fmt.Sprintf("events {}\nhttp {\n    include %s/*.conf;\n}\n", confDir)
	if err := os.WriteFile(wrapper, []byte(content), 0o600); err != nil {
		return false, "", err
	}
	defer os.Remove(wrapper)

	cmd := exec.Command("nginx", "-t", "-c", wrapper)
	out, err := cmd.CombinedOutput()
	return err == nil, string(out), err
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
