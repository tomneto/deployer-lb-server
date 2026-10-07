package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// --workdir is mandatory on purpose: defaulting it to the process's cwd would
// make the directory the panel's commands run in depend on where someone
// happened to launch the binary from.
func TestResolveWorkdir_Required(t *testing.T) {
	for _, in := range []string{"", "   "} {
		if _, err := resolveWorkdir(in); err == nil {
			t.Errorf("resolveWorkdir(%q) should fail", in)
		}
	}
}

func TestResolveWorkdir_MustExistAndBeADirectory(t *testing.T) {
	dir := t.TempDir()
	if _, err := resolveWorkdir(filepath.Join(dir, "nope")); err == nil {
		t.Error("a missing directory should fail at startup, not at the first command")
	}

	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveWorkdir(file); err == nil {
		t.Error("a file is not a working directory")
	}

	got, err := resolveWorkdir(dir)
	if err != nil {
		t.Fatalf("resolveWorkdir(%q): %v", dir, err)
	}
	if !filepath.IsAbs(got) {
		t.Errorf("resolveWorkdir returned a relative path %q", got)
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("RUNNER_X_BOOL", "yes")
	if !envBoolOr("RUNNER_X_BOOL", false) {
		t.Error(`"yes" should read as true`)
	}
	t.Setenv("RUNNER_X_BOOL", "garbage")
	if !envBoolOr("RUNNER_X_BOOL", true) {
		t.Error("an unparseable value must fall back, not flip")
	}

	t.Setenv("RUNNER_X_INT", "4096")
	if got := envIntOr("RUNNER_X_INT", 7); got != 4096 {
		t.Errorf("envIntOr = %d", got)
	}
	t.Setenv("RUNNER_X_INT", "12x")
	if got := envIntOr("RUNNER_X_INT", 7); got != 7 {
		t.Errorf("envIntOr on garbage = %d, want the fallback", got)
	}

	// Both spellings ops actually write, same as cmd/agent.
	t.Setenv("RUNNER_X_DUR", "90s")
	if got := envDurationOr("RUNNER_X_DUR", time.Second); got != 90*time.Second {
		t.Errorf("envDurationOr = %s", got)
	}
	t.Setenv("RUNNER_X_DUR", "90")
	if got := envDurationOr("RUNNER_X_DUR", time.Second); got != 90*time.Second {
		t.Errorf("envDurationOr on bare seconds = %s", got)
	}
}
