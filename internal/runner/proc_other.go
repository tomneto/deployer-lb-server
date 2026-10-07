//go:build !unix

package runner

import (
	"os"
	"os/exec"
)

// The runner ships for darwin and linux only (see .github/workflows/release.yml).
// These stubs exist so the package still compiles anywhere `go build ./...`
// might be run, with the honest caveat that without process groups a timeout
// can only kill the shell itself.
func isolateProcessGroup(*exec.Cmd) {}

func terminateGroup(pid int) error { return signalPID(pid, os.Interrupt) }
func killGroup(pid int) error      { return signalPID(pid, os.Kill) }

func signalPID(pid int, sig os.Signal) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Signal(sig)
}
