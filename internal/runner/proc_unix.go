//go:build unix

package runner

import (
	"os/exec"
	"syscall"
)

// isolateProcessGroup puts the child shell in a process group of its own.
//
// This is the whole reason the timeout does not leave orphans: `sh -c "npm
// test"` spawns children, and killing only the shell leaves them running with
// the pipe still open — the runner would then block forever reading output
// from a command it believes it already killed.
func isolateProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// signalProcessGroup sends sig to the whole group led by pid. The negative pid
// is the POSIX spelling of "the group", and it is what reaches the
// grandchildren.
func signalProcessGroup(pid int, sig syscall.Signal) error {
	if pid <= 0 {
		return syscall.ESRCH
	}
	// Negative pid: deliver to every process in the group. Fall back to the
	// single process if the group is already gone.
	if err := syscall.Kill(-pid, sig); err != nil {
		return syscall.Kill(pid, sig)
	}
	return nil
}

func terminateGroup(pid int) error { return signalProcessGroup(pid, syscall.SIGTERM) }
func killGroup(pid int) error      { return signalProcessGroup(pid, syscall.SIGKILL) }
