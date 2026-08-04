// Package provision will host host-provisioning logic used by setup.sh for
// both the `lb` and `agent` modes (pipe-improves.md §2.4/§5 B4):
// installing/verifying nginx (presence + minimum version) and the WireGuard
// hub/peer setup (interface, listen port, peers, handshake validation).
//
// Intentionally left as a stub: this is B4's scope, implemented by a
// parallel work stream in this same repo. B1 (this listener) only needs the
// package to exist so cmd/apply-server can eventually depend on it without
// a restructure; no code should be added here without coordinating with
// whoever owns B4.
package provision
