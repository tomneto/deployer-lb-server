#!/usr/bin/env bash
#
# Integration test for the deployer-lb-agent flow driven over REAL SSH
# (unlike scripts/test-provision.sh, which drives setup.sh via `docker
# exec`) — mirrors how selfApi's provisioning.py actually reaches a target
# in production: SSH in as root, run setup.sh, confirm the resulting agent
# reports land on an intake with connections/disk_io/agent_version present.
#
# This is the "run this locally before touching GitHub Actions" loop; the
# same commands are what the release.yml `integration-test` job runs.
#
# Usage:
#   bash scripts/test-agent-ssh.sh            # bring up local fixture, test, tear down
#   bash scripts/test-agent-ssh.sh --keep     # skip teardown, for inspection
#
# To point the same tests at a real reachable SSH host instead of the local
# docker fixture (e.g. because nested virtualization can't create a real
# WireGuard interface — known issue on Docker Desktop/WSL2's inner VM):
#   SKIP_FIXTURE=1 \
#   SSH_TEST_HOST=203.0.113.10 SSH_TEST_USER=root SSH_TEST_PASSWORD=... \
#   INTAKE_ADVERTISE_HOST=<address that host can reach this machine on> \
#   bash scripts/test-agent-ssh.sh
# No need to pre-clone the repo there: the test tars up this exact local
# checkout (uncommitted changes included) and extracts it into a fresh
# remote temp dir itself, cleaned up when the test ends. Set REPO_REMOTE_PATH
# explicitly only if you want a specific already-populated path used as-is
# instead. See tests/integration/agent_ssh_test.go's envOr() calls for every
# variable this accepts and its default (all default to the local fixture).
#
# Exit code is nonzero if the fixture never comes up or any test fails.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.ssh-test.yaml"
SKIP_FIXTURE="${SKIP_FIXTURE:-0}"

KEEP=0
if [[ "${1:-}" == "--keep" ]]; then
    KEEP=1
fi

cleanup() {
    if [[ "$SKIP_FIXTURE" == "1" ]]; then
        return
    fi
    if [[ "$KEEP" -eq 1 ]]; then
        echo "== --keep set, leaving container up — 'docker compose -f $COMPOSE_FILE down -v' to clean up =="
        return
    fi
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

if [[ "$SKIP_FIXTURE" == "1" ]]; then
    echo "== SKIP_FIXTURE=1: not touching docker-compose.ssh-test.yaml, targeting SSH_TEST_HOST=${SSH_TEST_HOST:-<unset!>} =="
else
    echo "== bringing up SSH-test fixture (systemd + sshd, Ubuntu 24.04) =="
    echo "== first run installs systemd/sshd/golang-go/git from scratch inside the container — can take several minutes on a fresh apt cache =="
    docker compose -f "$COMPOSE_FILE" up -d
fi

# No shell-level readiness probe here: a bare TCP connect to the published
# port succeeds via docker's port-forwarding proxy well before sshd is
# actually listening behind it (the container installs packages, then execs
# systemd, which only then starts the enabled sshd unit) — a false positive
# that just hides the real wait. tests/integration's own SSH dial retries
# for up to 5 minutes for this reason; -timeout below gives it room to do so.
echo "== running integration tests (go test -tags integration) =="
cd "$REPO_ROOT"
go test -tags integration -timeout 10m ./tests/integration/... -v
