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
#   bash scripts/test-agent-ssh.sh            # bring up, test, tear down
#   bash scripts/test-agent-ssh.sh --keep     # skip teardown, for inspection
#
# Exit code is nonzero if the fixture never comes up or any test fails.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.ssh-test.yaml"

KEEP=0
if [[ "${1:-}" == "--keep" ]]; then
    KEEP=1
fi

cleanup() {
    if [[ "$KEEP" -eq 1 ]]; then
        echo "== --keep set, leaving container up — 'docker compose -f $COMPOSE_FILE down -v' to clean up =="
        return
    fi
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== bringing up SSH-test fixture (systemd + sshd, Ubuntu 24.04) =="
docker compose -f "$COMPOSE_FILE" up -d

echo "== waiting for sshd to accept connections on \$SSH_TEST_PORT (default 2222) =="
port="${SSH_TEST_PORT:-2222}"
ready=0
for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then
        exec 3>&- 3<&-
        ready=1
        break
    fi
    sleep 1
done
if [[ "$ready" -ne 1 ]]; then
    echo "== sshd never came up on port ${port} =="
    exit 1
fi

echo "== running integration tests (go test -tags integration) =="
cd "$REPO_ROOT"
SSH_TEST_PORT="$port" go test -tags integration ./tests/integration/... -v
