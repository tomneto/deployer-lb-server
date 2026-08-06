#!/usr/bin/env bash
#
# Integration test for setup.sh's distro support (Ubuntu Server + Oracle
# Linux 9) — this IS the "test suite" for that concern, but it is NEVER run
# automatically: not by `go test ./...` (there's no Go here, it's pure
# shell+docker orchestration), not by any CI workflow. Reasons:
#   - real systemd (setup.sh needs systemctl/wg-quick@/nginx units) requires
#     --privileged + a mounted cgroup, which hosted GH Actions runners don't
#     grant to nested containers;
#   - it installs real packages and brings up real network interfaces —
#     appropriate for a manual/local loop, not for every push.
#
# Usage:
#   bash scripts/test-provision.sh                # both distros, mode lb
#   bash scripts/test-provision.sh --mode agent    # both distros, mode agent
#   bash scripts/test-provision.sh --keep          # skip teardown, for inspection
#
# Exit code is nonzero if setup.sh failed on either distro.
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
COMPOSE_FILE="$REPO_ROOT/docker-compose.provision-test.yaml"

MODE="lb"
KEEP=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode) MODE="$2"; shift 2 ;;
        --keep) KEEP=1; shift ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

SERVICES=(provision-test-ubuntu provision-test-oraclelinux)
WG_IPS=(10.10.9.1 10.10.9.2)

cleanup() {
    if [[ "$KEEP" -eq 1 ]]; then
        echo "== --keep set, leaving containers up — 'docker compose -f $COMPOSE_FILE down -v' to clean up =="
        return
    fi
    docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== bringing up test containers (Ubuntu 24.04 + Oracle Linux 9) =="
docker compose -f "$COMPOSE_FILE" up -d

# The Go toolchain and a couple of base tools aren't preinstalled on either
# distro's image — installing them here (once systemd is up) lets setup.sh's
# real `go build` fallback run end to end without needing a published GH
# release (that's a separate, one-time concern — cutting the actual release).
ensure_tools() {
    local svc="$1"
    docker exec "$svc" bash -lc '
        set -e
        if command -v apt-get >/dev/null 2>&1; then
            apt-get update -y
            apt-get install -y curl ca-certificates golang-go openssl
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y curl golang openssl dnf-plugins-core
        fi
    '
}

fail=0
for i in "${!SERVICES[@]}"; do
    svc="${SERVICES[$i]}"
    wg_ip="${WG_IPS[$i]}"

    echo "== [$svc] waiting for systemd to be ready =="
    ready=0
    for _ in $(seq 1 30); do
        if docker exec "$svc" systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'; then
            ready=1
            break
        fi
        sleep 1
    done
    if [[ "$ready" -ne 1 ]]; then
        echo "== [$svc] systemd never became ready — skipping =="
        fail=1
        continue
    fi

    echo "== [$svc] installing curl/go (setup.sh dependencies not shipped on the base image) =="
    ensure_tools "$svc"

    echo "== [$svc] running setup.sh $MODE =="
    if [[ "$MODE" == "lb" ]]; then
        cmd="bash setup.sh lb --wg-ip ${wg_ip} --wg-port 51820"
    else
        cmd="bash setup.sh agent --intake-url https://example.invalid/infra/agent/report --agent-token smoke-test-token --wg-ip ${wg_ip}"
    fi

    if docker exec "$svc" bash -lc "cd /repo && $cmd"; then
        echo "== [$svc] setup.sh $MODE OK =="
    else
        echo "== [$svc] setup.sh $MODE FAILED =="
        fail=1
    fi
done

exit "$fail"
