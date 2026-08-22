#!/usr/bin/env bash
# ipctl.sh — thin CLI over scripts/lib/ip-lib.sh, installed on managed hosts
# at /usr/local/bin/ipctl by setup.sh (step4). Invoked remotely by selfApi
# (api/services/backoffice/deploy/ip_control.py) over SSH so the backoffice
# frontend can label and block individual IPs without a separate inbound
# control channel on the agent — same arrangement as swapctl.
#
# Usage:
#   ipctl ensure                        — create the nft table/sets/chain
#   ipctl apply [--protect <cidr>]...   — reconcile sets to the desired state
#                                         read from STDIN (see below)
#   ipctl list                          — current set contents as JSON
#   ipctl status                        — nft/table/persistence health as JSON
#   ipctl restore                       — replay the persisted ruleset (boot)
#
# `apply` reads one `<block|allow> <cidr>` per line from stdin; `#` comments
# and blank lines are ignored. The list arrives on stdin rather than in argv
# on purpose: the agent reports process cmdlines back to the backoffice, and a
# blocklist visible in `ps` leaks the security policy to anyone who can read
# the process table.
#
# `--protect` is repeatable and names ranges that must never be blocked (the
# WireGuard overlay, the control-plane host, loopback). A block entry covering
# any of them aborts the whole apply before a single element is written —
# blocking the central server is a self-inflicted outage of the very panel you
# would use to undo it.
#
# All logging goes to stderr; `apply`, `list` and `status` write JSON to
# stdout. Non-zero exit on any failure.
set -euo pipefail

# Snapshot argv before the parser consumes it — the self-elevation below
# re-execs with the original invocation.
IPCTL_ARGS=("$@")

# Everything here needs root: `nft` refuses to read or write the ruleset
# otherwise. selfApi reaches this over SSH through executor.run, which does NOT
# prefix sudo, and provisioning explicitly accepts a NOPASSWD-sudo user as well
# as root (setup.sh's ELEVATION_PROBE_CMD) — so on those hosts every ipctl call
# would fail with a permission error that reads like "nft is broken". Same
# guard, same wording, as setup.sh's elevate_to_root().
#
# stdin matters here: `apply` reads the desired policy from it, and re-execing
# through sudo has to preserve it. `sudo` passes stdin through unchanged, so
# the pipe survives the exec.
if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1 && sudo -n true 2>/dev/null; then
        exec sudo -n bash "$0" ${IPCTL_ARGS[@]+"${IPCTL_ARGS[@]}"}
    fi
    echo "ipctl: needs root; the current user ($(id -un)) has no passwordless sudo (NOPASSWD)." >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$SCRIPT_DIR/lib/ip-lib.sh"
if [[ ! -f "$LIB" ]]; then
    # Installed layout: /usr/local/bin/ipctl -> lib at
    # /usr/local/lib/deployer-lb-server/ip-lib.sh
    LIB="/usr/local/lib/deployer-lb-server/ip-lib.sh"
fi
# shellcheck disable=SC1090
source "$LIB"

usage() {
    echo "usage: $(basename "$0") {ensure|apply [--protect <cidr>]...|list|status|restore}" >&2
    exit 1
}

[[ $# -ge 1 ]] || usage
cmd="$1"; shift || true

case "$cmd" in
    ensure)
        ip_guard_ensure
        ip_guard_persist
        ;;
    apply)
        protect=()
        while [[ $# -gt 0 ]]; do
            case "$1" in
                --protect)
                    [[ $# -ge 2 ]] || die "--protect requires a cidr"
                    protect+=("$2"); shift 2 ;;
                *) die "unknown option for apply: $1" ;;
            esac
        done
        ip_guard_apply ${protect[@]+"${protect[@]}"}
        ;;
    list)
        ip_guard_list_json
        ;;
    status)
        ip_guard_status_json
        ;;
    restore)
        ip_guard_restore
        ;;
    *)
        usage
        ;;
esac
