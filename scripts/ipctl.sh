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
