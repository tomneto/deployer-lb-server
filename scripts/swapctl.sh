#!/usr/bin/env bash
# swapctl.sh — thin CLI over scripts/lib/swap-lib.sh, installed on managed
# hosts at /usr/local/bin/swapctl by setup.sh (step4). Invoked remotely by
# selfApi (api/services/backoffice/deploy/swap_control.py) over SSH so the
# backoffice frontend can view/tune swap and drop OS caches without a
# separate inbound control channel on the agent.
#
# Usage:
#   swapctl status                 — print JSON snapshot to stdout
#   swapctl resize <size_mb>       — resize /swapfile to exactly <size_mb>
#   swapctl remove                 — swapoff + remove /swapfile
#   swapctl drop-caches [level]    — sync + drop caches (1|2|3, default 3)
#
# All logging goes to stderr; `status` is the only subcommand that writes to
# stdout (the JSON payload). Non-zero exit on any failure.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="$SCRIPT_DIR/lib/swap-lib.sh"
if [[ ! -f "$LIB" ]]; then
    # Installed layout: /usr/local/bin/swapctl -> lib at
    # /usr/local/lib/deployer-lb-server/swap-lib.sh
    LIB="/usr/local/lib/deployer-lb-server/swap-lib.sh"
fi
# shellcheck disable=SC1090
source "$LIB"

usage() {
    echo "usage: $(basename "$0") {status|resize <size_mb>|remove|drop-caches [level]}" >&2
    exit 1
}

[[ $# -ge 1 ]] || usage
cmd="$1"; shift || true

case "$cmd" in
    status)
        swap_snapshot_json
        ;;
    resize)
        [[ $# -eq 1 ]] || die "resize requires exactly one argument: <size_mb>"
        swap_resize "$1"
        ;;
    remove)
        swap_remove
        ;;
    drop-caches)
        drop_caches "${1:-3}"
        ;;
    *)
        usage
        ;;
esac
