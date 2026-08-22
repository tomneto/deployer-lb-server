#!/usr/bin/env bash
# ip-lib.sh — sourceable nftables IP-guard functions shared by setup.sh
# (provisioning time) and ipctl.sh (runtime control, invoked over SSH by
# selfApi). Same contract as swap-lib.sh: no side effects on source, every
# side-effecting action lives in a function.
#
# WHAT THIS OWNS, AND WHAT IT DELIBERATELY DOES NOT
#
# It owns exactly one nftables table, `inet bo_guard`, holding four sets:
# bo_allow_v4/v6 and bo_block_v4/v6. It never touches `filter`, `nat`, the
# docker chains, ufw, or CrowdSec's own `crowdsec-*` tables. That separation
# is the whole point: the backoffice declares operator rules here, CrowdSec's
# bouncer keeps its automatic decisions in its own table, and neither can
# clobber the other. Two owners of one table is how firewalls get bricked;
# two tables with one owner each is how they coexist.
#
# The chain policy is `accept`. This table only ever DROPS what it was told
# to drop — it is not a default-deny firewall and must never become one, or a
# failed sync would lock the operator out of the box it is trying to fix.
#
# The allow sets are evaluated before the block sets so a narrower allow can
# punch through a broader block (e.g. block 198.51.100.0/24 but allow
# 198.51.100.7). That is the only precedence rule, and selfApi's
# ip_rules.rules_for_target() relies on it.
#
# Callers are expected to already have `log()`/`die()`/`have()` defined
# (setup.sh does); ipctl.sh defines minimal fallbacks below when sourced
# standalone.

if ! declare -F have >/dev/null 2>&1; then
    have() { command -v "$1" >/dev/null 2>&1; }
fi
if ! declare -F log >/dev/null 2>&1; then
    log() { printf '[ip-lib] %s\n' "$*" >&2; }
fi
if ! declare -F die >/dev/null 2>&1; then
    die() { log "ERROR: $*"; exit 1; }
fi

IP_GUARD_TABLE="${IP_GUARD_TABLE:-bo_guard}"
IP_GUARD_CHAIN="${IP_GUARD_CHAIN:-input}"
# Runs before docker's chains (priority 0) so a blocked source never reaches a
# published container port. Still after conntrack's raw hooks, so established
# connections are unaffected until they close.
IP_GUARD_PRIORITY="${IP_GUARD_PRIORITY:--10}"
IP_GUARD_PERSIST_DIR="${IP_GUARD_PERSIST_DIR:-/etc/deployer-lb-server/nft}"
IP_GUARD_PERSIST_FILE="${IP_GUARD_PERSIST_FILE:-$IP_GUARD_PERSIST_DIR/bo_guard.nft}"

IP_GUARD_SETS=(bo_allow_v4 bo_allow_v6 bo_block_v4 bo_block_v6)

# `comm` requires its two inputs to be sorted in the SAME collation as the
# `sort` that produced them. A host with a UTF-8 locale sorts punctuation
# differently from the C locale, and a mismatch makes comm silently report
# bogus diffs — which here means re-adding elements that are already in the
# set on every single sync. Pin both to C.
export LC_ALL=C

# ─────────────────────────── nft discovery ───────────────────────────
#
# nft lives in /usr/sbin on Debian/Ubuntu and /sbin on RHEL, neither of which
# is reliably on a non-login SSH PATH — the exact reason swap_control.py has a
# `_looks_like_missing_binary` branch. Resolve it once, explicitly.

nft_bin() {
    if [[ -n "${NFT_BIN:-}" ]]; then printf '%s' "$NFT_BIN"; return 0; fi
    local c
    for c in nft /usr/sbin/nft /sbin/nft /usr/local/sbin/nft; do
        if command -v "$c" >/dev/null 2>&1; then NFT_BIN="$c"; printf '%s' "$c"; return 0; fi
    done
    return 1
}

ip_guard_have_nft() { nft_bin >/dev/null 2>&1; }

_nft() {
    local bin; bin="$(nft_bin)" || die "nft not found — install the nftables package"
    "$bin" "$@"
}

# ─────────────────────────── table lifecycle ───────────────────────────

ip_guard_table_present() {
    ip_guard_have_nft || return 1
    _nft list table inet "$IP_GUARD_TABLE" >/dev/null 2>&1
}

# Create table/sets/chain if missing and (re)install the chain rules, WITHOUT
# touching set contents. The flush-chain-then-readd dance is what makes this
# idempotent: `add table`/`add set`/`add chain` are no-ops when the object
# already exists, but `add rule` appends every time, so the chain has to be
# emptied first. Sets are never flushed here — that would drop every active
# block on a re-provision.
ip_guard_ensure() {
    ip_guard_have_nft || die "nft not found — install the nftables package"
    _nft -f - <<EOF
table inet $IP_GUARD_TABLE {
    set bo_allow_v4 { type ipv4_addr; flags interval; }
    set bo_allow_v6 { type ipv6_addr; flags interval; }
    set bo_block_v4 { type ipv4_addr; flags interval; }
    set bo_block_v6 { type ipv6_addr; flags interval; }
    chain $IP_GUARD_CHAIN { type filter hook input priority $IP_GUARD_PRIORITY; policy accept; }
}
flush chain inet $IP_GUARD_TABLE $IP_GUARD_CHAIN
table inet $IP_GUARD_TABLE {
    chain $IP_GUARD_CHAIN {
        ip saddr @bo_allow_v4 accept
        ip6 saddr @bo_allow_v6 accept
        ip saddr @bo_block_v4 drop
        ip6 saddr @bo_block_v6 drop
    }
}
EOF
}

# Dump the live table (rules AND set elements) to the persistence file so a
# reboot restores the same state. The `table`/`delete table` preamble is the
# canonical idempotent-restore trick: the bare `table` line creates it when
# absent so the `delete` that follows can never fail on a cold boot, and the
# delete guarantees the listing that follows is applied to an empty table
# instead of appending duplicate rules.
ip_guard_persist() {
    ip_guard_table_present || return 0
    mkdir -p "$IP_GUARD_PERSIST_DIR"
    local tmp="${IP_GUARD_PERSIST_FILE}.tmp.$$"
    {
        printf '# Generated by ip-lib.sh — do not edit by hand.\n'
        printf '# Restored at boot by deployer-lb-guard.service.\n'
        printf 'table inet %s\n' "$IP_GUARD_TABLE"
        printf 'delete table inet %s\n' "$IP_GUARD_TABLE"
        _nft list table inet "$IP_GUARD_TABLE"
    } >"$tmp"
    chmod 0644 "$tmp"
    mv -f "$tmp" "$IP_GUARD_PERSIST_FILE"
}

# Replay the persistence file — what deployer-lb-guard.service runs at boot.
# Kept here rather than as a bare `nft -f` in the unit so it goes through
# nft_bin() discovery and so a missing/empty file is a clean no-op instead of
# a unit failure.
ip_guard_restore() {
    if [[ ! -s "$IP_GUARD_PERSIST_FILE" ]]; then
        log "no persisted ruleset at $IP_GUARD_PERSIST_FILE — nothing to restore"
        return 0
    fi
    ip_guard_have_nft || die "nft not found — cannot restore $IP_GUARD_PERSIST_FILE"
    _nft -f "$IP_GUARD_PERSIST_FILE"
    log "restored $IP_GUARD_PERSIST_FILE"
}

# ─────────────────────────── set introspection ───────────────────────────

# Every element of one set, one per line, sorted and de-duplicated.
#
# Parsed out of plain `nft list set` output rather than `-j`: the JSON schema
# renders a bare address as a string but a CIDR as a nested
# {"prefix":{"addr":…,"len":…}} object, so JSON would need jq (not installable
# on every managed host) to be any easier than this. The text form is
# `elements = { 1.2.3.4, 5.6.7.0/24 }`, possibly wrapped across lines.
ip_guard_set_elements() {
    local set_name="$1"
    ip_guard_table_present || return 0
    _nft list set inet "$IP_GUARD_TABLE" "$set_name" 2>/dev/null \
        | tr '\n' ' ' \
        | sed -n 's/.*elements[[:space:]]*=[[:space:]]*{\([^}]*\)}.*/\1/p' \
        | tr ',' '\n' \
        | sed 's/[[:space:]]//g' \
        | grep -v '^$' \
        | sort -u
}

# ─────────────────────────── address helpers ───────────────────────────

ip_guard_is_v6() { [[ "$1" == *:* ]]; }

# Normalize what the backend sends into what nft stores. nft prints a /32 host
# route as a bare address, so sending "1.2.3.4/32" and reading back "1.2.3.4"
# would look like a diff forever and re-apply the same element on every sync.
ip_guard_normalize() {
    local cidr="$1"
    cidr="${cidr// /}"
    case "$cidr" in
        */32) ip_guard_is_v6 "$cidr" || cidr="${cidr%/32}" ;;
        */128) ip_guard_is_v6 "$cidr" && cidr="${cidr%/128}" ;;
    esac
    printf '%s' "$cidr"
}

_is_v4_addr() {
    [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

_v4_to_int() {
    local IFS=. a b c d
    read -r a b c d <<<"$1"
    printf '%s' "$(( (10#$a << 24) + (10#$b << 16) + (10#$c << 8) + 10#$d ))"
}

# Does IPv4 CIDR $1 contain address-or-CIDR $2? Used only by the protection
# guard below, so a conservative wrong answer must be "yes, it overlaps"
# (refuse) rather than "no" (silently block something critical).
_v4_contains() {
    local outer="$1" inner="$2"
    local o_addr="${outer%%/*}" o_len="${outer##*/}"
    local i_addr="${inner%%/*}" i_len="${inner##*/}"
    [[ "$o_len" == "$outer" ]] && o_len=32
    [[ "$i_len" == "$inner" ]] && i_len=32
    # Anything we cannot parse is treated as overlapping. This function only
    # ever gates a refusal, so the safe failure is "refuse", not "allow".
    _is_v4_addr "$o_addr" || return 0
    _is_v4_addr "$i_addr" || return 0
    [[ "$o_len" =~ ^[0-9]+$ ]] || return 0
    [[ "$i_len" =~ ^[0-9]+$ ]] || return 0
    (( o_len > 32 || i_len > 32 )) && return 0
    (( i_len < o_len )) && return 1
    local o_int i_int mask
    o_int="$(_v4_to_int "$o_addr")"
    i_int="$(_v4_to_int "$i_addr")"
    if (( o_len == 0 )); then return 0; fi
    mask=$(( 0xFFFFFFFF << (32 - o_len) & 0xFFFFFFFF ))
    (( (o_int & mask) == (i_int & mask) ))
}

# Do two IPv4 ranges intersect at all? Containment in EITHER direction counts.
#
# This being one-directional was a real bug: blocking a single host that sits
# inside a protected range (say 10.10.0.7 when 10.10.0.0/24 is the WireGuard
# overlay) is just as much a self-inflicted outage as blocking the whole
# subnet, but "does 10.10.0.7/32 contain 10.10.0.0/24" is false. Overlap, not
# containment, is the question the guard actually needs answered.
_v4_overlaps() {
    _v4_contains "$1" "$2" || _v4_contains "$2" "$1"
}

# Refuse a block entry that would cut the box off from the control plane.
# The protected list is supplied by the caller (selfApi passes the WireGuard
# subnet, the central server's public IP and the loopback ranges) because only
# the backend knows the topology — but loopback is hardcoded too, since no
# caller should ever be able to forget it.
#
# IPv4 gets real containment arithmetic: blocking 0.0.0.0/0 or 10.10.0.0/16
# must be caught, not just an exact match on 10.10.0.0/24. IPv6 gets an exact
# match plus ::1, which is weaker — documented rather than faked, and adequate
# because the WireGuard overlay and the central host are IPv4 today.
ip_guard_check_protected() {
    local entry="$1"; shift
    local protected=("$@" 127.0.0.0/8 ::1)
    local p
    for p in "${protected[@]}"; do
        [[ -z "$p" ]] && continue
        if ip_guard_is_v6 "$entry" || ip_guard_is_v6 "$p"; then
            [[ "$entry" == "$p" ]] && return 1
            continue
        fi
        if _v4_overlaps "$entry" "$p"; then
            return 1
        fi
    done
    return 0
}

# ─────────────────────────── apply ───────────────────────────

# Read the desired state from stdin and reconcile the four sets to match it.
#
# INPUT FORMAT — one `<action> <cidr>` per line, `#` comments and blank lines
# ignored:
#
#     block 203.0.113.4
#     block 198.51.100.0/24
#     allow 198.51.100.7
#
# Deliberately not JSON. Parsing JSON in bash means either jq (not present on
# every managed host, and installing a dependency to read a list of IPs is a
# bad trade) or a hand-rolled parser (a security-relevant input parser written
# in sed — worse). Two whitespace-separated tokens per line is unambiguous,
# and selfApi generates it in one join.
#
# It reconciles by DIFF, never by flush-and-refill: an element already in the
# set is left alone, so re-syncing an unchanged policy touches nothing and no
# packet is dropped in a window where the set was momentarily empty.
#
# Prints a JSON summary to stdout; everything else goes to stderr.
ip_guard_apply() {
    local protected=("$@")
    ip_guard_ensure

    local -A want=()
    local action cidr line
    while IFS= read -r line || [[ -n "$line" ]]; do
        line="${line%%#*}"
        # shellcheck disable=SC2086
        set -- $line
        [[ $# -eq 0 ]] && continue
        [[ $# -eq 2 ]] || die "malformed input line (expected '<block|allow> <cidr>'): $line"
        action="$1"; cidr="$(ip_guard_normalize "$2")"
        case "$action" in
            block|allow) ;;
            *) die "unknown action '$action' (expected block or allow)" ;;
        esac
        [[ -n "$cidr" ]] || die "empty cidr on line: $line"
        if [[ "$action" == "block" ]]; then
            ip_guard_check_protected "$cidr" ${protected[@]+"${protected[@]}"} \
                || die "refusing to block $cidr — it covers a protected range (WireGuard overlay, the control-plane host, or loopback)"
        fi
        local set_name
        if ip_guard_is_v6 "$cidr"; then
            set_name="bo_${action}_v6"
        else
            set_name="bo_${action}_v4"
        fi
        want["$set_name"]+="$cidr"$'\n'
    done

    local added=0 removed=0 unchanged=0
    local set_name
    for set_name in "${IP_GUARD_SETS[@]}"; do
        local desired current to_add to_del
        desired="$(printf '%s' "${want[$set_name]:-}" | grep -v '^$' | sort -u || true)"
        current="$(ip_guard_set_elements "$set_name")"
        to_add="$(comm -23 <(printf '%s\n' "$desired" | grep -v '^$') <(printf '%s\n' "$current" | grep -v '^$') || true)"
        to_del="$(comm -13 <(printf '%s\n' "$desired" | grep -v '^$') <(printf '%s\n' "$current" | grep -v '^$') || true)"

        local n_add n_del n_same
        n_add="$(printf '%s' "$to_add" | grep -c '^..*$' || true)"
        n_del="$(printf '%s' "$to_del" | grep -c '^..*$' || true)"
        n_same="$(comm -12 <(printf '%s\n' "$desired" | grep -v '^$') <(printf '%s\n' "$current" | grep -v '^$') | grep -c '^..*$' || true)"

        if (( n_add > 0 )); then
            log "$set_name: adding $n_add element(s)"
            _nft add element inet "$IP_GUARD_TABLE" "$set_name" \
                "{ $(printf '%s' "$to_add" | grep -v '^$' | paste -sd, -) }"
        fi
        if (( n_del > 0 )); then
            log "$set_name: removing $n_del element(s)"
            _nft delete element inet "$IP_GUARD_TABLE" "$set_name" \
                "{ $(printf '%s' "$to_del" | grep -v '^$' | paste -sd, -) }"
        fi
        added=$(( added + n_add ))
        removed=$(( removed + n_del ))
        unchanged=$(( unchanged + n_same ))
    done

    if (( added > 0 || removed > 0 )); then
        ip_guard_persist
    fi
    printf '{"added":%d,"removed":%d,"unchanged":%d}\n' "$added" "$removed" "$unchanged"
}

# ─────────────────────────── read-only reporting ───────────────────────────

_json_array_of_lines() {
    local first=1 item
    printf '['
    while IFS= read -r item; do
        [[ -z "$item" ]] && continue
        (( first )) || printf ','
        first=0
        printf '"%s"' "$item"
    done
    printf ']'
}

# Current contents of all four sets, as JSON. This is what the Go agent shells
# out to for its `security.guard` report section, and what selfApi diffs
# against the desired state to detect drift.
ip_guard_list_json() {
    printf '{"table_present":%s' "$(ip_guard_table_present && echo true || echo false)"
    local set_name
    for set_name in "${IP_GUARD_SETS[@]}"; do
        printf ',"%s":' "$set_name"
        ip_guard_set_elements "$set_name" | _json_array_of_lines
    done
    printf '}\n'
}

ip_guard_status_json() {
    local has_nft persist unit
    has_nft="$(ip_guard_have_nft && echo true || echo false)"
    persist="$([[ -f "$IP_GUARD_PERSIST_FILE" ]] && echo true || echo false)"
    unit=false
    if have systemctl && systemctl is-enabled deployer-lb-guard.service >/dev/null 2>&1; then
        unit=true
    fi
    local counts=""
    local set_name n
    for set_name in "${IP_GUARD_SETS[@]}"; do
        n="$(ip_guard_set_elements "$set_name" | grep -c '^..*$' || true)"
        counts+=",\"${set_name}_count\":${n}"
    done
    printf '{"nft_present":%s,"table_present":%s,"persist_file":"%s","persisted":%s,"boot_unit_enabled":%s%s}\n' \
        "$has_nft" \
        "$(ip_guard_table_present && echo true || echo false)" \
        "$IP_GUARD_PERSIST_FILE" "$persist" "$unit" "$counts"
}
