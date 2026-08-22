#!/usr/bin/env bash
# test-ipctl.sh — tier-1 test for scripts/lib/ip-lib.sh. Runs anywhere: no
# root, no nftables, no container. Same spirit as
# scripts/test-download-or-build-binary.sh (pure-logic tier).
#
# It drives ip-lib against a MOCK `nft` that keeps set contents in files, so
# the parts with actual semantics — the reconcile diff, the /32 normalization
# and the protected-range refusal — are exercised for real. What it cannot
# cover is whether the kernel accepts our ruleset; that is tier 2/3
# (docker-compose.provision-test.yaml), and the mock's job is only to make the
# logic testable, not to simulate netfilter.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ─────────────────────────── the mock nft ───────────────────────────

mkdir -p "$WORK/bin" "$WORK/state"
cat >"$WORK/bin/nft" <<'MOCK'
#!/usr/bin/env bash
# Mock nft: set elements live one-per-line in $NFT_STATE/<set>.
set -uo pipefail
S="$NFT_STATE"
case "${1:-}" in
    -f) cat >/dev/null; touch "$S/.table"; exit 0 ;;
    list)
        case "${2:-}" in
            table) [[ -f "$S/.table" ]] || { echo "No such file or directory" >&2; exit 1; }
                   echo "table inet bo_guard {"; echo "}"; exit 0 ;;
            set)   name="$5"
                   [[ -f "$S/.table" ]] || { echo "No such file or directory" >&2; exit 1; }
                   echo "table inet bo_guard {"
                   echo "  set $name {"
                   echo "    type ipv4_addr"
                   if [[ -s "$S/$name" ]]; then
                       echo "    elements = { $(paste -sd, - <"$S/$name") }"
                   fi
                   echo "  }"; echo "}"; exit 0 ;;
        esac ;;
    add)
        [[ "${2:-}" == element ]] || exit 0
        name="$5"; shift 5
        raw="$*"; raw="${raw#\{}"; raw="${raw%\}}"
        tr ',' '\n' <<<"$raw" | tr -d ' ' | grep -v '^$' >>"$S/$name"
        sort -u -o "$S/$name" "$S/$name"; exit 0 ;;
    delete)
        [[ "${2:-}" == element ]] || exit 0
        name="$5"; shift 5
        raw="$*"; raw="${raw#\{}"; raw="${raw%\}}"
        tr ',' '\n' <<<"$raw" | tr -d ' ' | grep -v '^$' >"$S/.del"
        grep -vxF -f "$S/.del" "$S/$name" >"$S/.keep" || true
        mv "$S/.keep" "$S/$name"; exit 0 ;;
esac
exit 0
MOCK
chmod +x "$WORK/bin/nft"

export NFT_STATE="$WORK/state"
export PATH="$WORK/bin:$PATH"
export IP_GUARD_PERSIST_DIR="$WORK/persist"
export IP_GUARD_PERSIST_FILE="$WORK/persist/bo_guard.nft"
for s in bo_allow_v4 bo_allow_v6 bo_block_v4 bo_block_v6; do : >"$NFT_STATE/$s"; done

# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/ip-lib.sh"

# ─────────────────────────── harness ───────────────────────────

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  FAIL %s\n     expected: %s\n     actual:   %s\n' "$1" "$2" "$3"; }
eq()   { [[ "$2" == "$3" ]] && ok "$1" || bad "$1" "$2" "$3"; }

apply() { ip_guard_apply "$@" 2>/dev/null; }

echo "== reconcile =="

out="$(printf 'block 203.0.113.4\nblock 198.51.100.0/24\nallow 8.8.8.8\n' | apply)"
eq "first apply adds three" '{"added":3,"removed":0,"unchanged":0}' "$out"

out="$(printf 'block 203.0.113.4\nblock 198.51.100.0/24\nallow 8.8.8.8\n' | apply)"
eq "re-apply is a no-op" '{"added":0,"removed":0,"unchanged":3}' "$out"

out="$(printf 'block 198.51.100.0/24\n' | apply)"
eq "dropping entries removes them" '{"added":0,"removed":2,"unchanged":1}' "$out"

out="$(printf '' | apply)"
eq "empty desired state clears everything" '{"added":0,"removed":1,"unchanged":0}' "$out"

echo "== input parsing =="

out="$(printf '# a comment\n\n   \nblock 203.0.113.9\n' | apply)"
eq "comments and blank lines ignored" '{"added":1,"removed":0,"unchanged":0}' "$out"

# /32 must land in the set as a bare address, or every sync re-adds it.
: >"$NFT_STATE/bo_block_v4"
out="$(printf 'block 203.0.113.9/32\n' | apply)"
eq "/32 is normalized on write" '{"added":1,"removed":0,"unchanged":0}' "$out"
eq "/32 stored bare" "203.0.113.9" "$(cat "$NFT_STATE/bo_block_v4")"
out="$(printf 'block 203.0.113.9\n' | apply)"
eq "bare form matches the /32 that wrote it" '{"added":0,"removed":0,"unchanged":1}' "$out"

: >"$NFT_STATE/bo_block_v4"; : >"$NFT_STATE/bo_block_v6"
out="$(printf 'block 2001:db8::1\nblock 203.0.113.9\n' | apply)"
eq "v4 and v6 routed to their own sets" '{"added":2,"removed":0,"unchanged":0}' "$out"
eq "v6 element in the v6 set" "2001:db8::1" "$(cat "$NFT_STATE/bo_block_v6")"

out="$(printf 'blork 1.2.3.4\n' | ip_guard_apply 2>&1)"; rc=$?
eq "unknown action rejected" "1" "$rc"
out="$(printf 'block\n' | ip_guard_apply 2>&1)"; rc=$?
eq "malformed line rejected" "1" "$rc"

echo "== protected ranges =="

prot=(10.10.0.0/24 203.0.113.200)

ip_guard_check_protected "198.51.100.0/24" "${prot[@]}" && r=allowed || r=refused
eq "unrelated range allowed" "allowed" "$r"

ip_guard_check_protected "10.10.0.0/24" "${prot[@]}" && r=allowed || r=refused
eq "exact overlay match refused" "refused" "$r"

ip_guard_check_protected "10.10.0.0/16" "${prot[@]}" && r=allowed || r=refused
eq "range CONTAINING the overlay refused" "refused" "$r"

ip_guard_check_protected "0.0.0.0/0" "${prot[@]}" && r=allowed || r=refused
eq "block-the-world refused" "refused" "$r"

ip_guard_check_protected "10.10.0.7" "${prot[@]}" && r=allowed || r=refused
eq "single host INSIDE the overlay refused" "refused" "$r"

ip_guard_check_protected "203.0.113.200" "${prot[@]}" && r=allowed || r=refused
eq "control-plane host refused" "refused" "$r"

ip_guard_check_protected "127.0.0.1" && r=allowed || r=refused
eq "loopback refused even with no --protect" "refused" "$r"

ip_guard_check_protected "10.11.0.0/24" "${prot[@]}" && r=allowed || r=refused
eq "adjacent range allowed" "allowed" "$r"

# A refusal must abort the WHOLE apply — a partially-applied policy is worse
# than a rejected one, because the operator sees success and the box is in a
# state nobody declared.
: >"$NFT_STATE/bo_block_v4"
printf 'block 198.51.100.5\nblock 10.10.0.0/24\n' | ip_guard_apply "${prot[@]}" >/dev/null 2>&1
eq "refused apply writes nothing at all" "" "$(cat "$NFT_STATE/bo_block_v4")"

echo
printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
