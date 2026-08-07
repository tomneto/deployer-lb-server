#!/usr/bin/env bash
#
# Unit test for setup.sh's download_or_build_binary() prebuilt-vs-checkout
# version check (the fix for "update agent" silently reinstalling a stale
# bin/<name> shipped by repo_source.py). Extracts just that function out of
# setup.sh — sourcing the whole file would run `main "$@"` — and exercises
# it against a throwaway git repo + fake binaries, no docker/systemd needed.
#
# Usage: bash scripts/test-download-or-build-binary.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
SETUP_SH="$REPO_ROOT/setup.sh"

MODE="test"
log()  { printf '[test][%s] %s\n' "$MODE" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }
# download_or_build_binary()'s go-build fallback path reads this global —
# point it somewhere unreachable so these tests never hit the network.
GH_RELEASE_BASE_URL="https://example.invalid/unused"

# Pull just the function body out of setup.sh so we exercise the real
# implementation, not a re-typed copy that could silently drift from it.
eval "$(sed -n '/^download_or_build_binary() {/,/^}/p' "$SETUP_SH")"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

cleanup_case() { rm -rf "$work/repo" "$work/bin_home" 2>/dev/null || true; }

setup_repo() {
    mkdir -p "$work/repo"
    git -C "$work/repo" init -q
    git -C "$work/repo" -c user.email=t@t -c user.name=t commit -q --allow-empty -m init
    git -C "$work/repo" tag v1.2.3
}

fake_binary() {
    # $1 = path, $2 = version string it should report on `-v`
    cat > "$1" <<EOF
#!/usr/bin/env bash
if [[ "\$1" == "-v" ]]; then
    echo "deployer-lb-agent $2"
    exit 0
fi
echo "not a real binary, only supports -v" >&2
exit 1
EOF
    chmod +x "$1"
}

fail=0
assert_eq() {
    local desc="$1" got="$2" want="$3"
    if [[ "$got" == "$want" ]]; then
        echo "ok - $desc"
    else
        echo "FAIL - $desc: got '$got', want '$want'"
        fail=1
    fi
}

# --- case 1: prebuilt version matches checkout -> prebuilt is used verbatim
cleanup_case
setup_repo
mkdir -p "$work/repo/bin"
fake_binary "$work/repo/bin/deployer-lb-agent" "v1.2.3"
REPO_ROOT="$work/repo" out="$(download_or_build_binary deployer-lb-agent agent cmd/agent)"
assert_eq "matching prebuilt is used" "$out" "$work/repo/bin/deployer-lb-agent"

# --- case 2: prebuilt version is stale -> must NOT be returned, falls
# through to the go-build path (asserted indirectly: go build produces a
# binary at /tmp/deployer-lb-agent.new, distinct from the prebuilt path).
cleanup_case
setup_repo
mkdir -p "$work/repo/bin" "$work/repo/cmd/agent"
fake_binary "$work/repo/bin/deployer-lb-agent" "v0.0.1-stale"
cat > "$work/repo/cmd/agent/main.go" <<'EOF'
package main

func main() {}
EOF
cat > "$work/repo/go.mod" <<'EOF'
module github.com/tomneto/deployer-lb-server

go 1.22
EOF
if have go; then
    REPO_ROOT="$work/repo" out="$(download_or_build_binary deployer-lb-agent agent cmd/agent)"
    if [[ "$out" == "$work/repo/bin/deployer-lb-agent" ]]; then
        echo "FAIL - stale prebuilt must not be reused: got '$out'"
        fail=1
    else
        echo "ok - stale prebuilt rejected, fell through to go build (out=$out)"
    fi
else
    echo "skip - stale-prebuilt-rejected case needs a local Go toolchain (not found in PATH)"
fi

# --- case 3: prebuilt binary present but doesn't understand -v (old/broken
# build predating the version flag) -> must not be reused either.
cleanup_case
setup_repo
mkdir -p "$work/repo/bin"
cat > "$work/repo/bin/deployer-lb-agent" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$work/repo/bin/deployer-lb-agent"
if have go; then
    # This case hits die() (no cmd/agent dir in the throwaway repo) — exit
    # inside a function called from a command substitution still trips
    # errexit in the parent shell even when the substitution is itself
    # `||`-guarded, so errexit must be off for this one call.
    set +e
    out="$(REPO_ROOT="$work/repo" download_or_build_binary deployer-lb-agent agent cmd/agent 2>/dev/null)"
    set -e
    if [[ "$out" == "$work/repo/bin/deployer-lb-agent" ]]; then
        echo "FAIL - prebuilt with no -v support must not be reused: got '$out'"
        fail=1
    else
        echo "ok - prebuilt with no -v support rejected"
    fi
else
    echo "skip - no-version-support case needs a local Go toolchain (not found in PATH)"
fi

exit "$fail"
