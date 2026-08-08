#!/usr/bin/env bash
#
# setup.sh — replicable, idempotent provisioner for deployer-lb-server.
#
# Implements plan step B4 (selfApi/pipe-improves.md §2.4/§5): the central
# runs this script over SSH at target registration time (D8), once per host,
# in one of two modes:
#
#   bash setup.sh lb    --port <porta> --nginx-conf-dir /etc/nginx/conf.d \
#                        --wg-ip <wireguard_ip> --wg-port <port> \
#                        --wg-peers <pubkey:ip,...> \
#                        [--lb-token <token> --lb-secret <secret>] \
#                        [--intake-url <url> --agent-token <token> --interval 8]
#   bash setup.sh agent --intake-url <url> --agent-token <token> \
#                        --interval 8 --wg-ip <wireguard_ip> \
#                        --wg-hub <pubkey:endpoint,...>
#
# `lb` mode also installs the telemetry agent (same binary/unit/env vars as
# agent mode) when --intake-url/--agent-token are provided, so LBs report
# host/ports/procs/units like any other server (WS-6 "LB de corpo inteiro").
#
# Every step is idempotent: "se já existe, valida e segue" — re-running this
# script (update, secret rotation, drift repair) must always be safe. No
# step here is ever executed as part of this task (per instructions); this
# file is meant to be read and reviewed before any real run, since it
# installs packages and touches network/firewall state.
#
# Steps (numbered comments below match §2.4 exactly):
#   1. Dependencies (nginx for lb / docker+wireguard-tools for agent; systemd;
#      binary — GH release download with local `go build` fallback)
#   2. WireGuard (D20): keypair, hub or peer config, validate-only if already
#      configured
#   3. Binary copy to /usr/local/bin/
#   4. Config: lb -> template+snippets+default_server catch-all;
#              agent -> iptables-bootstrap.sh + .env
#   5. systemd unit install/enable
#   6. Final validation (health/nginx -t/wg ping for lb; handshake+ping+test
#      POST for agent)

set -euo pipefail

# Snapshot the original argv BEFORE MODE parsing advances/shifts $@ — the
# self-elevation guard in elevate_to_root() needs the full original invocation
# to re-exec, and by the time main() runs $@ has already been consumed by the
# arg parser.
SCRIPT_ARGS=("$@")

# ---------------------------------------------------------------------------
# Globals / defaults
# ---------------------------------------------------------------------------

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)"
REPO_ROOT="$SCRIPT_DIR"

# TODO(D10): no GH release has been published yet for this repo. Point this
# at the real release asset URL once `deployer-lb-server` has a tag + CI
# upload job; until then the fallback is always `go build` from REPO_ROOT.
GH_RELEASE_BASE_URL="${GH_RELEASE_BASE_URL:-https://github.com/tomneto/deployer-lb-server/releases/latest/download}"

MODE="${1:-}"
[[ "$MODE" == "lb" || "$MODE" == "agent" ]] || {
    echo "usage: $0 {lb|agent} [options...]" >&2
    exit 1
}
shift || true

# lb-mode options
LB_PORT="127.0.0.1:8443"
NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_TEMPLATE_DIR="/etc/nginx/lb-templates"
NGINX_SNIPPETS_DIR="/etc/nginx/snippets"
NGINX_MIN_VERSION="1.18.0"
# wireguard-tools versiona por data (ex.: v1.0.20210914) desde que o módulo
# foi mainlined no kernel 5.6 (2020) — 1.0.20200513 é a primeira release
# estável pós-mainline, piso seguro pra qualquer distro atual.
WG_MIN_VERSION="1.0.20200513"

# agent-mode options
INTAKE_URL=""
AGENT_ID="$(hostname -f 2>/dev/null || hostname)"
AGENT_TOKEN=""
AGENT_INTERVAL="8"
# 1 = collect per-container stats (see write_agent_env). Overridable from the
# environment so a re-run of setup.sh on a busy host can turn it off without a
# new flag.
AGENT_DOCKER_STATS="${AGENT_DOCKER_STATS:-1}"
IPTABLES_BOOTSTRAP_SCRIPT="${IPTABLES_BOOTSTRAP_SCRIPT:-}"

# shared wireguard options
WG_IFACE="wg0"
WG_IP=""
WG_PORT="51820"
WG_PEERS=""   # lb: comma-separated pubkey:ip (peer allowed-ips it dials out to)
WG_HUB=""     # agent: comma-separated pubkey:endpoint (hub(s) to peer with)

LB_TOKEN=""
LB_SECRET=""

BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

log()  { printf '[setup.sh][%s] %s\n' "$MODE" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Distro detection (D-OS1) — informational + drives the RHEL-family-only
# steps below (EPEL, firewalld, SELinux). The package-manager probes
# (have apt-get/dnf/yum) remain the actual source of truth for which
# installer to run; this only decides which *extra* prerequisites a `dnf`
# host needs (Ubuntu never reaches those branches).
# ---------------------------------------------------------------------------

OS_ID="unknown"
OS_ID_LIKE=""
OS_VERSION_ID=""

detect_os() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_ID_LIKE="${ID_LIKE:-}"
        OS_VERSION_ID="${VERSION_ID:-}"
    fi
    local family="unknown"
    have apt-get && family="debian"
    have dnf && family="rhel"
    have yum && [[ "$family" == "unknown" ]] && family="rhel"
    log "detected distro: ${OS_ID} ${OS_VERSION_ID} (package family: ${family})"
}

# ---------------------------------------------------------------------------
# Arg parsing (both modes share the parser; unknown flags for the current
# mode are just ignored by the case default below so this stays one script)
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) LB_PORT="$2"; shift 2 ;;
        --nginx-conf-dir) NGINX_CONF_DIR="$2"; shift 2 ;;
        --lb-token) LB_TOKEN="$2"; shift 2 ;;
        --lb-secret) LB_SECRET="$2"; shift 2 ;;
        --intake-url) INTAKE_URL="$2"; shift 2 ;;
        --agent-id) AGENT_ID="$2"; shift 2 ;;
        --agent-token) AGENT_TOKEN="$2"; shift 2 ;;
        --interval) AGENT_INTERVAL="$2"; shift 2 ;;
        --wg-ip) WG_IP="$2"; shift 2 ;;
        --wg-port) WG_PORT="$2"; shift 2 ;;
        --wg-iface) WG_IFACE="$2"; shift 2 ;;
        --wg-peers) WG_PEERS="$2"; shift 2 ;;
        --wg-hub) WG_HUB="$2"; shift 2 ;;
        --iptables-bootstrap) IPTABLES_BOOTSTRAP_SCRIPT="$2"; shift 2 ;;
        *) die "unknown flag: $1" ;;
    esac
done

if [[ "$MODE" == "lb" ]]; then
    [[ -n "$WG_IP" ]] || die "--wg-ip is required for mode lb"
elif [[ "$MODE" == "agent" ]]; then
    [[ -n "$INTAKE_URL" ]] || die "--intake-url is required for mode agent"
    [[ -n "$AGENT_TOKEN" ]] || die "--agent-token is required for mode agent"
    [[ -n "$WG_IP" ]] || die "--wg-ip is required for mode agent"
fi

# ---------------------------------------------------------------------------
# Step 1 — Dependencies
# ---------------------------------------------------------------------------

version_ge() {
    # $1 = installed version, $2 = minimum required version (both "x.y.z...")
    local a="$1" b="$2"
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$b" ]]
}

wg_installed_version() {
    # `wg --version` prints "wireguard-tools v1.0.20210914" — extract just the
    # number (no "v"), same shape version_ge already expects.
    wg --version 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1
}

# wireguard-tools (and, on Oracle Linux, nothing extra for nginx — it's a
# plain AppStream package) is NOT in the base/AppStream repos of EL9: it
# needs EPEL. Idempotent — safe to call before every dnf/yum install attempt.
# Scoped to what we've actually confirmed: Oracle Linux has its own
# EPEL-compatible channel already present-but-disabled on the image
# (ol9_developer_EPEL); other dnf-based distros (Rocky/Alma/plain RHEL) fall
# back to the upstream `epel-release` package. Never fatal — if neither path
# applies (or the repo is already enabled) the subsequent package install is
# what actually fails/succeeds, this is just best-effort repo setup.
ensure_rhel_epel() {
    have dnf || return 0
    case "$OS_ID" in
        ol)
            local rel="${OS_VERSION_ID%%.*}"
            dnf config-manager --set-enabled "ol${rel}_developer_EPEL" 2>/dev/null \
                && log "enabled ol${rel}_developer_EPEL (Oracle Linux EPEL channel)" \
                || log "warning: could not enable ol${rel}_developer_EPEL (may already be enabled, or dnf-plugins-core missing)"
            ;;
        rocky|almalinux|rhel|centos)
            rpm -q epel-release >/dev/null 2>&1 \
                || dnf install -y epel-release 2>/dev/null \
                || log "warning: could not install epel-release for $OS_ID"
            ;;
    esac
}

install_or_upgrade_wireguard_tools() {
    if have apt-get; then
        # `install --only-upgrade` on a package that isn't installed yet
        # prints "Skipping ..." and exits 0 — not an error — so the `||
        # apt-get install` fallback below never ran and a host with no
        # wireguard-tools at all silently kept none installed. Plain
        # `apt-get install` already upgrades an existing package to the
        # newest available version, so it covers both cases on its own.
        apt-get update -y && apt-get install -y wireguard-tools
    elif have dnf; then
        ensure_rhel_epel
        dnf install -y wireguard-tools  # dnf install already upgrades in place
    elif have yum; then
        yum install -y wireguard-tools
    else
        die "no supported package manager found (apt-get/dnf/yum) to install/upgrade wireguard-tools"
    fi
}

# Shared by both modes: `lb` needs wireguard-tools for the hub interface
# (step2_wireguard_lb), `agent` needs it for the peer interface — same
# package, same version floor, same install-or-upgrade decision either way.
ensure_wireguard_tools_version() {
    if have wg; then
        local wg_ver
        wg_ver="$(wg_installed_version)"
        if [[ -z "$wg_ver" ]]; then
            log "warning: wg present but version could not be determined, attempting upgrade"
            wg_ver="0.0.0"
        fi
        if version_ge "$wg_ver" "$WG_MIN_VERSION"; then
            log "wireguard-tools $wg_ver already installed, OK"
        else
            log "wireguard-tools $wg_ver < required $WG_MIN_VERSION — upgrading"
            install_or_upgrade_wireguard_tools
            wg_ver="$(wg_installed_version)"
            [[ -n "$wg_ver" ]] && version_ge "$wg_ver" "$WG_MIN_VERSION" \
                || die "wireguard-tools upgrade did not reach $WG_MIN_VERSION (got '${wg_ver:-unknown}')"
            log "wireguard-tools upgraded to $wg_ver, OK"
        fi
    else
        log "wireguard-tools not found, installing"
        install_or_upgrade_wireguard_tools
    fi
}

step1_deps_lb() {
    log "step 1/6: dependencies (nginx, wireguard-tools)"
    if have nginx; then
        local ver
        ver="$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"
        [[ -n "$ver" ]] || die "nginx present but version could not be determined"
        version_ge "$ver" "$NGINX_MIN_VERSION" \
            || die "nginx $ver < required $NGINX_MIN_VERSION"
        nginx -t >/dev/null 2>&1 || log "warning: existing nginx config fails 'nginx -t' (pre-existing issue, not caused by this run)"
        log "nginx $ver already installed, OK"
    else
        log "nginx not found, installing"
        if have apt-get; then
            apt-get update -y && apt-get install -y nginx
        elif have dnf; then
            dnf install -y nginx
        elif have yum; then
            yum install -y nginx
        else
            die "no supported package manager found (apt-get/dnf/yum) to install nginx"
        fi
    fi
    ensure_wireguard_tools_version
    have systemctl || die "systemd (systemctl) not found — required for both modes"
}

install_docker() {
    # Primary path: Docker's own convenience script — same one-liner the
    # selfApi orchestrator's ensure_docker() reuses (C8: "mesmo script,
    # consistência"), so both callers install docker identically. On Oracle
    # Linux this script sometimes fails to recognize the distro by name; the
    # fallback below installs the official CentOS/RHEL docker-ce repo
    # instead, which is binary-compatible with EL9/Oracle Linux.
    log "docker not found, installing (official convenience script)"
    if curl -fsSL https://get.docker.com | sh; then
        return 0
    fi
    if have dnf; then
        log "get.docker.com failed — falling back to docker-ce repo (centos/EL9-compatible)"
        dnf install -y dnf-plugins-core 2>/dev/null \
            || log "warning: could not install dnf-plugins-core (may already be present)"
        dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo \
            || die "could not add docker-ce repo (OS_ID=${OS_ID} OS_VERSION_ID=${OS_VERSION_ID})"
        dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
            || die "docker-ce install failed via dnf fallback repo (OS_ID=${OS_ID} OS_VERSION_ID=${OS_VERSION_ID})"
        systemctl enable --now docker
        return 0
    fi
    die "docker install failed (get.docker.com) and no dnf fallback available on this distro"
}

step1_deps_agent() {
    log "step 1/6: dependencies (docker, wireguard-tools)"
    if have docker; then
        log "docker already installed, OK"
    else
        install_docker
    fi

    ensure_wireguard_tools_version
    have systemctl || die "systemd (systemctl) not found — required for both modes"
}

download_or_build_binary() {
    # $1 = binary name (deployer-lb-server | deployer-lb-agent)
    # $2 = build tag (lb | agent)
    # $3 = cmd package dir (cmd/apply-server | cmd/agent)
    local name="$1" tag="$2" cmddir="$3"
    local dest="/tmp/${name}.new"

    # Prebuilt binary shipped inside the checkout (the backoffice orchestrator
    # built it on the machine that had a Go toolchain — repo_source.py drops it
    # under $REPO_ROOT/bin/). Prefer it, but only when its stamped version
    # matches this checkout — otherwise repo_source.py dropped it before a
    # `git pull` and "update agent" would silently reinstall a stale binary
    # (no rebuild, no version check) even though the source has moved on.
    local prebuilt="$REPO_ROOT/bin/$name"
    if [[ -f "$prebuilt" ]]; then
        local checkout_ver prebuilt_ver
        checkout_ver="$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
        prebuilt_ver="$("$prebuilt" -v 2>/dev/null | awk '{print $2}')"
        if [[ "$prebuilt_ver" == "$checkout_ver" ]]; then
            log "using prebuilt binary shipped in checkout: $prebuilt (version $prebuilt_ver)"
            echo "$prebuilt"
            return 0
        fi
        log "prebuilt binary $prebuilt is stale (version '$prebuilt_ver', checkout is '$checkout_ver') — ignoring it"
    fi

    log "fetching binary: trying GH release first, falling back to local go build"
    # Release assets are published per-arch (name-linux-<goarch>, matching the
    # cross-compile matrix repo_source.py already builds for): a single
    # arch-less asset name would silently serve the wrong binary on a
    # non-amd64 host.
    local machine goarch
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64) goarch="amd64" ;;
        aarch64|arm64) goarch="arm64" ;;
        *) goarch="" ;;
    esac
    if [[ -n "$goarch" ]] && curl -fsSL --connect-timeout 10 --max-time 30 -o "$dest" "${GH_RELEASE_BASE_URL}/${name}-linux-${goarch}" 2>/dev/null && [[ -s "$dest" ]]; then
        log "downloaded ${name}-linux-${goarch} from GH release"
        chmod +x "$dest"
        echo "$dest"
        return 0
    fi

    log "GH release unavailable (expected until a release is published — TODO D10), building locally"
    have go || die "no GH release reachable and no local Go toolchain (go) to build ${name} from ${cmddir}"
    [[ -d "$REPO_ROOT/$cmddir" ]] || die "cannot build: $REPO_ROOT/$cmddir does not exist yet"
    # Stamp the build version so `<binary> -v` and the report/status payloads
    # can identify what is installed. A future GH release pipeline (TODO D10)
    # must inject the same ldflags.
    local ver
    ver="$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo dev)"
    ( cd "$REPO_ROOT" && go build -tags "$tag" \
        -ldflags "-X github.com/tomneto/deployer-lb-server/internal/version.Version=${ver}" \
        -o "$dest" "./$cmddir" )
    echo "$dest"
}

# ---------------------------------------------------------------------------
# Step 2 — WireGuard (D20)
# ---------------------------------------------------------------------------
#
# "instala se faltar; gera o par de chaves no host (a privada nunca sai
# dele); se já estiver configurado, só valida (handshake + ping)."

ensure_wg_installed() {
    have wg || die "wg (wireguard-tools) missing — step 1 should have installed it"
}

# Oracle Linux 9 ships firewalld active by default (unlike most Ubuntu cloud
# images, which rely on the provider's security group instead) — without
# this, nothing ever reaches the WireGuard hub or nginx on an OL9 LB. A
# no-op everywhere firewalld isn't running, so it never fights a cloud
# provider's own security group on Ubuntu.
# $1 = port, $2 = protocol (tcp|udp)
open_firewalld_port() {
    have firewall-cmd || return 0
    systemctl is-active --quiet firewalld || return 0
    local port="$1" proto="$2"
    if firewall-cmd --query-port="${port}/${proto}" >/dev/null 2>&1; then
        return 0
    fi
    log "firewalld active — opening ${port}/${proto}"
    firewall-cmd --permanent --add-port="${port}/${proto}" \
        && firewall-cmd --reload \
        || log "warning: could not open ${port}/${proto} on firewalld"
}

# SELinux is Enforcing by default on Oracle Linux 9. Best-effort baseline,
# not an exhaustive AVC list — `ausearch -m avc` after a real run is how any
# remaining denial gets found. No-op (and safe to call unconditionally) on
# Ubuntu, where SELinux is normally absent.
# $@ = paths to relabel (restorecon)
ensure_selinux_compat() {
    have getenforce || return 0
    [[ "$(getenforce)" != "Disabled" ]] || return 0
    log "SELinux active — applying best-effort compat${1:+ (relabeling $*)}"
    have setsebool && setsebool -P httpd_can_network_connect on 2>/dev/null
    if have restorecon && [[ $# -gt 0 ]]; then
        restorecon -Rv "$@" >/dev/null 2>&1 || true
    fi
}

ensure_wg_keypair() {
    local dir="/etc/wireguard"
    mkdir -p "$dir"
    chmod 700 "$dir"
    if [[ -s "$dir/privatekey" && -s "$dir/publickey" ]]; then
        log "WireGuard keypair already present, reusing (private key never leaves this host)"
    else
        log "generating new WireGuard keypair"
        umask 077
        wg genkey | tee "$dir/privatekey" | wg pubkey > "$dir/publickey"
    fi
    WG_PUBKEY="$(cat "$dir/publickey")"
    log "WireGuard public key: $WG_PUBKEY (send this back to the central for peering)"
}

wg_iface_configured() {
    ip link show "$WG_IFACE" >/dev/null 2>&1
}

# $1 = comma-separated pubkey:ip (lb peers) or pubkey:endpoint (agent hub)
parse_peer_list() {
    local list="$1"
    [[ -n "$list" ]] || return 0
    IFS=',' read -ra _pairs <<< "$list"
    for pair in "${_pairs[@]}"; do
        echo "$pair"
    done
}

# Emits [Peer] blocks from the union of $WG_PEERS (hub-style: spokes dialing
# in, AllowedIPs=<ip>/32, no endpoint) and $WG_HUB (peer-style: hub(s) this
# host dials out to, Endpoint + AllowedIPs=0.0.0.0/0 + PersistentKeepalive) —
# whichever are non-empty. A dual-role host (registered as both server and
# load_balancer) needs both sets in the same wg0.conf regardless of which
# mode's setup.sh invocation actually writes the file (whichever runs first
# wins, per wg_iface_configured() above — the other invocation only
# validates). Single-role hosts are unaffected: the list that doesn't apply
# to them is simply passed empty and this emits nothing for it.
write_wg_peer_blocks() {
    while IFS=: read -r pubkey ip; do
        [[ -n "$pubkey" ]] || continue
        echo ""
        echo "[Peer]"
        echo "PublicKey = ${pubkey}"
        echo "AllowedIPs = ${ip}/32"
    done < <(parse_peer_list "$WG_PEERS")

    while IFS=: read -r pubkey endpoint; do
        [[ -n "$pubkey" ]] || continue
        echo ""
        echo "[Peer]"
        echo "PublicKey = ${pubkey}"
        echo "Endpoint = ${endpoint}"
        echo "AllowedIPs = 0.0.0.0/0"
        echo "PersistentKeepalive = 25"
    done < <(parse_peer_list "$WG_HUB")
}

step2_wireguard_lb() {
    log "step 2/6: WireGuard (hub mode)"
    ensure_wg_installed
    ensure_wg_keypair
    # Hub receives fresh handshakes from spokes — needs the port open inbound.
    # An agent (spoke) never needs this: it only dials out to the hub.
    open_firewalld_port "$WG_PORT" udp

    if wg_iface_configured; then
        log "interface $WG_IFACE already configured — validating only (not touching config)"
        validate_wg_peers
        return 0
    fi

    log "configuring $WG_IFACE as hub (listen-port=$WG_PORT, address=$WG_IP)"
    local conf="/etc/wireguard/${WG_IFACE}.conf"
    {
        echo "[Interface]"
        echo "Address = ${WG_IP}/24"
        echo "ListenPort = ${WG_PORT}"
        echo "PrivateKey = $(cat /etc/wireguard/privatekey)"
        write_wg_peer_blocks
    } > "$conf"
    chmod 600 "$conf"

    systemctl enable --now "wg-quick@${WG_IFACE}" || die "failed to bring up wg-quick@${WG_IFACE}"
    validate_wg_peers
}

step2_wireguard_agent() {
    log "step 2/6: WireGuard (peer mode)"
    ensure_wg_installed
    ensure_wg_keypair

    if wg_iface_configured; then
        log "interface $WG_IFACE already configured — validating only (not touching config)"
        validate_wg_peers
        return 0
    fi

    log "configuring $WG_IFACE as peer of hub(s) (address=$WG_IP)"
    local conf="/etc/wireguard/${WG_IFACE}.conf"
    {
        echo "[Interface]"
        echo "Address = ${WG_IP}/24"
        echo "PrivateKey = $(cat /etc/wireguard/privatekey)"
        write_wg_peer_blocks
    } > "$conf"
    chmod 600 "$conf"

    systemctl enable --now "wg-quick@${WG_IFACE}" || die "failed to bring up wg-quick@${WG_IFACE}"
    validate_wg_peers
}

# Validation = handshake + ping bidirectional (D20). This only *checks*
# state — it never writes config — so it's safe to call unconditionally,
# including on hosts that were configured outside this script.
validate_wg_peers() {
    log "validating WireGuard: handshake + ping per peer on $WG_IFACE"
    local dump
    dump="$(wg show "$WG_IFACE" dump 2>/dev/null || true)"
    if [[ -z "$dump" ]]; then
        log "warning: 'wg show $WG_IFACE dump' returned nothing (interface down or no peers yet)"
        return 0
    fi
    local ok=0 total=0
    while IFS=$'\t' read -r pubkey _psk endpoint allowed_ips latest_hs _rx _tx _keepalive; do
        [[ -n "${pubkey:-}" ]] || continue
        total=$((total + 1))
        local age="never"
        if [[ "${latest_hs:-0}" != "0" ]]; then
            age="$(( $(date +%s) - latest_hs ))s ago"
        fi
        local target="${allowed_ips%%,*}"; target="${target%%/*}"
        local ping_result="skipped (no allowed-ip to target)"
        if [[ -n "$target" && "$target" != "(none)" ]]; then
            if ping -c1 -W1 "$target" >/dev/null 2>&1; then
                ping_result="ok"
                ok=$((ok + 1))
            else
                ping_result="FAILED"
            fi
        fi
        log "  peer ${pubkey:0:12}...  handshake=${age}  ping(${target:-?})=${ping_result}"
    done <<< "$(tail -n +2 <<< "$dump")"
    log "WireGuard validation: ${ok}/${total} peers pingable"
}

# ---------------------------------------------------------------------------
# Step 3 — Binary copy
# ---------------------------------------------------------------------------

step3_binary_lb() {
    log "step 3/6: installing binary to ${BIN_DIR}/deployer-lb-server"
    local tmp
    tmp="$(download_or_build_binary "deployer-lb-server" "lb" "cmd/apply-server")"
    install -m 0755 "$tmp" "${BIN_DIR}/deployer-lb-server"
    rm -f "$tmp"
    ensure_selinux_compat "${BIN_DIR}/deployer-lb-server"
}

step3_binary_agent() {
    log "step 3/6: installing binary to ${BIN_DIR}/deployer-lb-agent"
    local tmp
    tmp="$(download_or_build_binary "deployer-lb-agent" "agent" "cmd/agent")"
    install -m 0755 "$tmp" "${BIN_DIR}/deployer-lb-agent"
    rm -f "$tmp"
    ensure_selinux_compat "${BIN_DIR}/deployer-lb-agent"
}

# ---------------------------------------------------------------------------
# Step 4 — Config
# ---------------------------------------------------------------------------

# The env file deployer-lb-server.service reads (EnvironmentFile=-/etc/
# deployer-lb-server/lb.env) for --addr/--conf-dir/--template/--token/
# --secret — mirrors write_agent_env() below. Without this the unit starts
# with all flags empty (pre-existing gap, unrelated to distro — fixed here
# because step4_config_lb is already the step that owns these paths).
#
# --lb-token/--lb-secret are optional on this script: cmd/apply-server
# requires them to even start (LB_TOKEN/LB_SHARED_SECRET), but the caller
# (selfApi's provisioning.py) does not pass them yet — this writes whatever
# it gets, empty or not, and warns loudly when they're missing rather than
# silently leaving the LB unable to boot.
write_lb_env() {
    mkdir -p /etc/deployer-lb-server
    umask 077
    cat > /etc/deployer-lb-server/lb.env <<EOF
LB_LISTEN_ADDR=${LB_PORT}
NGINX_CONF_DIR=${NGINX_CONF_DIR}
NGINX_TEMPLATE_PATH=${NGINX_TEMPLATE_DIR}/nginx-app.conf.tmpl
LB_TOKEN=${LB_TOKEN}
LB_SHARED_SECRET=${LB_SECRET}
EOF
    chmod 600 /etc/deployer-lb-server/lb.env
    log "wrote /etc/deployer-lb-server/lb.env"
    if [[ -z "$LB_TOKEN" || -z "$LB_SECRET" ]]; then
        log "warning: --lb-token/--lb-secret not provided — deployer-lb-server will refuse to start (LB_TOKEN/LB_SHARED_SECRET required) until lb.env is filled in"
    fi
}

step4_config_lb() {
    log "step 4/6: config (template, snippets, default_server catch-all)"
    mkdir -p "$NGINX_TEMPLATE_DIR" "$NGINX_SNIPPETS_DIR" "$NGINX_CONF_DIR"

    install -m 0644 "$REPO_ROOT/conf/nginx-app.conf.tmpl" "$NGINX_TEMPLATE_DIR/nginx-app.conf.tmpl"
    install -m 0644 "$REPO_ROOT/snippets/cloudflare-real-ip.conf" "$NGINX_SNIPPETS_DIR/cloudflare-real-ip.conf"
    install -m 0644 "$REPO_ROOT/snippets/error-pages.conf" "$NGINX_SNIPPETS_DIR/error-pages.conf"

    # D19: catch-all for hostnames the DNS already resolves but this LB
    # doesn't know about yet — without it nginx falls back to the first
    # server block alphabetically, serving the wrong app.
    local default_conf="$NGINX_CONF_DIR/00-default.conf"
    if [[ -f "$default_conf" ]] && ! grep -q "managed-by: deployer-lb-server" "$default_conf"; then
        log "warning: $default_conf exists and is not managed by us — leaving it untouched"
    else
        cat > "$default_conf" <<'EOF'
# managed-by: deployer-lb-server (default_server catch-all — D19)
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
EOF
        log "wrote default_server catch-all at $default_conf"
    fi

    write_lb_env
    open_firewalld_port 80 tcp
    open_firewalld_port 443 tcp
    ensure_selinux_compat /etc/nginx "$NGINX_TEMPLATE_DIR" "$NGINX_SNIPPETS_DIR"

    nginx -t || die "nginx -t failed after installing template/snippets/catch-all"
}

step4_config_agent() {
    log "step 4/6: config (iptables-bootstrap.sh, .env)"

    local bootstrap="$IPTABLES_BOOTSTRAP_SCRIPT"
    if [[ -z "$bootstrap" ]]; then
        # Look for it alongside this checkout first (monorepo dev layout),
        # then fall back to the sibling selfApi checkout used in this repo's
        # own dev environment. Neither is guaranteed on a fresh target host.
        for candidate in \
            "$REPO_ROOT/iptables-bootstrap.sh" \
            "$REPO_ROOT/../selfApi/iptables-bootstrap.sh"
        do
            [[ -f "$candidate" ]] && { bootstrap="$candidate"; break; }
        done
    fi

    if [[ -n "$bootstrap" && -f "$bootstrap" ]]; then
        log "running iptables-bootstrap.sh from $bootstrap"
        bash "$bootstrap"
    else
        log "TODO: iptables-bootstrap.sh not found (checked --iptables-bootstrap, repo root, ../selfApi) — DNAT chain for blue-green must be provisioned manually or via --iptables-bootstrap=<path>"
    fi

    write_agent_env
}

# Shared by agent mode's step 4 and lb mode's extra agent install: writes the
# exact same env file the agent unit reads (EnvironmentFile= in
# systemd/deployer-lb-agent.service), so an agent on an LB host is configured
# identically to one on an app server.
write_agent_env() {
    mkdir -p /etc/deployer-lb-agent
    umask 077
    cat > /etc/deployer-lb-agent/.env <<EOF
INTAKE_URL=${INTAKE_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${AGENT_TOKEN}
AGENT_INTERVAL=${AGENT_INTERVAL}s
AGENT_WG_IFACE=${WG_IFACE}
AGENT_BUFFER_DIR=/var/lib/deployer-lb-agent/buffer
# Per-container CPU/mem/net/blkio, via \`docker stats --no-stream\`. Written
# explicitly (rather than left to the binary's default of 1) so the knob is
# visible to whoever has to tune this host: it is the only expensive call in a
# report tick — it blocks ~1s and scales with the container count. Set to 0 on a
# host with dozens of containers where it competes with AGENT_INTERVAL; the
# report then ships the container inventory without usage numbers.
AGENT_DOCKER_STATS=${AGENT_DOCKER_STATS}
EOF
    chmod 600 /etc/deployer-lb-agent/.env
    log "wrote /etc/deployer-lb-agent/.env (mode 600, not in any repo)"
}

# ---------------------------------------------------------------------------
# Step 5 — systemd
# ---------------------------------------------------------------------------

step5_systemd_lb() {
    log "step 5/6: systemd unit (deployer-lb-server.service)"
    if [[ -f "$REPO_ROOT/systemd/deployer-lb-server.service" ]]; then
        install -m 0644 "$REPO_ROOT/systemd/deployer-lb-server.service" "$SYSTEMD_DIR/deployer-lb-server.service"
    else
        log "TODO: systemd/deployer-lb-server.service not found yet in this checkout (owned by plan step B1/B3) — skipping unit install, binary was still installed to ${BIN_DIR}"
        return 0
    fi
    systemctl daemon-reload
    systemctl enable --now deployer-lb-server.service
    # enable --now is a no-op on an already-active unit; restart so a re-run
    # of setup.sh actually swaps the running process to the new binary.
    systemctl restart deployer-lb-server.service
}

step5_systemd_agent() {
    log "step 5/6: systemd unit (deployer-lb-agent.service)"
    install -m 0644 "$REPO_ROOT/systemd/deployer-lb-agent.service" "$SYSTEMD_DIR/deployer-lb-agent.service"
    systemctl daemon-reload
    systemctl enable --now deployer-lb-agent.service
    # enable --now is a no-op on an already-active unit; restart so a re-run
    # of setup.sh actually swaps the running process to the new binary.
    systemctl restart deployer-lb-agent.service
}

# ---------------------------------------------------------------------------
# Step 6 — Final validation
# ---------------------------------------------------------------------------

step6_validate_lb() {
    log "step 6/6: validation (health, nginx -t, wg ping)"
    nginx -t || die "nginx -t failed"
    if curl -fsS "http://${LB_PORT}/v1/health" >/dev/null 2>&1; then
        log "GET /v1/health OK"
    else
        log "warning: GET /v1/health did not respond yet (unit may still be starting, or --port doesn't match the listener's bind address)"
    fi
    validate_wg_peers
}

step6_validate_agent() {
    log "step 6/6: validation (handshake+ping, test POST)"
    validate_wg_peers
    validate_agent_intake
}

# Signed test POST to the intake — shared by agent mode's step 6 and lb
# mode's agent install (same HMAC scheme the agent binary itself uses).
validate_agent_intake() {
    local ts body sig
    ts="$(date +%s)"
    body='{"test":true}'
    if have openssl; then
        sig="$(printf '%s%s' "$ts" "$body" | openssl dgst -sha256 -hmac "$AGENT_TOKEN" | awk '{print $NF}')"
        if curl -fsS --connect-timeout 5 --max-time 15 -X POST "$INTAKE_URL" \
            -H "Content-Type: application/json" \
            -H "X-Agent-Id: ${AGENT_ID}" \
            -H "X-Agent-Ts: ${ts}" \
            -H "X-Agent-Token: ${sig}" \
            -d "$body" >/dev/null 2>&1; then
            log "test POST to intake OK"
        else
            log "warning: test POST to intake failed (central may be unreachable yet — the agent unit itself will retry/buffer)"
        fi
    else
        log "warning: openssl not found, skipping signed test POST (agent unit will still run its own signed reports)"
    fi
}

# ---------------------------------------------------------------------------
# Extra step (lb mode) — telemetry agent on the LB host (WS-6)
# ---------------------------------------------------------------------------
#
# LBs report host/ports/procs/units like any other server: install the agent
# binary + env + unit exactly the way agent mode does (reusing its step
# functions), skipping only the parts that don't apply to an LB host (docker
# install, iptables DNAT bootstrap — there is no blue-green swap here).
step_lb_agent() {
    if [[ -z "$INTAKE_URL" || -z "$AGENT_TOKEN" ]]; then
        log "extra step: telemetry agent NOT installed — pass --intake-url and --agent-token to make this LB report like any server (WS-6)"
        return 0
    fi
    log "extra step: installing telemetry agent on this LB (reports like any server)"
    step3_binary_agent
    write_agent_env
    step5_systemd_agent
    validate_agent_intake
}

# ---------------------------------------------------------------------------
# Root elevation
# ---------------------------------------------------------------------------

# setup.sh touches root-owned state (provisioning/nginx/systemd). It must not
# silently run as a non-root user and die with an opaque "Operation not
# permitted" mid-way — instead, when invoked as a normal user it transparently
# re-executes itself through passwordless sudo (NOPASSWD), and fails up front
# with actionable guidance when that isn't available. This is the belt-against-
# suspenders guard for the central's preflight (selfApi provisioning.py, step
# "ssh_provision"): the preflight catches plain non-root users before cloning,
# this catches every other path (manual runs, drift repair, future callers).
elevate_to_root() {
    if [[ "$(id -u)" -eq 0 ]]; then
        return 0
    fi
    if have sudo && sudo -n true 2>/dev/null; then
        # We hold passwordless sudo and the current user isn't root — re-exec
        # the exact same script as root, preserving the original argv (mode +
        # flags) so the re-run lands directly in main() below.
        log "not root — re-executing through passwordless sudo"
        exec sudo -n bash "$0" "${SCRIPT_ARGS[@]}"
        # exec never returns on success; if it does, fall through to die.
    fi
    die "this script needs root; the current user ($(id -un)) has no passwordless sudo (NOPASSWD). Register the target with a root SSH user or a passwordless-sudo user, or run this command manually as root."
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    elevate_to_root
    detect_os
    case "$MODE" in
        lb)
            step1_deps_lb
            step2_wireguard_lb
            step3_binary_lb
            step4_config_lb
            step5_systemd_lb
            step_lb_agent
            step6_validate_lb
            ;;
        agent)
            step1_deps_agent
            step2_wireguard_agent
            step3_binary_agent
            step4_config_agent
            step5_systemd_agent
            step6_validate_agent
            ;;
    esac
    log "done"
}

main "$@"
