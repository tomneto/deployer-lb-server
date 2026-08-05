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
#                        --wg-peers <pubkey:ip,...>
#   bash setup.sh agent --intake-url <url> --agent-token <token> \
#                        --interval 8 --wg-ip <wireguard_ip> \
#                        --wg-hub <pubkey:endpoint,...>
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
IPTABLES_BOOTSTRAP_SCRIPT="${IPTABLES_BOOTSTRAP_SCRIPT:-}"

# shared wireguard options
WG_IFACE="wg0"
WG_IP=""
WG_PORT="51820"
WG_PEERS=""   # lb: comma-separated pubkey:ip (peer allowed-ips it dials out to)
WG_HUB=""     # agent: comma-separated pubkey:endpoint (hub(s) to peer with)

BIN_DIR="/usr/local/bin"
SYSTEMD_DIR="/etc/systemd/system"

log()  { printf '[setup.sh][%s] %s\n' "$MODE" "$*" >&2; }
die()  { log "ERROR: $*"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# Arg parsing (both modes share the parser; unknown flags for the current
# mode are just ignored by the case default below so this stays one script)
# ---------------------------------------------------------------------------

while [[ $# -gt 0 ]]; do
    case "$1" in
        --port) LB_PORT="$2"; shift 2 ;;
        --nginx-conf-dir) NGINX_CONF_DIR="$2"; shift 2 ;;
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

install_or_upgrade_wireguard_tools() {
    if have apt-get; then
        apt-get update -y && apt-get install -y --only-upgrade wireguard-tools \
            || apt-get install -y wireguard-tools
    elif have dnf; then
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

step1_deps_agent() {
    log "step 1/6: dependencies (docker, wireguard-tools)"
    if have docker; then
        log "docker already installed, OK"
    else
        log "docker not found, installing (official convenience script)"
        curl -fsSL https://get.docker.com | sh
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

    log "fetching binary: trying GH release first, falling back to local go build"
    if curl -fsSL -o "$dest" "${GH_RELEASE_BASE_URL}/${name}" 2>/dev/null && [[ -s "$dest" ]]; then
        log "downloaded ${name} from GH release"
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
}

step3_binary_agent() {
    log "step 3/6: installing binary to ${BIN_DIR}/deployer-lb-agent"
    local tmp
    tmp="$(download_or_build_binary "deployer-lb-agent" "agent" "cmd/agent")"
    install -m 0755 "$tmp" "${BIN_DIR}/deployer-lb-agent"
    rm -f "$tmp"
}

# ---------------------------------------------------------------------------
# Step 4 — Config
# ---------------------------------------------------------------------------

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

    mkdir -p /etc/deployer-lb-agent
    umask 077
    cat > /etc/deployer-lb-agent/.env <<EOF
INTAKE_URL=${INTAKE_URL}
AGENT_ID=${AGENT_ID}
AGENT_TOKEN=${AGENT_TOKEN}
AGENT_INTERVAL=${AGENT_INTERVAL}s
AGENT_WG_IFACE=${WG_IFACE}
AGENT_BUFFER_DIR=/var/lib/deployer-lb-agent/buffer
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

    local ts body sig
    ts="$(date +%s)"
    body='{"test":true}'
    if have openssl; then
        sig="$(printf '%s%s' "$ts" "$body" | openssl dgst -sha256 -hmac "$AGENT_TOKEN" | awk '{print $NF}')"
        if curl -fsS -X POST "$INTAKE_URL" \
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
# Main
# ---------------------------------------------------------------------------

main() {
    case "$MODE" in
        lb)
            step1_deps_lb
            step2_wireguard_lb
            step3_binary_lb
            step4_config_lb
            step5_systemd_lb
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
