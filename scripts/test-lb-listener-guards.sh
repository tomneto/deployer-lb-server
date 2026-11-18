#!/usr/bin/env bash
#
# Unit tests for the three guards that stand between "setup.sh lb finished" and
# "the LB control port actually answers". All three came from the same incident:
# the listener was dead on 10.10.0.1:8443, the central saw only `connection
# refused`, and NOTHING in the provisioning run had said a word.
#
#   write_lb_env             — must NOT pin NGINX_TEMPLATE_PATH to the on-disk
#                              copy. The template is compiled into the binary
#                              (conf/embed.go); pinning the file re-opens the
#                              skew that makes VerifyTemplate() log.Fatal at
#                              boot, which is what killed the port.
#   assert_lb_port_not_public — the control port only ever binds loopback or
#                              the WireGuard address.
#   validate_lb_listener     — a health check that does not answer, on a unit
#                              that is not even starting, is a FAILED run.
#
# Same approach as scripts/test-download-or-build-binary.sh: the real function
# bodies are pulled out of setup.sh (sourcing it would run `main "$@"`), so a
# drift between test and implementation is impossible. No docker, no systemd,
# no root.
#
# Usage: bash scripts/test-lb-listener-guards.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
SETUP_SH="$REPO_ROOT/setup.sh"

MODE="test"
log() { printf '[test][%s] %s\n' "$MODE" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }
# Mesma definição do setup.sh. Sem ela, um `have x` dentro de uma função
# extraída vira "command not found" — que num `if` é só "falso", e o teste
# passa a exercitar um ramo diferente do que pensa estar exercitando.
have() { command -v "$1" >/dev/null 2>&1; }

extract() { eval "$(sed -n "/^$1() {/,/^}/p" "$SETUP_SH")"; }
# Uma espera de verdade deixaria o teste em LB_HEALTH_RETRIES segundos por
# caso; o que importa aqui é a decisão, não o relógio.
sleep() { :; }

extract existing_default_server
extract clear_distro_default_site
extract write_lb_env
extract assert_lb_port_not_public
extract validate_lb_listener
extract unit_failure_context

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

fail=0
ok()     { echo "ok - $1"; }
failed() { echo "FAIL - $1"; fail=1; }

# Roda uma função num subshell e devolve "rc|saída". `die` chama exit, então o
# subshell é o que separa "esta chamada morreu" de "o teste morreu".
run() {
    local out rc
    set +e
    out="$("$@" 2>&1)"
    rc=$?
    set -e
    printf '%s|%s' "$rc" "$out"
}

# --- write_lb_env ----------------------------------------------------------
LB_ENV_DIR="$work/lbenv"
LB_PORT="10.10.0.1:8443"
NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_TEMPLATE_PATH=""
LB_TOKEN="t"
LB_SECRET="s"
write_lb_env >/dev/null 2>&1

env_file="$LB_ENV_DIR/lb.env"
line="$(grep '^NGINX_TEMPLATE_PATH=' "$env_file")"
if [[ "$line" == "NGINX_TEMPLATE_PATH=" ]]; then
    ok "write_lb_env leaves NGINX_TEMPLATE_PATH empty (binary uses its embedded template)"
else
    failed "write_lb_env must not pin a template path, got '$line'"
fi

if grep -q '^LB_LISTEN_ADDR=10.10.0.1:8443$' "$env_file"; then
    ok "write_lb_env carries --port through to LB_LISTEN_ADDR"
else
    failed "LB_LISTEN_ADDR missing or wrong in $env_file"
fi

# O override continua existindo para quem o pede explicitamente.
NGINX_TEMPLATE_PATH="/tmp/alternative.tmpl"
write_lb_env >/dev/null 2>&1
if grep -q '^NGINX_TEMPLATE_PATH=/tmp/alternative.tmpl$' "$env_file"; then
    ok "an explicit NGINX_TEMPLATE_PATH is still honoured"
else
    failed "explicit NGINX_TEMPLATE_PATH override was dropped"
fi
NGINX_TEMPLATE_PATH=""

# --- assert_lb_port_not_public --------------------------------------------
WG_IP="10.10.0.1"

LB_PORT="127.0.0.1:8443"
result="$(run assert_lb_port_not_public)"
[[ "${result%%|*}" == 0 ]] && ok "loopback is accepted" || failed "loopback must be accepted: ${result#*|}"

LB_PORT="10.10.0.7:8443"
result="$(run assert_lb_port_not_public)"
[[ "${result%%|*}" == 0 ]] && ok "an address in the WireGuard /24 is accepted" || failed "wg address must be accepted: ${result#*|}"

LB_PORT="203.0.113.10:8443"
result="$(run assert_lb_port_not_public)"
if [[ "${result%%|*}" != 0 && "${result#*|}" == *"outside the WireGuard network"* ]]; then
    ok "a public address is refused"
else
    failed "a public --port must die, got rc=${result%%|*} out=${result#*|}"
fi

WG_IP=""
LB_PORT="203.0.113.10:8443"
result="$(run assert_lb_port_not_public)"
if [[ "${result%%|*}" != 0 ]]; then
    ok "a non-loopback address with no --wg-ip to check against is refused"
else
    failed "without --wg-ip a non-loopback --port must die"
fi
WG_IP="10.10.0.1"

# --- validate_lb_listener --------------------------------------------------
SYSTEMD_DIR="$work/systemd"
mkdir -p "$SYSTEMD_DIR"
touch "$SYSTEMD_DIR/deployer-lb-server.service"
LB_PORT="10.10.0.1:8443"

stub_dir="$work/bin"
mkdir -p "$stub_dir"
PATH="$stub_dir:$PATH"

write_stub() { printf '#!/usr/bin/env bash\n%s\n' "$2" > "$stub_dir/$1"; chmod +x "$stub_dir/$1"; }
write_stub journalctl 'echo "stub journal line"'

LB_HEALTH_RETRIES=2

# $1 = is-active output, $2 = NRestarts output
stub_systemctl() {
    write_stub systemctl "
[[ \"\$1\" == is-active ]] && { echo $1; exit 3; }
[[ \"\$1\" == show ]] && { echo $2; exit 0; }
echo 'stub status'"
}

# health OK
write_stub curl 'exit 0'
stub_systemctl active 0
result="$(run validate_lb_listener)"
[[ "${result%%|*}" == 0 ]] && ok "a listener answering /v1/health passes" || failed "healthy listener must pass: ${result#*|}"

# health down, unit still starting and not looping -> warning, not fatal
write_stub curl 'exit 7'
stub_systemctl activating 0
result="$(run validate_lb_listener)"
if [[ "${result%%|*}" == 0 && "${result#*|}" == *"still activating"* ]]; then
    ok "a unit that is still activating is a warning, not a failure"
else
    failed "activating unit must warn and pass, got rc=${result%%|*} out=${result#*|}"
fi

# health down, unit dead -> fatal, with the journal attached
stub_systemctl failed 0
result="$(run validate_lb_listener)"
if [[ "${result%%|*}" != 0 && "${result#*|}" == *"not answering"* && "${result#*|}" == *"stub journal line"* ]]; then
    ok "a dead listener fails the run and attaches the journal"
else
    failed "dead listener must die with journal context, got rc=${result%%|*} out=${result#*|}"
fi

# health down, unit "activating" but restarting over and over -> crash loop,
# which is the shape a log.Fatal at boot actually takes. This is the case the
# old warning-only validation let through.
stub_systemctl activating 5
result="$(run validate_lb_listener)"
if [[ "${result%%|*}" != 0 && "${result#*|}" == *"restarts=5"* ]]; then
    ok "a crash-looping listener fails even while systemd calls it activating"
else
    failed "crash loop must die, got rc=${result%%|*} out=${result#*|}"
fi

# --- existing_default_server / clear_distro_default_site -------------------
#
# Dois `default_server` na mesma porta é `nginx -t` vermelho, e foi assim que
# o passo 4 morreu no fixture Ubuntu: o pacote do nginx já traz
# sites-enabled/default. O que se fixa aqui é a decisão — medir pelo dump, e
# remover só o symlink do pacote.

NGINX_CONF_DIR="/etc/nginx/conf.d"
NGINX_SITES_ENABLED="$work/sites-enabled"
mkdir -p "$NGINX_SITES_ENABLED" "$work/sites-available"
touch "$work/sites-available/default"

# $1 = corpo do `nginx -T` (vazio = o dump falha)
stub_nginx_dump() {
    if [[ -z "${1:-}" ]]; then
        write_stub nginx 'exit 1'
        return
    fi
    printf '#!/usr/bin/env bash\ncat <<'"'"'DUMP'"'"'\n%s\nDUMP\n' "$1" > "$stub_dir/nginx"
    chmod +x "$stub_dir/nginx"
}

DUMP_STOCK="# configuration file /etc/nginx/nginx.conf:
http {
# configuration file $work/sites-enabled/default:
server {
    listen 80 default_server;
}"

DUMP_OURS_ONLY="# configuration file /etc/nginx/conf.d/00-default.conf:
server {
    listen 80 default_server;
    return 444;
}"

stub_nginx_dump "$DUMP_STOCK"
got="$(existing_default_server)"
if [[ "$got" == "$work/sites-enabled/default" ]]; then
    ok "existing_default_server aponta o arquivo que declara o default alheio"
else
    failed "esperava o site da distro, veio '$got'"
fi

stub_nginx_dump "$DUMP_OURS_ONLY"
got="$(existing_default_server)"
[[ -z "$got" ]] && ok "o nosso próprio catch-all não conta como rival" \
    || failed "o nosso catch-all foi contado como rival: '$got'"

stub_nginx_dump ""
got="$(existing_default_server)"
[[ "$got" == "?" ]] && ok "dump que não roda responde '?', não 'não há'" \
    || failed "esperava '?' quando o nginx -T falha, veio '$got'"

# O symlink do pacote, intacto: sai da frente.
ln -sf "$work/sites-available/default" "$NGINX_SITES_ENABLED/default"
write_stub dpkg 'exit 0'   # --verify silencioso = conffile intacto
if clear_distro_default_site >/dev/null 2>&1 && [[ ! -e "$NGINX_SITES_ENABLED/default" ]]; then
    ok "o site padrão do pacote é removido, e só o symlink"
else
    failed "o symlink stock deveria ter sido removido"
fi
[[ -f "$work/sites-available/default" ]] \
    && ok "sites-available/default continua lá (a remoção é reversível)" \
    || failed "a remoção apagou o arquivo de verdade"

# Editado à mão: não se toca.
ln -sf "$work/sites-available/default" "$NGINX_SITES_ENABLED/default"
write_stub dpkg 'echo "??5??????   /etc/nginx/sites-available/default"'
if clear_distro_default_site >/dev/null 2>&1; then
    failed "um default editado à mão não pode ser removido"
else
    [[ -L "$NGINX_SITES_ENABLED/default" ]] \
        && ok "default editado à mão é preservado, e a função recusa" \
        || failed "a função recusou mas apagou assim mesmo"
fi

# Sem sites-enabled (família RHEL): nada a fazer, e não é erro de execução.
rm -f "$NGINX_SITES_ENABLED/default"
clear_distro_default_site >/dev/null 2>&1 \
    && failed "sem symlink a função deveria recusar" \
    || ok "host sem sites-enabled: a função apenas recusa, sem tocar em nada"

exit "$fail"
