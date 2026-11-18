#!/usr/bin/env bash
#
# Invoca o `setup.sh` DE VERDADE e confere o que ele faz com os argumentos,
# antes de tocar no host.
#
# Existe porque os outros testes deste diretório extraem corpos de função com
# `sed` e os chamam isolados (`extract()` em test-lb-listener-guards.sh) —
# sourcear o arquivo rodaria `main "$@"`. O efeito colateral é que o código de
# TOPO, que é onde mora a validação de argumentos, nunca era executado por
# teste nenhum. Um `validate_net_name` chamado antes de ser definido passou por
# todos eles e parou o provisionamento da frota com exit 127.
#
# Como isto roda sem tocar na máquina: `id` e `sudo` são stubados no PATH para
# que `elevate_to_root` — a PRIMEIRA linha de `main()` — morra com "needs
# root". Ou seja, o script faz o parse inteiro e para na porta do primeiro
# passo. Nada é instalado, nada é escrito.
#
# Usage: bash scripts/test-setup-arg-validation.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
# Aceita um caminho: é assim que se confere que este teste REPROVA uma versão
# quebrada do script, e não só aprova a atual.
SETUP_SH="${1:-$REPO_ROOT/setup.sh}"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

stub_dir="$work/bin"
mkdir -p "$stub_dir"

# Não-root, sempre — inclusive quando a suíte roda dentro de um container.
cat > "$stub_dir/id" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
    -u)  echo 1000 ;;
    -un) echo tester ;;
    *)   echo "uid=1000(tester)" ;;
esac
EOF

# `have sudo` acha este; `sudo -n true` falha; elevate_to_root desiste.
cat > "$stub_dir/sudo" <<'EOF'
#!/usr/bin/env bash
exit 1
EOF
chmod +x "$stub_dir/id" "$stub_dir/sudo"

fail=0

# Roda o setup.sh e devolve "rc|saída combinada".
run_setup() {
    local out rc
    set +e
    out="$(PATH="$stub_dir:$PATH" bash "$SETUP_SH" "$@" 2>&1)"
    rc=$?
    set -e
    printf '%s|%s' "$rc" "$out"
}

check() {
    local desc="$1" want_rc="$2" want_text="$3"; shift 3
    local result rc out
    result="$(run_setup "$@")"
    rc="${result%%|*}"
    out="${result#*|}"

    if [[ "$rc" == 127 ]]; then
        echo "FAIL - $desc: exit 127 — alguma coisa no topo do script não existe ainda"
        echo "$out" | sed 's/^/    /'
        fail=1
        return
    fi
    if [[ "$rc" != "$want_rc" ]]; then
        echo "FAIL - $desc: esperava exit $want_rc, veio $rc"
        echo "$out" | sed 's/^/    /'
        fail=1
        return
    fi
    if [[ "$out" != *"$want_text"* ]]; then
        echo "FAIL - $desc: a saída não cita '$want_text'"
        echo "$out" | sed 's/^/    /'
        fail=1
        return
    fi
    echo "ok - $desc"
}

LB_OK=(lb --port 10.10.0.1:8443 --wg-ip 10.10.0.1 --net-name oci-lb)
AGENT_OK=(agent --intake-url http://10.10.0.1:9000 --agent-token tok --wg-ip 10.10.0.2 --net-name app-1)

# O parse chegou ao fim nos dois modos: parou na elevação, não em 127.
check "lb com argumentos válidos atravessa o parse e para na elevação" \
    1 "needs root" "${LB_OK[@]}"
check "agent com argumentos válidos atravessa o parse e para na elevação" \
    1 "needs root" "${AGENT_OK[@]}"

# A validação de nome de malha de fato executa (não é pulada nem explode).
check "lb recusa um nome de malha fora do formato" \
    1 "rótulo DNS" lb --port 10.10.0.1:8443 --wg-ip 10.10.0.1 --net-name NOME_RUIM
check "agent recusa um nome de malha fora do formato" \
    1 "rótulo DNS" agent --intake-url http://x --agent-token t --wg-ip 10.10.0.2 --net-name com.ponto

# Sem --net-name o passo é opcional: o script segue como antes da malha.
check "lb sem --net-name continua válido" \
    1 "needs root" lb --port 10.10.0.1:8443 --wg-ip 10.10.0.1

# As exigências que já existiam continuam valendo, e com a mensagem delas.
check "lb exige --wg-ip" \
    1 "--wg-ip is required for mode lb" lb --port 10.10.0.1:8443
check "agent exige --intake-url" \
    1 "--intake-url is required for mode agent" agent --agent-token tok --wg-ip 10.10.0.2
check "flag desconhecida é recusada pelo nome" \
    1 "unknown flag: --nao-existe" lb --wg-ip 10.10.0.1 --nao-existe x
check "modo inválido mostra o usage" \
    1 "usage:" banana

exit "$fail"
