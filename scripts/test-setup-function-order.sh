#!/usr/bin/env bash
#
# Nenhuma linha de código de TOPO do setup.sh pode chamar uma função definida
# mais abaixo no arquivo.
#
# Bash define função enquanto EXECUTA o arquivo, de cima para baixo. Dentro de
# outra função isso não importa — o corpo só roda quando `main` chama, e a essa
# altura o arquivo inteiro já foi lido. No topo importa, e importa calado: a
# chamada vira `command not found`, exit 127, antes de qualquer passo, sem uma
# linha `ERROR:` no log porque `die()` nunca chega a rodar. Foi assim que
# `validate_net_name` parou o provisionamento da frota inteira.
#
# Este é o primo shell do `check:tdz` do frontend: a linguagem aceita, o
# arquivo compila, e morre em runtime no lugar errado.
#
# O que ele deliberadamente NÃO faz: entender aspas. Linha inteira de
# comentário é ignorada, e o que vem depois de um ` #` é cortado — o bastante
# para o topo deste script, que é cabeçalho, parse de flags e `main "$@"`.
#
# Usage: bash scripts/test-setup-function-order.sh
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." &>/dev/null && pwd)"
# Um caminho pode ser passado como argumento: é o que deixa o próprio teste
# ser testado contra uma versão antiga do script (ver o final deste arquivo).
SETUP_SH="${1:-$REPO_ROOT/setup.sh}"

findings="$(awk '
# Definição: `nome() {` na coluna 0. Entra no corpo até um `}` na coluna 0.
/^[a-zA-Z_][a-zA-Z0-9_]*\(\)[ \t]*\{/ {
    name = $0
    sub(/\(\).*/, "", name)
    def[name] = NR
    infunc = 1
    next
}
infunc && /^\}/ { infunc = 0; next }
infunc { next }

# Daqui para baixo: só código de topo.
{
    line = $0
    sub(/^[ \t]+/, "", line)
    if (line ~ /^#/) next          # comentário inteiro
    sub(/[ \t]#.*$/, "", line)     # comentário no fim da linha
    if (line == "") next
    top[NR] = line
}

END {
    for (ln in top) {
        for (f in def) {
            if (top[ln] ~ ("(^|[ \t;&|$(`])" f "([ \t;&|)`]|$)") && ln + 0 < def[f] + 0) {
                printf "setup.sh:%d chama %s(), que só é definida na linha %d\n", ln, f, def[f]
            }
        }
    }
}' "$SETUP_SH" | sort -t: -k2 -n)"

if [[ -n "$findings" ]]; then
    echo "FAIL - função usada no topo antes de ser definida:"
    echo "$findings" | sed 's/^/    /'
    echo
    echo "    Mova a DEFINIÇÃO para cima da chamada. Como está, o setup.sh"
    echo "    morre com exit 127 ('command not found') antes do primeiro passo."
    exit 1
fi

echo "ok - nenhuma função é chamada no topo antes de ser definida"
