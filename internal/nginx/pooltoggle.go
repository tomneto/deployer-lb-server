package nginx

import (
	"fmt"
	"regexp"
	"strings"
)

// Tirar os backends de um upstream de rotação, sem mexer em mais nada.
//
// `down` é o jeito nativo do nginx de fazer isso: a config continua inteira,
// nenhum `location` muda, e voltar atrás é apagar uma palavra. As alternativas
// que foram consideradas — trocar o `proxy_pass` por `return 503`, ou apagar o
// bloco — mexem em N lugares em vez de um, e a segunda nem é reversível por
// um botão: um `proxy_pass` apontando para um upstream que não existe mais faz
// o `nginx -t` falhar, e aí o toggle derrubaria o vhost junto.
//
// Esta é a parte PURA do trabalho: texto entra, texto sai. Quem faz backup,
// valida com `nginx -t`, recarrega e reverte é o handler — e é lá que mora o
// risco, não aqui.

// upstreamBlockRe acha `upstream <nome> {` com o espaçamento que aparece na
// vida real (tab, vários espaços, chave na mesma linha).
func upstreamBlockRe(name string) *regexp.Regexp {
	return regexp.MustCompile(`(?m)^[ \t]*upstream[ \t]+` + regexp.QuoteMeta(name) + `[ \t]*\{`)
}

// serverLineRe captura uma diretiva `server` de dentro de um upstream:
//
//	 indentação  "server"  endereço e parâmetros          ";"  resto da linha
//	\1          	        \2                              \3
//
// O endereço e os parâmetros ficam juntos de propósito: `weight=3 max_fails=2`
// precisa sobreviver intacto, e modelar cada parâmetro aqui seria inventar um
// parser de nginx para escrever uma palavra.
var serverLineRe = regexp.MustCompile(`^([ \t]*)server[ \t]+([^;]+?)[ \t]*;(.*)$`)

// hasDownParam diz se a diretiva já está fora de rotação.
//
// Compara por PALAVRA, não por substring: um backend chamado
// `server downloads.internal:8080;` contém "down" e não está desabilitado —
// marcá-lo como já-desabilitado faria o toggle mentir sobre o estado atual.
func hasDownParam(params string) bool {
	for _, field := range strings.Fields(params) {
		if field == "down" {
			return true
		}
	}
	return false
}

func removeDownParam(params string) string {
	out := make([]string, 0, 4)
	for _, field := range strings.Fields(params) {
		if field == "down" {
			continue
		}
		out = append(out, field)
	}
	return strings.Join(out, " ")
}

// PoolToggleResult reports what actually changed, so the caller can tell the
// difference between "applied" and "there was nothing to do".
type PoolToggleResult struct {
	Config  string
	Changed int
	Total   int
}

// SetPoolDown marks every `server` of one upstream block as `down` (or clears
// it), returning the new config.
//
// Idempotent: calling it twice is a no-op the second time, and `Changed == 0`
// says so. The caller uses that to skip the whole write/validate/reload dance
// when nothing would change — a reload that serves no purpose is still a
// window in which the config could fail to come back.
func SetPoolDown(conf, pool string, down bool) (PoolToggleResult, error) {
	res := PoolToggleResult{Config: conf}
	if strings.TrimSpace(pool) == "" {
		return res, fmt.Errorf("pool name is empty")
	}

	loc := upstreamBlockRe(pool).FindStringIndex(conf)
	if loc == nil {
		return res, fmt.Errorf("upstream %q not found", pool)
	}

	// Walk braces from the block's opening one so a nested block (a `keepalive`
	// zone, a commented brace) cannot end the scan early.
	depth := 0
	end := -1
	for i := loc[1] - 1; i < len(conf); i++ {
		switch conf[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return res, fmt.Errorf("upstream %q is not closed", pool)
	}

	body := conf[loc[1]:end]
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		m := serverLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		indent, params, tail := m[1], m[2], m[3]
		res.Total++

		already := hasDownParam(params)
		if down == already {
			continue
		}
		if down {
			params += " down"
		} else {
			params = removeDownParam(params)
		}
		lines[i] = fmt.Sprintf("%sserver %s;%s", indent, params, tail)
		res.Changed++
	}

	if res.Total == 0 {
		return res, fmt.Errorf("upstream %q has no server directives", pool)
	}
	res.Config = conf[:loc[1]] + strings.Join(lines, "\n") + conf[end:]
	return res, nil
}

// PoolIsDown reports whether every server of the upstream is out of rotation —
// which is what the panel shows as the toggle's position.
//
// "every", not "any": a pool with one of three backends down is a pool that is
// still serving, and showing its toggle as off would be a lie.
func PoolIsDown(conf, pool string) (bool, bool) {
	res, err := SetPoolDown(conf, pool, true)
	if err != nil {
		return false, false
	}
	// Nothing left to change means they were all down already.
	return res.Changed == 0, true
}
