// Mexer nos backends de um upstream: acrescentar, remover, ajustar peso.
//
// `SetPoolDown` já sabia tirar o pool INTEIRO de rotação. O que faltava é o
// trabalho miúdo — subiu uma réplica nova, uma máquina saiu, aquele backend
// está recebendo tráfego demais —, e isso continuava sendo SSH.
//
// # Onde está o furo, e não é onde parece
//
// A reação natural é fazer uma allowlist de PARÂMETROS e achar que resolveu.
// Não resolve: o endereço é o campo mais perigoso dos dois, porque é o que
// vem digitado mais livremente. Um `10.0.0.1:80; } server { listen 80;` escapa
// do bloco e reescreve a config inteira, e nenhuma allowlist de nomes de
// parâmetro vê isso passar.
//
// Então os dois lados são validados por FORMA: o endereço contra uma regex
// ancorada, e cada parâmetro contra o shape do VALOR dele — não basta o nome
// estar na lista, `weight=abc` tem de cair também.
//
// # Remover é marcar `down`, por padrão
//
// Mesmo raciocínio do cabeçalho de `pooltoggle.go`: `down` é reversível
// apagando uma palavra, e apagar a linha não é reversível por um botão. Quem
// quiser apagar de verdade passa `hard`, que é uma decisão diferente e tem de
// parecer diferente.
//
// E o upstream não pode ficar vazio: um `upstream` sem nenhum `server` é
// config inválida, o `nginx -t` reprova e o reload falha. Isso é recusado
// ANTES de escrever, em vez de descoberto no rollback.
package nginx

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// backendAddrRe aceita `host:porta`, `[v6]:porta` e `unix:/caminho`.
//
// Ancorada nas duas pontas de propósito: sem o `$`, tudo que vier depois de um
// endereço válido passa — que é exatamente como a injeção entra.
var backendAddrRe = regexp.MustCompile(
	`^(?:unix:/[^\s;{}'"]+|\[[0-9a-fA-F:]+\](?::\d{1,5})?|[A-Za-z0-9_.-]+:\d{1,5})$`)

// backendParams é o que este editor sabe escrever, com o shape do valor.
//
// `nil` quer dizer parâmetro sem valor (`backup`, `down`). Um nome fora deste
// mapa é recusado — não porque todo o resto seja perigoso, mas porque o que
// este editor não sabe ler ele não deve reescrever: a linha original é
// preservada inteira nesse caso.
var backendParams = map[string]*regexp.Regexp{
	"weight":       regexp.MustCompile(`^[1-9]\d*$`),
	"max_fails":    regexp.MustCompile(`^\d+$`),
	"fail_timeout": regexp.MustCompile(`^\d+[smhdwMy]?$`),
	"max_conns":    regexp.MustCompile(`^\d+$`),
	"slow_start":   regexp.MustCompile(`^\d+[smh]?$`),
	"backup":       nil,
	"down":         nil,
	"resolve":      nil,
}

// BackendSpec é um servidor de upstream como a tela o descreve.
type BackendSpec struct {
	Address string
	Params  map[string]string
}

// PoolEditResult conta o que mudou, e o que sobrou.
type PoolEditResult struct {
	Config  string
	Changed int
	// Remaining é quantas diretivas `server` o bloco tem depois da mudança.
	Remaining int
	// Serving é quantas delas NÃO estão marcadas `down`. Zero significa que o
	// pool parou de atender — e quem pediu a mudança precisa saber disso,
	// porque não foi o que ele pediu.
	Serving int
}

// ValidateBackend recusa o que não deve chegar a um arquivo de config.
func ValidateBackend(spec BackendSpec) error {
	addr := strings.TrimSpace(spec.Address)
	if addr == "" {
		return fmt.Errorf("endereço vazio")
	}
	if !backendAddrRe.MatchString(addr) {
		return fmt.Errorf("endereço inválido: %q — esperado `host:porta`, "+
			"`[ipv6]:porta` ou `unix:/caminho`", spec.Address)
	}
	for name, value := range spec.Params {
		shape, known := backendParams[name]
		if !known {
			return fmt.Errorf("parâmetro não suportado por este editor: %q", name)
		}
		if shape == nil {
			// Parâmetro sem valor. Aceita vazio ou o próprio nome, que é como
			// um checkbox costuma chegar.
			if value != "" && value != name && value != "true" {
				return fmt.Errorf("o parâmetro %q não leva valor", name)
			}
			continue
		}
		if !shape.MatchString(value) {
			return fmt.Errorf("valor inválido para %s: %q", name, value)
		}
	}
	return nil
}

// renderBackend monta a linha, com os parâmetros em ordem estável.
//
// Ordem estável importa para o diff: sem ela, salvar duas vezes sem mudar
// nada produziria arquivos diferentes e o histórico encheria de versões que
// não mudaram coisa alguma.
func renderBackend(indent string, spec BackendSpec) string {
	names := make([]string, 0, len(spec.Params))
	for name := range spec.Params {
		names = append(names, name)
	}
	sort.Strings(names)

	parts := []string{strings.TrimSpace(spec.Address)}
	for _, name := range names {
		if shape := backendParams[name]; shape == nil {
			// Sem valor: só entra se estiver realmente ligado.
			if spec.Params[name] == "" && name != "" {
				continue
			}
			parts = append(parts, name)
			continue
		}
		parts = append(parts, name+"="+spec.Params[name])
	}
	return fmt.Sprintf("%sserver %s;", indent, strings.Join(parts, " "))
}

// poolBody localiza o corpo do upstream e devolve as linhas dele.
func poolBody(conf, pool string) (start, end int, lines []string, err error) {
	if strings.TrimSpace(pool) == "" {
		return 0, 0, nil, fmt.Errorf("pool name is empty")
	}
	loc := upstreamBlockRe(pool).FindStringIndex(conf)
	if loc == nil {
		return 0, 0, nil, fmt.Errorf("upstream %q not found", pool)
	}
	closing, err := MatchBrace(conf, loc[1]-1)
	if err != nil {
		return 0, 0, nil, fmt.Errorf("upstream %q is not closed", pool)
	}
	return loc[1], closing, strings.Split(conf[loc[1]:closing], "\n"), nil
}

// countBackends conta diretivas `server` e quantas servem.
func countBackends(lines []string) (total, serving int) {
	for _, line := range lines {
		m := serverLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		total++
		if !hasDownParam(m[2]) {
			serving++
		}
	}
	return total, serving
}

// addrOf extrai o endereço de uma diretiva `server`, para casar com o alvo.
func addrOf(params string) string {
	fields := strings.Fields(params)
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// indentOf devolve a indentação usada pelos backends do bloco, para a linha
// nova nascer alinhada com as vizinhas em vez de encostada na margem.
func indentOf(lines []string) string {
	for _, line := range lines {
		if m := serverLineRe.FindStringSubmatch(line); m != nil {
			return m[1]
		}
	}
	return "        "
}

func finish(conf string, start, end int, lines []string, changed int) PoolEditResult {
	total, serving := countBackends(lines)
	return PoolEditResult{
		Config:    conf[:start] + strings.Join(lines, "\n") + conf[end:],
		Changed:   changed,
		Remaining: total,
		Serving:   serving,
	}
}

// AddPoolServer acrescenta um backend ao upstream.
func AddPoolServer(conf, pool string, spec BackendSpec) (PoolEditResult, error) {
	res := PoolEditResult{Config: conf}
	if err := ValidateBackend(spec); err != nil {
		return res, err
	}
	start, end, lines, err := poolBody(conf, pool)
	if err != nil {
		return res, err
	}
	addr := strings.TrimSpace(spec.Address)
	for _, line := range lines {
		if m := serverLineRe.FindStringSubmatch(line); m != nil && addrOf(m[2]) == addr {
			return res, fmt.Errorf("o backend %s já está neste pool", addr)
		}
	}

	// Entra depois do último `server`, não no fim do bloco: `keepalive` e
	// afins costumam fechar o upstream, e uma diretiva `server` depois deles
	// continua válida mas quebra a leitura de quem abrir o arquivo.
	indent := indentOf(lines)
	insert := 0
	for i, line := range lines {
		if serverLineRe.MatchString(line) {
			insert = i + 1
		}
	}
	novo := renderBackend(indent, spec)
	lines = append(lines[:insert], append([]string{novo}, lines[insert:]...)...)
	return finish(conf, start, end, lines, 1), nil
}

// RemovePoolServer tira um backend de rotação — ou do arquivo, com `hard`.
//
// O padrão é marcar `down`, e não apagar: é reversível apagando uma palavra, e
// quem apagou a linha não tem botão para desfazer. Apagar de verdade é uma
// decisão diferente e tem de ser pedida por nome.
func RemovePoolServer(conf, pool, address string, hard bool) (PoolEditResult, error) {
	res := PoolEditResult{Config: conf}
	start, end, lines, err := poolBody(conf, pool)
	if err != nil {
		return res, err
	}
	addr := strings.TrimSpace(address)
	total, _ := countBackends(lines)

	achou := -1
	for i, line := range lines {
		if m := serverLineRe.FindStringSubmatch(line); m != nil && addrOf(m[2]) == addr {
			achou = i
			break
		}
	}
	if achou < 0 {
		return res, fmt.Errorf("o backend %s não está neste pool", addr)
	}

	if hard {
		if total <= 1 {
			// Um `upstream` sem nenhum `server` é config inválida: o nginx
			// recusa e o reload falha. Recusar aqui é melhor que descobrir no
			// rollback.
			return res, fmt.Errorf("este é o último backend de %s — um upstream "+
				"vazio não passa no nginx -t", pool)
		}
		lines = append(lines[:achou], lines[achou+1:]...)
		return finish(conf, start, end, lines, 1), nil
	}

	m := serverLineRe.FindStringSubmatch(lines[achou])
	if hasDownParam(m[2]) {
		return finish(conf, start, end, lines, 0), nil
	}
	lines[achou] = fmt.Sprintf("%sserver %s down;%s", m[1], m[2], m[3])
	return finish(conf, start, end, lines, 1), nil
}

// SetPoolServerParams reescreve os parâmetros de um backend.
//
// Só a linha daquele backend é tocada, e ela é remontada a partir do endereço
// mais os parâmetros validados — o que significa que um parâmetro que este
// editor não conhece SERIA PERDIDO. Por isso a função recusa quando a linha
// atual tem algo fora do mapa: perder `slow_start` em silêncio seria pior que
// não deixar editar.
func SetPoolServerParams(conf, pool, address string, params map[string]string) (PoolEditResult, error) {
	res := PoolEditResult{Config: conf}
	spec := BackendSpec{Address: address, Params: params}
	if err := ValidateBackend(spec); err != nil {
		return res, err
	}
	start, end, lines, err := poolBody(conf, pool)
	if err != nil {
		return res, err
	}
	addr := strings.TrimSpace(address)

	for i, line := range lines {
		m := serverLineRe.FindStringSubmatch(line)
		if m == nil || addrOf(m[2]) != addr {
			continue
		}
		// O que já está na linha e este editor não sabe reescrever.
		for _, field := range strings.Fields(m[2])[1:] {
			name := field
			if idx := strings.Index(field, "="); idx >= 0 {
				name = field[:idx]
			}
			if _, known := backendParams[name]; !known {
				return res, fmt.Errorf("o backend %s usa %q, que este editor não "+
					"expressa — editá-lo aqui perderia essa diretiva", addr, name)
			}
		}
		nova := renderBackend(m[1], spec) + m[3]
		if nova == line {
			return finish(conf, start, end, lines, 0), nil
		}
		lines[i] = nova
		return finish(conf, start, end, lines, 1), nil
	}
	return res, fmt.Errorf("o backend %s não está neste pool", addr)
}
