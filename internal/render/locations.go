package render

// Vários `location` por vhost — e por que a validação aqui é paranoica.
//
// Até aqui o template emitia UM `location /` apontando para o pool do app.
// Isso não expressa o que um nginx escrito à mão faz: `location ~` regex,
// `location =` exato, `^~` com precedência, vários locations por vhost, e
// `proxy_pass` para um destino que não é pool nenhum. Enquanto for assim,
// migrar um vhost existente para o canal gerido PERDE comportamento, e
// "o painel pode gerenciar este LB" é uma promessa que não se cumpre.
//
// O que torna este arquivo diferente do resto do pacote: tudo aqui vira linha
// de config do nginx VERBATIM, via text/template. Um `;` num caminho fecha a
// diretiva e abre outra; um `}` fecha o bloco; uma quebra de linha começa uma
// diretiva nova. Não é escaping que resolve — é allowlist. Por isso cada
// classe abaixo lista o que PODE existir, e tudo que não está lá é recusado
// sem tentativa de limpeza. Enumerar o que é perigoso é como se perde um
// load balancer.

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// MaxLocations limita o tamanho de um vhost gerado. O corpo de /v1/apply já é
// limitado a ~64KB, mas 64KB cabem centenas de locations, e um vhost com
// centenas de rotas é um erro de quem gerou o payload, não uma intenção.
const MaxLocations = 32

// LocationSpec é um bloco `location`.
//
// `Locations` vazio renderiza o `location /` histórico, byte a byte — a
// compatibilidade não é um ramo separado do template, é esta struct devolvida
// como default. Ver OrderedLocations.
type LocationSpec struct {
	// Matcher é o operador do próprio nginx, verbatim: "", "=", "^~", "~",
	// "~*". Named location ("@nome") é DELIBERADAMENTE recusada: nada neste
	// template salta para uma (`try_files`, `error_page` e afins não são
	// emitidos), então ela renderizaria, passaria no `nginx -t` e não rotearia
	// nada. Suportá-la só faz sentido junto do que salta para ela.
	Matcher string `json:"matcher"`
	Path    string `json:"path"`
	// ProxyPass é um destino externo absoluto. Vazio significa "o pool deste
	// vhost" — quem manda o payload nunca nomeia o pool, então o nome do
	// upstream jamais é escolhido de fora.
	ProxyPass string `json:"proxy_pass,omitempty"`
	// Websocket sobrepõe o flag do vhost para esta rota. Ponteiro para
	// "não declarado" continuar distinto de "declarado false": um vhost
	// websocket com uma rota que explicitamente não é são coisas diferentes
	// de um vhost websocket com uma rota que não disse nada.
	Websocket *bool `json:"websocket,omitempty"`
}

// WantsWebsocket resolve a herança do flag do vhost.
func (l LocationSpec) WantsWebsocket(p Payload) bool {
	if l.Websocket != nil {
		return *l.Websocket
	}
	return p.Websocket
}

// Destination é o argumento do `proxy_pass` desta rota.
//
// Método, e não func de template: uma func no funcMap pode ser chamada do
// template com qualquer argumento, e o funcMap é a superfície que se quer
// pequena. Um método só existe sobre um valor já validado.
func (l LocationSpec) Destination(p Payload) string {
	if l.ProxyPass != "" {
		return l.ProxyPass
	}
	return "http://" + UpstreamName(p.PipelineRef)
}

// defaultLocation é o `location /` de sempre — a rota implícita de um payload
// que não declara nenhuma.
func defaultLocation() LocationSpec {
	return LocationSpec{Matcher: "", Path: "/"}
}

// OrderedLocations devolve as rotas na ordem em que o arquivo deve declará-las.
//
// A precedência do nginx: todos os `=` primeiro; depois ele guarda o prefixo
// mais longo que casa, e um `^~` que casa curto-circuita a busca; depois tenta
// as REGEX **na ordem do arquivo**, e a primeira que casa vence; se nenhuma
// casar, usa o prefixo guardado.
//
// Logo a ordem relativa de `=`, `^~` e prefixo é irrelevante para roteamento
// (agrupá-los é só legibilidade do arquivo gerado), e a ordem das REGEX é
// load-bearing: trocar duas de lugar muda para onde o tráfego vai. Por isso
// `sort.SliceStable` com chave só do grupo — determinístico no agrupamento, e
// preservando exatamente a ordem que o operador escreveu dentro dele.
//
// Não injeta um `location /` catch-all quando o operador declarou rotas: um
// vhost só com `/api` responde 404 em `/`, e isso é decisão de quem escreveu,
// não um descuido para o template corrigir sozinho.
func (p Payload) OrderedLocations() []LocationSpec {
	if len(p.Locations) == 0 {
		return []LocationSpec{defaultLocation()}
	}
	out := make([]LocationSpec, len(p.Locations))
	copy(out, p.Locations)
	sort.SliceStable(out, func(i, j int) bool {
		return matcherGroup(out[i].Matcher) < matcherGroup(out[j].Matcher)
	})
	return out
}

func matcherGroup(m string) int {
	switch m {
	case "=":
		return 0
	case "^~":
		return 1
	case "~", "~*":
		return 3
	default: // prefixo
		return 2
	}
}

var (
	// Caminho de prefixo/exato/^~: caminho de URL comum. Sem `;` `{` `}` `#`
	// espaço `"` `'` nem `$` — `$` fora porque nginx interpola variável em
	// várias posições e um caminho com `$arg_x` é config que se comporta
	// diferente do que está escrito.
	locPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~/-]{0,255}$`)

	// Padrão de location regex. Metacaractere de PCRE é permitido; sintaxe de
	// bloco do nginx não. `{` e `}` ficam de fora mesmo sendo quantificador
	// válido em PCRE: eles terminam um bloco no lexer do nginx, e nenhum
	// quantificador vale esse risco. `$` entra aqui porque numa location regex
	// ele é âncora de fim, não interpolação. `:` entra porque `(?:` é das
	// construções mais comuns num regex real — quem termina diretiva no lexer
	// do nginx é whitespace, `;`, `{` e `}`, e esses seguem fora.
	locRegexRe = regexp.MustCompile(`^[A-Za-z0-9._~/^$()|*+?:\[\]\\-]{1,200}$`)

	// Destino externo. Sem `$` ⇒ sem proxy_pass variável, que muda em silêncio
	// a semântica de resolução do nginx e passa a exigir um `resolver`.
	proxyPassRe = regexp.MustCompile(
		`^https?://[A-Za-z0-9._-]{1,253}(?::[0-9]{1,5})?(?:/[A-Za-z0-9._~/-]{0,200})?$`)

	proxyPassHostRe = regexp.MustCompile(`^https?://([A-Za-z0-9._-]{1,253})(?::([0-9]{1,5}))?`)
)

// hasControlBytes é checagem explícita, redundante com as regexes acima.
//
// Em Go, `$` numa regexp sem `(?m)` ancora no fim do TEXTO, então um `\n`
// final já não passaria. Isto existe para a garantia não depender de quem lê
// saber esse detalhe: a intenção ("nada de controle chega ao arquivo de
// config") fica escrita, e a mensagem de erro fica legível.
func hasControlBytes(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// validateLocations devolve erros legíveis, ou nil. Roda dentro de
// ValidatePayload, ou seja ANTES de qualquer escrita em disco.
func validateLocations(p *Payload) []string {
	if len(p.Locations) == 0 {
		return nil
	}
	var errs []string
	if len(p.Locations) > MaxLocations {
		errs = append(errs, fmt.Sprintf(
			"too many locations: %d (max %d)", len(p.Locations), MaxLocations))
		return errs
	}

	seen := map[string]bool{}
	usesPool := false

	for i, loc := range p.Locations {
		where := fmt.Sprintf("locations[%d]", i)

		if hasControlBytes(loc.Path) || hasControlBytes(loc.ProxyPass) {
			errs = append(errs, where+": control characters are not allowed")
			continue
		}

		switch loc.Matcher {
		case "", "=", "^~":
			if !locPathRe.MatchString(loc.Path) {
				errs = append(errs, fmt.Sprintf(
					"%s: invalid path %q: must match %s", where, loc.Path, locPathRe))
			}
			if strings.Contains(loc.Path, "..") || strings.Contains(loc.Path, "//") {
				errs = append(errs, where+": path must not contain '..' or '//'")
			}
		case "~", "~*":
			if !locRegexRe.MatchString(loc.Path) {
				errs = append(errs, fmt.Sprintf(
					"%s: invalid regex %q: must match %s", where, loc.Path, locRegexRe))
				break
			}
			// Compilar é um segundo filtro, e um estreitamento deliberado: o
			// RE2 de Go não aceita backreference nem lookaround, que o PCRE do
			// nginx aceita. Recusar aqui é perder expressividade real — e o
			// relatório de fidelidade é quem diz, vhost a vhost, que um regex
			// não cabe neste canal, em vez de o apply descobrir em produção.
			if _, err := regexp.Compile(loc.Path); err != nil {
				errs = append(errs, fmt.Sprintf(
					"%s: regex does not compile under Go's RE2 (no backreferences "+
						"or lookaround): %v", where, err))
			}
		default:
			// Inclui "@": ver o comentário de LocationSpec.Matcher.
			errs = append(errs, fmt.Sprintf(
				`%s: invalid matcher %q: must be one of "", "=", "^~", "~", "~*"`,
				where, loc.Matcher))
		}

		key := loc.Matcher + " " + loc.Path
		if seen[key] {
			errs = append(errs, fmt.Sprintf("%s: duplicate location %q", where, key))
		}
		seen[key] = true

		if loc.ProxyPass == "" {
			usesPool = true
			continue
		}
		errs = append(errs, validateProxyPass(where, loc)...)
	}

	// A regra de upstreams deixa de ser "nunca vazio" e passa a ser "não vazio
	// quando alguma rota usa o pool". Um vhost 100% externo não tem backend
	// deste sistema, e exigir um seria pedir um valor inventado; mas uma rota
	// que cai no pool com `upstreams: []` renderiza `proxy_pass
	// http://x_pool;` para um upstream que o arquivo não declara, e o nginx
	// recusa a config inteira.
	if usesPool && len(p.Upstreams) == 0 {
		errs = append(errs,
			"upstreams must not be empty: some location proxies to this app's pool")
	}
	return errs
}

func validateProxyPass(where string, loc LocationSpec) []string {
	var errs []string
	if !proxyPassRe.MatchString(loc.ProxyPass) {
		return append(errs, fmt.Sprintf(
			"%s: invalid proxy_pass %q: must be http(s)://host[:port][/path] "+
				"with no variables", where, loc.ProxyPass))
	}

	m := proxyPassHostRe.FindStringSubmatch(loc.ProxyPass)
	if m == nil {
		return append(errs, where+": could not read proxy_pass host")
	}
	if m[2] != "" {
		port, err := strconv.Atoi(m[2])
		if err != nil || port < 1 || port > 65535 {
			errs = append(errs, fmt.Sprintf("%s: invalid proxy_pass port %q", where, m[2]))
		}
	}
	// Um vhost gerido apontando para 127.0.0.1 no host do LB serve tudo que
	// está bound localmente (métricas, admin, socket de controle) para a
	// internet. Link-local cobre 169.254.169.254, o metadata da nuvem.
	if ip := net.ParseIP(m[1]); ip != nil {
		switch {
		case ip.IsLoopback():
			errs = append(errs, where+
				": proxy_pass to a loopback address would expose whatever is "+
				"bound locally on the load balancer")
		case ip.IsUnspecified():
			errs = append(errs, where+": proxy_pass to an unspecified address")
		case ip.IsLinkLocalUnicast():
			errs = append(errs, where+
				": proxy_pass to a link-local address (cloud metadata lives there)")
		case ip.IsMulticast():
			errs = append(errs, where+": proxy_pass to a multicast address")
		}
	}

	// nginx proíbe proxy_pass com parte de URI dentro de location regex.
	// Dizer isso aqui é melhor que deixar o `nginx -t` dizer pior, mais tarde
	// e com o payload já rejeitado sem retry.
	if loc.Matcher == "~" || loc.Matcher == "~*" {
		if rest := proxyPassHostRe.ReplaceAllString(loc.ProxyPass, ""); rest != "" {
			errs = append(errs, where+
				": nginx forbids a proxy_pass with a URI part inside a regex "+
				"location — drop the path from proxy_pass")
		}
	}
	return errs
}
