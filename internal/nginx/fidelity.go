package nginx

// "O painel consegue reproduzir este vhost?" — e, quando não, o que exatamente
// se perderia.
//
// Por que isto NÃO mora em inventory.go: aquele arquivo é tolerante por
// contrato ("anything it fails to recognise is simply left out rather than
// guessed"), e é isso que o mantém útil para desenhar uma tela. Fidelidade tem
// o contrato oposto — tudo tem de ser contabilizado, e o que não for
// reconhecido conta CONTRA. Dois arquivos com cabeçalhos opostos é o ponto;
// um arquivo com os dois contratos é como o comportamento lossy vaza para o
// lado estrito e um relatório passa a tranquilizar em vez de informar.
//
// O que este arquivo nunca pode fazer: emitir um payload pronto para aplicar.
// No instante em que fizer, alguém aplica, e um classificador construído sobre
// leitura tolerante vira escritor de config de produção. Ele nomeia o que se
// perderia; quem escreve o `lb_options` é uma pessoa.

import (
	"regexp"
	"sort"
	"strings"

	"github.com/tomneto/deployer-lb-server/internal/render"
)

// Os três vereditos.
const (
	// VerdictReproducible: o template gera este vhost sem perder nada. Exige
	// também que cada location passe na MESMA validação do caminho de escrita
	// — é o acoplamento que impede o relatório de liberar o que o listener
	// recusaria.
	VerdictReproducible = "reproducible"
	// VerdictWithLoss: dá para gerar, mas alguma coisa muda de valor ou some.
	VerdictWithLoss = "reproducible_with_loss"
	// VerdictNot: tem diretiva que o template não expressa de jeito nenhum —
	// ou que este classificador não reconheceu, que dá no mesmo para quem
	// precisa decidir se migra.
	VerdictNot = "not_reproducible"
)

// Finding é uma diretiva que atrapalha, com onde e quantas vezes.
type Finding struct {
	Directive string `json:"directive"` // primeiro token, verbatim
	Context   string `json:"context"`   // "server" ou `location ~ \.php$`
	Count     int    `json:"count"`
	Line      int    `json:"line"` // primeira ocorrência, 1-based no dump
	Reason    string `json:"reason"`
	Raw       string `json:"raw,omitempty"` // a linha, truncada
}

// VhostFidelity é o veredito de um `server {}`.
type VhostFidelity struct {
	File        string   `json:"file"`
	App         string   `json:"app,omitempty"`
	Managed     bool     `json:"managed"`
	ServerNames []string `json:"server_names"`
	Verdict     string   `json:"verdict"`
	// Blockers impedem; Losses deixam reproduzir com mudança de comportamento.
	// Separados porque as decisões que eles pedem são diferentes: uma é "não
	// migre", a outra é "migre sabendo o que muda".
	Blockers []Finding `json:"blockers"`
	Losses   []Finding `json:"losses"`
	Matched  []string  `json:"matched"`
	// UnparsedLines conta o que nem deu para tokenizar. Existe para o número
	// ficar VISÍVEL: `applyLocationLine` (inventory.go) descarta o que não
	// entende em silêncio, e silêncio aqui seria o relatório mentindo por
	// omissão.
	UnparsedLines int `json:"unparsed_lines"`
}

var (
	fidLocationRe  = regexp.MustCompile(`^location\s+(?:(=|~\*|~|\^~)\s+)?(\S+)\s*\{`)
	fidDirectiveRe = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\s*(.*?);$`)
	// Diretiva que ABRE bloco — `if (...) {`, `limit_except GET {`. Sem isto
	// elas caem em UnparsedLines: continuam bloqueando (que é o certo), mas o
	// relatório diria "4 linhas não interpretadas" onde podia dizer "`if` em
	// server". O veredito seria o mesmo e a utilidade, não.
	fidBlockRe = regexp.MustCompile(`^([a-zA-Z_][a-zA-Z0-9_]*)\s*(.*?)\s*\{$`)
)

// expressible lista o que o template de fato emite hoje.
//
// O valor importa tanto quanto o nome: `client_max_body_size` é diretiva
// expressível, e `client_max_body_size 1g` é um valor que o template não
// produz. Tratar isso como "bate" é o que separaria um relatório verdadeiro de
// um relatório que tranquiliza. Por isso cada entrada diz se qualquer valor
// serve, ou quais.
//
// nil ⇒ qualquer valor (o template parametriza essa diretiva).
var expressible = map[string][]string{
	"server_name":                nil,
	"proxy_pass":                 nil,
	"proxy_connect_timeout":      nil,
	"proxy_read_timeout":         nil,
	"proxy_send_timeout":         nil,
	"limit_req":                  nil,
	"limit_req_zone":             nil,
	"limit_req_status":           nil,
	"proxy_cache":                nil,
	"proxy_cache_path":           nil,
	"proxy_cache_valid":          nil,
	"proxy_cache_use_stale":      nil,
	"keepalive":                  nil,
	"keepalive_timeout":          nil,
	"listen":                     {"80"},
	"underscores_in_headers":     {"on"},
	"client_max_body_size":       {"100m"},
	"proxy_http_version":         {"1.1"},
	"proxy_pass_request_headers": {"on"},
	"proxy_next_upstream":        {"error timeout http_502 http_503 http_504"},
	"proxy_next_upstream_tries":  {"2"},
	"include": {
		"snippets/error-pages.conf",
		"snippets/cloudflare-real-ip.conf",
	},
	"add_header": {"X-Cache-Status $upstream_cache_status"},
	"proxy_set_header": {
		`Connection ""`,
		"Host $host",
		"X-Real-IP $remote_addr",
		"X-Forwarded-For $proxy_add_x_forwarded_for",
		"X-Forwarded-Proto $scheme",
		"Upgrade $http_upgrade",
		`Connection "upgrade"`,
	},
}

// blockers: diretivas cuja presença torna o vhost irreproduzível por este
// template, com o motivo em uma frase — o motivo é o que a pessoa lê para
// decidir, e "não suportado" não ajuda ninguém.
var blockers = map[string]string{
	"ssl_certificate":      "TLS termina aqui; o template assume HTTP puro na origem (o cert é da borda)",
	"ssl_certificate_key":  "TLS termina aqui; o template assume HTTP puro na origem",
	"ssl_protocols":        "TLS termina aqui; o template assume HTTP puro na origem",
	"ssl_ciphers":          "TLS termina aqui; o template assume HTTP puro na origem",
	"return":               "resposta sintética (redirect/código fixo); o template só sabe fazer proxy",
	"rewrite":              "reescrita de URI; o template não expressa",
	"try_files":            "cascata de arquivos/fallback; o template não expressa",
	"error_page":           "página de erro própria; o template inclui o snippet padrão e nada mais",
	"auth_basic":           "autenticação na borda; o template não expressa",
	"auth_basic_user_file": "autenticação na borda; o template não expressa",
	"auth_request":         "autorização por subrequest; o template não expressa",
	"satisfy":              "combinação de regras de acesso; o template não expressa",
	"allow":                "regra de acesso por endereço; o template não expressa",
	"deny":                 "regra de acesso por endereço; o template não expressa",
	"if":                   "bloco condicional; o template não expressa",
	"set":                  "variável definida na config; o template não expressa",
	"sub_filter":           "reescrita do corpo da resposta; o template não expressa",
	"alias":                "mapeia a rota para um caminho em disco; o template só faz proxy",
	"root":                 "serve arquivo do disco; o template só faz proxy",
	"index":                "serve arquivo do disco; o template só faz proxy",
	"autoindex":            "listagem de diretório; o template só faz proxy",
	"internal":             "rota só alcançável por redirecionamento interno",
	"limit_except":         "restrição por método HTTP; o template não expressa",
	"grpc_pass":            "proxy gRPC; o template só faz proxy HTTP",
	"fastcgi_pass":         "proxy FastCGI; o template só faz proxy HTTP",
	"uwsgi_pass":           "proxy uWSGI; o template só faz proxy HTTP",
	"scgi_pass":            "proxy SCGI; o template só faz proxy HTTP",
	"resolver":             "resolução DNS em runtime, que acompanha proxy_pass com variável",
	"access_log":           "log próprio deste vhost; o template usa o do servidor",
	"error_log":            "log próprio deste vhost; o template usa o do servidor",
}

// Fidelity classifies every `server {}` in a dump.
//
// Nunca falha: um dump que não dá para ler produz lista vazia, e o chamador
// ainda tem o texto cru. Mas, ao contrário do inventário, o que ele não
// entende DENTRO de um vhost conta contra aquele vhost, em vez de sumir.
func Fidelity(dump string) []VhostFidelity {
	out := []VhostFidelity{}

	var (
		file      string
		managed   bool
		app       string
		cur       *VhostFidelity
		depth     int
		context   = "server"
		locations []render.LocationSpec
		curLoc    *render.LocationSpec
		findings  map[string]*Finding
		isBlocker map[string]bool
	)

	flush := func() {
		if cur == nil {
			return
		}
		cur.Blockers, cur.Losses = splitFindings(findings, isBlocker)
		cur.Verdict = verdictOf(cur, locations)
		sort.Strings(cur.Matched)
		out = append(out, *cur)
		cur, curLoc, findings, isBlocker, locations = nil, nil, nil, nil, nil
		context = "server"
	}

	for n, raw := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(raw)

		if m := fileMarkerRe.FindStringSubmatch(line); m != nil {
			flush()
			file, managed, app, depth = m[1], false, "", 0
			continue
		}
		if cur == nil && depth == 0 && strings.HasPrefix(line, "#") {
			if mm := managedByRe.FindStringSubmatch(line); mm != nil {
				managed, app = true, mm[1]
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if cur == nil {
			if invServerRe.MatchString(line) {
				cur = &VhostFidelity{File: file, Managed: managed, App: app,
					ServerNames: []string{}, Blockers: []Finding{},
					Losses: []Finding{}, Matched: []string{}}
				findings = map[string]*Finding{}
				isBlocker = map[string]bool{}
				locations = []render.LocationSpec{}
				depth = 1
			}
			continue
		}

		depth += strings.Count(line, "{") - strings.Count(line, "}")

		if m := fidLocationRe.FindStringSubmatch(line); m != nil {
			context = strings.TrimSpace("location " + m[1] + " " + m[2])
			loc := render.LocationSpec{Matcher: m[1], Path: m[2]}
			locations = append(locations, loc)
			curLoc = &locations[len(locations)-1]
			// Named location: o template não tem nada que salte para ela, e
			// por isso ela não é expressível — mesmo sendo uma linha que o
			// parser entendeu perfeitamente.
			if strings.HasPrefix(m[2], "@") {
				record(findings, isBlocker, Finding{
					Directive: "location " + m[2], Context: "server", Line: n + 1,
					Reason: "named location: só é alcançada por try_files/error_page, " +
						"que este template não emite",
					Raw: truncate(line),
				}, true)
			}
			continue
		}

		if depth <= 0 {
			flush()
			depth = 0
			continue
		}

		classify(line, n+1, context, curLoc, cur, findings, isBlocker)
		if strings.HasSuffix(line, "}") && depth == 1 {
			context, curLoc = "server", nil
		}
	}
	flush()
	return out
}

// classify põe uma linha em uma das três caixas. O default de token
// desconhecido é BLOQUEIO: "não reconheci" não pode ser lido como "tudo bem".
func classify(line string, lineNo int, context string, curLoc *render.LocationSpec,
	v *VhostFidelity, findings map[string]*Finding, isBlocker map[string]bool) {

	m := fidDirectiveRe.FindStringSubmatch(line)
	if m == nil {
		m = fidBlockRe.FindStringSubmatch(line)
	}
	if m == nil {
		if line == "}" || line == "{" {
			return
		}
		// Não deu nem para tokenizar. Some do relatório como diretiva, mas o
		// CONTADOR aparece — é o que impede o número de linhas analisadas de
		// mentir por omissão.
		v.UnparsedLines++
		return
	}
	name, value := m[1], strings.TrimSpace(m[2])

	if reason, bad := blockers[name]; bad {
		record(findings, isBlocker, Finding{
			Directive: name, Context: context, Line: lineNo,
			Reason: reason, Raw: truncate(line),
		}, true)
		return
	}

	if name == "server" && curLoc == nil {
		// Linha `server <host>:<porta>;` de um bloco upstream — não é deste
		// vhost. Acontece em arquivo que declara os dois.
		return
	}

	if name == "proxy_pass" && curLoc != nil {
		curLoc.ProxyPass = externalProxyPass(value)
	}
	if name == "server_name" {
		v.ServerNames = append(v.ServerNames, strings.Fields(value)...)
	}

	allowed, known := expressible[name]
	if !known {
		record(findings, isBlocker, Finding{
			Directive: name, Context: context, Line: lineNo,
			Reason: "diretiva não classificada — este relatório não afirma " +
				"fidelidade sobre o que não reconhece",
			Raw: truncate(line),
		}, true)
		return
	}
	if allowed == nil {
		v.Matched = appendUnique(v.Matched, name)
		return
	}
	for _, ok := range allowed {
		if value == ok {
			v.Matched = appendUnique(v.Matched, name)
			return
		}
	}
	// Diretiva certa, valor que o template não produz. É perda, não bloqueio:
	// dá para migrar sabendo que este valor muda.
	record(findings, isBlocker, Finding{
		Directive: name, Context: context, Line: lineNo,
		Reason: "o template emite esta diretiva, mas não com este valor — " +
			"migrar trocaria o valor por " + strings.Join(allowed, " | "),
		Raw: truncate(line),
	}, false)
}

// externalProxyPass devolve o destino quando ele NÃO é um upstream local.
//
// Um `proxy_pass http://algum_pool;` aponta para um upstream declarado no
// mesmo arquivo, e no template isso é "o pool deste app" — não um destino
// externo. Confundir os dois faria o relatório validar um ProxyPass que o
// payload nunca carregaria.
func externalProxyPass(value string) string {
	if !strings.Contains(value, ".") && !strings.Contains(value, ":") {
		return ""
	}
	return value
}

func record(findings map[string]*Finding, isBlocker map[string]bool, f Finding, blocker bool) {
	key := f.Directive + "|" + f.Context + "|" + f.Reason
	if ex, ok := findings[key]; ok {
		ex.Count++
		return
	}
	f.Count = 1
	findings[key] = &f
	isBlocker[key] = blocker
}

func splitFindings(findings map[string]*Finding, isBlocker map[string]bool) ([]Finding, []Finding) {
	blockers := []Finding{}
	losses := []Finding{}
	keys := make([]string, 0, len(findings))
	for k := range findings {
		keys = append(keys, k)
	}
	// Ordem estável por linha: o relatório é comparado entre execuções, e um
	// mapa iterado em ordem aleatória faria duas leituras iguais parecerem
	// diferentes.
	sort.Slice(keys, func(i, j int) bool {
		return findings[keys[i]].Line < findings[keys[j]].Line
	})
	for _, k := range keys {
		if isBlocker[k] {
			blockers = append(blockers, *findings[k])
		} else {
			losses = append(losses, *findings[k])
		}
	}
	return blockers, losses
}

// verdictOf fecha o veredito — e `reproducible` tem uma exigência a mais que
// "não achei problema".
func verdictOf(v *VhostFidelity, locations []render.LocationSpec) string {
	if len(v.Blockers) > 0 || v.UnparsedLines > 0 {
		return VerdictNot
	}
	if len(v.Losses) > 0 {
		return VerdictWithLoss
	}
	// O acoplamento com o lado de ESCRITA. Sem ele o relatório poderia dizer
	// "o painel reproduz" sobre um vhost cujo regex o `ValidatePayload`
	// recusaria — e a pessoa descobriria isso só no apply, depois de ter
	// decidido migrar. Mesma função, não uma segunda cópia das regras.
	if len(locations) > 0 {
		probe := render.Payload{
			SchemaVersion:  render.CurrentSchemaVersion,
			Revision:       1,
			IdempotencyKey: "fidelity:probe",
			PipelineRef:    "probe",
			Repo:           "owner/probe",
			Domains:        []string{"probe.invalid"},
			Exposure:       "external",
			Upstreams:      []render.Upstream{{IP: "10.0.0.1", Port: 80}},
			Timeouts:       render.Timeouts{Read: 1, Send: 1, Connect: 1},
			Locations:      locations,
		}
		if errs := render.ValidatePayload(&probe); len(errs) > 0 {
			v.Blockers = append(v.Blockers, Finding{
				Directive: "location", Context: "server", Count: 1,
				Reason: "o canal de escrita recusaria estas rotas: " +
					strings.Join(errs, "; "),
			})
			return VerdictNot
		}
	}
	return VerdictReproducible
}

func appendUnique(xs []string, s string) []string {
	for _, x := range xs {
		if x == s {
			return xs
		}
	}
	return append(xs, s)
}

func truncate(s string) string {
	const max = 160
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
