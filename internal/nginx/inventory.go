package nginx

import (
	"regexp"
	"strconv"
	"strings"
)

// Inventory is what the panel shows about a running nginx: the pools, the
// vhosts, and which of them this listener actually manages.
//
// It is built from `nginx -T`, which is the only source that tells the whole
// truth. Reading conf.d alone would describe what this listener WROTE, and on
// a host whose nginx.conf does not include conf.d those are different things —
// the vhosts serving production traffic can live entirely outside the
// listener's reach, and a panel that showed only managed files would report an
// empty load balancer while nine domains answered requests.
//
// Deliberately tolerant and lossy. This is not an nginx parser and must never
// be used to rewrite config: it answers "what is served here, and by whom",
// and anything it fails to recognise is simply left out rather than guessed.
type Inventory struct {
	Pools  []Pool  `json:"pools"`
	Vhosts []Vhost `json:"vhosts"`
}

// Pool is an `upstream` block: a name and the backends behind it.
type Pool struct {
	Name    string       `json:"name"`
	File    string       `json:"file"`
	Managed bool         `json:"managed"`
	Servers []PoolServer `json:"servers"`
	// Down is true when EVERY backend carries the `down` parameter — the
	// position of the panel's toggle. "every", not "any": a pool with one of
	// three backends out is still serving, and showing it as disabled would
	// be a lie.
	Down bool `json:"down"`

	// Mesmo papel que em Vhost: um upstream dentro de uma cerca. `Down` e
	// `Disabled` são estados DIFERENTES e a tela não pode achatá-los — um
	// pool `down` continua declarado e o nginx o lê; um pool desligado não
	// existe para o nginx, e um `proxy_pass` que ainda aponte para ele faz o
	// reload falhar.
	Disabled   bool   `json:"disabled,omitempty"`
	DisabledID string `json:"disabled_id,omitempty"`
	DisabledAt string `json:"disabled_at,omitempty"`
	DisabledBy string `json:"disabled_by,omitempty"`
}

type PoolServer struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Raw keeps whatever followed the address (weight, max_fails, backup…),
	// so the panel can show it without this struct having to model it.
	Raw string `json:"raw,omitempty"`
	// Down mirrors the nginx `down` parameter on this one backend.
	Down bool `json:"down,omitempty"`
	// Healthy is a TCP probe result, filled in by the handler and not by the
	// parser — a pointer so that "not measured" stays distinct from "refused
	// the connection". Those two mean opposite things to whoever is looking
	// at a backend that stopped serving, and a plain bool would collapse them.
	//
	// TCP only: it says the address accepts a connection, never that the
	// application answers 200. The panel must word it that way.
	Healthy *bool `json:"healthy,omitempty"`
}

// Vhost is a `server` block.
type Vhost struct {
	ServerNames []string   `json:"server_names"`
	Listen      []string   `json:"listen"`
	File        string     `json:"file"`
	Managed     bool       `json:"managed"`
	App         string     `json:"app,omitempty"`
	Locations   []Location `json:"locations"`

	// Disabled e companhia descrevem um bloco que está DENTRO de uma cerca —
	// comentado, portanto invisível ao nginx, e visível só aqui.
	//
	// Precisam existir porque este parser descarta comentário: sem eles, o
	// vhost desligado some da tela, e o que some da tela não tem como ser
	// religado. Um bloco desligado continua listado, na mesma posição (ordem
	// de arquivo é ordem de resolução do nginx), com a procedência que a cerca
	// guarda. `DisabledBy` é ALEGADO, nunca verificado — o HMAC autentica o
	// painel, não a pessoa, e a tela precisa dizer isso.
	Disabled   bool   `json:"disabled,omitempty"`
	DisabledID string `json:"disabled_id,omitempty"`
	DisabledAt string `json:"disabled_at,omitempty"`
	DisabledBy string `json:"disabled_by,omitempty"`

	// Ref é o endereço deste bloco, opaco: o painel o devolve verbatim para
	// dizer em QUAL bloco mexer. Vazio num vhost desligado, que é endereçado
	// pelo id da cerca (`DisabledID`) e não por conteúdo.
	Ref string `json:"ref,omitempty"`
}

// Location is one `location` block inside a vhost.
//
// `Matcher` is nginx's own operator — "" (prefix), "=", "~", "~*", "^~" or a
// named location starting with "@". The panel shows it verbatim instead of
// translating: an operator mistranslated is a routing bug, and the people
// reading this screen know nginx.
type Location struct {
	Matcher   string `json:"matcher"`
	Path      string `json:"path"`
	ProxyPass string `json:"proxy_pass,omitempty"`
	// Pool is set when ProxyPass points at an upstream declared in this same
	// config, which is what lets the panel link a route to its backends.
	Pool      string `json:"pool,omitempty"`
	Websocket bool   `json:"websocket,omitempty"`
	Root      string `json:"root,omitempty"`

	// Mesmo papel que em Vhost: um `location` dentro de uma cerca. Ele
	// precisa continuar aparecendo, e por um motivo mais agudo que o do
	// vhost — uma rota desligada não derruba o domínio, ela MOVE o tráfego
	// para o location mais genérico que casa. Some da tela e ninguém
	// entende por que `/api` virou a home.
	Disabled   bool   `json:"disabled,omitempty"`
	DisabledID string `json:"disabled_id,omitempty"`
	DisabledAt string `json:"disabled_at,omitempty"`
	DisabledBy string `json:"disabled_by,omitempty"`
	Ref        string `json:"ref,omitempty"`
}

var (
	// fileMarkerRe e managedByRe são de legacy.go: é o mesmo dump e a mesma
	// pergunta ("de quem é este arquivo"), então duplicar o padrão aqui seria
	// criar duas respostas que divergem no dia em que uma mudar.
	invUpstreamRe = regexp.MustCompile(`^upstream\s+(\S+)\s*\{`)
	invServerRe   = regexp.MustCompile(`^server\s*\{`)
	invSrvNameRe  = regexp.MustCompile(`^server_name\s+([^;]+);`)
	invListenRe   = regexp.MustCompile(`^listen\s+([^;]+);`)
	invLocationRe = regexp.MustCompile(`^location\s+(?:(=|~\*|~|\^~)\s+)?(\S+)\s*\{`)
	invProxyRe    = regexp.MustCompile(`^proxy_pass\s+([^;]+);`)
	invRootRe     = regexp.MustCompile(`^root\s+([^;]+);`)
	invBackendRe  = regexp.MustCompile(`^server\s+([^\s;]+?):(\d+)\s*([^;]*);`)
	invUpgradeRe  = regexp.MustCompile(`(?i)^proxy_set_header\s+Upgrade\s`)
	invSchemeRe   = regexp.MustCompile(`^https?://([^/;]+)`)

	// A mesma pergunta que `fileMarkerRe`, mas sobre o dump INTEIRO em vez de
	// uma linha. A original é ancorada à string toda porque é aplicada linha a
	// linha; reusá-la aqui não casaria nada, e trocar a dela por multilinha
	// mudaria o comportamento de todos os outros chamadores.
	fileMarkerLineRe = regexp.MustCompile(`(?m)^# configuration file (.+):[ \t]*\r?$`)
)

// applyLocationLine extrai de uma linha o que interessa dentro de um
// `location`. Separado para que a linha de abertura de um bloco inline passe
// exatamente pela mesma leitura das linhas seguintes de um bloco normal.
func applyLocationLine(loc *Location, line string) {
	switch {
	case invProxyRe.MatchString(line):
		m := invProxyRe.FindStringSubmatch(line)
		loc.ProxyPass = strings.TrimSpace(m[1])
		if h := invSchemeRe.FindStringSubmatch(loc.ProxyPass); h != nil {
			loc.Pool = h[1]
		}
	case invUpgradeRe.MatchString(line):
		loc.Websocket = true
	case invRootRe.MatchString(line):
		loc.Root = strings.TrimSpace(invRootRe.FindStringSubmatch(line)[1])
	}
}

// afterBrace devolve o que sobra da linha depois do primeiro `{`, para que o
// conteúdo de um bloco escrito numa linha só não se perca.
func afterBrace(line string) string {
	if i := strings.Index(line, "{"); i >= 0 {
		return strings.TrimSpace(line[i+1:])
	}
	return ""
}

// BuildInventory parses `nginx -T` output. It never fails: a dump it cannot
// make sense of yields an empty inventory, and the caller still has the raw
// text to show.
func BuildInventory(dump string) Inventory {
	inv := Inventory{Pools: []Pool{}, Vhosts: []Vhost{}}

	var (
		file     string
		managed  bool
		app      string
		depth    int
		pool     *Pool
		vhost    *Vhost
		loc      *Location
		locDepth int
	)

	for _, raw := range strings.Split(dump, "\n") {
		line := strings.TrimSpace(raw)

		if m := fileMarkerRe.FindStringSubmatch(line); m != nil {
			file, managed, app = m[1], false, ""
			depth, pool, vhost, loc = 0, nil, nil, nil
			continue
		}
		// The managed header is only meaningful as the file's first real line,
		// same rule ParseManagedConf enforces — a comment further down must not
		// be able to claim a hand-written file as ours.
		if depth == 0 && pool == nil && vhost == nil && strings.HasPrefix(line, "#") {
			if m := managedByRe.FindStringSubmatch(line); m != nil {
				managed, app = true, m[1]
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Um bloco pode caber numa linha só — `upstream p { server x:1; }` é
		// nginx válido. Por isso a linha de abertura não é descartada: o que
		// vem depois do `{` é reprocessado como se fosse a linha seguinte, e
		// a contagem de chaves sai da linha inteira. Sem isso o conteúdo
		// inline sumia e o `depth` nunca voltava a zero, levando junto todos
		// os blocos seguintes do arquivo.
		switch {
		case pool == nil && vhost == nil && invUpstreamRe.MatchString(line):
			m := invUpstreamRe.FindStringSubmatch(line)
			pool = &Pool{Name: m[1], File: file, Managed: managed,
				Servers: []PoolServer{}}
			depth = 1
			if line = afterBrace(line); line == "" {
				continue
			}
		case pool == nil && vhost == nil && invServerRe.MatchString(line):
			vhost = &Vhost{File: file, Managed: managed, App: app,
				ServerNames: []string{}, Listen: []string{},
				Locations: []Location{}}
			depth = 1
			if line = afterBrace(line); line == "" {
				continue
			}
		}

		if pool == nil && vhost == nil {
			continue
		}

		depth += strings.Count(line, "{") - strings.Count(line, "}")

		if pool != nil {
			if m := invBackendRe.FindStringSubmatch(line); m != nil {
				port, _ := strconv.Atoi(m[2])
				raw := strings.TrimSpace(m[3])
				pool.Servers = append(pool.Servers, PoolServer{
					Host: m[1], Port: port, Raw: raw,
					// Por PALAVRA, não por substring: `downloads.internal`
					// contém "down" e não está fora de rotação.
					Down: hasDownParam(raw)})
			}
			if depth <= 0 {
				// O pool está desabilitado quando TODO backend está — e um
				// pool sem backend nenhum não está desabilitado, está vazio.
				pool.Down = len(pool.Servers) > 0
				for _, srv := range pool.Servers {
					if !srv.Down {
						pool.Down = false
						break
					}
				}
				inv.Pools = append(inv.Pools, *pool)
				pool, depth = nil, 0
			}
			continue
		}

		// Inside a server block.
		if loc != nil {
			applyLocationLine(loc, line)
			if depth <= locDepth {
				vhost.Locations = append(vhost.Locations, *loc)
				loc = nil
			}
			continue
		}

		switch {
		case invSrvNameRe.MatchString(line):
			names := strings.Fields(invSrvNameRe.FindStringSubmatch(line)[1])
			vhost.ServerNames = append(vhost.ServerNames, names...)
		case invListenRe.MatchString(line):
			vhost.Listen = append(vhost.Listen,
				strings.TrimSpace(invListenRe.FindStringSubmatch(line)[1]))
		case invLocationRe.MatchString(line):
			m := invLocationRe.FindStringSubmatch(line)
			loc = &Location{Matcher: m[1], Path: m[2]}
			locDepth = depth - 1
			// Mesmo caso dos blocos acima: `location / { proxy_pass X; }`
			// numa linha só é válido, e descartar o resto perderia o destino.
			if rest := afterBrace(line); rest != "" {
				applyLocationLine(loc, rest)
				if strings.Contains(rest, "}") {
					vhost.Locations = append(vhost.Locations, *loc)
					loc = nil
				}
			}
		}

		if depth <= 0 {
			inv.Vhosts = append(inv.Vhosts, *vhost)
			vhost, depth = nil, 0
		}
	}

	// E, por último, o que o laço acima JAMAIS veria: os blocos que estão
	// dentro de uma cerca. Ele descarta toda linha iniciada por `#`, que é
	// justamente o que um bloco desligado é.
	//
	// Vem depois, e não no meio do laço, de propósito: a varredura de cercas é
	// posicional e independente do estado do laço, e enfiá-la no meio da
	// máquina de estados acrescentaria quatro ramos a um lugar onde cada ramo
	// já custa caro para entender.
	attachFenced(&inv, dump)
	return inv
}

// fencedInventory lê o que está desligado, recursivamente.
//
// Recursivo porque cercas aninham: desligar um location e depois o server
// inteiro deixa a cerca de dentro ainda prefixada dentro do corpo da de fora.
// `BuildInventory` sobre o corpo torna a chamar esta função, e cada nível
// desprefixa o seu.
func attachFenced(inv *Inventory, dump string) {
	for file, section := range sectionsByFile(dump) {
		fences := ScanFences(section)
		if len(fences) == 0 {
			continue
		}
		// Os `server` que o nginx AINDA lê, em ordem de arquivo, e os índices
		// dos vhosts correspondentes. As duas listas se alinham pelo mesmo
		// argumento de `AttachRefs`: as duas varreduras percorrem o mesmo
		// texto na mesma direção, e o que está cercado é invisível às duas.
		var servers []Span
		if spans, err := ScanBlocks(section); err == nil {
			for _, sp := range FlattenSpans(spans) {
				if sp.Kind == "server" {
					servers = append(servers, sp)
				}
			}
		}
		var vidx []int
		for i := range inv.Vhosts {
			if inv.Vhosts[i].File == file && !inv.Vhosts[i].Disabled {
				vidx = append(vidx, i)
			}
		}

		for _, f := range fences {
			// O corpo é reparseado como se fosse um arquivo, com o marcador
			// na frente para que `File` saia preenchido — é o mesmo caminho
			// que o dump de verdade percorre.
			sub := BuildInventory("# configuration file " + file + ":\n" + f.Body + "\n")
			if len(sub.Vhosts) > 0 || len(sub.Pools) > 0 {
				for _, v := range sub.Vhosts {
					v.Disabled, v.DisabledID = true, f.Meta.ID
					v.DisabledAt, v.DisabledBy = f.Meta.At, f.Meta.By
					inv.Vhosts = append(inv.Vhosts, v)
				}
				for _, p := range sub.Pools {
					p.Disabled, p.DisabledID = true, f.Meta.ID
					p.DisabledAt, p.DisabledBy = f.Meta.At, f.Meta.By
					inv.Pools = append(inv.Pools, p)
				}
				continue
			}

			// Não declarou bloco de topo nenhum: é uma cerca DENTRO de um
			// `server` — um location desligado. Ele tem de voltar para o vhost
			// que o contém, senão some da tela; e sumir aqui é pior que no
			// vhost, porque uma rota desligada não derruba o domínio, ela move
			// o tráfego para o location mais genérico que casa.
			locs := fencedLocations(f.Body)
			if len(locs) == 0 {
				continue
			}
			for i, sp := range servers {
				if f.Start <= sp.Open || f.End >= sp.End {
					continue
				}
				if i >= len(vidx) {
					break
				}
				v := &inv.Vhosts[vidx[i]]
				for _, l := range locs {
					l.Disabled, l.DisabledID = true, f.Meta.ID
					l.DisabledAt, l.DisabledBy = f.Meta.At, f.Meta.By
					v.Locations = append(v.Locations, l)
				}
				break
			}
		}
	}
}

// fencedLocations lê as rotas de dentro de uma cerca.
//
// O corpo é embrulhado num `server` sintético porque o parser só reconhece
// `location` dentro de um — reusar o parser de verdade é melhor que escrever
// um segundo, que divergiria do primeiro na primeira diretiva nova.
func fencedLocations(body string) []Location {
	sub := BuildInventory("# configuration file _:\nserver {\n" + body + "\n}\n")
	if len(sub.Vhosts) == 0 {
		return nil
	}
	return sub.Vhosts[0].Locations
}

// sectionsByFile reparte o dump por arquivo de origem.
//
// Um dump sem marcador nenhum (o corpo de uma cerca sendo reparseado, por
// exemplo) conta como uma seção só, de arquivo desconhecido — devolver nada
// aqui faria o aninhamento parar no segundo nível.
func sectionsByFile(dump string) map[string]string {
	out := map[string]string{}
	marks := fileMarkerLineRe.FindAllStringSubmatchIndex(dump, -1)
	if len(marks) == 0 {
		out[""] = dump
		return out
	}
	if first := marks[0][0]; first > 0 {
		out[""] = dump[:first]
	}
	for i, m := range marks {
		end := len(dump)
		if i+1 < len(marks) {
			end = marks[i+1][0]
		}
		file := dump[m[2]:m[3]]
		out[file] += dump[m[1]:end]
	}
	return out
}

// ResolvePools marks which pool each location points at, so the panel can link
// a route to its backends. Only names declared in this same config count: a
// proxy_pass to an external host is a destination, not a pool, and showing it
// as one would invent a backend that does not exist here.
func (inv *Inventory) ResolvePools() {
	known := map[string]bool{}
	for _, p := range inv.Pools {
		// Pool desligado não é pool conhecido: para o nginx ele não existe, e
		// um location que aponte para ele não tem backend nenhum — tem um
		// reload que vai falhar. Marcá-lo como resolvido mostraria backends
		// saudáveis para uma rota que está quebrada.
		if p.Disabled {
			continue
		}
		known[p.Name] = true
	}
	for vi := range inv.Vhosts {
		for li := range inv.Vhosts[vi].Locations {
			loc := &inv.Vhosts[vi].Locations[li]
			if loc.Pool != "" && !known[loc.Pool] {
				loc.Pool = ""
			}
		}
	}
}
