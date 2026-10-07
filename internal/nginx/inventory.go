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
}

type PoolServer struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	// Raw keeps whatever followed the address (weight, max_fails, backup…),
	// so the panel can show it without this struct having to model it.
	Raw string `json:"raw,omitempty"`
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
				pool.Servers = append(pool.Servers, PoolServer{
					Host: m[1], Port: port, Raw: strings.TrimSpace(m[3])})
			}
			if depth <= 0 {
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
	return inv
}

// ResolvePools marks which pool each location points at, so the panel can link
// a route to its backends. Only names declared in this same config count: a
// proxy_pass to an external host is a destination, not a pool, and showing it
// as one would invent a backend that does not exist here.
func (inv *Inventory) ResolvePools() {
	known := map[string]bool{}
	for _, p := range inv.Pools {
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
