package render

import (
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func withLocations(locs ...LocationSpec) Payload {
	p := validPayload()
	p.SchemaVersion = CurrentSchemaVersion
	p.Locations = locs
	return p
}

// A tabela que justifica a allowlist existir.
//
// Tudo aqui vira linha de nginx.conf verbatim. Um `;` fecha a diretiva e abre
// outra, um `}` fecha o bloco, uma quebra de linha começa uma diretiva nova.
// Se qualquer destes passar, um payload pode escrever config arbitrária num
// load balancer de produção.
func TestValidateLocations_RejectsInjection(t *testing.T) {
	cases := []struct {
		name string
		loc  LocationSpec
	}{
		{"ponto e vírgula fecha a diretiva", LocationSpec{Path: "/x; return 444"}},
		{"chave fecha o bloco", LocationSpec{Path: "/x} location / { proxy_pass http://evil"}},
		{"comentário engole o resto da linha", LocationSpec{Path: "/x #c"}},
		{"quebra de linha começa outra diretiva", LocationSpec{Path: "/x\nreturn 301 http://evil"}},
		{"CR também é quebra", LocationSpec{Path: "/x\rreturn 301 http://evil"}},
		{"tab", LocationSpec{Path: "/x\treturn 444"}},
		{"NUL", LocationSpec{Path: "/x\x00"}},
		{"variável no caminho", LocationSpec{Path: "/x$arg_a"}},
		{"aspas", LocationSpec{Path: `/x" "`}},
		{"espaço", LocationSpec{Path: "/x y"}},
		{"travessia", LocationSpec{Path: "/a/../../etc"}},
		{"barra dupla", LocationSpec{Path: "/a//b"}},
		{"caminho não absoluto", LocationSpec{Path: "x"}},
		{"acima do tamanho", LocationSpec{Path: "/" + strings.Repeat("a", 300)}},
		{"matcher inventado", LocationSpec{Matcher: "!~", Path: "/x"}},
		// Named location: recusada por não haver nada neste template que salte
		// para ela. Renderizaria, passaria no nginx -t e não rotearia nada.
		{"named location", LocationSpec{Matcher: "@", Path: "@fallback"}},
		{"@ sem matcher", LocationSpec{Path: "@fallback"}},
		{"regex com chave", LocationSpec{Matcher: "~", Path: `^/a{1}$`}},
		{"regex com ponto e vírgula", LocationSpec{Matcher: "~", Path: `^/a;b`}},
		{"proxy_pass com diretiva colada", LocationSpec{Path: "/x", ProxyPass: "http://evil;return 301"}},
		{"proxy_pass variável", LocationSpec{Path: "/x", ProxyPass: "http://$backend"}},
		{"proxy_pass sem esquema", LocationSpec{Path: "/x", ProxyPass: "evil.example.com"}},
		{"proxy_pass para loopback", LocationSpec{Path: "/x", ProxyPass: "http://127.0.0.1:8001"}},
		{"proxy_pass para o metadata da nuvem", LocationSpec{Path: "/x", ProxyPass: "http://169.254.169.254/"}},
		{"proxy_pass para 0.0.0.0", LocationSpec{Path: "/x", ProxyPass: "http://0.0.0.0:80"}},
		{"proxy_pass com porta inválida", LocationSpec{Path: "/x", ProxyPass: "http://a.example.com:99999"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := withLocations(tc.loc)
			errs := ValidatePayload(&p)
			if len(errs) == 0 {
				t.Fatalf("payload hostil aceito: %+v", tc.loc)
			}
			// Nada é assertado sobre Render() aqui de propósito. Render não
			// valida — ele renderiza o que recebe, e um payload hostil
			// renderizado produz config hostil. A garantia é de ORDEM, não do
			// template: ValidatePayload roda antes de qualquer escrita em
			// disco (§2.3, server.go handleApply). Quem prova isso é
			// TestApplyRejectsHostileLocationWithoutTouchingConfDir, no
			// pacote lbserver, onde a ordem de fato existe. Assertar aqui
			// testaria uma promessa que ninguém faz.
		})
	}
}

// O que PRECISA passar: as formas que o nginx escrito à mão do LB da OCI usa.
// Uma allowlist que recusa tudo é segura e inútil.
func TestValidateLocations_AcceptsRealWorld(t *testing.T) {
	p := withLocations(
		LocationSpec{Matcher: "=", Path: "/health_check"},
		LocationSpec{Matcher: "^~", Path: "/static/"},
		LocationSpec{Matcher: "~*", Path: `\.(?:css|js|png)$`},
		LocationSpec{Matcher: "~", Path: `^/api/v[0-9]+/`},
		LocationSpec{Path: "/"},
		LocationSpec{Path: "/externo", ProxyPass: "https://www.example.com"},
		LocationSpec{Path: "/ws", Websocket: boolPtr(true)},
	)
	if errs := ValidatePayload(&p); len(errs) > 0 {
		t.Fatalf("formas legítimas recusadas: %v", errs)
	}
}

// A ordem das regex é a única que muda roteamento: o nginx tenta as regex na
// ordem do arquivo e a primeira que casa vence. Reordenar duas é reescrever
// para onde o tráfego vai, sem ninguém ter pedido.
func TestOrderedLocations_PreservesRegexInputOrder(t *testing.T) {
	p := withLocations(
		LocationSpec{Matcher: "~", Path: "^/a"},
		LocationSpec{Matcher: "~*", Path: "^/b"},
		LocationSpec{Matcher: "~", Path: "^/c"},
	)
	got := []string{}
	for _, l := range p.OrderedLocations() {
		got = append(got, l.Path)
	}
	want := []string{"^/a", "^/b", "^/c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ordem das regex mudou: %v, queria %v", got, want)
		}
	}
}

func TestOrderedLocations_GroupsByNginxPrecedence(t *testing.T) {
	p := withLocations(
		LocationSpec{Matcher: "~", Path: "^/regex"},
		LocationSpec{Path: "/prefixo"},
		LocationSpec{Matcher: "^~", Path: "/curto-circuito"},
		LocationSpec{Matcher: "=", Path: "/exato"},
	)
	got := []string{}
	for _, l := range p.OrderedLocations() {
		got = append(got, l.Matcher)
	}
	want := []string{"=", "^~", "", "~"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("agrupamento = %v, queria %v", got, want)
		}
	}
}

// Sem locations declaradas, a rota implícita é o `location /` de sempre — é
// isso que faz o caso legado passar pelo MESMO caminho do template, em vez de
// um ramo `else` com uma segunda cópia do corpo de proxy.
func TestOrderedLocations_EmptyIsTheHistoricalRootLocation(t *testing.T) {
	p := validPayload()
	locs := p.OrderedLocations()
	if len(locs) != 1 || locs[0].Matcher != "" || locs[0].Path != "/" {
		t.Fatalf("default mudou: %+v", locs)
	}
	if got := locs[0].Destination(p); got != "http://app_a_pool" {
		t.Fatalf("destino default = %q", got)
	}
}

// Upstreams vazio é legítimo só quando NENHUMA rota cai no pool do app.
// Senão o arquivo renderiza `proxy_pass http://x_pool;` para um upstream que
// ele não declara, e o nginx recusa a config inteira — levando junto todos os
// outros vhosts.
func TestValidatePayload_EmptyUpstreamsOnlyWhenAllLocationsExternal(t *testing.T) {
	externo := withLocations(
		LocationSpec{Path: "/", ProxyPass: "https://www.example.com"})
	externo.Upstreams = nil
	if errs := ValidatePayload(&externo); len(errs) > 0 {
		t.Fatalf("vhost 100%% externo devia ser válido sem upstreams: %v", errs)
	}

	misto := withLocations(
		LocationSpec{Path: "/externo", ProxyPass: "https://www.example.com"},
		LocationSpec{Path: "/"},
	)
	misto.Upstreams = nil
	errs := ValidatePayload(&misto)
	if len(errs) == 0 {
		t.Fatal("rota para o pool com upstreams vazio tem de ser recusada")
	}

	// E o contrato antigo continua: sem locations, upstreams vazio é erro.
	legado := validPayload()
	legado.Upstreams = nil
	if errs := ValidatePayload(&legado); len(errs) == 0 {
		t.Fatal("payload sem locations e sem upstreams tem de ser recusado")
	}
}

// O nginx proíbe proxy_pass com parte de URI dentro de location regex. Dizer
// isso aqui é melhor que o `nginx -t` dizer pior e mais tarde — um 400 do
// apply é marcado FAILED sem retry.
func TestValidatePayload_RejectsProxyPassURIInRegexLocation(t *testing.T) {
	p := withLocations(LocationSpec{
		Matcher: "~", Path: "^/api", ProxyPass: "https://www.example.com/v1"})
	errs := ValidatePayload(&p)
	if len(errs) == 0 {
		t.Fatal("combinação proibida pelo nginx foi aceita")
	}
	if !strings.Contains(strings.Join(errs, " "), "regex location") {
		t.Fatalf("o erro não explica o motivo: %v", errs)
	}

	// Sem parte de URI, a mesma combinação é válida.
	ok := withLocations(LocationSpec{
		Matcher: "~", Path: "^/api", ProxyPass: "https://www.example.com"})
	if errs := ValidatePayload(&ok); len(errs) > 0 {
		t.Fatalf("proxy_pass sem URI em regex é legítimo: %v", errs)
	}
}

func TestValidatePayload_RejectsDuplicateAndOverLimitLocations(t *testing.T) {
	dup := withLocations(
		LocationSpec{Path: "/a"},
		LocationSpec{Path: "/a"},
	)
	if errs := ValidatePayload(&dup); len(errs) == 0 {
		t.Fatal("location duplicada aceita")
	}

	// Mesmo caminho com matcher diferente NÃO é duplicata: `= /a` e `/a` são
	// duas rotas distintas para o nginx.
	ok := withLocations(
		LocationSpec{Matcher: "=", Path: "/a"},
		LocationSpec{Path: "/a"},
	)
	if errs := ValidatePayload(&ok); len(errs) > 0 {
		t.Fatalf("matchers diferentes não são duplicata: %v", errs)
	}

	muitas := make([]LocationSpec, MaxLocations+1)
	for i := range muitas {
		muitas[i] = LocationSpec{Path: "/p" + string(rune('a'+i%26)) + string(rune('a'+i/26))}
	}
	p := withLocations(muitas...)
	if errs := ValidatePayload(&p); len(errs) == 0 {
		t.Fatal("limite de locations não aplicado")
	}
}

// O perigo que a versão existe para matar não é o bump — é o SILÊNCIO. Um
// listener que só entende v1 recebendo `locations` ignoraria o campo e
// responderia "reloaded", registrando um apply bem-sucedido que não roteia o
// que mandaram rotear. Declarar locations como v1 é esse mesmo engano vindo do
// outro lado, e tem de ser recusado alto.
func TestSchemaVersion_LocationsRequireV2(t *testing.T) {
	v1ComLocations := withLocations(LocationSpec{Path: "/a"})
	v1ComLocations.SchemaVersion = SupportedSchemaVersion
	errs := ValidatePayload(&v1ComLocations)
	if len(errs) == 0 {
		t.Fatal("locations declaradas como v1 foram aceitas")
	}
	if !strings.Contains(strings.Join(errs, " "), "schema_version") {
		t.Fatalf("o erro não aponta a versão: %v", errs)
	}
}

func TestSchemaVersion_AcceptsOneAndTwoRejectsTheRest(t *testing.T) {
	for _, v := range []int{SupportedSchemaVersion, CurrentSchemaVersion} {
		p := validPayload()
		p.SchemaVersion = v
		if errs := ValidatePayload(&p); len(errs) > 0 {
			t.Errorf("schema_version %d devia ser aceita: %v", v, errs)
		}
	}
	for _, v := range []int{0, 3, -1} {
		p := validPayload()
		p.SchemaVersion = v
		if errs := ValidatePayload(&p); len(errs) == 0 {
			t.Errorf("schema_version %d devia ser recusada", v)
		}
	}
}

func TestCapabilitiesAdvertisesLocations(t *testing.T) {
	caps := Capabilities()
	found := false
	for _, c := range caps {
		if c == "locations.v1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sem a capability o sender não tem como saber antes de tentar: %v", caps)
	}
}

// ──────────────── O template, com várias rotas ────────────────

func TestNginxAppTemplate_MultiLocation(t *testing.T) {
	p := withLocations(
		LocationSpec{Matcher: "~", Path: `^/api/`},
		LocationSpec{Path: "/"},
		LocationSpec{Matcher: "=", Path: "/health_check"},
	)
	out, err := Render(templateRelPath, p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	for _, want := range []string{
		"location = /health_check {",
		"location / {",
		"location ~ ^/api/ {",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("faltou %q\n%s", want, out)
		}
	}

	// A ordem no ARQUIVO é o que o nginx lê. `=` antes de prefixo antes de
	// regex é a ordem que o OrderedLocations promete.
	iExato := strings.Index(out, "location = /health_check")
	iPrefixo := strings.Index(out, "location / {")
	iRegex := strings.Index(out, "location ~ ^/api/")
	if !(iExato < iPrefixo && iPrefixo < iRegex) {
		t.Errorf("ordem errada: exato=%d prefixo=%d regex=%d\n%s",
			iExato, iPrefixo, iRegex, out)
	}

	// Cada rota carrega o corpo de proxy inteiro — um location sem os headers
	// de encaminhamento entrega o IP do LB como se fosse o do cliente.
	if n := strings.Count(out, "proxy_set_header X-Forwarded-For"); n != 3 {
		t.Errorf("esperava o corpo em 3 locations, veio %d\n%s", n, out)
	}
}

func TestNginxAppTemplate_ExternalOnlyOmitsUpstreamBlock(t *testing.T) {
	p := withLocations(LocationSpec{Path: "/", ProxyPass: "https://www.example.com"})
	p.Upstreams = nil

	out, err := Render(templateRelPath, p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	// `upstream x {}` sem servidor nenhum o nginx recusa, e recusar a config
	// derruba todos os vhosts do arquivo, não só este. O alvo é o BLOCO:
	// `proxy_next_upstream` também contém "upstream ", e mirar nisso faria o
	// teste falhar pelo motivo errado.
	if strings.Contains(out, "upstream app_a_pool {") {
		t.Errorf("bloco upstream vazio emitido\n%s", out)
	}
	if !strings.Contains(out, "proxy_pass https://www.example.com;") {
		t.Errorf("destino externo não chegou\n%s", out)
	}
	// server_name tem de continuar saindo: é por ele que o /v1/status
	// reconstrói os domínios do app depois de um restart.
	if !strings.Contains(out, "server_name app-a.workspacefy.com;") {
		t.Errorf("server_name sumiu — o /v1/status depende dele\n%s", out)
	}
}

func TestNginxAppTemplate_WebsocketPerLocation(t *testing.T) {
	p := withLocations(
		LocationSpec{Path: "/", Websocket: boolPtr(false)},
		LocationSpec{Path: "/ws", Websocket: boolPtr(true)},
	)
	p.Websocket = false

	out, err := Render(templateRelPath, p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}
	if n := strings.Count(out, `proxy_set_header Connection "upgrade";`); n != 1 {
		t.Errorf("esperava upgrade em exatamente uma rota, veio %d\n%s", n, out)
	}

	// Herança: rota que não declara nada segue o flag do vhost.
	herda := withLocations(LocationSpec{Path: "/a"}, LocationSpec{Path: "/b"})
	herda.Websocket = true
	out2, err := Render(templateRelPath, herda)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(out2, `proxy_set_header Connection "upgrade";`); n != 2 {
		t.Errorf("as duas rotas deviam herdar websocket, veio %d\n%s", n, out2)
	}
}
