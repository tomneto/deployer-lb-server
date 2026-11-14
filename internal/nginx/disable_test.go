package nginx

import (
	"strings"
	"testing"
)

const fenceConf = `http {
    server {
        listen 80;
        server_name penpot.workspacefy.com;

        location / {
            proxy_pass http://penpot_pool;
        }
    }
}
`

// firstSpanOfKind acha o primeiro bloco de um tipo no texto.
func firstSpanOfKind(t *testing.T, conf, kind string) Span {
	t.Helper()
	spans, err := ScanBlocks(conf)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range FlattenSpans(spans) {
		if s.Kind == kind {
			return s
		}
	}
	t.Fatalf("nenhum bloco %q no fixture", kind)
	return Span{}
}

func disableFirst(t *testing.T, conf, kind, id string) string {
	t.Helper()
	span := firstSpanOfKind(t, conf, kind)
	out, err := DisableSpan(conf, span, FenceMeta{
		ID: id, Kind: kind, Label: "penpot.workspacefy.com",
		At: "2026-11-14T12:00:00Z", By: "fulano",
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDisableEnableRoundTripsByteForByte(t *testing.T) {
	// O contrato inteiro deste arquivo. Se religar não devolver o arquivo
	// IDÊNTICO, o painel está reescrevendo config de produção de leve a cada
	// clique — e ninguém percebe, porque continua sendo nginx válido.
	off := disableFirst(t, fenceConf, "server", "aaaa1111")
	if off == fenceConf {
		t.Fatal("desligar não mudou nada")
	}
	// A indentação original viaja DENTRO do corpo cercado — é o que a faz
	// voltar intacta. Por isso o prefixo vem antes dela, não depois.
	if !strings.Contains(off, "#|     server {") {
		t.Fatalf("o corpo não foi cercado:\n%s", off)
	}
	back, err := EnableFence(off, "aaaa1111")
	if err != nil {
		t.Fatal(err)
	}
	if back != fenceConf {
		t.Fatalf("o round-trip não devolveu o original:\n--- esperado ---\n%q\n--- veio ---\n%q",
			fenceConf, back)
	}
}

func TestRoundTripPreservesFileWithoutTrailingNewline(t *testing.T) {
	// `ReadConfTree` ACRESCENTA a quebra final quando falta, então o dump e o
	// disco já diferem exatamente neste byte. Reconstruir o arquivo com
	// Split/Join o perderia.
	conf := strings.TrimSuffix(fenceConf, "\n")
	off := disableFirst(t, conf, "server", "bbbb2222")
	back, err := EnableFence(off, "bbbb2222")
	if err != nil {
		t.Fatal(err)
	}
	if back != conf {
		t.Fatalf("a ausência de quebra final não sobreviveu:\n%q", back)
	}
}

func TestRoundTripPreservesCRLF(t *testing.T) {
	// O `\r` viaja no fim da linha e tem de voltar lá. Qualquer TrimSpace no
	// desprefixo o comeria.
	conf := strings.ReplaceAll(fenceConf, "\n", "\r\n")
	off := disableFirst(t, conf, "server", "cccc3333")
	back, err := EnableFence(off, "cccc3333")
	if err != nil {
		t.Fatal(err)
	}
	if back != conf {
		t.Fatalf("o CRLF não sobreviveu ao round-trip:\n%q", back)
	}
}

func TestRoundTripPreservesIndentationOnBlankLines(t *testing.T) {
	// A regra da ORDEM do desprefixo. Uma linha de só espaços vira `#|    `;
	// se o desprefixo tentar `#|` antes de `#| `, ela volta com um espaço a
	// mais. Perda silenciosa de indentação em arquivo de produção.
	conf := strings.Replace(fenceConf,
		"        server_name penpot.workspacefy.com;\n\n",
		"        server_name penpot.workspacefy.com;\n        \n", 1)
	off := disableFirst(t, conf, "server", "dddd4444")
	back, err := EnableFence(off, "dddd4444")
	if err != nil {
		t.Fatal(err)
	}
	if back != conf {
		t.Fatalf("a linha em branco indentada não voltou igual:\n%q", back)
	}
}

func TestNestedFenceUnnestsOneLevelOnly(t *testing.T) {
	// Desligar um location e depois o server inteiro aninha as cercas.
	// Religar o server tem de devolver o location AINDA desligado — tirar
	// dois níveis religaria algo que ninguém mandou religar.
	locOff := disableFirst(t, fenceConf, "location", "1111aaaa")
	srv := firstSpanOfKind(t, locOff, "server")
	bothOff, err := DisableSpan(locOff, srv, FenceMeta{ID: "2222bbbb", Kind: "vhost"})
	if err != nil {
		t.Fatal(err)
	}
	back, err := EnableFence(bothOff, "2222bbbb")
	if err != nil {
		t.Fatal(err)
	}
	if back != locOff {
		t.Fatalf("religar o server não devolveu o estado com o location desligado:\n%q", back)
	}
	if !strings.Contains(back, "lb-off id=1111aaaa") {
		t.Fatal("a cerca de dentro foi religada junto")
	}
}

func TestEnableMatchesFenceByIDNotByFirstTerminator(t *testing.T) {
	// É o motivo de o ID existir nas duas pontas. Com cercas aninhadas, o
	// terminador de DENTRO aparece primeiro no texto; fechar nele devolveria
	// metade do bloco de fora e deixaria o resto comentado.
	locOff := disableFirst(t, fenceConf, "location", "1111aaaa")
	srv := firstSpanOfKind(t, locOff, "server")
	bothOff, _ := DisableSpan(locOff, srv, FenceMeta{ID: "2222bbbb", Kind: "vhost"})

	inner := strings.Index(bothOff, "#| #<<< lb-off id=1111aaaa")
	outer := strings.Index(bothOff, "#<<< lb-off id=2222bbbb")
	if inner < 0 || outer < 0 || inner > outer {
		t.Fatalf("o fixture precisa ter o terminador de dentro ANTES do de fora:\n%s", bothOff)
	}
	back, _ := EnableFence(bothOff, "2222bbbb")
	// A cerca de fora some inteira; a de dentro, que ninguém mandou religar,
	// fica. Procurar por `#| ` aqui não provaria nada: o corpo da cerca
	// interna legitimamente continua prefixado.
	if strings.Contains(back, "id=2222bbbb") {
		t.Fatalf("a cerca de fora não foi removida:\n%s", back)
	}
	if strings.Contains(back, "#| #") {
		t.Fatalf("sobrou um nível de prefixo do bloco de fora:\n%s", back)
	}
}

func TestFenceFieldsRejectNewlineInjection(t *testing.T) {
	// `By` é texto arbitrário do cliente indo para dentro de um arquivo de
	// config. Sem sanitizar, isto fecha o bloco e abre outro — e o arquivo
	// continua sendo nginx VÁLIDO, que é o pior jeito de falhar.
	span := firstSpanOfKind(t, fenceConf, "server")
	out, err := DisableSpan(fenceConf, span, FenceMeta{
		ID: "eeee5555", Kind: "vhost",
		By: "x\n}\nserver {\n    listen 80;\n    server_name invadido.com;",
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "server_name invadido.com") &&
		!strings.Contains(out, "#>>> lb-off id=eeee5555") {
		t.Fatal("a injeção escapou da linha de cerca")
	}
	// A prova de verdade: o arquivo resultante não ganhou nenhum bloco novo.
	before, _ := ScanBlocks(fenceConf)
	after, _ := ScanBlocks(out)
	if len(FlattenSpans(after)) >= len(FlattenSpans(before)) {
		t.Fatalf("a injeção criou bloco: antes %d, depois %d\n%s",
			len(FlattenSpans(before)), len(FlattenSpans(after)), out)
	}
	if strings.Count(out, "\n#>>> lb-off") > 1 || strings.Count(out, "#>>> lb-off") > 1 {
		t.Fatalf("a injeção criou uma segunda cerca:\n%s", out)
	}
}

func TestFenceFieldCannotForgeAMarker(t *testing.T) {
	span := firstSpanOfKind(t, fenceConf, "server")
	out, _ := DisableSpan(fenceConf, span, FenceMeta{
		ID: "ffff6666", Kind: "vhost", By: "#<<< lb-off id=ffff6666",
	})
	// Se o campo pudesse forjar o terminador, religar devolveria o bloco
	// cortado no meio.
	back, err := EnableFence(out, "ffff6666")
	if err != nil {
		t.Fatal(err)
	}
	if back != fenceConf {
		t.Fatalf("o campo forjou um terminador e o round-trip quebrou:\n%q", back)
	}
}

func TestEnableRefusesUnknownID(t *testing.T) {
	if _, err := EnableFence(fenceConf, "naoexiste"); err == nil {
		t.Fatal("religar um id inexistente tem de dar erro")
	}
}

func TestScanFencesIgnoresHandWrittenCommentWithoutFence(t *testing.T) {
	// O vhost comentado à mão que já existe no LB não é uma cerca: o painel
	// não pode fingir que o desligou nem oferecer religá-lo, porque não sabe
	// onde ele termina.
	hand := `http {
    # server {
    #     listen 80;
    # }
}
`
	if got := ScanFences(hand); len(got) != 0 {
		t.Fatalf("comentário à mão não é cerca; vieram %d", len(got))
	}
}

func TestScanFencesReadsBackTheMetadata(t *testing.T) {
	off := disableFirst(t, fenceConf, "server", "aaaa1111")
	fences := ScanFences(off)
	if len(fences) != 1 {
		t.Fatalf("esperava 1 região desligada, vieram %d", len(fences))
	}
	m := fences[0].Meta
	if m.ID != "aaaa1111" || m.Kind != "server" {
		t.Fatalf("metadados não voltaram: %+v", m)
	}
	if m.Label != "penpot.workspacefy.com" || m.At != "2026-11-14T12:00:00Z" || m.By != "fulano" {
		t.Fatalf("rótulo, data ou autor não voltaram: %+v", m)
	}
}

func TestDisabledBlockIsInvisibleToTheConfigParser(t *testing.T) {
	// A outra metade do ponto: depois de desligado, o nginx não vê mais o
	// bloco. Se visse, o toggle não teria efeito nenhum.
	off := disableFirst(t, fenceConf, "server", "aaaa1111")
	spans, err := ScanBlocks(off)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range FlattenSpans(spans) {
		if s.Kind == "server" {
			t.Fatalf("o bloco desligado ainda é lido como config:\n%s", off)
		}
	}
}

func TestDisabledVhostStillAppearsInTheInventory(t *testing.T) {
	// A metade do recurso que decide se ele é usável: o nginx deixa de ver o
	// bloco, mas a TELA continua vendo. Sem isto, desligar um vhost o faz
	// sumir do painel e ninguém mais consegue religá-lo — que é exatamente o
	// que acontece hoje com o penpot comentado à mão.
	off := disableFirst(t, fenceConf, "server", "aaaa1111")
	inv := BuildInventory("# configuration file /etc/nginx/nginx.conf:\n" + off)

	if len(inv.Vhosts) != 1 {
		t.Fatalf("o vhost desligado sumiu do inventário (vieram %d)", len(inv.Vhosts))
	}
	v := inv.Vhosts[0]
	if !v.Disabled {
		t.Fatal("o vhost apareceu, mas não marcado como desligado")
	}
	if v.DisabledID != "aaaa1111" || v.DisabledBy != "fulano" {
		t.Fatalf("a procedência da cerca não chegou ao inventário: %+v", v)
	}
	if v.File != "/etc/nginx/nginx.conf" {
		t.Fatalf("o arquivo de origem se perdeu: %q", v.File)
	}
	if len(v.ServerNames) != 1 || v.ServerNames[0] != "penpot.workspacefy.com" {
		t.Fatalf("o domínio não foi lido de dentro da cerca: %+v", v.ServerNames)
	}
	// E as rotas de dentro continuam legíveis, senão a tela não sabe dizer o
	// que volta a responder ao religar.
	if len(v.Locations) != 1 {
		t.Fatalf("as rotas do vhost desligado não foram lidas: %+v", v.Locations)
	}
}

func TestEnabledAndDisabledVhostsCoexistInTheInventory(t *testing.T) {
	two := `http {
    server {
        listen 80;
        server_name vivo.example.com;
    }
    server {
        listen 80;
        server_name morto.example.com;
    }
}
`
	spans, _ := ScanBlocks(two)
	var second Span
	for _, s := range FlattenSpans(spans) {
		if s.Kind == "server" {
			second = s
		}
	}
	off, err := DisableSpan(two, second, FenceMeta{ID: "9999zzzz", Kind: "vhost"})
	if err != nil {
		t.Fatal(err)
	}
	inv := BuildInventory("# configuration file /etc/nginx/nginx.conf:\n" + off)
	if len(inv.Vhosts) != 2 {
		t.Fatalf("esperava os dois vhosts, veio %d", len(inv.Vhosts))
	}
	var vivo, morto *Vhost
	for i := range inv.Vhosts {
		switch inv.Vhosts[i].ServerNames[0] {
		case "vivo.example.com":
			vivo = &inv.Vhosts[i]
		case "morto.example.com":
			morto = &inv.Vhosts[i]
		}
	}
	if vivo == nil || morto == nil {
		t.Fatalf("faltou um dos dois: %+v", inv.Vhosts)
	}
	if vivo.Disabled {
		t.Fatal("o vhost no ar foi marcado como desligado")
	}
	if !morto.Disabled {
		t.Fatal("o vhost desligado não foi marcado")
	}
}

func TestDisabledPoolIsReportedApartFromADownPool(t *testing.T) {
	// `down` e `desligado` são estados diferentes: um pool `down` continua
	// declarado e o nginx o lê; um desligado não existe para o nginx, e um
	// proxy_pass que ainda aponte para ele faz o reload FALHAR. Achatá-los na
	// tela mandaria procurar no lugar errado.
	conf := `http {
    upstream morto_pool {
        server 10.0.0.9:80;
    }
}
`
	span := firstSpanOfKind(t, conf, "upstream")
	off, err := DisableSpan(conf, span, FenceMeta{ID: "7777pppp", Kind: "pool"})
	if err != nil {
		t.Fatal(err)
	}
	inv := BuildInventory("# configuration file /etc/nginx/nginx.conf:\n" + off)
	if len(inv.Pools) != 1 {
		t.Fatalf("o pool desligado sumiu do inventário (vieram %d)", len(inv.Pools))
	}
	if !inv.Pools[0].Disabled {
		t.Fatal("o pool apareceu sem a marca de desligado")
	}
	if inv.Pools[0].Down {
		t.Fatal("desligado virou `down` — são estados diferentes")
	}
}

func TestDisabledPoolIsNotResolvedAsALocationPool(t *testing.T) {
	// Um location apontando para upstream desligado não tem backend: tem um
	// reload que vai falhar. Resolvê-lo mostraria backends saudáveis para uma
	// rota quebrada, que é o diagnóstico errado no pior momento.
	conf := `http {
    upstream morto_pool {
        server 10.0.0.9:80;
    }
    server {
        listen 80;
        server_name x.example.com;
        location / {
            proxy_pass http://morto_pool;
        }
    }
}
`
	span := firstSpanOfKind(t, conf, "upstream")
	off, err := DisableSpan(conf, span, FenceMeta{ID: "6666uuuu", Kind: "pool"})
	if err != nil {
		t.Fatal(err)
	}
	inv := BuildInventory("# configuration file /etc/nginx/nginx.conf:\n" + off)
	inv.ResolvePools()

	var loc *Location
	for i := range inv.Vhosts {
		for j := range inv.Vhosts[i].Locations {
			if !inv.Vhosts[i].Disabled {
				loc = &inv.Vhosts[i].Locations[j]
			}
		}
	}
	if loc == nil {
		t.Fatalf("o location do vhost no ar sumiu: %+v", inv.Vhosts)
	}
	if loc.Pool != "" {
		t.Fatalf("o location foi resolvido para um pool que o nginx não lê: %q", loc.Pool)
	}
}
