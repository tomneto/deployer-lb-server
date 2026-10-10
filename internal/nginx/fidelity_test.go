package nginx

import (
	"strings"
	"testing"
)

// dump monta um `nginx -T` sintético com um vhost só.
func dumpWith(body string) string {
	return "# configuration file /etc/nginx/nginx.conf:\nhttp {\n" + body + "\n}\n"
}

const vhostSimples = `    server {
        listen 80;
        server_name a.example.com;
        underscores_in_headers on;
        client_max_body_size 100m;
        include snippets/error-pages.conf;
        include snippets/cloudflare-real-ip.conf;
        location / {
            proxy_pass http://app_pool;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_connect_timeout 10s;
            proxy_read_timeout 120s;
            proxy_send_timeout 120s;
            proxy_next_upstream_tries 2;
        }
    }`

func onlyVhost(t *testing.T, dump string) VhostFidelity {
	t.Helper()
	out := Fidelity(dump)
	if len(out) != 1 {
		t.Fatalf("esperava 1 vhost, veio %d: %+v", len(out), out)
	}
	return out[0]
}

func TestFidelityAcceptsAVhostTheTemplateReallyProduces(t *testing.T) {
	v := onlyVhost(t, dumpWith(vhostSimples))
	if v.Verdict != VerdictReproducible {
		t.Fatalf("veredito = %s\nblockers=%+v\nlosses=%+v\nunparsed=%d",
			v.Verdict, v.Blockers, v.Losses, v.UnparsedLines)
	}
	if len(v.ServerNames) != 1 || v.ServerNames[0] != "a.example.com" {
		t.Errorf("server_names = %v", v.ServerNames)
	}
}

// O default para token desconhecido é BLOQUEIO. "Não reconheci" não pode ser
// apresentado como "tudo bem" — é assim que um relatório de fidelidade vira
// um convite para migrar e perder comportamento.
func TestFidelityTreatsAnUnknownDirectiveAsABlocker(t *testing.T) {
	v := onlyVhost(t, dumpWith(strings.Replace(vhostSimples,
		"        location / {",
		"        frobnicate on;\n        location / {", 1)))

	if v.Verdict != VerdictNot {
		t.Fatalf("diretiva desconhecida não bloqueou: %s", v.Verdict)
	}
	found := false
	for _, b := range v.Blockers {
		if b.Directive == "frobnicate" {
			found = true
			if !strings.Contains(b.Reason, "não classificada") {
				t.Errorf("motivo não explica: %q", b.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("a diretiva desconhecida não foi nomeada: %+v", v.Blockers)
	}
}

// Diretiva certa com valor que o template não produz é PERDA, nunca "bate".
// Esta é a asserção que separa um relatório verdadeiro de um tranquilizador.
func TestFidelityCountsAValueMismatchAsLossNotMatch(t *testing.T) {
	v := onlyVhost(t, dumpWith(strings.Replace(vhostSimples,
		"client_max_body_size 100m;", "client_max_body_size 1g;", 1)))

	if v.Verdict != VerdictWithLoss {
		t.Fatalf("veredito = %s (queria perda), blockers=%+v", v.Verdict, v.Blockers)
	}
	if len(v.Losses) != 1 || v.Losses[0].Directive != "client_max_body_size" {
		t.Fatalf("perda não nomeada: %+v", v.Losses)
	}
	if !strings.Contains(v.Losses[0].Reason, "100m") {
		t.Errorf("o motivo não diz para que valor mudaria: %q", v.Losses[0].Reason)
	}
	for _, m := range v.Matched {
		if m == "client_max_body_size" {
			t.Error("valor divergente foi contado como diretiva que bate")
		}
	}
}

func TestFidelityNamesEachBlockingDirective(t *testing.T) {
	cases := map[string]string{
		"try_files":       "        try_files $uri $uri/ =404;",
		"rewrite":         "        rewrite ^/old /new permanent;",
		"return":          "        return 301 https://example.com;",
		"ssl_certificate": "        ssl_certificate /etc/ssl/a.pem;",
		"root":            "        root /var/www;",
		"set":             "        set $x 1;",
		// Abre bloco em vez de terminar com `;` — e mesmo assim tem de ser
		// NOMEADA, não virar "linha não interpretada".
		"if":           "        if ($http_user_agent ~ Bot) {\n            return 403;\n        }",
		"limit_except": "        limit_except GET {\n            deny all;\n        }",
	}
	for name, directive := range cases {
		t.Run(name, func(t *testing.T) {
			v := onlyVhost(t, dumpWith(strings.Replace(vhostSimples,
				"        location / {", directive+"\n        location / {", 1)))
			if v.Verdict != VerdictNot {
				t.Fatalf("%s devia bloquear, veredito = %s", name, v.Verdict)
			}
			if len(v.Blockers) == 0 {
				t.Fatalf("nenhum blocker nomeado para %s", name)
			}
			// O motivo é o que a pessoa lê para decidir; "não suportado" não
			// ajudaria ninguém a saber o que perde.
			if len(v.Blockers[0].Reason) < 20 {
				t.Errorf("motivo curto demais: %q", v.Blockers[0].Reason)
			}
		})
	}
}

// Named location é entendida perfeitamente pelo parser e mesmo assim bloqueia:
// nada neste template salta para ela, então reproduzir o vhost criaria uma
// rota inalcançável.
func TestFidelityBlocksNamedLocations(t *testing.T) {
	v := onlyVhost(t, dumpWith(strings.Replace(vhostSimples,
		"        location / {",
		"        location @fallback {\n            proxy_pass http://outro_pool;\n        }\n        location / {", 1)))

	if v.Verdict != VerdictNot {
		t.Fatalf("named location não bloqueou: %s", v.Verdict)
	}
	found := false
	for _, b := range v.Blockers {
		if strings.Contains(b.Directive, "@fallback") {
			found = true
		}
	}
	if !found {
		t.Fatalf("a named location não foi nomeada: %+v", v.Blockers)
	}
}

// O acoplamento com o lado de escrita: nada pode ser marcado "reproduzível" se
// o `ValidatePayload` recusaria aquelas rotas. Sem isto o relatório liberaria
// uma migração que o apply rejeita depois — com a decisão já tomada.
func TestFidelityNeverClaimsMoreThanTheWriteSideAccepts(t *testing.T) {
	// Backreference: PCRE do nginx aceita, o RE2 de Go não — então o canal de
	// escrita recusa, e o relatório tem de recusar junto.
	v := onlyVhost(t, dumpWith(strings.Replace(vhostSimples,
		"        location / {",
		`        location ~ ^/(a)\1$ {
            proxy_pass http://app_pool;
        }
        location / {`, 1)))

	if v.Verdict == VerdictReproducible {
		t.Fatalf("marcou como reproduzível algo que o apply recusaria: %+v", v)
	}
	joined := ""
	for _, b := range v.Blockers {
		joined += b.Reason
	}
	if !strings.Contains(joined, "canal de escrita") {
		t.Errorf("o motivo não diz que é o lado de escrita: %+v", v.Blockers)
	}
}

// Linha que nem dá para tokenizar some como diretiva — mas o CONTADOR aparece,
// e ele basta para bloquear. É o oposto do que applyLocationLine faz, e de
// propósito.
func TestFidelityCountsLinesItCouldNotEvenTokenize(t *testing.T) {
	v := onlyVhost(t, dumpWith(strings.Replace(vhostSimples,
		"        location / {", "        isto nao termina com ponto e virgula\n        location / {", 1)))

	if v.UnparsedLines == 0 {
		t.Fatal("linha ilegível sumiu sem deixar rastro")
	}
	if v.Verdict != VerdictNot {
		t.Fatalf("linha ilegível não bloqueou: %s", v.Verdict)
	}
}

// Ocorrências repetidas viram uma linha com contagem, não N linhas iguais —
// senão um vhost com vinte `try_files` enterra o resto do relatório.
func TestFidelityGroupsRepeatedFindings(t *testing.T) {
	v := onlyVhost(t, dumpWith(strings.Replace(vhostSimples,
		"        location / {",
		"        return 404;\n        return 404;\n        return 404;\n        location / {", 1)))

	count := 0
	for _, b := range v.Blockers {
		if b.Directive == "return" {
			count++
			if b.Count != 3 {
				t.Errorf("contagem = %d, queria 3", b.Count)
			}
		}
	}
	if count != 1 {
		t.Fatalf("esperava uma entrada agrupada, veio %d", count)
	}
}

// Vários vhosts no mesmo dump são julgados separadamente: um irreproduzível
// não pode contaminar o veredito do vizinho.
func TestFidelityJudgesEachVhostOnItsOwn(t *testing.T) {
	ruim := strings.Replace(vhostSimples, "server_name a.example.com;",
		"server_name b.example.com;\n        try_files $uri =404;", 1)
	out := Fidelity(dumpWith(vhostSimples + "\n" + ruim))

	if len(out) != 2 {
		t.Fatalf("esperava 2 vhosts, veio %d", len(out))
	}
	if out[0].Verdict != VerdictReproducible {
		t.Errorf("o primeiro vhost foi contaminado: %s %+v", out[0].Verdict, out[0].Blockers)
	}
	if out[1].Verdict != VerdictNot {
		t.Errorf("o segundo devia bloquear: %s", out[1].Verdict)
	}
}

// Nunca falha: um dump ilegível devolve lista vazia, e quem chamou ainda tem o
// texto cru para mostrar.
func TestFidelityNeverPanicsOnGarbage(t *testing.T) {
	for _, s := range []string{"", "}}}{{{", "server {", "# configuration file x:\n"} {
		if out := Fidelity(s); out == nil {
			t.Errorf("devolveu nil para %q — tem de ser lista vazia", s)
		}
	}
}

// `server 10.0.0.1:80;` dentro de um bloco upstream não é diretiva deste
// vhost. Confundir as duas faria todo arquivo com upstream parecer
// irreproduzível.
func TestFidelityIgnoresUpstreamServerLines(t *testing.T) {
	dump := dumpWith(`    upstream app_pool {
        server 10.10.0.2:10200;
        keepalive 16;
    }
` + vhostSimples)
	v := onlyVhost(t, dump)
	if v.Verdict != VerdictReproducible {
		t.Fatalf("o bloco upstream contaminou o vhost: %s %+v", v.Verdict, v.Blockers)
	}
}
