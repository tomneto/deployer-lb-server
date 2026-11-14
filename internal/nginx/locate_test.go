package nginx

import (
	"errors"
	"strings"
	"testing"
)

// O caso 80/443: dois `server` com o MESMO server_name. É a razão de existir
// deste arquivo — endereçar por nome desligaria só um dos dois.
const twoListenerConf = `http {
    server {
        listen 80;
        server_name app.example.com;
        return 301 https://app.example.com$request_uri;
    }

    server {
        listen 443 ssl;
        server_name app.example.com;
        location / {
            proxy_pass http://app_pool;
        }
    }
}
`

func refsOfKind(t *testing.T, conf, kind string) []Ref {
	t.Helper()
	refs, err := RefsForFile("/etc/nginx/nginx.conf", conf)
	if err != nil {
		t.Fatal(err)
	}
	var out []Ref
	for _, r := range refs {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	return out
}

func TestTwoServersSharingServerNameGetDistinctRefs(t *testing.T) {
	// Se os dois recebessem o mesmo endereço, desabilitar "o vhost" desligaria
	// um só — e a porta 80 ficaria redirecionando para um 443 que já não
	// responde. É o desfecho que este teste existe para impedir.
	servers := refsOfKind(t, twoListenerConf, "server")
	if len(servers) != 2 {
		t.Fatalf("esperava 2 blocos server, vieram %d", len(servers))
	}
	if servers[0].Digest == servers[1].Digest {
		t.Fatal("os dois vhosts do mesmo domínio receberam o MESMO endereço")
	}
}

func TestRefSurvivesBlockShiftWhenDigestMatches(t *testing.T) {
	// Alguém acrescentou linhas ACIMA do bloco. Os offsets todos mudaram, o
	// texto do bloco não. Um endereço baseado em posição apontaria para o lugar
	// errado; baseado em conteúdo, continua certo.
	servers := refsOfKind(t, twoListenerConf, "server")
	ref := servers[1]

	shifted := strings.Replace(twoListenerConf, "http {",
		"http {\n    # comentario novo\n    client_max_body_size 100m;", 1)

	span, err := ResolveRef(shifted, ref)
	if err != nil {
		t.Fatalf("o ref devia sobreviver ao deslocamento: %v", err)
	}
	if !strings.Contains(span.Text(shifted), "listen 443 ssl;") {
		t.Fatalf("resolveu para o bloco errado:\n%s", span.Text(shifted))
	}
	if span.Header == ref.Start {
		t.Fatal("o teste não provou nada: o bloco não chegou a se deslocar")
	}
}

func TestRefIsStaleWhenBlockTextChanged(t *testing.T) {
	// O bloco foi editado à mão desde que a tela o leu. Escrever sobre ele
	// apagaria a edição de outra pessoa sem avisar — recusar é a resposta.
	servers := refsOfKind(t, twoListenerConf, "server")
	edited := strings.Replace(twoListenerConf, "listen 443 ssl;",
		"listen 443 ssl http2;", 1)

	if _, err := ResolveRef(edited, servers[1]); !errors.Is(err, ErrStaleRef) {
		t.Fatalf("esperava ErrStaleRef, veio %v", err)
	}
}

func TestRefIsAmbiguousWhenTwoBlocksAreIdentical(t *testing.T) {
	// Dois blocos byte a byte iguais. Escolher "o primeiro" seria sortear qual
	// parte da produção muda.
	dup := `http {
    upstream a {
        server 10.0.0.1:80;
    }
    upstream a {
        server 10.0.0.1:80;
    }
}
`
	refs := refsOfKind(t, dup, "upstream")
	if len(refs) != 2 || refs[0].Digest != refs[1].Digest {
		t.Fatalf("o fixture precisa ter dois blocos idênticos; veio %d", len(refs))
	}
	// Com o offset zerado não há desempate possível.
	blind := refs[0]
	blind.Start = -1
	if _, err := ResolveRef(dup, blind); !errors.Is(err, ErrAmbiguousRef) {
		t.Fatalf("esperava ErrAmbiguousRef, veio %v", err)
	}
	// Mas o ref original, com o offset intacto, ainda resolve: o arquivo não
	// mudou, e o desempate por posição é legítimo aí.
	if _, err := ResolveRef(dup, refs[1]); err != nil {
		t.Fatalf("com o offset intacto o desempate devia funcionar: %v", err)
	}
}

func TestRefRoundTripsThroughEncoding(t *testing.T) {
	// O painel recebe a string e devolve verbatim; se ela não voltar igual, o
	// endereço vira outro bloco.
	servers := refsOfKind(t, twoListenerConf, "server")
	back, err := DecodeRef(servers[0].Encode())
	if err != nil {
		t.Fatal(err)
	}
	if back != servers[0] {
		t.Fatalf("o ref não sobreviveu à ida e volta:\n%+v\n%+v", back, servers[0])
	}
}

func TestRefWithoutDigestIsRefused(t *testing.T) {
	// Sem digest só sobra o offset — exatamente o endereçamento frágil que
	// este arquivo recusa.
	naked := Ref{File: "/etc/nginx/nginx.conf", Kind: "server", Start: 10}
	if _, err := DecodeRef(naked.Encode()); err == nil {
		t.Fatal("ref sem digest tem de ser recusado")
	}
}

func TestRefsCoverNestedLocations(t *testing.T) {
	// Um location é endereçável do mesmo jeito que um server — é o que torna
	// possível desligar uma rota sem derrubar o domínio.
	locs := refsOfKind(t, twoListenerConf, "location")
	if len(locs) != 1 {
		t.Fatalf("esperava 1 location endereçável, vieram %d", len(locs))
	}
}
