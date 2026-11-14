package lbserver

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

// O vhost do intake, como ele é na config de produção: um `error_page` que
// redireciona para um `location @fallback`.
const locationConf = `events {}
http {
    server {
        listen 80;
        server_name intake.workspacefy.com;

        location / {
            proxy_pass http://intake_pool;
            error_page 502 503 504 = @fallback;
        }

        location /metricas {
            proxy_pass http://metricas_pool;
        }

        location @fallback {
            proxy_pass https://www.workspacefy.com;
        }
    }
}
`

func locationServer(t *testing.T) (*Server, string) {
	t.Helper()
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(locationConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}
	return srv, conf
}

// locRef devolve o ref do location cujo caminho casa.
func locRef(t *testing.T, conf, path string) string {
	t.Helper()
	raw, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	dump := "# configuration file " + conf + ":\n" + string(raw)
	inv := nginx.BuildInventory(dump)
	inv.AttachRefs(dump)
	for _, v := range inv.Vhosts {
		for _, l := range v.Locations {
			if l.Path == path && l.Ref != "" {
				return l.Ref
			}
		}
	}
	t.Fatalf("location %q não ganhou endereço", path)
	return ""
}

func doLocation(t *testing.T, srv *Server, payload map[string]any, nonce string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := signedRequest(t, http.MethodPost, "/v1/location", srv.cfg.Now(),
		testSecret, testToken, body, nonce)
	return doApply(t, srv, req)
}

func TestDisablingARouteKeepsTheDomainUp(t *testing.T) {
	// A diferença toda em relação ao vhost: o domínio continua respondendo, e
	// é por isso que desligar uma rota engana. O bloco some para o nginx, o
	// `server` fica.
	srv, conf := locationServer(t)
	code, body := doLocation(t, srv, map[string]any{
		"disabled": true, "refs": []string{locRef(t, conf, "/metricas")}, "by": "fulano",
	}, "nonce-loc-1")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}

	after, _ := os.ReadFile(conf)
	got := string(after)
	inv := nginx.BuildInventory("# configuration file " + conf + ":\n" + got)
	if len(inv.Vhosts) != 1 {
		t.Fatalf("o vhost tinha de continuar inteiro, vieram %d", len(inv.Vhosts))
	}
	var viva, morta int
	for _, l := range inv.Vhosts[0].Locations {
		if l.Disabled {
			morta++
		} else {
			viva++
		}
	}
	if morta != 1 {
		t.Fatalf("esperava 1 rota desligada e visível, veio %d:\n%s", morta, got)
	}
	if viva != 2 {
		t.Fatalf("as outras duas rotas tinham de continuar no ar, vieram %d", viva)
	}
}

func TestDisablingANamedLocationThatIsRedirectedToIsRefused(t *testing.T) {
	// `error_page ... = @fallback` com o `@fallback` desligado faz o nginx
	// recusar a config INTEIRA. É barato recusar aqui e caro descobrir no
	// reload, ainda mais num host onde o `nginx -t` não roda.
	srv, conf := locationServer(t)
	original, _ := os.ReadFile(conf)

	code, body := doLocation(t, srv, map[string]any{
		"disabled": true, "refs": []string{locRef(t, conf, "@fallback")},
	}, "nonce-loc-2")
	if code != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", code, body)
	}
	if body["reason"] != "named_location" {
		t.Fatalf("o motivo precisa ser nomeado: %v", body)
	}
	refs, _ := body["referenced_by"].([]any)
	if len(refs) == 0 {
		t.Fatalf("a recusa precisa dizer QUEM redireciona para lá: %v", body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != string(original) {
		t.Fatal("a recusa escreveu no arquivo mesmo assim")
	}
}

func TestANamedLocationNobodyRedirectsToIsNotRefused(t *testing.T) {
	// O portão não pode ser "toda rota nomeada é intocável": uma `@orfa` que
	// ninguém referencia pode ser desligada sem risco, e recusar seria
	// bloquear uma operação legítima.
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	orfa := strings.Replace(locationConf,
		"            error_page 502 503 504 = @fallback;\n", "", 1)
	if err := os.WriteFile(conf, []byte(orfa), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}

	code, body := doLocation(t, srv, map[string]any{
		"disabled": true, "refs": []string{locRef(t, conf, "@fallback")},
	}, "nonce-loc-3")
	if code != http.StatusOK {
		t.Fatalf("rota nomeada sem quem a referencie podia ser desligada: %d %v", code, body)
	}
}

func TestRouteToggleRoundTripsTheFileExactly(t *testing.T) {
	srv, conf := locationServer(t)
	original, _ := os.ReadFile(conf)

	if code, body := doLocation(t, srv, map[string]any{
		"disabled": true, "refs": []string{locRef(t, conf, "/metricas")}, "by": "fulano",
	}, "nonce-loc-rt1"); code != http.StatusOK {
		t.Fatalf("desligar falhou: %d %v", code, body)
	}

	mid, _ := os.ReadFile(conf)
	fences := nginx.ScanFences(string(mid))
	if len(fences) != 1 {
		t.Fatalf("esperava 1 cerca, vieram %d", len(fences))
	}
	if code, body := doLocation(t, srv, map[string]any{
		"disabled": false,
		"fences":   []map[string]any{{"file": conf, "id": fences[0].Meta.ID}},
	}, "nonce-loc-rt2"); code != http.StatusOK {
		t.Fatalf("religar falhou: %d %v", code, body)
	}

	back, _ := os.ReadFile(conf)
	if string(back) != string(original) {
		t.Fatalf("o arquivo não voltou idêntico:\n%s", back)
	}
}

func TestLocationRouteRefusesABlockThatIsNotALocation(t *testing.T) {
	// Endereçar um `server` por esta rota desligaria o domínio inteiro
	// achando que se desligava uma rota. Recusar nomeia o engano.
	srv, conf := locationServer(t)
	raw, _ := os.ReadFile(conf)
	dump := "# configuration file " + conf + ":\n" + string(raw)
	inv := nginx.BuildInventory(dump)
	inv.AttachRefs(dump)

	code, body := doLocation(t, srv, map[string]any{
		"disabled": true, "refs": []string{inv.Vhosts[0].Ref},
	}, "nonce-loc-4")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa, veio %d: %v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "não um location") {
		t.Fatalf("a recusa precisa dizer o que foi endereçado: %v", body)
	}
}
