package lbserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

const dumpSample = `# configuration file /etc/nginx/nginx.conf:
http {
    upstream legacy_pool {
        server 10.10.0.2:10000;
    }
    server {
        listen 80;
        server_name legacy.workspacefy.com;
        location / {
            proxy_pass http://legacy_pool;
        }
    }
}
`

func doDump(t *testing.T, srv *Server) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	srv.Routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/dump", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

// O motivo de /v1/dump existir: /v1/status responde "o que eu apliquei", que
// num host cujo nginx.conf não inclui o conf dir gerido não tem relação
// nenhuma com o que o nginx serve. O status reportaria um LB vazio enquanto
// os vhosts de produção vivem num arquivo que este listener nunca escreveu.
func TestDumpSeesConfigTheListenerNeverWrote(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	srv, _ := newTestServer(t, runner)

	status, body := doDump(t, srv)
	if status != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", status, body)
	}

	pools, _ := body["pools"].([]any)
	if len(pools) != 1 {
		t.Fatalf("esperava 1 pool, veio %v", body["pools"])
	}
	vhosts, _ := body["vhosts"].([]any)
	if len(vhosts) != 1 {
		t.Fatalf("esperava 1 vhost, veio %v", body["vhosts"])
	}
	// E o status, no mesmo servidor, não enxerga nada disso.
	if apps, _ := getStatus(t, srv)["apps"].(map[string]any); len(apps) != 0 {
		t.Fatalf("status deveria estar vazio, veio %v", apps)
	}
}

func TestDumpRequiresBearer(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/dump", nil))

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("dump sem token devia ser 401, veio %d", rr.Code)
	}
}

func TestDumpRejectsNonGet(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/dump", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("esperava 405, veio %d", rr.Code)
	}
}

// `nginx -T` sai com código diferente de zero numa config que ele recusa, e a
// reclamação dele é justamente o que alguém olhando um LB quebrado precisa
// ler. Devolver 500 vazio esconderia a única informação útil.
func TestDumpStillReturnsTextWhenNginxComplains(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) {
		return "nginx: [emerg] unknown directive \"proxy_passs\"", errors.New("exit 1")
	}
	srv, _ := newTestServer(t, runner)

	status, body := doDump(t, srv)
	if status != http.StatusOK {
		t.Fatalf("esperava 200 com erro no corpo, veio %d", status)
	}
	if body["status"] != "error" {
		t.Errorf("status deveria ser error: %v", body["status"])
	}
	if raw, _ := body["raw"].(string); raw == "" {
		t.Error("a saída do nginx foi descartada — é o que explica a falha")
	}
}
