package lbserver

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

func doFidelity(t *testing.T, srv *Server) (int, map[string]any) {
	t.Helper()
	mux := http.NewServeMux()
	srv.Routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/fidelity", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

func TestFidelityEndpointReportsEachVhost(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	srv, _ := newTestServer(t, runner)

	status, body := doFidelity(t, srv)
	if status != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", status, body)
	}
	vhosts, _ := body["vhosts"].([]any)
	if len(vhosts) != 1 {
		t.Fatalf("esperava 1 vhost, veio %v", body["vhosts"])
	}
	v := vhosts[0].(map[string]any)
	if v["verdict"] == nil || v["verdict"] == "" {
		t.Error("vhost sem veredito")
	}
	// A contagem é o que a tela mostra primeiro: "dos nove, quantos dá para
	// reproduzir".
	if _, ok := body["counts"].(map[string]any); !ok {
		t.Errorf("sem contagem por veredito: %v", body["counts"])
	}
}

// Somente leitura é contrato, não detalhe de implementação: o relatório existe
// para informar uma decisão que uma pessoa toma, e um endpoint que também
// escrevesse transformaria um classificador num escritor de config.
func TestFidelityEndpointIsReadOnly(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	runner.TestFunc = func(string) (bool, string, error) {
		t.Fatal("o relatório de fidelidade rodou `nginx -t`")
		return false, "", nil
	}
	runner.ReloadFunc = func() (string, error) {
		t.Fatal("o relatório de fidelidade recarregou o nginx")
		return "", nil
	}
	srv, _ := newTestServer(t, runner)

	if status, _ := doFidelity(t, srv); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}

	mux := http.NewServeMux()
	srv.Routes(mux)
	req := httptest.NewRequest(http.MethodPost, "/v1/fidelity", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST devia ser 405, veio %d", rr.Code)
	}
}

func TestFidelityEndpointRequiresBearer(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	mux := http.NewServeMux()
	srv.Routes(mux)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/fidelity", nil))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sem token devia ser 401, veio %d", rr.Code)
	}
}
