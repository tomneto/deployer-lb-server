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

const backendsServerConf = `events {}
http {
    upstream app_pool {
        server 10.0.0.2:8080 weight=3;
        server 10.0.0.3:8080;
        keepalive 16;
    }
    server {
        listen 80;
        server_name app.example.com;
        location / { proxy_pass http://app_pool; }
    }
}
`

func backendsServer(t *testing.T) (*Server, string) {
	t.Helper()
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(backendsServerConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}
	return srv, conf
}

func doPoolServers(t *testing.T, srv *Server, payload map[string]any, nonce string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := signedRequest(t, http.MethodPost, "/v1/pool/servers", srv.cfg.Now(),
		testSecret, testToken, body, nonce)
	return doApply(t, srv, req)
}

func TestAddBackendAppliesAndReloads(t *testing.T) {
	srv, conf := backendsServer(t)
	code, body := doPoolServers(t, srv, map[string]any{
		"pool": "app_pool", "file": conf, "op": "add",
		"address": "10.0.0.4:8080", "params": map[string]string{"weight": "2"},
	}, "nonce-be-1")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	after, _ := os.ReadFile(conf)
	if !strings.Contains(string(after), "server 10.0.0.4:8080 weight=2;") {
		t.Fatalf("o backend não entrou:\n%s", after)
	}
	if body["serving"] != float64(3) {
		t.Fatalf("esperava 3 servindo, veio %v", body["serving"])
	}
}

func TestRemoveBackendMarksDownByDefault(t *testing.T) {
	srv, conf := backendsServer(t)
	code, body := doPoolServers(t, srv, map[string]any{
		"pool": "app_pool", "file": conf, "op": "remove",
		"address": "10.0.0.3:8080",
	}, "nonce-be-2")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	after, _ := os.ReadFile(conf)
	if !strings.Contains(string(after), "server 10.0.0.3:8080 down;") {
		t.Fatalf("esperava a linha marcada down:\n%s", after)
	}
	// A linha continua lá: `down` é reversível apagando uma palavra.
	if body["remaining"] != float64(2) {
		t.Fatalf("a linha tinha de continuar no arquivo: %v", body)
	}
}

func TestPoolBecomingUnservedIsReportedNotRefused(t *testing.T) {
	// Marcar down o último que atendia é legítimo — mas quem pediu precisa
	// saber, porque pediu para tirar UM backend e o pool inteiro parou.
	srv, conf := backendsServer(t)
	doPoolServers(t, srv, map[string]any{
		"pool": "app_pool", "file": conf, "op": "remove", "address": "10.0.0.2:8080",
	}, "nonce-be-3")
	code, body := doPoolServers(t, srv, map[string]any{
		"pool": "app_pool", "file": conf, "op": "remove", "address": "10.0.0.3:8080",
	}, "nonce-be-4")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	if body["serving"] != float64(0) {
		t.Fatalf("esperava serving 0, veio %v", body["serving"])
	}
	note, _ := body["note"].(string)
	if !strings.Contains(note, "nenhum backend") {
		t.Fatalf("o aviso tinha de aparecer: %v", body)
	}
}

func TestInjectedAddressNeverReachesTheFile(t *testing.T) {
	srv, conf := backendsServer(t)
	original, _ := os.ReadFile(conf)
	code, body := doPoolServers(t, srv, map[string]any{
		"pool": "app_pool", "file": conf, "op": "add",
		"address": "10.0.0.9:80; } server { listen 80; server_name invadido.com;",
	}, "nonce-be-5")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa, veio %d: %v", code, body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != string(original) {
		t.Fatalf("a injeção chegou ao arquivo:\n%s", after)
	}
}

func TestPoolServersDryRunWritesNothing(t *testing.T) {
	srv, conf := backendsServer(t)
	original, _ := os.ReadFile(conf)
	code, body := doPoolServers(t, srv, map[string]any{
		"pool": "app_pool", "file": conf, "op": "add",
		"address": "10.0.0.5:8080", "dry_run": true,
	}, "nonce-be-6")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	if body["dry_run"] != true {
		t.Fatalf("a resposta precisa dizer que foi simulação: %v", body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != string(original) {
		t.Fatal("o dry-run escreveu no arquivo")
	}
}

func TestPoolServersRefusesAnUnknownOperation(t *testing.T) {
	srv, conf := backendsServer(t)
	code, _ := doPoolServers(t, srv, map[string]any{
		"pool": "app_pool", "file": conf, "op": "apagar-tudo",
	}, "nonce-be-7")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa, veio %d", code)
	}
}
