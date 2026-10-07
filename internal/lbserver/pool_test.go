package lbserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

const poolConf = `events {}
http {
    upstream n8n_pool {
        server 10.10.0.2:11000;
    }
    server {
        listen 80;
        location / { proxy_pass http://n8n_pool; }
    }
}
`

func poolServer(t *testing.T, runner *nginx.FakeRunner) (*Server, string) {
	t.Helper()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(poolConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	return srv, conf
}

func doPool(t *testing.T, srv *Server, pool string, down bool, nonce string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"pool": pool, "down": down})
	req := signedRequest(t, http.MethodPost, "/v1/pool", srv.cfg.Now(),
		testSecret, testToken, body, nonce)
	return doApply(t, srv, req)
}

func TestPoolTogglePutsBackendsDownAndReloads(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, conf := poolServer(t, runner)

	status, body := doPool(t, srv, "n8n_pool", true, "n1")
	if status != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", status, body)
	}
	after, _ := os.ReadFile(conf)
	if !strings.Contains(string(after), "server 10.10.0.2:11000 down;") {
		t.Fatalf("a mudança não chegou ao arquivo:\n%s", after)
	}
	if runner.ReloadCalls != 1 {
		t.Fatalf("esperava 1 reload, veio %d", runner.ReloadCalls)
	}
	// O backup fica AO LADO, dentro de /etc/nginx: é o único diretório que a
	// unit pode escrever sob ProtectSystem=strict.
	entries, _ := os.ReadDir(filepath.Dir(conf))
	var backups int
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak-") {
			backups++
			// Nunca `.conf`: um `include *.conf` não pode servir o backup.
			if strings.HasSuffix(e.Name(), ".conf") {
				t.Fatalf("o backup não pode terminar em .conf: %s", e.Name())
			}
		}
	}
	if backups != 1 {
		t.Fatalf("esperava 1 backup, veio %d", backups)
	}
}

// A rede de verdade. O `nginx -t` não roda neste host, então é o reload que
// protege: o nginx recusa config inválida e segue servindo a anterior.
func TestPoolToggleRestoresWhenReloadFails(t *testing.T) {
	runner := nginx.NewFakeRunner()
	calls := 0
	runner.ReloadFunc = func() (string, error) {
		calls++
		if calls == 1 {
			return "nginx: configuration file test failed", fmt.Errorf("exit 1")
		}
		return "reloaded", nil
	}
	srv, conf := poolServer(t, runner)

	status, body := doPool(t, srv, "n8n_pool", true, "n2")
	if status != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", status, body)
	}
	if body["restored"] != true {
		t.Fatalf("precisa dizer que restaurou: %v", body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != poolConf {
		t.Fatalf("o arquivo tinha de voltar ao original:\n%s", after)
	}
	// Restaurou E recarregou de volta: deixar o nginx com a config velha no
	// disco e a nova em memória seria o pior dos dois mundos.
	if calls != 2 {
		t.Fatalf("esperava reload de restauração, veio %d chamadas", calls)
	}
}

func TestPoolToggleRestoresWhenTestLiveRejects(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.TestLiveFunc = func() (bool, string, error) {
		return false, "nginx: [emerg] invalid parameter", fmt.Errorf("exit 1")
	}
	srv, conf := poolServer(t, runner)

	status, _ := doPool(t, srv, "n8n_pool", true, "n3")
	if status != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d", status)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != poolConf {
		t.Fatal("reprovado no nginx -t tem de restaurar")
	}
	if runner.ReloadCalls != 1 {
		t.Fatalf("só o reload de restauração deve ter corrido, veio %d", runner.ReloadCalls)
	}
}

// O caso REAL deste LB: a sonda não consegue rodar. Recusar a mudança por isso
// travaria a ferramenta justamente no host onde ela é necessária.
func TestPoolToggleProceedsWhenTestLiveCannotRun(t *testing.T) {
	runner := nginx.NewFakeRunner() // TestLiveFunc nil = sandbox barra a sonda
	srv, conf := poolServer(t, runner)

	status, body := doPool(t, srv, "n8n_pool", true, "n4")
	if status != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", status, body)
	}
	if body["validated"] != false {
		t.Fatalf("precisa dizer que NÃO validou: %v", body)
	}
	after, _ := os.ReadFile(conf)
	if !strings.Contains(string(after), "down;") {
		t.Fatal("a mudança tinha de ser aplicada mesmo assim")
	}
}

func TestPoolToggleIsANoOpWhenAlreadyInThatState(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, _ := poolServer(t, runner)
	doPool(t, srv, "n8n_pool", true, "n5")
	before := runner.ReloadCalls

	status, body := doPool(t, srv, "n8n_pool", true, "n6")
	if status != http.StatusOK {
		t.Fatalf("esperava 200, veio %d", status)
	}
	// Um reload que não serve para nada ainda é uma janela em que a config
	// pode não voltar.
	if runner.ReloadCalls != before {
		t.Fatalf("não podia recarregar de novo, veio %d", runner.ReloadCalls)
	}
	if body["changed"] != float64(0) {
		t.Fatalf("esperava changed=0, veio %v", body["changed"])
	}
}

func TestPoolToggleRoundTrips(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, conf := poolServer(t, runner)
	doPool(t, srv, "n8n_pool", true, "n7")
	doPool(t, srv, "n8n_pool", false, "n8")
	after, _ := os.ReadFile(conf)
	if string(after) != poolConf {
		t.Fatalf("ligar de volta tem de devolver o original:\n%s", after)
	}
}

func TestPoolToggleRefusesUnsignedAndUnknown(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, conf := poolServer(t, runner)

	// Mudar a config exige assinatura, não só bearer — ler é bearer só.
	body, _ := json.Marshal(map[string]any{"pool": "n8n_pool", "down": true})
	req := signedRequest(t, http.MethodPost, "/v1/pool", srv.cfg.Now(),
		"segredo-errado", testToken, body, "n9")
	if status, _ := doApply(t, srv, req); status != http.StatusUnauthorized {
		t.Fatalf("assinatura errada tinha de dar 401, veio %d", status)
	}

	if status, _ := doPool(t, srv, "nao_existe", true, "n10"); status != http.StatusBadRequest {
		t.Fatalf("pool inexistente tinha de dar 400, veio %d", status)
	}
	if status, _ := doPool(t, srv, "", true, "n11"); status != http.StatusBadRequest {
		t.Fatalf("pool vazio tinha de dar 400, veio %d", status)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != poolConf {
		t.Fatal("nenhuma recusa pode ter tocado o arquivo")
	}
}

func TestPoolToggleRejectsReplayedNonce(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, _ := poolServer(t, runner)
	body, _ := json.Marshal(map[string]any{"pool": "n8n_pool", "down": true})
	now := srv.cfg.Now()
	req1 := signedRequest(t, http.MethodPost, "/v1/pool", now, testSecret, testToken, body, "same")
	doApply(t, srv, req1)
	req2 := signedRequest(t, http.MethodPost, "/v1/pool", now, testSecret, testToken, body, "same")
	if status, _ := doApply(t, srv, req2); status != http.StatusUnauthorized {
		t.Fatalf("nonce repetido tinha de dar 401, veio %d", status)
	}
}

func TestBackupPathStaysNextToTheOriginal(t *testing.T) {
	got := backupPath("/etc/nginx/nginx.conf", time.Date(2026, 10, 7, 20, 30, 40, 0, time.UTC))
	want := "/etc/nginx/.nginx.conf.bak-20261007-203040"
	if got != want {
		t.Fatalf("esperava %s, veio %s", want, got)
	}
}
