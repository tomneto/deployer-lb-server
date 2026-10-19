package lbserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

// O estado real do LB de produção: nove domínios servidos de um arquivo
// escrito à mão, e nenhum `include` do diretório onde o listener escreve.
const disconnectedMainConf = `events {}
http {
    include /etc/nginx/mime.types;
    server {
        listen 80;
        server_name legado.exemplo.com;
        location / { proxy_pass http://127.0.0.1:9000; }
    }
}
`

func includeServer(t *testing.T, runner *nginx.FakeRunner) (*Server, string, string) {
	t.Helper()
	srv, confDir := newTestServer(t, runner)
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte(disconnectedMainConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	return srv, conf, confDir
}

func doInclude(t *testing.T, srv *Server, force bool, nonce string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"force": force})
	req := signedRequest(t, http.MethodPost, "/v1/include", srv.cfg.Now(),
		testSecret, testToken, body, nonce)
	return doApply(t, srv, req)
}

func TestIncludeConnectsTheChannelAndReloads(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, conf, confDir := includeServer(t, runner)

	status, body := doInclude(t, srv, false, "i1")
	if status != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", status, body)
	}
	if body["changed"] != true {
		t.Fatalf("esperava changed: %v", body)
	}
	after, _ := os.ReadFile(conf)
	if !strings.Contains(string(after), "include "+confDir+"/*.conf;") {
		t.Fatalf("a linha não chegou ao arquivo:\n%s", after)
	}
	if runner.ReloadCalls != 1 {
		t.Fatalf("esperava 1 reload, veio %d", runner.ReloadCalls)
	}
	// O backup fica ao lado, e nunca termina em .conf — senão o include que
	// acabamos de escrever poderia servir o próprio backup.
	entries, _ := os.ReadDir(filepath.Dir(conf))
	var backups int
	for _, e := range entries {
		if strings.Contains(e.Name(), ".bak-") {
			backups++
			if strings.HasSuffix(e.Name(), ".conf") {
				t.Fatalf("o backup não pode terminar em .conf: %s", e.Name())
			}
		}
	}
	if backups != 1 {
		t.Fatalf("esperava 1 backup, veio %d", backups)
	}
}

func TestIncludeIsANoOpWhenAlreadyConnected(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, conf, _ := includeServer(t, runner)

	if _, _ = doInclude(t, srv, false, "i2a"); runner.ReloadCalls != 1 {
		t.Fatalf("a primeira chamada tinha de recarregar")
	}
	before, _ := os.ReadFile(conf)

	status, body := doInclude(t, srv, false, "i2b")
	if status != http.StatusOK || body["changed"] != false {
		t.Fatalf("a segunda chamada não pode mudar nada: %d %v", status, body)
	}
	if runner.ReloadCalls != 1 {
		t.Fatalf("um reload sem propósito ainda é uma janela de risco: %d", runner.ReloadCalls)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != string(before) {
		t.Fatal("o arquivo não podia ser reescrito")
	}
}

// A única coisa que ligar o canal pode mudar em produção: um vhost esquecido
// no conf dir que declara um domínio já servido à mão. O nginx não falha nisso
// — ele avisa e ignora um dos dois —, então quem tem de falhar é a rota.
func TestIncludeRefusesOnDomainCollisionAndObeysForce(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) {
		return "# configuration file /etc/nginx/nginx.conf:\n" + disconnectedMainConf, nil
	}
	srv, conf, confDir := includeServer(t, runner)
	managed := "# managed-by: deployer-lb-server app=legado revision=3\n" +
		"server {\n    listen 80;\n    server_name legado.exemplo.com;\n}\n"
	if err := os.WriteFile(filepath.Join(confDir, "legado.conf"), []byte(managed), 0o644); err != nil {
		t.Fatal(err)
	}

	status, body := doInclude(t, srv, false, "i3")
	if status != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", status, body)
	}
	cols, _ := body["collisions"].([]any)
	if len(cols) != 1 || cols[0] != "legado.exemplo.com" {
		t.Fatalf("a lista de domínios em conflito tem de vir por extenso: %v", body)
	}
	if untouched, _ := os.ReadFile(conf); string(untouched) != disconnectedMainConf {
		t.Fatal("uma recusa não pode ter escrito no arquivo")
	}
	if runner.ReloadCalls != 0 {
		t.Fatal("uma recusa não pode ter recarregado o nginx")
	}

	status, body = doInclude(t, srv, true, "i4")
	if status != http.StatusOK || body["changed"] != true {
		t.Fatalf("com force a mudança tem de passar: %d %v", status, body)
	}
	after, _ := os.ReadFile(conf)
	if !strings.Contains(string(after), "include "+confDir+"/*.conf;") {
		t.Fatalf("a linha não chegou ao arquivo:\n%s", after)
	}
}

func TestIncludeRestoresWhenReloadFails(t *testing.T) {
	runner := nginx.NewFakeRunner()
	calls := 0
	runner.ReloadFunc = func() (string, error) {
		calls++
		if calls == 1 {
			return "nginx: configuration file test failed", fmt.Errorf("exit 1")
		}
		return "reloaded", nil
	}
	srv, conf, _ := includeServer(t, runner)

	status, body := doInclude(t, srv, false, "i5")
	if status != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", status, body)
	}
	if body["restored"] != true {
		t.Fatalf("precisa dizer que restaurou: %v", body)
	}
	if after, _ := os.ReadFile(conf); string(after) != disconnectedMainConf {
		t.Fatalf("o arquivo tinha de voltar ao original:\n%s", after)
	}
	if calls != 2 {
		t.Fatalf("restaurar sem recarregar de volta deixa o nginx com a config velha: %d", calls)
	}
}

func TestIncludeRestoresWhenTestLiveRejects(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.TestLiveFunc = func() (bool, string, error) {
		return false, "nginx: [emerg] invalid parameter", fmt.Errorf("exit 1")
	}
	srv, conf, _ := includeServer(t, runner)

	status, _ := doInclude(t, srv, false, "i6")
	if status != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d", status)
	}
	if after, _ := os.ReadFile(conf); string(after) != disconnectedMainConf {
		t.Fatal("reprovado no nginx -t, o arquivo tinha de voltar")
	}
}

// A sandbox deste LB impede o `nginx -t` de rodar. "Não pôde rodar" não é
// "reprovou": tratar os dois igual travaria a correção no host que precisa.
func TestIncludeProceedsWhenTestLiveCannotRun(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.TestLiveFunc = func() (bool, string, error) {
		return false, "nginx: [emerg] open() \"/run/nginx.pid\" failed (13: Permission denied)",
			fmt.Errorf("exit 1")
	}
	srv, _, _ := includeServer(t, runner)

	status, body := doInclude(t, srv, false, "i7")
	if status != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", status, body)
	}
	if body["validated"] != false {
		t.Fatalf("`validated` tem de dizer que ninguém validou: %v", body)
	}
}

func TestIncludeRefusesUnsignedAndReplayed(t *testing.T) {
	srv, _, _ := includeServer(t, nginx.NewFakeRunner())
	req := signedRequest(t, http.MethodPost, "/v1/include", srv.cfg.Now(),
		"segredo-errado", testToken, []byte(`{}`), "i8")
	if status, _ := doApply(t, srv, req); status != http.StatusUnauthorized {
		t.Fatalf("assinatura errada tem de dar 401, veio %d", status)
	}

	srv2, _, _ := includeServer(t, nginx.NewFakeRunner())
	body, _ := json.Marshal(map[string]any{})
	r1 := signedRequest(t, http.MethodPost, "/v1/include", srv2.cfg.Now(),
		testSecret, testToken, body, "mesmo")
	r2 := signedRequest(t, http.MethodPost, "/v1/include", srv2.cfg.Now(),
		testSecret, testToken, body, "mesmo")
	if status, _ := doApply(t, srv2, r1); status != http.StatusOK {
		t.Fatalf("a primeira tinha de passar, veio %d", status)
	}
	if status, _ := doApply(t, srv2, r2); status != http.StatusUnauthorized {
		t.Fatalf("nonce repetido tem de dar 401, veio %d", status)
	}
}
