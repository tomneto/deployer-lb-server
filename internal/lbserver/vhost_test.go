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

// O caso que obriga a rota a aceitar lista: dois `server` com o mesmo
// server_name, um redirecionando na 80 e outro servindo na 443.
const vhostConf = `events {}
http {
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

    server {
        listen 80 default_server;
        server_name _;
        return 444;
    }
}
`

func vhostServer(t *testing.T) (*Server, string) {
	t.Helper()
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(vhostConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	// O dump do fake devolve o arquivo com o marcador, como `nginx -T` faria.
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}
	return srv, conf
}

// refsFor devolve os refs dos vhosts cujo server_name casa.
func refsFor(t *testing.T, srv *Server, conf, name string) []string {
	t.Helper()
	raw, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	dump := "# configuration file " + conf + ":\n" + string(raw)
	inv := nginx.BuildInventory(dump)
	inv.AttachRefs(dump)
	var out []string
	for _, v := range inv.Vhosts {
		for _, n := range v.ServerNames {
			if n == name && v.Ref != "" {
				out = append(out, v.Ref)
			}
		}
	}
	return out
}

func doVhost(t *testing.T, srv *Server, payload map[string]any, nonce string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := signedRequest(t, http.MethodPost, "/v1/vhost", srv.cfg.Now(),
		testSecret, testToken, body, nonce)
	return doApply(t, srv, req)
}

func TestVhostToggleDisablesEveryBlockOfTheDomainAtOnce(t *testing.T) {
	// A transação. Desligar só o bloco da 443 deixaria a porta 80
	// redirecionando para um 443 que já não responde — meio toggle aplicado é
	// pior que nenhum.
	srv, conf := vhostServer(t)
	refs := refsFor(t, srv, conf, "app.example.com")
	if len(refs) != 2 {
		t.Fatalf("o fixture precisa ter 2 blocos para app.example.com, tem %d", len(refs))
	}

	code, body := doVhost(t, srv, map[string]any{
		"disabled": true, "refs": refs, "by": "fulano",
	}, "nonce-vhost-1")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}

	after, _ := os.ReadFile(conf)
	got := string(after)
	if strings.Count(got, "#>>> lb-off") != 2 {
		t.Fatalf("os dois blocos tinham de ser cercados:\n%s", got)
	}
	// E o nginx não vê mais nenhum dos dois.
	inv := nginx.BuildInventory("# configuration file " + conf + ":\n" + got)
	for _, v := range inv.Vhosts {
		for _, n := range v.ServerNames {
			if n == "app.example.com" && !v.Disabled {
				t.Fatalf("sobrou um bloco de app.example.com no ar:\n%s", got)
			}
		}
	}
	// O default_server, que ninguém mandou tocar, continua intacto.
	if !strings.Contains(got, "listen 80 default_server;") ||
		strings.Contains(got, "#|         listen 80 default_server;") {
		t.Fatalf("o default_server foi afetado:\n%s", got)
	}
}

func TestDisablingTheDefaultServerRequiresForce(t *testing.T) {
	// Desligar o `default_server` muda, em silêncio, quem atende todo o
	// tráfego não reclamado da porta. É barato recusar e caro descobrir
	// depois.
	srv, conf := vhostServer(t)
	refs := refsFor(t, srv, conf, "_")
	if len(refs) != 1 {
		t.Fatalf("esperava 1 default_server no fixture, veio %d", len(refs))
	}

	code, body := doVhost(t, srv, map[string]any{
		"disabled": true, "refs": refs,
	}, "nonce-vhost-2")
	if code != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", code, body)
	}
	if body["reason"] != "default_server" {
		t.Fatalf("o motivo da recusa tem de ser nomeado: %v", body)
	}
	before, _ := os.ReadFile(conf)
	if strings.Contains(string(before), "lb-off") {
		t.Fatal("a recusa escreveu no arquivo mesmo assim")
	}

	// Com `force`, passa.
	code, body = doVhost(t, srv, map[string]any{
		"disabled": true, "refs": refs, "force": true,
	}, "nonce-vhost-3")
	if code != http.StatusOK {
		t.Fatalf("com force esperava 200, veio %d: %v", code, body)
	}
}

func TestVhostToggleRoundTripsTheFileExactly(t *testing.T) {
	// Desligar e religar tem de devolver o arquivo IDÊNTICO. Senão o painel
	// reescreve config de produção de leve a cada clique.
	srv, conf := vhostServer(t)
	original, _ := os.ReadFile(conf)

	refs := refsFor(t, srv, conf, "app.example.com")
	if code, body := doVhost(t, srv, map[string]any{
		"disabled": true, "refs": refs, "by": "fulano",
	}, "nonce-rt-1"); code != http.StatusOK {
		t.Fatalf("desligar falhou: %d %v", code, body)
	}

	// Religar: o endereço agora é o id da cerca, não o ref.
	mid, _ := os.ReadFile(conf)
	var targets []map[string]any
	for _, f := range nginx.ScanFences(string(mid)) {
		targets = append(targets, map[string]any{"file": conf, "id": f.Meta.ID})
	}
	if len(targets) != 2 {
		t.Fatalf("esperava 2 cercas, vieram %d", len(targets))
	}
	if code, body := doVhost(t, srv, map[string]any{
		"disabled": false, "fences": targets,
	}, "nonce-rt-2"); code != http.StatusOK {
		t.Fatalf("religar falhou: %d %v", code, body)
	}

	back, _ := os.ReadFile(conf)
	if string(back) != string(original) {
		t.Fatalf("o arquivo não voltou idêntico:\n--- antes ---\n%s\n--- depois ---\n%s",
			original, back)
	}
}

func TestVhostToggleRestoresEveryFileWhenReloadFails(t *testing.T) {
	// A rede. Se o reload falhar, NADA pode ficar aplicado — nem o arquivo que
	// já tinha sido escrito.
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(vhostConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}
	original, _ := os.ReadFile(conf)
	refs := refsFor(t, srv, conf, "app.example.com")

	runner.ReloadFunc = func() (string, error) {
		return "boom", fmt.Errorf("systemctl error")
	}
	code, body := doVhost(t, srv, map[string]any{
		"disabled": true, "refs": refs,
	}, "nonce-fail-1")
	if code != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", code, body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != string(original) {
		t.Fatalf("o arquivo não foi restaurado:\n%s", after)
	}
	// O reload de restauração também falhou (o fake falha sempre), então o
	// pior caso tem de aparecer inteiro.
	if body["restored"] != false {
		t.Fatalf("`restored: false` é o pior caso e tem de ser reportado: %v", body)
	}
}

func TestVhostDryRunWritesNothing(t *testing.T) {
	// O dry-run roda o MESMO planejamento da escrita real e para antes do
	// disco — é o que torna a pré-visualização honesta.
	srv, conf := vhostServer(t)
	original, _ := os.ReadFile(conf)
	refs := refsFor(t, srv, conf, "app.example.com")

	code, body := doVhost(t, srv, map[string]any{
		"disabled": true, "refs": refs, "dry_run": true,
	}, "nonce-dry-1")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	if body["dry_run"] != true {
		t.Fatalf("a resposta precisa dizer que foi simulação: %v", body)
	}
	files, _ := body["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("esperava a prévia de 1 arquivo, veio %v", body["files"])
	}
	after, _ := os.ReadFile(conf)
	if string(after) != string(original) {
		t.Fatal("o dry-run escreveu no arquivo")
	}
}

func TestVhostRefusesFileOutsideTheLoadedConfig(t *testing.T) {
	// Sem este confinamento, um `file` vindo do cliente escreve em qualquer
	// lugar que a unit alcance.
	srv, conf := vhostServer(t)
	refs := refsFor(t, srv, conf, "app.example.com")

	ref, err := nginx.DecodeRef(refs[0])
	if err != nil {
		t.Fatal(err)
	}
	ref.File = filepath.Join(t.TempDir(), "alheio.conf")
	if err := os.WriteFile(ref.File, []byte("server {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	code, body := doVhost(t, srv, map[string]any{
		"disabled": true, "refs": []string{ref.Encode()},
	}, "nonce-out-1")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa, veio %d: %v", code, body)
	}
}

func TestVhostRefusesStaleRef(t *testing.T) {
	// O bloco foi editado à mão desde que a tela o leu. Escrever por cima
	// apagaria a edição de outra pessoa sem avisar.
	srv, conf := vhostServer(t)
	refs := refsFor(t, srv, conf, "app.example.com")

	edited := strings.Replace(vhostConf, "listen 443 ssl;", "listen 443 ssl http2;", 1)
	if err := os.WriteFile(conf, []byte(edited), 0o644); err != nil {
		t.Fatal(err)
	}

	code, body := doVhost(t, srv, map[string]any{
		"disabled": true, "refs": refs,
	}, "nonce-stale-1")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa por ref obsoleto, veio %d: %v", code, body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "mudou") {
		t.Fatalf("a recusa precisa dizer que o bloco mudou: %v", body)
	}
}
