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

const rawConf = `events {}
http {
    upstream app_pool {
        server 10.0.0.2:8080;
    }
    server {
        listen 80;
        server_name app.example.com;
        location / {
            proxy_pass http://app_pool;
        }
    }
}
`

func fileServer(t *testing.T, allowRaw bool) (*Server, string) {
	t.Helper()
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(rawConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	srv.cfg.AllowRawEdit = allowRaw
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}
	return srv, conf
}

func readFileRoute(t *testing.T, srv *Server, path string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "/v1/file?path="+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	return doApply(t, srv, req)
}

func writeFileRoute(t *testing.T, srv *Server, payload map[string]any, nonce string) (int, map[string]any) {
	t.Helper()
	body, _ := json.Marshal(payload)
	req := signedRequest(t, http.MethodPost, "/v1/file", srv.cfg.Now(),
		testSecret, testToken, body, nonce)
	return doApply(t, srv, req)
}

func TestFileReadReturnsContentAndDigest(t *testing.T) {
	srv, conf := fileServer(t, true)
	code, body := readFileRoute(t, srv, conf)
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	if body["content"] != rawConf {
		t.Fatal("o conteúdo não voltou inteiro")
	}
	if body["digest"] == "" {
		t.Fatal("sem digest não há como escrever com segurança depois")
	}
	// A tela precisa saber ANTES de deixar digitar: oferecer um editor que
	// vai recusar no fim é pior que não oferecer editor.
	if body["writable"] != true {
		t.Fatalf("o host permite edição crua e a resposta diz que não: %v", body)
	}
}

func TestFileReadSaysWhenWritingIsOff(t *testing.T) {
	srv, conf := fileServer(t, false)
	_, body := readFileRoute(t, srv, conf)
	if body["writable"] != false {
		t.Fatalf("o host NÃO permite edição crua e a resposta não diz: %v", body)
	}
}

func TestRawWriteIsRefusedWhenTheCapabilityIsOff(t *testing.T) {
	// Escrever um arquivo de nginx arbitrário é controle equivalente a root do
	// processo nginx. A capacidade nasce desligada e tem de ser ligada de
	// propósito.
	srv, conf := fileServer(t, false)
	original, _ := os.ReadFile(conf)

	code, body := writeFileRoute(t, srv, map[string]any{
		"path": conf, "content": "events {}\n", "base_digest": fileDigest(original),
	}, "nonce-raw-off")
	if code != http.StatusForbidden {
		t.Fatalf("esperava 403, veio %d: %v", code, body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != string(original) {
		t.Fatal("a recusa escreveu no arquivo mesmo assim")
	}
}

func TestRawWriteRejectsStaleBaseDigest(t *testing.T) {
	// Duas telas abertas na mesma config: sem isto, a última a salvar apaga a
	// outra e ninguém fica sabendo.
	srv, conf := fileServer(t, true)
	original, _ := os.ReadFile(conf)
	velho := fileDigest(original)

	// Alguém editou por SSH no meio do caminho.
	mudado := strings.Replace(rawConf, "listen 80;", "listen 8080;", 1)
	if err := os.WriteFile(conf, []byte(mudado), 0o644); err != nil {
		t.Fatal(err)
	}

	code, body := writeFileRoute(t, srv, map[string]any{
		"path": conf, "content": "events {}\n", "base_digest": velho,
	}, "nonce-raw-stale")
	if code != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", code, body)
	}
	if body["reason"] != "stale_digest" {
		t.Fatalf("o motivo precisa ser nomeado: %v", body)
	}
	// O conteúdo novo volta junto: é o que deixa a tela mostrar o que o outro
	// fez SEM perder o que a pessoa digitou.
	if body["current"] != mudado {
		t.Fatalf("a recusa precisa devolver o conteúdo atual: %v", body["current"])
	}
	after, _ := os.ReadFile(conf)
	if string(after) != mudado {
		t.Fatal("a recusa escreveu por cima")
	}
}

func TestRawWriteRequiresABaseDigest(t *testing.T) {
	srv, conf := fileServer(t, true)
	code, body := writeFileRoute(t, srv, map[string]any{
		"path": conf, "content": "events {}\n",
	}, "nonce-raw-nodigest")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa, veio %d: %v", code, body)
	}
}

func TestRawWriteRefusesAPathTheNginxNeverLoaded(t *testing.T) {
	// O confinamento desta rota: sem ele, um `path` vindo do cliente escreve
	// em qualquer lugar que a unit alcance.
	srv, _ := fileServer(t, true)
	alheio := filepath.Join(t.TempDir(), "segredo.conf")
	if err := os.WriteFile(alheio, []byte("nada\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, body := writeFileRoute(t, srv, map[string]any{
		"path": alheio, "content": "events {}\n", "base_digest": "x",
	}, "nonce-raw-out")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa, veio %d: %v", code, body)
	}
	// E a leitura também: senão a rota vira um `cat` de qualquer arquivo.
	if code, _ := readFileRoute(t, srv, alheio); code != http.StatusBadRequest {
		t.Fatalf("a leitura tinha de recusar também, veio %d", code)
	}
}

func TestRawWriteRefusesASymlinkEscape(t *testing.T) {
	// `filepath.Clean` não resolve elo simbólico: um link apontando para fora
	// passaria numa comparação textual e falharia na vida.
	srv, _ := fileServer(t, true)
	dir := t.TempDir()
	alvo := filepath.Join(dir, "fora.txt")
	if err := os.WriteFile(alvo, []byte("segredo\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "parece-config.conf")
	if err := os.Symlink(alvo, link); err != nil {
		t.Skip("symlink indisponível neste filesystem")
	}
	code, _ := writeFileRoute(t, srv, map[string]any{
		"path": link, "content": "events {}\n", "base_digest": "x",
	}, "nonce-raw-link")
	if code != http.StatusBadRequest {
		t.Fatalf("esperava recusa do elo simbólico, veio %d", code)
	}
}

func TestRawWriteAppliesAndReloads(t *testing.T) {
	srv, conf := fileServer(t, true)
	original, _ := os.ReadFile(conf)
	novo := strings.Replace(rawConf, "listen 80;", "listen 8080;", 1)

	code, body := writeFileRoute(t, srv, map[string]any{
		"path": conf, "content": novo,
		"base_digest": fileDigest(original), "by": "fulano",
	}, "nonce-raw-ok")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != novo {
		t.Fatalf("o arquivo não ficou com o conteúdo enviado:\n%s", after)
	}
	// O backup existe, e não é `.conf` — senão um `include *.conf` o serviria.
	backups, _ := body["backups"].([]any)
	if len(backups) != 1 {
		t.Fatalf("esperava 1 backup, veio %v", body["backups"])
	}
	if strings.HasSuffix(backups[0].(string), ".conf") {
		t.Fatalf("o backup não pode terminar em .conf: %v", backups[0])
	}
}

func TestRawWriteOfIdenticalContentWritesNothing(t *testing.T) {
	// Um reload que não serve para nada ainda é uma janela em que a config
	// pode não voltar.
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(rawConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	srv.cfg.AllowRawEdit = true
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}

	code, body := writeFileRoute(t, srv, map[string]any{
		"path": conf, "content": rawConf, "base_digest": fileDigest([]byte(rawConf)),
	}, "nonce-raw-same")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	if runner.ReloadCalls != 0 {
		t.Fatalf("não havia o que escrever e o nginx foi recarregado %d vez(es)",
			runner.ReloadCalls)
	}
}

func TestRawWriteRestoresWhenReloadFails(t *testing.T) {
	runner := nginx.NewFakeRunner()
	srv, _ := newTestServer(t, runner)
	conf := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(conf, []byte(rawConf), 0o644); err != nil {
		t.Fatal(err)
	}
	srv.cfg.MainConf = conf
	srv.cfg.AllowRawEdit = true
	runner.DumpFunc = func() (string, error) {
		b, err := os.ReadFile(conf)
		return "# configuration file " + conf + ":\n" + string(b), err
	}
	runner.ReloadFunc = func() (string, error) {
		return "boom", errFakeReload
	}

	code, body := writeFileRoute(t, srv, map[string]any{
		"path": conf, "content": "isto nao e config valida\n",
		"base_digest": fileDigest([]byte(rawConf)),
	}, "nonce-raw-fail")
	if code != http.StatusConflict {
		t.Fatalf("esperava 409, veio %d: %v", code, body)
	}
	after, _ := os.ReadFile(conf)
	if string(after) != rawConf {
		t.Fatalf("o arquivo não foi restaurado:\n%s", after)
	}
}

func TestRawDryRunShowsBeforeAndAfterWithoutWriting(t *testing.T) {
	srv, conf := fileServer(t, true)
	original, _ := os.ReadFile(conf)
	novo := strings.Replace(rawConf, "listen 80;", "listen 8080;", 1)

	code, body := writeFileRoute(t, srv, map[string]any{
		"path": conf, "content": novo,
		"base_digest": fileDigest(original), "dry_run": true,
	}, "nonce-raw-dry")
	if code != http.StatusOK {
		t.Fatalf("esperava 200, veio %d: %v", code, body)
	}
	files, _ := body["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("esperava a prévia de 1 arquivo: %v", body)
	}
	prev, _ := files[0].(map[string]any)
	if prev["before"] != rawConf || prev["after"] != novo {
		t.Fatal("a prévia não trouxe os dois lados do diff")
	}
	after, _ := os.ReadFile(conf)
	if string(after) != rawConf {
		t.Fatal("o dry-run escreveu no arquivo")
	}
}

// errFakeReload é "o systemctl falhou", para o fake poder reprovar o reload.
var errFakeReload = &writeError{"systemctl error"}
