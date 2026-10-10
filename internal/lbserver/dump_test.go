package lbserver

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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

// A saúde de um backend de pool só existia para conf que ESTE listener
// escreveu — ou seja, para o conjunto vazio num LB cujo nginx.conf não inclui
// o conf dir. Os pools que de fato carregam tráfego ficavam sem medida
// nenhuma, que é justamente onde ela importa.
func TestDumpReportsBackendHealthForHandWrittenPools(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	srv, _ := newTestServer(t, runner)
	dialer := newFakeDialer()
	srv.cfg.DialTimeout = dialer.dial

	_, body := doDump(t, srv)
	pool := body["pools"].([]any)[0].(map[string]any)
	server := pool["servers"].([]any)[0].(map[string]any)

	if server["healthy"] != true {
		t.Fatalf("esperava healthy=true, veio %v", server["healthy"])
	}
	if dialer.callsFor("10.10.0.2:10000") != 1 {
		t.Fatalf("esperava uma sondagem, veio %d",
			dialer.callsFor("10.10.0.2:10000"))
	}
}

func TestDumpReportsARefusedBackendAsUnhealthy(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	srv, _ := newTestServer(t, runner)
	dialer := newFakeDialer()
	dialer.unhealthy["10.10.0.2:10000"] = true
	srv.cfg.DialTimeout = dialer.dial

	_, body := doDump(t, srv)
	pool := body["pools"].([]any)[0].(map[string]any)
	server := pool["servers"].([]any)[0].(map[string]any)

	// `false`, não ausente: "recusou a conexão" e "não foi medido" significam
	// coisas opostas para quem olha um backend que parou de servir.
	if healthy, ok := server["healthy"]; !ok || healthy != false {
		t.Fatalf("esperava healthy=false presente, veio %v (presente=%v)",
			healthy, ok)
	}
}

// Backend desligado de propósito não é sondado: pintá-lo de vermelho faria o
// painel gritar sobre algo que a própria pessoa desligou.
func TestDumpDoesNotProbeBackendsTakenOutOfRotation(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) {
		return `# configuration file /etc/nginx/nginx.conf:
http {
    upstream p { server 10.10.0.2:10000 down; }
}
`, nil
	}
	srv, _ := newTestServer(t, runner)
	dialer := newFakeDialer()
	srv.cfg.DialTimeout = dialer.dial

	_, body := doDump(t, srv)
	if dialer.callsFor("10.10.0.2:10000") != 0 {
		t.Fatal("não podia ter sondado um backend fora de rotação")
	}
	pool := body["pools"].([]any)[0].(map[string]any)
	if pool["down"] != true {
		t.Fatalf("o pool tinha de vir marcado como desabilitado: %v", pool)
	}
	server := pool["servers"].([]any)[0].(map[string]any)
	if _, measured := server["healthy"]; measured {
		t.Fatal("não medido não pode virar um healthy qualquer")
	}
}

// ──────────── Onde este listener escreve, e o que o nginx leu ────────────
//
// O LB da OCI serve nove domínios de um nginx.conf monolítico e o painel
// mostrava "nenhum vhost gerido" sem nunca conseguir dizer POR QUÊ. A causa
// (o nginx.conf não inclui /etc/nginx/conf.d) só é afirmável com dois fatos
// juntos: quais arquivos o nginx carregou, e o que existe no conf dir. Um
// sozinho não separa "não está incluído" de "não há nada para incluir".

func TestDumpReportsWhereItWritesAndWhatNginxLoaded(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	srv, confDir := newTestServer(t, runner)

	_, body := doDump(t, srv)

	if body["conf_dir"] != confDir {
		t.Errorf("conf_dir = %v, queria %q", body["conf_dir"], confDir)
	}
	// MainConf vazio na config de teste tem de sair como o default que o
	// ReadConfTree aplica, não como "" — "" faria o painel dizer "não sei"
	// sobre um arquivo que o fallback acabaria de ler.
	if body["main_conf"] != "/etc/nginx/nginx.conf" {
		t.Errorf("main_conf = %v, queria o default", body["main_conf"])
	}

	files, _ := body["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("esperava 1 arquivo carregado, veio %v", body["files"])
	}
	f := files[0].(map[string]any)
	if f["file"] != "/etc/nginx/nginx.conf" {
		t.Errorf("file = %v", f["file"])
	}
	if f["managed"] != false {
		t.Errorf("o monolítico não é gerido por nós: %v", f["managed"])
	}
}

func TestDumpListsConfDirAndTagsManagedFiles(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	srv, confDir := newTestServer(t, runner)

	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(confDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("app-a.conf", "# managed-by: deployer-lb-server app=app-a revision=7\nserver {}\n")
	write("legado.conf", "server { server_name x.example.com; }\n")
	// Os três que não contam, pelas MESMAS regras do statusApps: um backup,
	// um dotfile e um diretório. Se as duas leituras do mesmo diretório
	// divergirem sobre o que é um arquivo, elas contam histórias diferentes.
	write("velho.conf.bak", "irrelevante\n")
	write(".oculto.conf", "irrelevante\n")
	if err := os.Mkdir(filepath.Join(confDir, "sub.conf"), 0o755); err != nil {
		t.Fatal(err)
	}

	_, body := doDump(t, srv)

	if body["conf_dir_error"] != "" {
		t.Fatalf("o diretório era legível: %v", body["conf_dir_error"])
	}
	rows, _ := body["conf_dir_files"].([]any)
	if len(rows) != 2 {
		t.Fatalf("esperava 2 confs, veio %v", rows)
	}
	byName := map[string]map[string]any{}
	for _, r := range rows {
		m := r.(map[string]any)
		byName[m["name"].(string)] = m
	}
	if byName["app-a.conf"]["managed"] != true || byName["app-a.conf"]["app"] != "app-a" {
		t.Errorf("app-a.conf devia ser gerido: %v", byName["app-a.conf"])
	}
	// Conf escrito à mão continua na lista: a pergunta é "há algo aqui para
	// o nginx incluir", e um arquivo que não é nosso responde isso igual.
	if byName["legado.conf"]["managed"] != false {
		t.Errorf("legado.conf não é nosso: %v", byName["legado.conf"])
	}
}

// Diretório ilegível NÃO é diretório vazio. Achatar os dois deixaria o painel
// afirmar "o nginx.conf não inclui este diretório" a partir de uma medição
// que falhou — e mandar alguém consertar o arquivo errado.
func TestDumpKeepsUnreadableConfDirDistinctFromEmpty(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return dumpSample, nil }
	srv, _ := newTestServer(t, runner)
	srv.cfg.ConfDir = filepath.Join(t.TempDir(), "nao-existe")

	status, body := doDump(t, srv)
	if status != http.StatusOK {
		t.Fatalf("um diretório ilegível não pode derrubar o dump: %d", status)
	}
	if body["conf_dir_error"] == "" {
		t.Error("o motivo de não ter lido é a informação, e sumiu")
	}
	rows, ok := body["conf_dir_files"].([]any)
	if !ok || rows == nil {
		t.Errorf("conf_dir_files tem de serializar [], nunca null: %v", body["conf_dir_files"])
	}
}

// O contrato é do JSON, não do `|| []` de quem consome. Um null aqui vira
// crash ou estado vazio inventado do outro lado do fio.
func TestDumpNeverSerializesNullSlices(t *testing.T) {
	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) { return "", nil }
	srv, _ := newTestServer(t, runner)

	mux := http.NewServeMux()
	srv.Routes(mux)
	req := httptest.NewRequest(http.MethodGet, "/v1/dump", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	for _, key := range []string{`"files":null`, `"conf_dir_files":null`,
		`"pools":null`, `"vhosts":null`} {
		if strings.Contains(rr.Body.String(), key) {
			t.Errorf("corpo contém %s\n%s", key, rr.Body.String())
		}
	}
}

// O fallback de ler os arquivos existe porque `nginx -T` não roda sob o
// sandbox da unit. Ele é o caminho que o LB de produção usa de verdade — se
// os campos novos faltassem justamente ali, o diagnóstico não existiria no
// único host onde ele importa.
func TestDumpCarriesTheNewFieldsThroughTheFileFallback(t *testing.T) {
	dir := t.TempDir()
	main := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(main, []byte("http {\n    server { server_name a.example.com; }\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	runner := nginx.NewFakeRunner()
	runner.DumpFunc = func() (string, error) {
		return "", errors.New("nginx -T não roda sob o sandbox")
	}
	srv, confDir := newTestServer(t, runner)
	srv.cfg.MainConf = main

	_, body := doDump(t, srv)

	if body["source"] != "arquivos de config" {
		t.Fatalf("esperava o fallback, veio %v", body["source"])
	}
	if body["conf_dir"] != confDir {
		t.Errorf("conf_dir sumiu no fallback: %v", body["conf_dir"])
	}
	if body["main_conf"] != main {
		t.Errorf("main_conf = %v, queria %q", body["main_conf"], main)
	}
	files, _ := body["files"].([]any)
	if len(files) != 1 {
		t.Fatalf("esperava o nginx.conf na lista, veio %v", body["files"])
	}
}
