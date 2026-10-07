package nginx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// O fallback existe porque `nginx -T` não roda sob o sandbox da unit: a config
// principal declara `pid /run/nginx.pid`, ProtectSystem=strict deixa /run
// somente-leitura, e `-g "pid ..."` falha com "directive is duplicate". Ler
// nunca é bloqueado — só escrever.
func TestReadConfTreeFollowsIncludes(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "nginx.conf"), `
pid /run/nginx.pid;
http {
    include conf.d/*.conf;
    upstream main_pool { server 10.0.0.1:80; }
}
`)
	writeFile(t, filepath.Join(dir, "conf.d", "app.conf"), `
server {
    server_name a.example.com;
}
`)

	out, err := ReadConfTree(filepath.Join(dir, "nginx.conf"))
	if err != nil {
		t.Fatalf("erro inesperado: %v", err)
	}
	if !strings.Contains(out, "a.example.com") {
		t.Errorf("include não seguido:\n%s", out)
	}
	// Os marcadores têm de ser os mesmos do `nginx -T`, senão o inventário
	// precisaria de dois parsers.
	if strings.Count(out, "# configuration file ") != 2 {
		t.Errorf("marcadores de arquivo errados:\n%s", out)
	}
}

func TestReadConfTreeIsParseableByTheInventory(t *testing.T) {
	// A prova que importa: as duas fontes alimentam o MESMO parser.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "nginx.conf"), `
http {
    upstream backend_pool { server 10.10.0.2:10000; }
    server {
        listen 80;
        server_name backend.example.com;
        location / { proxy_pass http://backend_pool; }
    }
}
`)
	out, _ := ReadConfTree(filepath.Join(dir, "nginx.conf"))
	inv := BuildInventory(out)
	inv.ResolvePools()

	if len(inv.Pools) != 1 || len(inv.Vhosts) != 1 {
		t.Fatalf("inventário vazio a partir da leitura direta: %+v", inv)
	}
	if inv.Vhosts[0].Locations[0].Pool != "backend_pool" {
		t.Errorf("location não ligada ao pool: %+v", inv.Vhosts[0].Locations[0])
	}
}

func TestReadConfTreeSurvivesBrokenIncludes(t *testing.T) {
	// Um glob que não casa nada é legítimo para o nginx, e um arquivo
	// ilegível não pode custar a árvore inteira.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "nginx.conf"), `
http {
    include /caminho/que/nao/existe/*.conf;
    upstream p { server 1.2.3.4:80; }
}
`)
	out, err := ReadConfTree(filepath.Join(dir, "nginx.conf"))
	if err != nil {
		t.Fatalf("include quebrado não devia ser fatal: %v", err)
	}
	if !strings.Contains(out, "upstream p") {
		t.Errorf("resto da config perdido:\n%s", out)
	}
}

func TestReadConfTreeIgnoresVariableIncludes(t *testing.T) {
	// `include $algo` é o nginx resolvendo em runtime; adivinhar inventaria
	// config que pode não existir.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "nginx.conf"), "http {\n    include $dir/x.conf;\n}\n")
	if _, err := ReadConfTree(filepath.Join(dir, "nginx.conf")); err != nil {
		t.Fatalf("não devia falhar: %v", err)
	}
}

func TestReadConfTreeDoesNotEmitTheSameFileTwice(t *testing.T) {
	// Um glob pode nomear o mesmo arquivo duas vezes; emiti-lo duas vezes
	// faria a tela mostrar vhosts duplicados que não existem.
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "nginx.conf"),
		"http {\n    include conf.d/app.conf;\n    include conf.d/*.conf;\n}\n")
	writeFile(t, filepath.Join(dir, "conf.d", "app.conf"), "server { server_name x; }\n")

	out, _ := ReadConfTree(filepath.Join(dir, "nginx.conf"))
	if n := strings.Count(out, "server_name x"); n != 1 {
		t.Errorf("arquivo emitido %d vezes:\n%s", n, out)
	}
}

func TestReadConfTreeReportsAMissingMainFile(t *testing.T) {
	if _, err := ReadConfTree(filepath.Join(t.TempDir(), "ausente.conf")); err == nil {
		t.Error("arquivo principal ausente devia ser erro")
	}
}
