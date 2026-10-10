package lbserver

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomneto/deployer-lb-server/conf"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

// O template embutido e o binário saem do mesmo build, então esta é a única
// combinação que roda em produção — e ela tem de executar.
func TestVerifyTemplateAcceptsTheEmbeddedTemplate(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	srv.cfg.TemplatePath = "" // o caminho normal: template embutido

	if err := srv.VerifyTemplate(); err != nil {
		t.Fatalf("o template que vai no binário não executa: %v", err)
	}
}

// A sonda só vale se ela FALHAR quando deve. Uma verificação de boot que nunca
// reprovou nada é um log a mais, não uma garantia.
func TestVerifyTemplateRefusesATemplateThatCannotExecute(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "quebrado.tmpl")
	// Campo que não existe no Payload: é exatamente a forma do skew que isto
	// existe para pegar — template novo, binário velho.
	if err := os.WriteFile(path, []byte(
		"# managed-by: x\n{{.CampoQueNaoExiste}}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, _ := newTestServer(t, nil)
	srv.cfg.TemplatePath = path

	err := srv.VerifyTemplate()
	if err == nil {
		t.Fatal("template impossível de executar foi aceito no boot")
	}
	if !strings.Contains(err.Error(), "não executa") {
		t.Errorf("a mensagem não explica o que houve: %v", err)
	}
}

// Executar sem erro não basta. Sem o cabeçalho na primeira linha, o listener
// perde o direito de sobrescrever e de remover o que ele mesmo escreveu — e
// descobriria isso só no primeiro DELETE.
func TestVerifyTemplateRefusesATemplateWithoutTheManagedHeader(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sem-cabecalho.tmpl")
	if err := os.WriteFile(path, []byte("server { server_name {{ join .Domains \" \" }}; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv, _ := newTestServer(t, nil)
	srv.cfg.TemplatePath = path

	err := srv.VerifyTemplate()
	if err == nil {
		t.Fatal("template sem o cabeçalho managed-by foi aceito")
	}
	if !strings.Contains(err.Error(), "managed-by") {
		t.Errorf("a mensagem não aponta o cabeçalho: %v", err)
	}
}

// O embutido é o MESMO arquivo que o setup.sh instala e que os goldens
// renderizam do disco — não uma segunda cópia que possa divergir.
func TestEmbeddedTemplateIsTheFileOnDisk(t *testing.T) {
	onDisk, err := os.ReadFile("../../conf/nginx-app.conf.tmpl")
	if err != nil {
		t.Fatal(err)
	}
	if conf.NginxAppTemplate != string(onDisk) {
		t.Fatal("o template embutido divergiu do arquivo em conf/")
	}
}

// Com o template embutido, um apply normal continua produzindo um arquivo que
// o manifesto reconhece. É o caminho que a frota inteira vai passar a usar.
func TestRenderVhostUsesTheEmbeddedTemplateByDefault(t *testing.T) {
	srv, _ := newTestServer(t, nil)
	srv.cfg.TemplatePath = ""

	p := validPayload(1, "")
	out, err := srv.renderVhost(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := nginx.ParseManagedConf(out); !ok {
		t.Fatalf("o arquivo gerado não é reconhecido como gerido:\n%s", out)
	}
	if !strings.Contains(out, "client_max_body_size 100m;") {
		t.Error("o limite de corpo sumiu — o proxy volta a 413 nos uploads")
	}
}
