package nginx

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// `nginx -t` opens the pidfile even when it is only validating, and the
// default is /run/nginx.pid. The unit runs under ProtectSystem=strict with
// /etc/nginx as the only writable path, so /run is read-only and the probe
// failed on something unrelated to the configuration:
//
//	[emerg] open() "/run/nginx.pid" failed (30: Read-only file system)
//
// That produced a permanent `config_ok: false` in /v1/status on a host whose
// config is valid — the backoffice drew "config inválida" in red next to an
// nginx serving traffic, and RealRunner.Test discards the message, so the
// reason was invisible everywhere.
func TestTestArgsOverridesThePidPath(t *testing.T) {
	args := testArgs("/etc/nginx/conf.d/.nginx-test.conf", "/etc/nginx/conf.d/.nginx-test.pid")

	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "pid /etc/nginx/conf.d/.nginx-test.pid;") {
		t.Fatalf("pid override ausente: %q", joined)
	}
	if strings.Contains(joined, "/run/nginx.pid") {
		t.Fatalf("ainda aponta para /run: %q", joined)
	}
	// error_log é diretiva de contexto main, então só cabe aqui — e o default
	// compilado aponta para /var/log/nginx, fora do sandbox.
	if !strings.Contains(joined, "error_log stderr;") {
		t.Fatalf("error_log nao redirecionado: %q", joined)
	}
}

// O access_log default NÃO vem do nginx.conf vivo (o wrapper nunca o inclui):
// é o caminho com que o nginx foi COMPILADO — /var/log/nginx/access.log no
// Debian/Ubuntu —, e foi o que sobrou falhando depois de resolver o pidfile.
func TestWrapperDesligaOAccessLog(t *testing.T) {
	got := wrapperContent("/etc/nginx/conf.d")

	if !strings.Contains(got, "access_log off;") {
		t.Fatalf("wrapper nao desliga o access_log:\n%s", got)
	}
	if !strings.Contains(got, "include /etc/nginx/conf.d/*.conf;") {
		t.Fatalf("wrapper nao inclui o overlay:\n%s", got)
	}
}

// Enumerados juntos de proposito: corrigir um caminho por vez so empurra o
// erro para o proximo, e foi o que aconteceu tres vezes — pid, depois
// access_log, depois /var/lib/nginx/body. Esta lista foi verificada contra o
// host real dentro do sandbox da unit.
func TestWrapperRedirecionaTodosOsCaminhosDeEscrita(t *testing.T) {
	got := wrapperContent("/etc/nginx/conf.d")
	tmp := testTempDir("/etc/nginx/conf.d")

	for _, d := range []string{
		"client_body_temp_path", "proxy_temp_path",
		"fastcgi_temp_path", "uwsgi_temp_path", "scgi_temp_path",
	} {
		if !strings.Contains(got, d+" "+tmp+"/") {
			t.Fatalf("%s nao aponta para dentro de %s:\n%s", d, tmp, got)
		}
	}
	for _, fora := range []string{"/var/lib/nginx", "/var/log/nginx", "/run/"} {
		if strings.Contains(got, fora) {
			t.Fatalf("wrapper ainda referencia %s:\n%s", fora, got)
		}
	}
}

// O diretorio de scratch tem de nascer e morrer com o teste: deixa-lo para
// tras polui o conf-dir, e o `include *.conf` do proprio wrapper varre esse
// diretorio.
func TestTempDirFicaDentroDoConfDirENaoEConf(t *testing.T) {
	tmp := testTempDir("/etc/nginx/conf.d")

	if filepath.Dir(tmp) != "/etc/nginx/conf.d" {
		t.Fatalf("scratch fora do confDir: %s", tmp)
	}
	if strings.HasSuffix(tmp, ".conf") {
		t.Fatalf("scratch casaria com include *.conf: %s", tmp)
	}
}

// The pidfile lives beside the wrapper because that directory is writable by
// definition — and must not be swept up by the wrapper's own `include *.conf`.
func TestTestPidPathIsBesideTheWrapperAndNotAConf(t *testing.T) {
	pid := testPidPath("/etc/nginx/conf.d")

	if got := filepath.Dir(pid); got != "/etc/nginx/conf.d" {
		t.Fatalf("pid fora do confDir: %s", got)
	}
	if strings.HasSuffix(pid, ".conf") {
		t.Fatalf("pid casaria com include *.conf: %s", pid)
	}
}

// End-to-end against the real binary when there is one. Skipped where nginx is
// not installed (developer laptops), so it never turns into a flaky gate.
func TestRealRunnerAcceptsAValidOverlay(t *testing.T) {
	if _, err := exec.LookPath("nginx"); err != nil {
		t.Skip("nginx não instalado neste host")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.conf"),
		[]byte("server {\n    listen 8081;\n    server_name _;\n}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	ok, out, err := RealRunner{}.Test(dir)
	if !ok {
		t.Fatalf("overlay válido recusado: err=%v out=%s", err, out)
	}
}
