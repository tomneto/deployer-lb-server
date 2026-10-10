package lbserver

// O que existe no ConfDir agora — a segunda metade de um diagnóstico que a
// primeira metade sozinha não sustenta.
//
// GET /v1/dump sabe dizer quais arquivos o nginx carregou. "Nenhum deles está
// em /etc/nginx/conf.d" parece prova de que o nginx.conf não inclui esse
// diretório, mas é exatamente o que se veria se o diretório estivesse VAZIO —
// e as duas conclusões levam a lugares opostos: uma manda consertar o
// nginx.conf do host, a outra manda aplicar um vhost e olhar de novo.
//
// Separar as duas custa um ReadDir de um diretório que este processo já lê em
// statusApps. É barato, e sem ele o painel teria de escolher entre calar ou
// afirmar o que não mediu.

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

// confDirFiles lists the *.conf files sitting in this listener's conf dir.
//
// Same skip rules as statusApps (directories, non-.conf, dotfiles) so the two
// readings of the same directory can never disagree about what counts as a
// file. Unlike statusApps it also reports UNMANAGED files: the question here
// is "is there anything here for nginx to include", and a hand-written conf in
// that directory answers it just as well as one we wrote.
//
// Returns a non-nil slice plus an error string. "empty" and "unreadable" must
// stay distinguishable all the way to the screen — collapsing them would let
// the panel report a proven cause from a failed measurement.
func (s *Server) confDirFiles() ([]map[string]any, string) {
	files := make([]map[string]any, 0)
	if s.cfg.ConfDir == "" {
		// Sem diretório configurado não há o que listar, e dizer "vazio"
		// seria afirmar sobre um lugar que não existe.
		return files, "conf dir not configured"
	}
	entries, err := os.ReadDir(s.cfg.ConfDir)
	if err != nil {
		return files, err.Error()
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".conf") || strings.HasPrefix(name, ".") {
			continue
		}
		row := map[string]any{"name": name, "managed": false}
		if data, err := os.ReadFile(filepath.Join(s.cfg.ConfDir, name)); err == nil {
			if mc, ok := nginx.ParseManagedConf(string(data)); ok {
				row["managed"] = true
				row["app"] = mc.App
			}
		}
		// Um arquivo ilegível continua na lista: ele existe, e é a existência
		// que responde a pergunta desta função. Some só o que não é conf.
		files = append(files, row)
	}
	return files, ""
}
