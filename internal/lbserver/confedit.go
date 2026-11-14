// O envelope de toda escrita na config do LB, num lugar só.
//
// `pool.go` e `include.go` nasceram cada um com a sua cópia da mesma dança —
// autenticar, fazer backup datado, escrever, tentar `nginx -t`, recarregar,
// reler e restaurar em qualquer falha. Duas cópias já divergiam em detalhe; com
// as rotas novas (vhost, location, backends, arquivo cru) seriam seis, e é o
// tipo de código em que a sexta cópia é a que esquece o restore.
//
// A ordem é a de `pool.go`, e cada passo continua existindo pelo mesmo motivo:
//
//  1. LOCK. Ler-modificar-escrever tem de ser atômico; sem isso duas
//     requisições leem o mesmo texto e a última apaga a outra.
//  2. backup datado ao lado do arquivo (/etc/nginx é o único diretório que a
//     unit pode escrever, sob ProtectSystem=strict).
//  3. escrita ATÔMICA, para um reload concorrente nunca ler meio arquivo.
//  4. `nginx -t`, quando ele roda. Neste LB ele NÃO roda. Quando a sonda não
//     puder correr, seguimos; quando puder e REPROVAR, restauramos e paramos.
//  5. reload. Esta é a rede de verdade e não depende do passo 4: o nginx
//     recusa config inválida e CONTINUA servindo a anterior.
//  6. releitura, com a mesma sonda que decidiu.
//
// O que é novo aqui e não existia nas duas cópias: a transação abrange VÁRIOS
// arquivos. Desabilitar um vhost quase nunca é mexer num bloco só — o padrão é
// `server` na 80 redirecionando e outro na 443 servindo, e eles podem estar em
// arquivos diferentes. Meio toggle aplicado é pior que nenhum: deixa a porta 80
// mandando para um 443 que já não responde. Por isso: um backup por arquivo,
// todas as escritas, UM reload, e restauração de TODOS se qualquer passo
// falhar.
package lbserver

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/auth"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

// authenticateWrite roda o preâmbulo que toda rota de escrita compartilha.
//
// A ordem não é arbitrária: o limite de tamanho vem ANTES do HMAC, porque
// assinar um corpo que não se quis ler inteiro é assinar outra coisa. Ler a
// config é bearer só; mudá-la exige bearer E assinatura E nonce não repetido.
func (s *Server) authenticateWrite(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, time.Time, bool) {
	now := s.cfg.Now()
	if limit <= 0 {
		limit = s.cfg.MaxBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"body too large or unreadable"}})
		return nil, now, false
	}
	if !auth.VerifyBearer(r.Header.Get("Authorization"), s.cfg.Token) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return nil, now, false
	}
	ts, nonce, sig := r.Header.Get("X-Payload-Ts"), r.Header.Get("X-Payload-Nonce"), r.Header.Get("X-Payload-Sig")
	if err := auth.CheckTimestamp(ts, now, s.cfg.TSWindow); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"status": "unauthorized", "error": err.Error()})
		return nil, now, false
	}
	if !auth.VerifySignature(s.cfg.Secret, ts, nonce, body, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return nil, now, false
	}
	if !s.nonces.CheckAndStore(nonce, now) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"status": "unauthorized", "error": "nonce replay"})
		return nil, now, false
	}
	return body, now, true
}

// fileEdit é o conteúdo NOVO de um arquivo, inteiro.
type fileEdit struct {
	Path    string
	Content string
}

// editPlan é o que uma rota decidiu fazer, antes de qualquer escrita.
//
// Separar o PLANO da execução é o que torna o `dry_run` honesto: ele roda o
// mesmo código que a escrita real rodaria e para antes de tocar no disco. Um
// dry-run que simulasse por outro caminho mostraria uma coisa e aplicaria
// outra.
type editPlan struct {
	Edits []fileEdit
	// Noop: não há o que fazer. Não escrever é a resposta certa — um reload
	// que não serve para nada ainda é uma janela em que a config pode não
	// voltar.
	Noop bool
	Body map[string]any
	// Conflict interrompe ANTES de escrever, com o código e o corpo próprios
	// da rota (colisão de domínio, ref obsoleto, `default_server`).
	Conflict     map[string]any
	ConflictCode int
}

// applyConfEdit executa um plano sob o envelope inteiro.
//
// `verify` recebe um leitor do estado no disco DEPOIS do reload e devolve erro
// se a mudança não estiver lá — é o passo "reler com a mesma sonda que
// decidiu", e cada rota sabe o que precisa conferir.
func (s *Server) applyConfEdit(
	w http.ResponseWriter,
	now time.Time,
	dryRun bool,
	plan func() (editPlan, error),
	verify func(read func(string) string) error,
) {
	if s.cfg.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	p, err := plan()
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "error": err.Error()})
		return
	}
	if p.Conflict != nil {
		code := p.ConflictCode
		if code == 0 {
			code = http.StatusConflict
		}
		writeJSON(w, code, p.Conflict)
		return
	}
	if p.Noop || len(p.Edits) == 0 {
		body := p.Body
		if body == nil {
			body = map[string]any{}
		}
		body["status"], body["changed"] = "ok", 0
		writeJSON(w, http.StatusOK, body)
		return
	}

	// `dry_run` para AQUI: o plano já está pronto e nada foi ao disco.
	if dryRun {
		body := p.Body
		if body == nil {
			body = map[string]any{}
		}
		previews := make([]map[string]any, 0, len(p.Edits))
		for _, e := range p.Edits {
			before, _ := os.ReadFile(e.Path)
			previews = append(previews, map[string]any{
				"path": e.Path, "before": string(before), "after": e.Content})
		}
		body["status"], body["dry_run"], body["files"] = "ok", true, previews
		writeJSON(w, http.StatusOK, body)
		return
	}

	saved := make([]savedFile, 0, len(p.Edits))

	// restoreAll desfaz TUDO que já foi escrito e recarrega. Parcial seria o
	// pior desfecho possível: metade do toggle aplicado.
	restoreAll := func(reason string, code int) {
		restored := true
		var reloadErr, reloadOut string
		for _, f := range saved {
			if err := nginx.WriteAtomic(f.path, f.original, f.mode); err != nil {
				restored = false
				reloadErr = err.Error()
			}
		}
		out, err := s.cfg.Runner.Reload()
		if err != nil {
			restored, reloadErr, reloadOut = false, err.Error(), out
		}
		payload := map[string]any{
			"status": "error", "error": reason, "restored": restored,
			"backups": backupList(saved),
		}
		if !restored {
			payload["restore_reload_error"] = reloadErr
			payload["restore_reload_output"] = reloadOut
		}
		writeJSON(w, code, payload)
	}

	for _, e := range p.Edits {
		original, err := os.ReadFile(e.Path)
		if err != nil {
			restoreAll("não foi possível ler "+e.Path+": "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		mode := os.FileMode(0o644)
		if info, serr := os.Stat(e.Path); serr == nil {
			mode = info.Mode().Perm()
		}
		backup := backupPath(e.Path, now)
		if err := os.WriteFile(backup, original, mode); err != nil {
			restoreAll("não foi possível gravar o backup: "+err.Error(),
				http.StatusInternalServerError)
			return
		}
		saved = append(saved, savedFile{e.Path, backup, original, mode})

		if err := nginx.WriteAtomic(e.Path, []byte(e.Content), mode); err != nil {
			restoreAll("não foi possível escrever "+e.Path+": "+err.Error(),
				http.StatusInternalServerError)
			return
		}
	}

	tested, ok, out := s.testLive()
	if tested && !ok {
		restoreAll("nginx -t reprovou a config: "+out, http.StatusConflict)
		return
	}
	if reloadOut, err := s.cfg.Runner.Reload(); err != nil {
		restoreAll("reload falhou: "+err.Error()+" "+reloadOut, http.StatusConflict)
		return
	}

	if verify != nil {
		read := func(path string) string {
			b, _ := os.ReadFile(path)
			return string(b)
		}
		if err := verify(read); err != nil {
			restoreAll("a config no disco não reflete a mudança depois do reload: "+
				err.Error(), http.StatusConflict)
			return
		}
	}

	body := p.Body
	if body == nil {
		body = map[string]any{}
	}
	body["status"], body["changed"] = "ok", len(p.Edits)
	body["validated"], body["backups"] = tested, backupList(saved)
	writeJSON(w, http.StatusOK, body)
}

// savedFile guarda o que é preciso para desfazer uma escrita.
type savedFile struct {
	path, backup string
	original     []byte
	mode         os.FileMode
}

func backupList(saved []savedFile) []string {
	out := make([]string, 0, len(saved))
	for _, f := range saved {
		out = append(out, f.backup)
	}
	return out
}

// mainConfPath aplica o mesmo default de ReadConfTree, e pelo mesmo motivo: o
// campo nasceu sem ninguém preenchê-lo e o /v1/dump funciona em produção
// justamente porque o leitor aplica este default.
func (s *Server) mainConfPath() string {
	if s.cfg.MainConf == "" {
		return "/etc/nginx/nginx.conf"
	}
	return s.cfg.MainConf
}

var errNoSuchFile = fmt.Errorf("arquivo não faz parte da config que o nginx carregou")
