// POST /v1/include — ligar o canal entre o que o painel escreve e o que o
// nginx lê.
//
// O defeito que esta rota corrige é o que o /v1/dump já sabia MEDIR e ninguém
// sabia consertar sem SSH: o listener escreve em /etc/nginx/conf.d, o
// nginx.conf do host não inclui esse diretório, e todo apply fica no disco sem
// efeito. Nada acusa isso — a config é válida, o reload passa, o tráfego segue
// na config escrita à mão —, então o painel dizia "o que você aplicar não terá
// efeito" e parava ali.
//
// Mesmo contrato de escrita do /v1/pool, pelo mesmo motivo: o alvo é o
// nginx.conf que alguém escreveu à mão, no LB que carrega o tráfego. Backup
// datado ao lado, escreve, `nginx -t` quando ele roda, reload, relê com a
// mesma sonda que detectou o defeito, e restaura em qualquer falha.
//
// A diferença em relação ao toggle de pool é o passo a mais ANTES de escrever:
// ligar o canal faz o nginx passar a ler vhosts que ele nunca leu. Se algum
// deles declarar um `server_name` que já é servido pela config escrita à mão,
// o nginx não falha — ele avisa "conflicting server name" e ignora o
// duplicado. Um deploy antigo e esquecido no conf dir poderia, assim, mudar o
// que responde em produção sem erro nenhum. Por isso a colisão é recusa (409),
// e só passa com `force` explícito de quem leu a lista.
package lbserver

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/tomneto/deployer-lb-server/internal/auth"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

type includeRequest struct {
	// Force só existe para ser recusado por omissão: o default de uma rota
	// que muda o que responde em produção não pode ser "siga assim mesmo".
	Force bool `json:"force"`
}

// currentConfig devolve o texto da config que o nginx serve agora, pela mesma
// ordem de fontes do /v1/dump: `nginx -T` quando ele roda, e o leitor de
// arquivos quando a sandbox não deixa.
func (s *Server) currentConfig(mainConf string) string {
	if s.cfg.Runner != nil {
		if out, err := s.cfg.Runner.DumpConfig(); err == nil && strings.TrimSpace(out) != "" {
			return out
		}
	}
	tree, _ := nginx.ReadConfTree(mainConf)
	return tree
}

// isUnderDir compara por fronteira de `/`, nunca por substring: um vhost em
// /etc/nginx/conf.d.bak não está em /etc/nginx/conf.d.
func isUnderDir(path, dir string) bool {
	base := strings.TrimRight(filepath.Clean(dir), "/")
	return strings.HasPrefix(filepath.Clean(path), base+"/")
}

// domainCollisions lista os `server_name` que o conf dir declara e que a
// config de hoje já serve de outro arquivo.
//
// Vazio é o caso normal (o conf dir só tem o que o painel aplicou para
// domínios que ninguém mais serve); não-vazio é a única coisa que ligar o
// canal pode mudar em produção, e por isso ela é dita por extenso.
func (s *Server) domainCollisions(dump string) []string {
	if s.cfg.ConfDir == "" {
		return nil
	}
	served := map[string]bool{}
	for _, v := range nginx.BuildInventory(dump).Vhosts {
		if v.File != "" && isUnderDir(v.File, s.cfg.ConfDir) {
			// Já incluído — não é colisão, é o mesmo arquivo.
			continue
		}
		for _, name := range v.ServerNames {
			if name != "" && name != "_" {
				served[name] = true
			}
		}
	}

	entries, err := os.ReadDir(s.cfg.ConfDir)
	if err != nil {
		return nil
	}
	hits := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".conf") || strings.HasPrefix(name, ".") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.cfg.ConfDir, name))
		if err != nil {
			continue
		}
		for _, v := range nginx.BuildInventory(string(data)).Vhosts {
			for _, d := range v.ServerNames {
				if served[d] {
					hits[d] = true
				}
			}
		}
	}
	out := make([]string, 0, len(hits))
	for d := range hits {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleInclude(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	// Tamanho antes do HMAC, igual ao /v1/apply e ao /v1/pool: assinar um
	// corpo que não se quis ler inteiro é assinar outra coisa.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"body too large or unreadable"}})
		return
	}
	if !auth.VerifyBearer(r.Header.Get("Authorization"), s.cfg.Token) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}
	ts, nonce, sig := r.Header.Get("X-Payload-Ts"), r.Header.Get("X-Payload-Nonce"), r.Header.Get("X-Payload-Sig")
	now := s.cfg.Now()
	if err := auth.CheckTimestamp(ts, now, s.cfg.TSWindow); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized", "error": err.Error()})
		return
	}
	if !auth.VerifySignature(s.cfg.Secret, ts, nonce, body, sig) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}
	if !s.nonces.CheckAndStore(nonce, now) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized", "error": "nonce replay"})
		return
	}

	var req includeRequest
	if len(strings.TrimSpace(string(body))) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"status": "invalid", "errors": []string{"body is not JSON"}})
			return
		}
	}
	if s.cfg.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
		return
	}
	if strings.TrimSpace(s.cfg.ConfDir) == "" {
		// Sem diretório configurado não há canal para ligar, e escolher um
		// aqui seria inventar onde o listener escreve.
		writeJSON(w, http.StatusConflict, map[string]any{
			"status": "invalid",
			"error":  "este listener não tem conf dir configurado"})
		return
	}
	// Mesmo default de ReadConfTree e do /v1/pool: o campo nasceu sem ninguém
	// preenchê-lo, e recusar em vazio seria recusar numa configuração que
	// comprovadamente roda em produção.
	mainConf := s.cfg.MainConf
	if mainConf == "" {
		mainConf = "/etc/nginx/nginx.conf"
	}
	prefix := filepath.Dir(mainConf)

	original, err := os.ReadFile(mainConf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "cannot read " + mainConf + ": " + err.Error()})
		return
	}

	res, err := nginx.EnsureConfDirInclude(string(original), s.cfg.ConfDir, prefix)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "error": err.Error()})
		return
	}
	if !res.Changed {
		// Já estava ligado. Não escrever é a resposta certa: um reload que não
		// serve para nada ainda é uma janela em que a config pode não voltar.
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "changed": false, "conf_dir": s.cfg.ConfDir,
			"main_conf": mainConf,
			"note":      "o nginx.conf já inclui esse diretório",
		})
		return
	}

	collisions := s.domainCollisions(s.currentConfig(mainConf))
	if len(collisions) > 0 && !req.Force {
		writeJSON(w, http.StatusConflict, map[string]any{
			"status":     "conflict",
			"collisions": collisions,
			"conf_dir":   s.cfg.ConfDir,
			"main_conf":  mainConf,
			"error": "há domínio declarado nos dois lados: ligar o canal faria " +
				"o nginx carregar vhosts duplicados, e ele resolve isso em " +
				"silêncio",
		})
		return
	}

	info, statErr := os.Stat(mainConf)
	mode := os.FileMode(0o644)
	if statErr == nil {
		mode = info.Mode().Perm()
	}

	backup := backupPath(mainConf, now)
	if err := os.WriteFile(backup, original, mode); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "cannot write backup: " + err.Error()})
		return
	}

	restore := func(reason string, code int) {
		_ = os.WriteFile(mainConf, original, mode)
		reloadOut, reloadErr := s.cfg.Runner.Reload()
		payload := map[string]any{
			"status": "error", "error": reason, "restored": true, "backup": backup,
		}
		if reloadErr != nil {
			payload["restore_reload_error"] = reloadErr.Error()
			payload["restore_reload_output"] = reloadOut
			payload["restored"] = false
		}
		writeJSON(w, code, payload)
	}

	if err := os.WriteFile(mainConf, []byte(res.Config), mode); err != nil {
		_ = os.Remove(backup)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "cannot write config: " + err.Error()})
		return
	}

	// `nginx -t` best-effort: neste LB ele não roda sob a sandbox, e tratar
	// "não pôde rodar" como reprovação travaria a correção justamente no host
	// que precisa dela. Quem protege de verdade é o reload — o nginx recusa
	// config inválida e segue servindo a anterior.
	tested, ok, out := s.testLive()
	if tested && !ok {
		restore("nginx -t reprovou a config: "+out, http.StatusConflict)
		return
	}

	if reloadOut, err := s.cfg.Runner.Reload(); err != nil {
		restore("reload falhou: "+err.Error()+" "+reloadOut, http.StatusConflict)
		return
	}

	after, err := os.ReadFile(mainConf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "applied but could not re-read: " + err.Error(),
			"backup": backup})
		return
	}
	if !nginx.ConfDirIncluded(string(after), s.cfg.ConfDir, prefix) {
		restore("a config no disco não reflete a mudança depois do reload",
			http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "changed": true, "line": res.Line,
		"conf_dir": s.cfg.ConfDir, "main_conf": mainConf,
		"backup": backup, "validated": tested,
		"collisions": collisions,
	})
}
