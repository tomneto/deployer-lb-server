// POST /v1/pool — tirar os backends de um upstream de rotação, e devolver.
//
// É a primeira escrita deste listener FORA do seu próprio conf dir: o alvo é o
// nginx.conf que alguém escreveu à mão, no LB que carrega o tráfego. Daí o
// contrato abaixo, que é o mesmo que o painel já usa para mexer no sshd de um
// host remoto.
//
// A ordem importa e cada passo existe por um motivo:
//
//  1. backup datado, ao lado do arquivo (/etc/nginx é gravável pela unit —
//     ReadWritePaths — e /tmp não é, sob ProtectSystem=strict);
//  2. escreve;
//  3. `nginx -t`, quando ele roda. Neste LB ele NÃO roda: a unit tem
//     ProtectSystem=strict e o nginx.conf declara `pid /run/nginx.pid`, que é
//     read-only ali — é por isso que /v1/dump já cai no leitor de arquivos em
//     vez de usar `nginx -T`. Quando a sonda não puder rodar, seguimos; quando
//     puder e REPROVAR, restauramos e paramos;
//  4. reload. Esta é a rede de verdade, e ela não depende do passo 3: o nginx
//     recusa recarregar uma config inválida e CONTINUA servindo a anterior.
//     Se o reload falhar, restauramos e recarregamos de volta;
//  5. lê o arquivo de novo e confere que a mudança está lá — a mesma lição de
//     "reler com a mesma sonda que detectou".
package lbserver

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/auth"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

type poolRequest struct {
	Pool string `json:"pool"`
	// Down, e não Enabled: é a palavra que o nginx usa, e traduzir aqui
	// criaria duas linguagens para o mesmo estado entre o painel e o arquivo.
	Down bool `json:"down"`
}

// backupPath keeps the copy NEXT to the original, inside /etc/nginx — the one
// directory this unit may write to. The name deliberately avoids `.conf` so no
// `include *.conf` anywhere can pick the backup up and serve it.
func backupPath(conf string, now time.Time) string {
	dir, base := filepath.Split(conf)
	return filepath.Join(dir, fmt.Sprintf(".%s.bak-%s", base, now.UTC().Format("20060102-150405")))
}

func (s *Server) handlePool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	// O limite de tamanho vem ANTES do HMAC, igual ao /v1/apply: assinar um
	// corpo que não se quis ler inteiro é assinar outra coisa.
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"body too large or unreadable"}})
		return
	}
	// Escrita: bearer E assinatura, igual ao /v1/apply. Ler a config é bearer
	// só; mudá-la não pode ser.
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

	var req poolRequest
	if err := json.Unmarshal(body, &req); err != nil || strings.TrimSpace(req.Pool) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"pool is required"}})
		return
	}
	if s.cfg.Runner == nil || s.cfg.MainConf == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
		return
	}

	original, err := os.ReadFile(s.cfg.MainConf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "cannot read " + s.cfg.MainConf + ": " + err.Error()})
		return
	}

	res, err := nginx.SetPoolDown(string(original), req.Pool, req.Down)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "invalid", "error": err.Error()})
		return
	}
	if res.Changed == 0 {
		// Já estava assim. Não escrever é a resposta certa: um reload que não
		// serve para nada ainda é uma janela em que a config pode não voltar.
		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ok", "changed": 0, "backends": res.Total,
			"note": "o pool já estava nesse estado",
		})
		return
	}

	info, statErr := os.Stat(s.cfg.MainConf)
	mode := os.FileMode(0o644)
	if statErr == nil {
		mode = info.Mode().Perm()
	}

	backup := backupPath(s.cfg.MainConf, now)
	if err := os.WriteFile(backup, original, mode); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "cannot write backup: " + err.Error()})
		return
	}

	restore := func(reason string, code int) {
		_ = os.WriteFile(s.cfg.MainConf, original, mode)
		reloadOut, reloadErr := s.cfg.Runner.Reload()
		payload := map[string]any{
			"status": "error", "error": reason, "restored": true, "backup": backup,
		}
		if reloadErr != nil {
			// O pior caso que esta rota pode produzir, e ele tem de aparecer
			// inteiro: restauramos o arquivo e o nginx não voltou.
			payload["restore_reload_error"] = reloadErr.Error()
			payload["restore_reload_output"] = reloadOut
			payload["restored"] = false
		}
		writeJSON(w, code, payload)
	}

	if err := os.WriteFile(s.cfg.MainConf, []byte(res.Config), mode); err != nil {
		_ = os.Remove(backup)
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "cannot write config: " + err.Error()})
		return
	}

	// Passo 3, best-effort. `TestLive` devolve ran=false quando a sandbox não
	// deixa a sonda rodar — e aí NÃO tratamos isso como reprovação: recusar a
	// mudança porque o validador não pôde correr travaria a ferramenta
	// justamente no host onde ela é mais necessária.
	tested, ok, out := s.testLive()
	if tested && !ok {
		restore("nginx -t reprovou a config: "+out, http.StatusConflict)
		return
	}

	if reloadOut, err := s.cfg.Runner.Reload(); err != nil {
		restore("reload falhou: "+err.Error()+" "+reloadOut, http.StatusConflict)
		return
	}

	// Passo 5: reler com a mesma sonda que decidiu.
	after, err := os.ReadFile(s.cfg.MainConf)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": "applied but could not re-read: " + err.Error(),
			"backup": backup})
		return
	}
	isDown, known := nginx.PoolIsDown(string(after), req.Pool)
	if !known || isDown != req.Down {
		restore("a config no disco não reflete a mudança depois do reload", http.StatusConflict)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok", "pool": req.Pool, "down": req.Down,
		"changed": res.Changed, "backends": res.Total,
		"backup": backup, "validated": tested,
	})
}

// testLive runs `nginx -t` against the real configuration, reporting whether
// the probe could run at all — which is a different question from whether the
// config is valid, and conflating them is what would turn an unrunnable probe
// into a permanent refusal.
func (s *Server) testLive() (ran bool, ok bool, output string) {
	tester, supported := s.cfg.Runner.(interface{ TestLive() (bool, string, error) })
	if !supported {
		return false, false, ""
	}
	valid, out, err := tester.TestLive()
	if err != nil && !valid && strings.Contains(out, "Permission denied") {
		// A sonda não correu — é o caso conhecido deste LB, o mesmo que já faz
		// o /v1/dump cair no leitor de arquivos.
		return false, false, out
	}
	return true, valid, out
}
