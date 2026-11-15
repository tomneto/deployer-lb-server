// POST /v1/pool/servers — acrescentar, remover e ajustar backends.
//
// `/v1/pool` já tirava o pool INTEIRO de rotação. O que faltava é o trabalho
// miúdo: subiu uma réplica, uma máquina saiu, aquele backend está pegando
// tráfego demais.
//
// Três operações numa rota só porque são a mesma transação sobre o mesmo
// bloco, e separá-las em três rotas faria a tela ter de orquestrar a ordem —
// que é precisamente o que não se quer quando cada passo é um reload.
//
// O envelope é o compartilhado: lock, backup, escrita atômica, `nginx -t`
// quando ele roda, reload, releitura e restauração em qualquer falha.
package lbserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

type poolServersRequest struct {
	// Pool é o nome do upstream.
	Pool string `json:"pool"`
	// File é onde ele está declarado. Vem do inventário; sem ele não dá para
	// saber qual arquivo abrir num LB com vários.
	File string `json:"file"`
	// Op é "add", "remove" ou "params".
	Op      string            `json:"op"`
	Address string            `json:"address"`
	Params  map[string]string `json:"params"`
	// Hard só vale para "remove": apaga a linha em vez de marcar `down`.
	// Nasce falso porque `down` é reversível apagando uma palavra, e apagar a
	// linha não tem botão de desfazer.
	Hard   bool `json:"hard"`
	DryRun bool `json:"dry_run"`
}

func (s *Server) handlePoolServers(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	body, now, ok := s.authenticateWrite(w, r, 0)
	if !ok {
		return
	}
	var req poolServersRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"corpo inválido"}})
		return
	}

	var res nginx.PoolEditResult

	s.applyConfEdit(w, now, req.DryRun,
		func() (editPlan, error) {
			file := req.File
			if file == "" {
				file = s.mainConfPath()
			}
			resolved, err := s.editableFile(file)
			if err != nil {
				return editPlan{}, err
			}
			raw, err := os.ReadFile(resolved)
			if err != nil {
				return editPlan{}, err
			}
			conf := string(raw)

			switch req.Op {
			case "add":
				res, err = nginx.AddPoolServer(conf, req.Pool,
					nginx.BackendSpec{Address: req.Address, Params: req.Params})
			case "remove":
				res, err = nginx.RemovePoolServer(conf, req.Pool, req.Address, req.Hard)
			case "params":
				res, err = nginx.SetPoolServerParams(conf, req.Pool, req.Address, req.Params)
			default:
				return editPlan{}, fmt.Errorf("operação desconhecida: %q", req.Op)
			}
			if err != nil {
				return editPlan{}, err
			}

			// `serving: 0` não é erro — marcar down o último que atendia é
			// uma operação legítima. Mas quem pediu precisa saber, porque não
			// foi isso que ele pediu: ele tirou UM backend, e o pool inteiro
			// parou de responder.
			info := map[string]any{
				"pool": req.Pool, "op": req.Op, "address": req.Address,
				"remaining": res.Remaining, "serving": res.Serving,
			}
			if res.Serving == 0 && res.Remaining > 0 {
				info["note"] = "nenhum backend deste pool atende mais — " +
					"quem acessar recebe erro do nginx até algum voltar"
			}
			if res.Changed == 0 {
				return editPlan{Noop: true, Body: info}, nil
			}
			return editPlan{
				Edits: []fileEdit{{Path: resolved, Content: res.Config}},
				Body:  info,
			}, nil
		},
		nil)
}
