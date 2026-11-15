// GET e POST /v1/file — ler e escrever um arquivo de config inteiro.
//
// É a válvula de escape das rotas estruturadas. O toggle de vhost comenta um
// bloco; o de location, uma rota; o de pool, um parâmetro. Tudo que não cabe
// nessas três formas — um `map`, um `limit_req_zone`, um header novo, um
// `proxy_cache_path` — continuaria exigindo SSH sem isto.
//
// # Por que esta rota é diferente de todas as outras
//
// As outras escrevem dentro de um envelope fechado: comentam um bloco que já
// estava no arquivo, ou mexem num parâmetro de um bloco que já existe. O pior
// que uma delas faz é desligar algo que estava ligado.
//
// Esta aceita TEXTO ARBITRÁRIO. Escrever um arquivo de nginx qualquer é
// controle equivalente a root do processo nginx: dá para trocar o `user`,
// acrescentar `load_module`, incluir qualquer diretório do disco. Filtrar
// diretiva a diretiva é jogo perdido — a lista de o-que-é-perigoso nunca fica
// pronta, e cada item que falta é um buraco.
//
// Então o controle é de CAPACIDADE, não de conteúdo: `AllowRawEdit` nasce
// desligada, e quem a liga num host sabe o que está liberando.
//
// # Concorrência otimista
//
// A escrita exige `base_digest`, o sha256 do conteúdo que foi lido. Se o
// arquivo mudou no disco desde a leitura — outra pessoa no painel, alguém por
// SSH, um apply do próprio listener —, a escrita é recusada com 409 em vez de
// sobrescrever em silêncio. Sem isso, duas telas abertas na mesma config
// fazem a última a salvar apagar a outra, e ninguém fica sabendo.
package lbserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"github.com/tomneto/deployer-lb-server/internal/auth"
)

type fileWriteRequest struct {
	Path string `json:"path"`
	// Content é o arquivo INTEIRO, não um patch. Patch exigiria que os dois
	// lados concordassem sobre o estado anterior, que é exatamente o que
	// `base_digest` já verifica de forma mais simples.
	Content string `json:"content"`
	// BaseDigest é o sha256 do que foi lido. Vazio não é aceito: seria
	// escrever por cima sem olhar.
	BaseDigest string `json:"base_digest"`
	By         string `json:"by"`
	DryRun     bool   `json:"dry_run"`
}

// fileDigest identifica o conteúdo de um arquivo.
func fileDigest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

// handleFileRead devolve um arquivo de config com o digest dele.
//
// Leitura é bearer só, como todas as outras leituras deste listener. O que
// protege aqui não é a assinatura, é o confinamento: `editableFile` só aceita
// caminho que o nginx carregou de fato, então `/etc/shadow` e o `.htpasswd` do
// vizinho não são alcançáveis por esta rota.
func (s *Server) handleFileRead(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	if !auth.VerifyBearer(r.Header.Get("Authorization"), s.cfg.Token) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}
	path := r.URL.Query().Get("path")
	resolved, err := s.editableFile(path)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "error": err.Error()})
		return
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{
			"status": "error", "error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"path":    resolved,
		"content": string(raw),
		"digest":  fileDigest(raw),
		"lines":   strings.Count(string(raw), "\n") + 1,
		// A tela precisa saber se dá para escrever ANTES de deixar a pessoa
		// digitar — oferecer um editor que vai recusar no fim é pior que não
		// oferecer editor nenhum.
		"writable": s.cfg.AllowRawEdit,
	})
}

func (s *Server) handleFileWrite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	// O limite próprio desta rota, antes do HMAC — mesma ordem das outras:
	// assinar um corpo que não se quis ler inteiro é assinar outra coisa.
	body, now, ok := s.authenticateWrite(w, r, s.cfg.MaxRawBodyBytes)
	if !ok {
		return
	}
	// A capacidade é verificada DEPOIS da autenticação, para que um host com
	// a rota desligada não vire um oráculo de token válido.
	if !s.cfg.AllowRawEdit {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"status": "forbidden",
			"error": "a edição de texto cru está desligada neste load balancer. " +
				"Ela dá controle equivalente a root do processo nginx, então é " +
				"opt-in: ligue `AllowRawEdit` na configuração do listener.",
		})
		return
	}

	var req fileWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"corpo inválido"}})
		return
	}
	if strings.TrimSpace(req.BaseDigest) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid",
			"error": "base_digest é obrigatório: sem ele a escrita seria por cima " +
				"do que estiver lá, sem olhar",
		})
		return
	}

	s.applyConfEdit(w, now, req.DryRun,
		func() (editPlan, error) {
			resolved, err := s.editableFile(req.Path)
			if err != nil {
				return editPlan{}, err
			}
			current, err := os.ReadFile(resolved)
			if err != nil {
				return editPlan{}, err
			}
			atual := fileDigest(current)
			if atual != req.BaseDigest {
				// O arquivo mudou desde a leitura. Devolver o conteúdo novo
				// junto é o que permite à tela mostrar o que o outro fez sem
				// perder o que a pessoa digitou.
				return editPlan{
					ConflictCode: http.StatusConflict,
					Conflict: map[string]any{
						"status": "conflict", "reason": "stale_digest",
						"path":   resolved,
						"digest": atual,
						"current": string(current),
						"error": "este arquivo mudou no LB depois que a tela o leu — " +
							"alguém editou, ou o painel aplicou. Nada foi escrito.",
					},
				}, nil
			}
			if string(current) == req.Content {
				return editPlan{Noop: true, Body: map[string]any{
					"path": resolved, "note": "o conteúdo é idêntico ao que já está lá",
				}}, nil
			}
			return editPlan{
				Edits: []fileEdit{{Path: resolved, Content: req.Content}},
				Body: map[string]any{
					"path":   resolved,
					"digest": fileDigest([]byte(req.Content)),
					"by":     req.By,
				},
			}, nil
		},
		// Reler com a mesma sonda que decidiu: o arquivo no disco tem de ser
		// exatamente o que se mandou escrever.
		func(read func(string) string) error {
			resolved, err := s.editableFile(req.Path)
			if err != nil {
				return err
			}
			if read(resolved) != req.Content {
				return errWriteNotReflected
			}
			return nil
		})
}

var errWriteNotReflected = &writeError{"o arquivo no disco não é o que foi enviado"}

type writeError struct{ msg string }

func (e *writeError) Error() string { return e.msg }
