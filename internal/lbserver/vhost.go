// POST /v1/vhost — desligar e religar um vhost escrito à mão.
//
// A operação que motivou tudo isto. A config de produção deste LB tem um vhost
// comentado à unha, trinta linhas, sem dizer quem desligou nem quando — porque
// até agora o único jeito de tirar um domínio do ar era SSH.
//
// # Por que a rota recebe uma LISTA
//
// "Desabilitar o vhost" quase nunca é mexer num bloco só. O padrão universal é
// dois `server` com o mesmo `server_name`: um na 80 que redireciona, outro na
// 443 que serve. Desligar só o segundo produz o pior desfecho possível — a
// porta 80 continua redirecionando para um 443 que agora cai no
// `default_server` de outra pessoa. Por isso a rota aceita vários refs e os
// aplica como UMA transação: um backup por arquivo, um reload, e restauração
// de todos se qualquer passo falhar.
//
// # Os dois portões
//
// Desligar quase nunca quebra o `nginx -t`. RELIGAR quebra o tempo todo — o
// upstream sumiu, o certificado sumiu, o domínio foi reocupado. E neste host o
// `nginx -t` não roda, então a única rede é o reload seguido de restore. Daí
// recusar antes de escrever, nos dois casos em que a recusa é barata e o
// estrago não:
//
//   - desligar um vhost que é `default_server` muda, em silêncio, quem atende
//     todo o resto do tráfego daquela porta;
//   - religar um vhost cujo domínio outro bloco passou a servir cria
//     `conflicting server name`, que o nginx resolve escolhendo um sozinho,
//     sem erro nenhum.
//
// Os dois passam com `force` explícito, pelo mesmo contrato de `/v1/include`:
// 409 com a lista do que foi encontrado, e a decisão volta para quem leu.
package lbserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

type vhostRequest struct {
	// Disabled diz para que lado vai o toggle.
	Disabled bool `json:"disabled"`
	// Refs endereça os blocos a DESLIGAR (ver internal/nginx/locate.go).
	Refs []string `json:"refs"`
	// Fences endereça as regiões a RELIGAR, por arquivo e id da cerca.
	Fences []fenceTarget `json:"fences"`
	// By é ALEGADO: o HMAC autentica o painel, não a pessoa.
	By     string `json:"by"`
	Force  bool   `json:"force"`
	DryRun bool   `json:"dry_run"`
}

type fenceTarget struct {
	File string `json:"file"`
	ID   string `json:"id"`
}

func (s *Server) handleVhost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	body, now, ok := s.authenticateWrite(w, r, 0)
	if !ok {
		return
	}
	var req vhostRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"corpo inválido"}})
		return
	}

	s.applyConfEdit(w, now, req.DryRun,
		func() (editPlan, error) {
			if req.Disabled {
				return s.planDisableVhosts(req, now)
			}
			return s.planEnableVhosts(req)
		},
		nil)
}

// planDisableVhosts monta a transação de desligar.
func (s *Server) planDisableVhosts(req vhostRequest, now time.Time) (editPlan, error) {
	if len(req.Refs) == 0 {
		return editPlan{}, fmt.Errorf("nenhum bloco informado")
	}

	// Agrupa por arquivo: cada arquivo é lido uma vez e reescrito uma vez,
	// mesmo quando leva dois blocos (o caso 80/443 no mesmo arquivo).
	byFile := map[string][]nginx.Ref{}
	for _, raw := range req.Refs {
		ref, err := nginx.DecodeRef(raw)
		if err != nil {
			return editPlan{}, err
		}
		if _, err := s.editableFile(ref.File); err != nil {
			return editPlan{}, err
		}
		byFile[ref.File] = append(byFile[ref.File], ref)
	}

	var edits []fileEdit
	var defaults []string
	var touched []map[string]any

	for file, refs := range byFile {
		raw, err := os.ReadFile(file)
		if err != nil {
			return editPlan{}, fmt.Errorf("não foi possível ler %s: %w", file, err)
		}
		conf := string(raw)

		spans := make([]nginx.Span, 0, len(refs))
		for _, ref := range refs {
			span, err := nginx.ResolveRef(conf, ref)
			if err != nil {
				return editPlan{}, fmt.Errorf("%s: %w", file, err)
			}
			if isDefaultServer(span, conf) {
				defaults = append(defaults, describeSpan(span, conf))
			}
			spans = append(spans, span)
		}

		// De trás para frente: desligar um bloco muda todos os offsets
		// seguintes, e aplicar do fim para o começo mantém válidos os
		// offsets dos que ainda faltam.
		sort.Slice(spans, func(i, j int) bool { return spans[i].Header > spans[j].Header })

		out := conf
		for _, span := range spans {
			meta := nginx.FenceMeta{
				ID: nginx.NewFenceID(), Kind: "vhost",
				Label: describeSpan(span, conf),
				At:    now.Format("2006-01-02T15:04:05Z07:00"),
				By:    req.By,
			}
			out, err = nginx.DisableSpan(out, span, meta)
			if err != nil {
				return editPlan{}, err
			}
			touched = append(touched, map[string]any{
				"file": file, "id": meta.ID, "label": meta.Label})
		}
		if out != conf {
			edits = append(edits, fileEdit{Path: file, Content: out})
		}
	}

	if len(defaults) > 0 && !req.Force {
		return editPlan{
			Conflict: map[string]any{
				"status": "conflict", "reason": "default_server",
				"blocks": defaults,
				"error": "este vhost é o `default_server` da porta: desligá-lo muda " +
					"em silêncio quem atende todo o resto do tráfego dela",
			},
		}, nil
	}
	if len(edits) == 0 {
		return editPlan{Noop: true,
			Body: map[string]any{"note": "nada a desligar"}}, nil
	}
	return editPlan{Edits: edits, Body: map[string]any{"disabled": touched}}, nil
}

// planEnableVhosts monta a transação de religar, com o portão de colisão.
func (s *Server) planEnableVhosts(req vhostRequest) (editPlan, error) {
	if len(req.Fences) == 0 {
		return editPlan{}, fmt.Errorf("nenhuma região informada")
	}

	// O que já responde hoje, para saber se religar cria domínio duplicado.
	// A pergunta é a mesma de `domainCollisions`, e a resposta sai da mesma
	// fonte: a config que o nginx serve AGORA.
	served := map[string]bool{}
	for _, v := range nginx.BuildInventory(s.currentConfig(s.mainConfPath())).Vhosts {
		if v.Disabled {
			continue
		}
		for _, n := range v.ServerNames {
			if n != "" && n != "_" {
				served[n] = true
			}
		}
	}

	byFile := map[string][]string{}
	for _, t := range req.Fences {
		if _, err := s.editableFile(t.File); err != nil {
			return editPlan{}, err
		}
		byFile[t.File] = append(byFile[t.File], t.ID)
	}

	var edits []fileEdit
	var collisions []string
	var touched []map[string]any

	for file, ids := range byFile {
		raw, err := os.ReadFile(file)
		if err != nil {
			return editPlan{}, fmt.Errorf("não foi possível ler %s: %w", file, err)
		}
		out := string(raw)
		for _, id := range ids {
			// O que está dentro desta cerca já declara algum domínio que
			// outro bloco serve?
			for _, f := range nginx.ScanFences(out) {
				if f.Meta.ID != id {
					continue
				}
				for _, v := range nginx.BuildInventory(f.Body).Vhosts {
					for _, n := range v.ServerNames {
						if served[n] {
							collisions = append(collisions, n)
						}
					}
				}
			}
			next, err := nginx.EnableFence(out, id)
			if err != nil {
				return editPlan{}, err
			}
			out = next
			touched = append(touched, map[string]any{"file": file, "id": id})
		}
		if out != string(raw) {
			edits = append(edits, fileEdit{Path: file, Content: out})
		}
	}

	if len(collisions) > 0 && !req.Force {
		sort.Strings(collisions)
		return editPlan{
			Conflict: map[string]any{
				"status": "conflict", "reason": "server_name",
				"collisions": collisions,
				"error": "esses domínios já são servidos por outro bloco: religar " +
					"faria o nginx carregar os dois e escolher um sozinho, sem erro nenhum",
			},
		}, nil
	}
	if len(edits) == 0 {
		return editPlan{Noop: true,
			Body: map[string]any{"note": "nada a religar"}}, nil
	}
	return editPlan{Edits: edits, Body: map[string]any{"enabled": touched}}, nil
}

// editableFile confina a escrita aos arquivos que o nginx REALMENTE carregou.
//
// Não é zelo: sem isto, um `file` vindo do cliente escreve em qualquer lugar
// que a unit alcance. `filepath.Clean` sozinho não basta porque não resolve
// symlink — `sites-enabled/x.conf -> /etc/passwd` passaria no Clean e falharia
// na vida.
func (s *Server) editableFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("arquivo não informado")
	}
	resolved, err := nginx.ResolveSymlinks(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	for _, f := range nginx.ParseDump(s.currentConfig(s.mainConfPath())) {
		if r, err := nginx.ResolveSymlinks(f.File); err == nil && r == resolved {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("%s: %w", path, errNoSuchFile)
}

// isDefaultServer diz se o bloco reivindica o tráfego não reclamado de uma
// porta. Mudar isso sem avisar é mudar o que responde a todo domínio que não
// casa com nenhum `server_name`.
func isDefaultServer(span nginx.Span, conf string) bool {
	for _, line := range strings.Split(span.Text(conf), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "listen ") && strings.Contains(t, "default_server") {
			return true
		}
	}
	return false
}

// describeSpan nomeia o bloco para a cerca e para a tela.
func describeSpan(span nginx.Span, conf string) string {
	for _, line := range strings.Split(span.Text(conf), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "server_name ") {
			names := strings.TrimSuffix(strings.TrimPrefix(t, "server_name "), ";")
			return strings.TrimSpace(names)
		}
	}
	return "(sem server_name)"
}
