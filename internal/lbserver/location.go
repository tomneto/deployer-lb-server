// POST /v1/location — desligar e religar uma rota, sem derrubar o domínio.
//
// Mesma maquinaria do /v1/vhost, granularidade mais fina. A diferença que
// importa não é técnica, é de consequência: desligar um vhost tira o domínio
// do ar, e isso é VISÍVEL. Desligar um `location` não derruba nada — o nginx
// simplesmente passa a casar aquele caminho no location mais genérico que
// existir, quase sempre o `/`.
//
// É um modo de falha pior do que 404, porque parece funcionar: `/api/v1/x`
// deixa de ir para o backend e passa a ser servido pela home. Por isso a tela
// precisa dizer QUAL rota assume, e por isso a rota desligada continua
// listada — some da tela e ninguém entende por que `/api` virou a home.
//
// # O portão próprio desta rota
//
// Um `location @nome` é alvo de redirecionamento interno. Se qualquer
// `try_files`, `error_page` ou `proxy_intercept_errors` do mesmo `server`
// apontar para ele e ele sumir, o nginx recusa a config inteira com
// "could not find named location". Isso é barato de detectar antes de
// escrever e caro de descobrir no reload — ainda mais num host onde o
// `nginx -t` não roda e a única rede é o reload seguido de restore.
//
// A config de produção deste LB tem exatamente esse caso: o `intake` usa
// `error_page 502 503 504 = @fallback` com um `location @fallback` logo
// abaixo.
package lbserver

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

type locationRequest struct {
	Disabled bool          `json:"disabled"`
	Refs     []string      `json:"refs"`
	Fences   []fenceTarget `json:"fences"`
	By       string        `json:"by"`
	Force    bool          `json:"force"`
	DryRun   bool          `json:"dry_run"`
}

// namedRefRe acha quem aponta para um `@nome`. Uma regex só para as três
// diretivas porque a pergunta é uma só — "alguém redireciona para cá?" — e
// três regexes divergiriam no dia em que aparecer a quarta.
var namedRefRe = regexp.MustCompile(`(?m)^[ \t]*(?:try_files|error_page|proxy_intercept_errors)\b[^;]*?(@[A-Za-z0-9_-]+)`)

func (s *Server) handleLocation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	body, now, ok := s.authenticateWrite(w, r, 0)
	if !ok {
		return
	}
	var req locationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"status": "invalid", "errors": []string{"corpo inválido"}})
		return
	}

	s.applyConfEdit(w, now, req.DryRun,
		func() (editPlan, error) {
			if req.Disabled {
				return s.planDisableLocations(req, now)
			}
			return s.planEnableFences(req.Fences, req.Force)
		},
		nil)
}

func (s *Server) planDisableLocations(req locationRequest, now time.Time) (editPlan, error) {
	if len(req.Refs) == 0 {
		return editPlan{}, fmt.Errorf("nenhuma rota informada")
	}

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
	var orphans []string
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
			if span.Kind != "location" {
				return editPlan{}, fmt.Errorf("%s: o bloco endereçado é um %q, não um location",
					file, span.Kind)
			}
			if who := namedLocationUsers(conf, span); len(who) > 0 {
				orphans = append(orphans, who...)
			}
			spans = append(spans, span)
		}

		// Do fim para o começo: desligar um bloco desloca tudo que vem depois.
		sort.Slice(spans, func(i, j int) bool { return spans[i].Header > spans[j].Header })

		out := conf
		for _, span := range spans {
			meta := nginx.FenceMeta{
				ID: nginx.NewFenceID(), Kind: "location",
				Label: locationLabel(span),
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

	if len(orphans) > 0 && !req.Force {
		sort.Strings(orphans)
		return editPlan{
			Conflict: map[string]any{
				"status": "conflict", "reason": "named_location",
				"referenced_by": orphans,
				"error": "esta rota é alvo de redirecionamento interno: desligá-la " +
					"faz o nginx recusar a config inteira com `could not find named " +
					"location`, e o reload falha",
			},
		}, nil
	}
	if len(edits) == 0 {
		return editPlan{Noop: true, Body: map[string]any{"note": "nada a desligar"}}, nil
	}
	return editPlan{Edits: edits, Body: map[string]any{"disabled": touched}}, nil
}

// planEnableFences religa regiões por id. Serve para location e para qualquer
// outra coisa cercada: religar é a mesma operação, só muda o que estava lá.
func (s *Server) planEnableFences(targets []fenceTarget, _ bool) (editPlan, error) {
	if len(targets) == 0 {
		return editPlan{}, fmt.Errorf("nenhuma região informada")
	}
	byFile := map[string][]string{}
	for _, t := range targets {
		if _, err := s.editableFile(t.File); err != nil {
			return editPlan{}, err
		}
		byFile[t.File] = append(byFile[t.File], t.ID)
	}

	var edits []fileEdit
	var touched []map[string]any
	for file, ids := range byFile {
		raw, err := os.ReadFile(file)
		if err != nil {
			return editPlan{}, fmt.Errorf("não foi possível ler %s: %w", file, err)
		}
		out := string(raw)
		for _, id := range ids {
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
	if len(edits) == 0 {
		return editPlan{Noop: true, Body: map[string]any{"note": "nada a religar"}}, nil
	}
	return editPlan{Edits: edits, Body: map[string]any{"enabled": touched}}, nil
}

// namedLocationUsers diz quem redireciona para esta rota, quando ela é nomeada.
//
// Procura no `server` que a contém, não no arquivo inteiro: um `@fallback` de
// outro vhost é outro location, e acusar conflito por homonímia faria a tela
// recusar uma operação legítima.
func namedLocationUsers(conf string, span nginx.Span) []string {
	name := locationLabel(span)
	if !strings.HasPrefix(name, "@") {
		return nil
	}
	scope := enclosingServer(conf, span)
	var out []string
	for _, m := range namedRefRe.FindAllStringSubmatch(scope, -1) {
		if m[1] == name {
			out = append(out, strings.TrimSpace(strings.SplitN(
				strings.TrimSpace(m[0]), " ", 2)[0])+" → "+name)
		}
	}
	return out
}

// enclosingServer devolve o texto do `server` que contém o span, ou o arquivo
// inteiro quando não houver um.
func enclosingServer(conf string, span nginx.Span) string {
	spans, err := nginx.ScanBlocks(conf)
	if err != nil {
		return conf
	}
	for _, sp := range nginx.FlattenSpans(spans) {
		if sp.Kind == "server" && span.Header > sp.Open && span.End < sp.End {
			return sp.Text(conf)
		}
	}
	return conf
}

// locationLabel é o caminho da rota, com o operador quando houver — o mesmo
// que a tela mostra, porque é assim que alguém a reconhece.
func locationLabel(span nginx.Span) string {
	if len(span.Args) == 0 {
		return "(sem caminho)"
	}
	if len(span.Args) >= 2 {
		return span.Args[0] + " " + span.Args[1]
	}
	return span.Args[0]
}
