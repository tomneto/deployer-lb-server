package lbserver

// GET /v1/fidelity — "o painel conseguiria reproduzir os vhosts que este nginx
// serve, e o que perderia tentando?"
//
// Somente leitura, e isso é contrato, não detalhe: o relatório existe para
// INFORMAR uma decisão de migração que uma pessoa toma. Um endpoint que
// também aplicasse faria de um classificador construído sobre leitura
// tolerante um escritor de config de produção.
//
// Mesma auth do /v1/dump (bearer, sem HMAC): ele revela topologia — domínios,
// destinos, diretivas — e nenhum segredo, e o plano põe HMAC só na escrita.

import (
	"net/http"
	"strings"

	"github.com/tomneto/deployer-lb-server/internal/auth"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
	"github.com/tomneto/deployer-lb-server/internal/version"
)

func (s *Server) handleFidelity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"status": "invalid"})
		return
	}
	if !auth.VerifyBearer(r.Header.Get("Authorization"), s.cfg.Token) {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "unauthorized"})
		return
	}
	if s.cfg.Runner == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
		return
	}

	// Mesmas duas fontes do /v1/dump, e pelo mesmo motivo: `nginx -T` não roda
	// sob o sandbox da unit, e ler os arquivos é o caminho que o LB de
	// produção usa de verdade. `source` vai na resposta para o relatório nunca
	// passar por medida o que foi leitura de menor fidelidade.
	source := "nginx -T"
	dump, err := s.cfg.Runner.DumpConfig()
	if err != nil {
		tree, readErr := nginx.ReadConfTree(s.cfg.MainConf)
		if readErr != nil || strings.TrimSpace(tree) == "" {
			writeJSON(w, http.StatusOK, map[string]any{
				"status": "error", "error": err.Error(),
				"source": source, "vhosts": []any{},
			})
			return
		}
		dump, source = tree, "arquivos de config"
	}

	vhosts := nginx.Fidelity(dump)
	counts := map[string]int{
		nginx.VerdictReproducible: 0,
		nginx.VerdictWithLoss:     0,
		nginx.VerdictNot:          0,
	}
	for _, v := range vhosts {
		counts[v.Verdict]++
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"version": version.Version,
		"source":  source,
		"vhosts":  vhosts,
		"counts":  counts,
	})
}
