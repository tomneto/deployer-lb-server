package lbserver

// De onde sai o template, e por que o listener se recusa a subir sem conferir.

import (
	"fmt"

	"github.com/tomneto/deployer-lb-server/conf"
	"github.com/tomneto/deployer-lb-server/internal/render"
)

// renderVhost renderiza o conf de um app pelo template embutido, ou pelo
// override em disco quando alguém pediu um.
func (s *Server) renderVhost(p render.Payload) (string, error) {
	if s.cfg.TemplatePath != "" {
		return render.Render(s.cfg.TemplatePath, p)
	}
	return render.RenderString(conf.NginxAppTemplate, p)
}

// VerifyTemplate renderiza um payload-sonda pelo template que este servidor
// de fato usaria.
//
// Chamado no boot, e fatal se falhar. O ponto é QUANDO a falha aparece: um
// template que não executa vira 400 em todo apply (`runApplyLocked`), e o
// lb_sync_worker marca 400 como FAILED sem retry — ou seja, um template
// quebrado derrubaria em silêncio o canal de aplicação inteiro daquele host,
// pipeline por pipeline, até alguém reparar. Falhando no boot, o serviço não
// sobe, o canário da frota não recupera e o rollout trava: comportamento que o
// agent_update_worker já sabe tratar.
//
// A sonda não toca disco nem rede — é só Execute sobre um payload sintético.
func (s *Server) VerifyTemplate() error {
	probe := render.Payload{
		SchemaVersion:  render.CurrentSchemaVersion,
		Revision:       1,
		IdempotencyKey: "probe:boot",
		PipelineRef:    "probe",
		Repo:           "owner/probe",
		Domains:        []string{"probe.invalid"},
		Exposure:       "internal",
		Upstreams:      []render.Upstream{{IP: "127.0.0.1", Port: 1}},
		Timeouts:       render.Timeouts{Read: 1, Send: 1, Connect: 1},
		// Exercita os dois ramos que um binário antigo não conseguiria
		// executar: o laço de locations e o destino por rota. Uma sonda que
		// só renderizasse o caso simples passaria num template que quebra
		// exatamente onde o recurso novo mora.
		Locations: []render.LocationSpec{
			{Matcher: "=", Path: "/probe"},
			{Path: "/"},
		},
	}
	out, err := s.renderVhost(probe)
	if err != nil {
		return fmt.Errorf("template não executa: %w", err)
	}
	// Executar sem erro não basta: um template que perdesse o cabeçalho
	// renderizaria liso e produziria arquivos que o próprio listener se
	// recusa a sobrescrever ou remover depois.
	if len(out) < len("# managed-by:") || out[:len("# managed-by:")] != "# managed-by:" {
		return fmt.Errorf(
			"a primeira linha do template não é o cabeçalho `# managed-by:` — " +
				"sem ele o listener não pode reescrever nem remover o que escreve")
	}
	return nil
}
