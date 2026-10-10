package render

// A guarda de regressão do template, byte a byte.
//
// `template_file_test.go` assere SUBSTRING: ele prova que o que precisa estar
// na saída está. Isso não pega o que esta suíte existe para pegar — uma linha
// a mais, uma indentação trocada, um `{{-}}` que comeu uma quebra. Numa
// mudança que transforma o `location /` fixo num laço sobre locations, é
// exatamente esse tipo de diferença que escapa de toda asserção de conteúdo e
// chega em produção como uma config que "parece igual".
//
// Os arquivos de `testdata/golden/` têm de ser gerados e commitados ANTES de
// qualquer edição do template. Golden gerado depois da mudança não prova nada:
// ele congela o resultado novo e passa a concordar com o próprio erro.
//
// Para regenerar deliberadamente:
//
//	go test ./internal/render/ -run TestGolden -update
//
// e LER o diff do `git diff testdata/golden/` antes de commitar. Um golden que
// muda sem que alguém tenha querido mudá-lo é a notícia, não o incômodo.

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var updateGolden = flag.Bool("update", false,
	"reescreve os arquivos de testdata/golden com a saída atual")

// goldenCases cobre cada ramo condicional do template. Um ramo sem golden é um
// ramo onde a byte-identidade não está provada.
func goldenCases() map[string]Payload {
	base := func() Payload {
		return Payload{
			SchemaVersion:  SupportedSchemaVersion,
			Revision:       42,
			IdempotencyKey: "app-a:run-1",
			PipelineRef:    "app-a",
			Repo:           "owner/app-a",
			Domains:        []string{"app-a.workspacefy.com"},
			Exposure:       "external",
			Upstreams:      []Upstream{{IP: "10.10.0.2", Port: 10200}},
			Timeouts:       Timeouts{Read: 120, Send: 120, Connect: 10},
		}
	}

	websocket := base()
	websocket.Websocket = true

	cache := base()
	cache.Cache = CacheConfig{Enabled: true}

	rateLimit := base()
	rateLimit.RateLimit = RateLimitConfig{Enabled: true, Rate: 10, Burst: 25}

	// Zero nos dois campos: o template tem de renderizar os defaults de
	// `Resolved()`, nunca `rate=0r/s`.
	rateLimitDefaults := base()
	rateLimitDefaults.RateLimit = RateLimitConfig{Enabled: true}

	// Vários domínios e vários upstreams exercitam os dois `range` do
	// template, que são onde o controle de espaço em branco é mais frágil.
	multi := base()
	multi.Domains = []string{
		"app-a.workspacefy.com",
		"www.app-a.workspacefy.com",
		"app-a.example.com",
	}
	multi.Upstreams = []Upstream{
		{IP: "10.10.0.2", Port: 10200},
		{IP: "10.10.0.3", Port: 10200},
	}

	// Tudo ligado ao mesmo tempo: é a combinação que ninguém testa à mão e a
	// que mais tem chance de empilhar blocos na ordem errada.
	everything := multi
	everything.Websocket = true
	everything.Cache = CacheConfig{Enabled: true}
	everything.RateLimit = RateLimitConfig{Enabled: true, Rate: 10, Burst: 25}

	return map[string]Payload{
		"base":                base(),
		"websocket":           websocket,
		"cache":               cache,
		"rate-limit":          rateLimit,
		"rate-limit-defaults": rateLimitDefaults,
		"multi":               multi,
		"everything":          everything,
	}
}

func TestGoldenTemplateRendersByteForByte(t *testing.T) {
	for name, payload := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			// O template REAL, o mesmo arquivo que o setup.sh instala — um
			// golden contra template inline provaria só que a cópia do teste
			// não mudou.
			got, err := Render(templateRelPath, payload)
			if err != nil {
				t.Fatalf("Render() error = %v", err)
			}

			path := filepath.Join("testdata", "golden", name+".conf")
			if *updateGolden {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Logf("golden reescrito: %s", path)
				return
			}

			wantBytes, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("golden ausente (%v).\n"+
					"Gere com: go test ./internal/render/ -run TestGolden -update\n"+
					"ATENÇÃO: só gere a partir de um template que você ainda NÃO mudou.",
					err)
			}
			want := string(wantBytes)
			if got == want {
				return
			}
			t.Errorf("a saída do template mudou:\n%s", lineDiff(want, got))
		})
	}
}

// lineDiff mostra a primeira divergência com contexto, em vez de despejar dois
// arquivos de 95 linhas e deixar a conferência para o olho.
func lineDiff(want, got string) string {
	wantLines := strings.Split(want, "\n")
	gotLines := strings.Split(got, "\n")

	var b strings.Builder
	n := len(wantLines)
	if len(gotLines) > n {
		n = len(gotLines)
	}
	shown := 0
	for i := 0; i < n; i++ {
		w, g := "", ""
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w == g {
			continue
		}
		b.WriteString("linha ")
		b.WriteString(itoa(i + 1))
		b.WriteString(":\n  golden: ")
		b.WriteString(quote(w))
		b.WriteString("\n  atual:  ")
		b.WriteString(quote(g))
		b.WriteString("\n")
		shown++
		if shown >= 10 {
			b.WriteString("... (mais divergências omitidas)\n")
			break
		}
	}
	if shown == 0 {
		// Mesmas linhas e mesmo assim diferentes: é o terminador do arquivo.
		b.WriteString("as linhas são iguais — a diferença está no fim do " +
			"arquivo (quebra de linha final)\n")
	}
	return b.String()
}

// quote marca o espaço em branco do fim da linha, que é invisível num diff e é
// justamente o que um `{{-}}` mal colocado produz.
func quote(s string) string {
	return "\"" + s + "\""
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}
