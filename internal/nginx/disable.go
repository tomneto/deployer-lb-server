// Desligar um bloco sem perdê-lo.
//
// A operação que o painel precisa fazer é a que as pessoas já fazem à mão:
// comentar o bloco. A config de produção deste LB tem um vhost inteiro
// comentado assim, trinta linhas, sem dizer quem desligou nem quando.
//
// Comentar com `#` puro tem dois defeitos que impedem o painel de fazê-lo:
//
//   - não dá para desfazer com precisão. Não se distingue o comentário que o
//     painel escreveu do que uma pessoa escreveu, e não se sabe onde o bloco
//     comentado termina;
//   - `BuildInventory` descarta toda linha iniciada por `#`, então o bloco
//     some da tela. Quem desligou não consegue religar — e quem não sabia que
//     ele existia não descobre.
//
// Daí a cerca, com identidade nas duas pontas:
//
//	#>>> lb-off id=k3f9 vhost penpot.workspacefy.com | 2026-11-14T12:00:00Z | fulano (não verificado)
//	#| server {
//	#|     listen 80;
//	#| }
//	#<<< lb-off id=k3f9
//
// O ID importa: sem ele, desligar um bloco que já contém outra cerca faz o
// terminador de dentro fechar a de fora, e religar devolveria metade do bloco.
//
// # O round-trip é o contrato
//
// `Enable(Disable(x)) == x`, byte a byte. Três coisas o quebram se não forem
// tratadas, e todas têm teste:
//
//   - **arquivo sem quebra final**: por isso se fatia por offset e nunca se
//     reconstrói o arquivo com Split/Join;
//   - **CRLF**: o `\r` fica no fim da linha e viaja junto com ela; o
//     desprefixo é TrimPrefix exato e JAMAIS TrimSpace;
//   - **a ordem do desprefixo**: `#| ` tem de ser tentado ANTES de `#|`.
//     Invertido, uma linha `  foo` virava `#|   foo` e voltava com um espaço a
//     mais. Perda silenciosa de indentação em config de produção.
//
// Não há digest do corpo na cerca, de propósito. Este arquivo é editado à mão
// por contrato, e um conserto legítimo feito dentro da região cercada viraria
// um conflito insolúvel. A cerca guarda identidade e procedência, não
// integridade.
package nginx

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

const (
	fenceBodyPrefix = "#| "
	fenceOpenWord   = "#>>> lb-off"
	fenceCloseWord  = "#<<< lb-off"
)

var (
	// A âncora `^[ \t]*` e o `id=` obrigatório: um comentário qualquer que
	// mencione "lb-off" não pode ser confundido com uma cerca de verdade.
	// O `\r?` no fim não é zelo: num arquivo CRLF a linha termina em `\r\n`,
	// e sem ele `[ \t]*$` não casa — a cerca ficava invisível e religar
	// respondia "nenhuma região com esse id" sobre um bloco que estava ali.
	fenceOpenRe = regexp.MustCompile(
		`(?m)^[ \t]*#>>> lb-off id=([A-Za-z0-9]+)[ \t]*([^\n]*?)\r?$`)
	fenceCloseRe = regexp.MustCompile(
		`(?m)^[ \t]*#<<< lb-off id=([A-Za-z0-9]+)[ \t]*\r?$`)
)

// FenceMeta é o que a cerca conta a quem abrir o arquivo por SSH.
//
// `By` é ALEGADO, não verificado: o envelope HMAC autentica a origem da
// requisição (o painel), nunca a identidade da pessoa. Dizer o contrário no
// arquivo seria dar a um campo mais autoridade do que ele tem.
type FenceMeta struct {
	ID    string
	Kind  string
	Label string
	At    string
	By    string
}

// Fence é uma região desligada encontrada no texto.
type Fence struct {
	Meta FenceMeta
	// Start e End delimitam a região INTEIRA, cercas incluídas.
	Start, End int
	// Body é o texto original, já sem os prefixos.
	Body string
}

// NewFenceID devolve um identificador curto para parear as duas cercas.
func NewFenceID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "lboff"
	}
	return hex.EncodeToString(b[:])
}

// sanitizeFenceField tira de um campo tudo que poderia virar config.
//
// Sem isto, `By` é injeção direta: o campo é texto arbitrário vindo do cliente
// e vai interpolado numa linha do arquivo. Um `by` igual a "x\n}\nserver {"
// fecharia o bloco e abriria outro — e o arquivo ainda seria nginx válido, que
// é o pior jeito de falhar.
func sanitizeFenceField(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r':
			// Quebra de linha é o vetor: ela escapa da linha de comentário.
			out.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			// Controle some: não há motivo legítimo e eles atrapalham a
			// leitura do arquivo no terminal.
		default:
			out.WriteRune(r)
		}
	}
	clean := strings.TrimSpace(out.String())
	// Um campo nunca pode conter os marcadores, ou ele cria uma cerca dentro
	// da cerca e o pareamento por ID deixa de valer.
	clean = strings.ReplaceAll(clean, fenceOpenWord, "lb-off")
	clean = strings.ReplaceAll(clean, fenceCloseWord, "lb-off")
	clean = strings.ReplaceAll(clean, "#>>>", ">>>")
	clean = strings.ReplaceAll(clean, "#<<<", "<<<")
	if len(clean) > 120 {
		clean = clean[:120]
	}
	return clean
}

// lineStartOf devolve o começo da linha que contém `at`.
func lineStartOf(conf string, at int) int {
	if i := strings.LastIndexByte(conf[:at], '\n'); i >= 0 {
		return i + 1
	}
	return 0
}

// lineEndOf devolve o fim da linha que contém `at` (índice do `\n`, ou o fim).
func lineEndOf(conf string, at int) int {
	if i := strings.IndexByte(conf[at:], '\n'); i >= 0 {
		return at + i
	}
	return len(conf)
}

// DisableSpan comenta o bloco, cercado e identificado.
//
// A região desligada vai do começo da LINHA do cabeçalho até o `}` — incluir a
// indentação do cabeçalho é o que deixa todos os `#|` na mesma coluna e,
// principalmente, o que faz a indentação original viajar dentro do corpo
// cercado, de onde ela volta intacta.
func DisableSpan(conf string, span Span, meta FenceMeta) (string, error) {
	if span.End <= span.Header || span.End >= len(conf) {
		return conf, fmt.Errorf("bloco com limites inválidos")
	}
	if meta.ID == "" {
		meta.ID = NewFenceID()
	}
	if !regexp.MustCompile(`^[A-Za-z0-9]+$`).MatchString(meta.ID) {
		return conf, fmt.Errorf("id de cerca inválido: %q", meta.ID)
	}

	start := span.Header
	// Só engole a indentação se for SÓ indentação: `} server {` numa linha só
	// existe, e levar o `}` do vizinho junto seria corromper o arquivo.
	if ls := lineStartOf(conf, span.Header); strings.TrimSpace(conf[ls:span.Header]) == "" {
		start = ls
	}
	end := span.End + 1

	body := conf[start:end]
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		lines[i] = fenceBodyPrefix + line
	}

	// As linhas de cerca entram com o MESMO terminador do arquivo. Escrever
	// `\n` cru num arquivo CRLF deixaria duas convenções no mesmo lugar — e,
	// pior, o `\r` que fecha a última linha do bloco deixaria de voltar no
	// lugar certo ao religar.
	nl := "\n"
	if strings.Contains(body, "\r\n") || strings.HasPrefix(conf[end:], "\r\n") {
		nl = "\r\n"
	}

	head := strings.TrimRight(fmt.Sprintf("%s id=%s %s %s | %s | %s",
		fenceOpenWord, meta.ID,
		sanitizeFenceField(meta.Kind), sanitizeFenceField(meta.Label),
		sanitizeFenceField(meta.At), sanitizeFenceField(meta.By)), " |")
	tail := fmt.Sprintf("%s id=%s", fenceCloseWord, meta.ID)

	// O corpo é rejuntado com `\n` puro de propósito: num arquivo CRLF cada
	// linha JÁ termina em `\r`, que o Split deixou nela. Juntar com `\r\n`
	// duplicaria o retorno. O `nl` serve só aos terminadores das duas linhas
	// de cerca, que são texto novo.
	return conf[:start] + head + nl +
		strings.Join(lines, "\n") + nl +
		tail + conf[end:], nil
}

// ScanFences acha todas as regiões desligadas do texto.
//
// Parear por ID, e não "a próxima linha de fechamento": com cercas aninhadas
// o terminador de dentro aparece primeiro, e fechar nele devolveria metade do
// bloco de fora.
func ScanFences(conf string) []Fence {
	var out []Fence
	for _, open := range fenceOpenRe.FindAllStringSubmatchIndex(conf, -1) {
		id := conf[open[2]:open[3]]
		rest := conf[open[1]:]
		var closeAt = -1
		for _, c := range fenceCloseRe.FindAllStringSubmatchIndex(rest, -1) {
			if rest[c[2]:c[3]] == id {
				closeAt = open[1] + c[1]
				break
			}
		}
		if closeAt < 0 {
			// Abertura sem fechamento: não é uma região, é texto. Ignorar é
			// melhor que adivinhar onde ela terminaria.
			continue
		}
		closeStart := lineStartOf(conf, closeAt)
		// O corpo começa DEPOIS do terminador da linha de cabeçalho, e termina
		// no começo da linha de fechamento.
		bodyStart := lineEndOf(conf, open[1])
		if bodyStart < len(conf) {
			bodyStart++ // pula o `\n`
		}
		// `End` aponta para o terminador da linha de fechamento, não para
		// depois dele: aquele terminador pertencia ao bloco original e tem de
		// voltar com ele. Apontar depois comeria o `\r` de um arquivo CRLF.
		end := lineEndOf(conf, closeStart)
		if end > closeStart && conf[end-1] == '\r' {
			end--
		}
		out = append(out, Fence{
			Meta:  parseFenceHead(id, conf[open[4]:open[5]]),
			Start: lineStartOf(conf, open[0]),
			End:   end,
			Body:  unprefixBody(conf[bodyStart:closeStart]),
		})
	}
	return out
}

// parseFenceHead lê `vhost nome | data | autor` de volta. Tolerante: um campo
// ausente vira vazio, nunca erro — a cerca é informação, não contrato.
func parseFenceHead(id, rest string) FenceMeta {
	meta := FenceMeta{ID: id}
	parts := strings.Split(rest, "|")
	what := strings.Fields(strings.TrimSpace(parts[0]))
	if len(what) > 0 {
		meta.Kind = what[0]
	}
	if len(what) > 1 {
		meta.Label = strings.Join(what[1:], " ")
	}
	if len(parts) > 1 {
		meta.At = strings.TrimSpace(parts[1])
	}
	if len(parts) > 2 {
		meta.By = strings.TrimSpace(parts[2])
	}
	return meta
}

// unprefixBody tira UM nível de prefixo de cada linha.
//
// A ordem das duas tentativas é o contrato: `#| ` antes de `#|`. Invertida,
// uma linha originalmente `  foo` volta com um espaço a mais — e ninguém
// percebe, porque o arquivo continua válido.
func unprefixBody(raw string) string {
	// Tira exatamente UM terminador do fim — o da última linha do corpo, que
	// no arquivo original era o que separava o bloco do que vinha depois.
	trimmed := raw
	switch {
	case strings.HasSuffix(trimmed, "\r\n"):
		trimmed = strings.TrimSuffix(trimmed, "\r\n")
	case strings.HasSuffix(trimmed, "\n"):
		trimmed = strings.TrimSuffix(trimmed, "\n")
	}
	if trimmed == "" {
		return ""
	}
	lines := strings.Split(trimmed, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, fenceBodyPrefix) {
			lines[i] = strings.TrimPrefix(line, fenceBodyPrefix)
			continue
		}
		lines[i] = strings.TrimPrefix(line, "#|")
	}
	return strings.Join(lines, "\n")
}

// EnableFence devolve ao arquivo o bloco que a cerca guardava.
func EnableFence(conf, id string) (string, error) {
	for _, f := range ScanFences(conf) {
		if f.Meta.ID != id {
			continue
		}
		// `End` é o fim da linha de fechamento; a quebra que a segue
		// pertencia ao bloco original e volta com ele.
		return conf[:f.Start] + f.Body + conf[f.End:], nil
	}
	return conf, fmt.Errorf("nenhuma região desligada com id %q", id)
}
