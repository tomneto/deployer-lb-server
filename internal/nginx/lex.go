// Onde um bloco de config começa e termina — a única resposta, para todo mundo.
//
// Havia duas, e elas discordavam. `pooltoggle.go` andava pelas chaves contando
// `{` e `}` byte a byte; `inventory.go` descartava a linha comentada ANTES de
// contar. Num arquivo com chave dentro de comentário as duas enxergam blocos
// diferentes — e enquanto só `upstream` era editado isso não machucava ninguém,
// porque o corpo de um upstream é pobre demais para ter comentário com chave.
//
// No minuto em que o painel passa a endereçar `server` e `location` para
// ESCRITA, a discordância vira corrupção silenciosa: a tela mostra um bloco, a
// escrita corta outro. Daí este arquivo, e daí a regra de que ninguém mais
// conta chave na mão.
//
// O que quebra a contagem ingênua, tudo real em config escrita à mão:
//
//	# location /antigo {        chave comentada: sobe o depth e nunca desce
//	location ~ "^/v(1|2){1,2}/" {   o nginx EXIGE aspas quando o parâmetro tem
//	                                chave, e o quantificador conta como bloco
//	return 503 '{';             chave solta dentro de string
//	add_header X-Foo "a } b";   idem, fechando o bloco cedo
//
// Não é um parser de nginx: é um léxico de chaves, aspas e comentário. Ele não
// sabe o que uma diretiva significa, e não precisa saber — a pergunta que
// responde é só "até onde vai este bloco".
package nginx

import (
	"fmt"
	"strings"
)

// Span é um bloco delimitado por chaves, com o cabeçalho que o abre.
//
// Os offsets são em BYTES sobre o texto que foi escaneado, e é por isso que
// quem escreve precisa escanear o arquivo do disco, nunca o dump: o dump leva
// os marcadores `# configuration file ...` injetados por ReadConfTree, e um
// offset medido nele aponta para o lugar errado do arquivo.
type Span struct {
	// Kind é a primeira palavra do cabeçalho — `server`, `location`,
	// `upstream`, `http`, `events`, `if`…
	Kind string
	// Args são as palavras seguintes, com aspas já removidas.
	Args []string
	// Header é o offset do primeiro byte do cabeçalho; Open, o da chave que
	// abre; End, o da chave que fecha. O bloco inteiro é conf[Header:End+1].
	Header int
	Open   int
	End    int
	// Line é a linha (1-based) onde o cabeçalho começa.
	Line int
	// Children são os blocos imediatamente aninhados, na ordem do arquivo.
	Children []Span
}

// Text devolve o bloco inteiro, cabeçalho incluído.
func (s Span) Text(conf string) string {
	if s.Header < 0 || s.End >= len(conf) || s.Header > s.End {
		return ""
	}
	return conf[s.Header : s.End+1]
}

// Arg devolve o i-ésimo argumento, ou "" — poupa quem lê de checar tamanho
// antes de cada acesso, que é onde nasce panic em parser tolerante.
func (s Span) Arg(i int) string {
	if i < 0 || i >= len(s.Args) {
		return ""
	}
	return s.Args[i]
}

// estado do léxico. Fora de aspas, `#` comenta até o fim da linha; dentro, não.
type lexState int

const (
	lexCode lexState = iota
	lexComment
	lexSingle
	lexDouble
)

// scanner percorre a config uma vez, classificando cada byte. Os dois
// consumidores (MatchBrace e ScanBlocks) compartilham exatamente esta
// travessia, que é o ponto do arquivo: duas travessias voltariam a divergir.
type scanner struct {
	conf  string
	i     int
	state lexState
}

// next avança um byte e diz se ele é estrutural — isto é, se é uma chave que
// conta. Devolve o byte e sua posição; `structural` é falso para tudo que está
// dentro de comentário ou de aspas.
func (s *scanner) next() (b byte, at int, structural bool, ok bool) {
	if s.i >= len(s.conf) {
		return 0, 0, false, false
	}
	at = s.i
	b = s.conf[s.i]
	s.i++

	switch s.state {
	case lexComment:
		if b == '\n' {
			s.state = lexCode
		}
		return b, at, false, true

	case lexSingle, lexDouble:
		// A barra invertida escapa o PRÓXIMO byte, inclusive a própria aspa de
		// fechamento. Consumir os dois aqui é o que impede `"a \" b"` de
		// terminar a string cedo.
		if b == '\\' && s.i < len(s.conf) {
			s.i++
			return b, at, false, true
		}
		if (s.state == lexSingle && b == '\'') || (s.state == lexDouble && b == '"') {
			s.state = lexCode
		}
		return b, at, false, true

	default: // lexCode
		switch b {
		case '#':
			s.state = lexComment
		case '\'':
			s.state = lexSingle
		case '"':
			s.state = lexDouble
		case '{', '}':
			return b, at, true, true
		}
		return b, at, false, true
	}
}

// MatchBrace acha a chave que fecha a aberta em `open`.
//
// Erra — em vez de chutar — quando `open` não é uma chave de abertura ou quando
// o bloco não fecha. Um fim chutado é pior que uma recusa: ele vira uma escrita
// que corta o arquivo no meio.
func MatchBrace(conf string, open int) (int, error) {
	if open < 0 || open >= len(conf) || conf[open] != '{' {
		return 0, fmt.Errorf("offset %d não é uma chave de abertura", open)
	}
	// Escanear desde o início, e não desde `open`: o estado léxico em `open`
	// depende de tudo que veio antes. Começar no meio é supor que não havia
	// aspas abertas — e é exatamente a suposição que este arquivo existe para
	// não fazer.
	sc := &scanner{conf: conf}
	depth := 0
	for {
		b, at, structural, ok := sc.next()
		if !ok {
			break
		}
		// Chave antes do alvo não conta: a profundidade começa a ser medida na
		// própria chave que se quer fechar.
		if !structural || at < open {
			continue
		}
		if b == '{' {
			depth++
			continue
		}
		depth--
		if depth == 0 {
			return at, nil
		}
	}
	return 0, fmt.Errorf("bloco aberto em %d não é fechado", open)
}

// ScanBlocks devolve todos os blocos do texto, aninhados.
//
// Tolerante por fora, exato por dentro: um arquivo que não fecha um bloco
// devolve erro, mas um cabeçalho que este léxico não entende vira um Span com
// `Kind` esquisito em vez de derrubar a varredura. O inventário acima dele
// continua podendo ignorar o que não reconhece.
func ScanBlocks(conf string) ([]Span, error) {
	sc := &scanner{conf: conf}

	var top []Span
	var stack []*Span
	// boundary é onde o cabeçalho do próximo bloco pode começar: logo depois do
	// último `;`, `{` ou `}` que o léxico viu em código.
	boundary := 0

	for {
		b, at, structural, ok := sc.next()
		if !ok {
			break
		}
		// O `;` não é estrutural para contagem de chaves, mas delimita
		// cabeçalho: sem ele, o header de um bloco engoliria a diretiva
		// anterior inteira.
		if !structural {
			if b == ';' && sc.state == lexCode {
				boundary = at + 1
			}
			continue
		}

		if b == '{' {
			raw := conf[boundary:at]
			start := boundary + headerStart(raw)
			args := splitArgs(raw)
			span := Span{
				Header: start,
				Open:   at,
				Line:   1 + strings.Count(conf[:start], "\n"),
			}
			if len(args) > 0 {
				span.Kind, span.Args = args[0], args[1:]
			}
			stack = append(stack, &span)
			boundary = at + 1
			continue
		}

		// '}'
		if len(stack) == 0 {
			return nil, fmt.Errorf("chave de fechamento sem abertura na posição %d", at)
		}
		done := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		done.End = at
		if len(stack) == 0 {
			top = append(top, *done)
		} else {
			parent := stack[len(stack)-1]
			parent.Children = append(parent.Children, *done)
		}
		boundary = at + 1
	}

	if len(stack) != 0 {
		open := stack[len(stack)-1]
		return nil, fmt.Errorf("bloco %q aberto na linha %d não é fechado", open.Kind, open.Line)
	}
	return top, nil
}

// headerStart acha a primeira letra do cabeçalho de verdade.
//
// O trecho entre a diretiva anterior e a `{` carrega também o espaço em branco
// e QUALQUER comentário que houver no meio — e num LB escrito à mão há sempre
// um: `# location /antigo {` logo acima do `server {` é o estado normal do
// arquivo. Pular só espaço faria o cabeçalho começar no `#` e o bloco se
// chamar "#".
func headerStart(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ', '\t', '\r', '\n':
		case '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		default:
			return i
		}
	}
	return len(s)
}

// splitArgs quebra o cabeçalho em palavras respeitando aspas e comentário.
//
// `strings.Fields` não serve por duas razões: `location ~ "^/v(1|2){1,2}/"`
// viraria quatro pedaços com o padrão mutilado, e um comentário acima da
// diretiva entraria como argumento.
func splitArgs(header string) []string {
	var out []string
	var cur strings.Builder
	state := lexCode
	wrote := false

	flush := func() {
		if wrote {
			out = append(out, cur.String())
			cur.Reset()
			wrote = false
		}
	}

	for i := 0; i < len(header); i++ {
		b := header[i]
		switch state {
		case lexSingle, lexDouble:
			if b == '\\' && i+1 < len(header) {
				i++
				cur.WriteByte(header[i])
				wrote = true
				continue
			}
			if (state == lexSingle && b == '\'') || (state == lexDouble && b == '"') {
				state = lexCode
				continue
			}
			cur.WriteByte(b)
			wrote = true
		default:
			switch b {
			case '\'':
				state = lexSingle
				wrote = true
			case '"':
				state = lexDouble
				wrote = true
			case '#':
				// Comentário no meio do cabeçalho: descarta até o fim da linha
				// e o que já estava acumulado some junto, porque pertence à
				// linha comentada, não à diretiva.
				flush()
				out = nil
				for i < len(header) && header[i] != '\n' {
					i++
				}
			case ' ', '\t', '\r', '\n':
				flush()
			default:
				cur.WriteByte(b)
				wrote = true
			}
		}
	}
	flush()
	return out
}
