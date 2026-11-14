// Como apontar para um bloco de config sem errar o alvo.
//
// A tentação é endereçar um vhost por `(arquivo, server_name)`. Não funciona, e
// o contraexemplo é a regra e não a exceção: o padrão universal é DOIS blocos
// `server` com o mesmo `server_name` — um escutando 80 e redirecionando, outro
// escutando 443 e servindo. Desabilitar "o vhost" desligando só um produz o
// pior desfecho possível: a porta 80 continua redirecionando para um 443 que
// agora cai no `default_server` de outra pessoa.
//
// Some a isso `server` sem `server_name` nenhum, o mesmo nome declarado em dois
// arquivos (o cenário que `domainCollisions` existe para detectar), e o dump
// divergindo do disco porque alguém editou à mão desde o último reload.
//
// Então o endereço é um Ref: arquivo, tipo, posição e — o que decide — o
// DIGEST do texto exato do bloco.
//
//	enumera-se pelo dump     (é a visão completa, com todos os arquivos)
//	resolve-se contra o disco (é lá que se escreve)
//
// Os offsets do dump NÃO são os offsets do arquivo: `ReadConfTree` injeta o
// marcador `# configuration file ...` e, com `nginx -T`, o nginx faz o mesmo.
// Por isso `Start` é só uma dica para desempate, nunca autoridade. Quem decide
// é o digest, que é conteúdo e sobrevive a deslocamento.
//
// Os dois desfechos ruins têm nomes diferentes de propósito, porque mandam a
// pessoa para lugares opostos:
//
//	ErrStaleRef      o bloco mudou desde que a tela o leu — releia e refaça
//	ErrAmbiguousRef  dois blocos idênticos; escolher um seria sorteio
package nginx

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"fmt"
)

var (
	// ErrStaleRef: nenhum bloco com esse digest existe mais no arquivo.
	ErrStaleRef = errors.New("o bloco mudou no arquivo desde que foi lido")
	// ErrAmbiguousRef: mais de um bloco com o mesmo digest. Escrever em "o
	// primeiro" seria escolher por sorteio qual parte da produção muda.
	ErrAmbiguousRef = errors.New("há mais de um bloco idêntico a este no arquivo")
)

// Ref é o endereço de um bloco, opaco para quem o carrega.
//
// O painel recebe `Encode()` e devolve a mesma string verbatim; ele não lê nem
// monta o conteúdo. Isso mantém a regra de resolução inteira deste lado, onde
// ela pode ser testada.
type Ref struct {
	File   string `json:"f"`
	Kind   string `json:"k"`
	Start  int    `json:"s"`
	End    int    `json:"e"`
	Digest string `json:"d"`
}

// BlockDigest identifica um bloco pelo texto exato, cabeçalho incluído.
//
// Hex curto, e não o sha256 inteiro: isto viaja em JSON a cada linha da tela, e
// 16 bytes já tornam colisão acidental irrelevante nesta escala — um arquivo de
// config tem dezenas de blocos, não bilhões.
func BlockDigest(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:16])
}

// Encode serializa o Ref para viajar até o painel e voltar.
func (r Ref) Encode() string {
	raw, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeRef lê de volta o que Encode produziu.
func DecodeRef(s string) (Ref, error) {
	var r Ref
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return r, fmt.Errorf("ref inválido: %w", err)
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return r, fmt.Errorf("ref inválido: %w", err)
	}
	if r.Digest == "" {
		// Sem digest não há como resolver com segurança, e cair no offset
		// seria exatamente o endereçamento frágil que este arquivo recusa.
		return r, errors.New("ref sem digest")
	}
	return r, nil
}

// FlattenSpans devolve todos os blocos, pais antes dos filhos, em ordem de
// arquivo. É a lista sobre a qual a resolução trabalha.
func FlattenSpans(spans []Span) []Span {
	out := make([]Span, 0, len(spans))
	for _, s := range spans {
		out = append(out, s)
		out = append(out, FlattenSpans(s.Children)...)
	}
	return out
}

// RefsForFile monta um Ref para cada bloco de um arquivo.
//
// `conf` é o texto DAQUELE arquivo — não o dump inteiro. Quem tem o dump fatia
// por `# configuration file` antes de chamar.
func RefsForFile(file, conf string) ([]Ref, error) {
	spans, err := ScanBlocks(conf)
	if err != nil {
		return nil, err
	}
	all := FlattenSpans(spans)
	refs := make([]Ref, 0, len(all))
	for _, s := range all {
		refs = append(refs, Ref{
			File:   file,
			Kind:   s.Kind,
			Start:  s.Header,
			End:    s.End,
			Digest: BlockDigest(s.Text(conf)),
		})
	}
	return refs, nil
}

// ResolveRef acha, no texto ATUAL do arquivo, o bloco que o Ref endereça.
//
// Digest primeiro, offset só como desempate — e desempate que nunca inventa:
// quando dois blocos têm o mesmo digest a função recusa, porque escolher um
// seria sortear qual parte da produção muda.
func ResolveRef(conf string, ref Ref) (Span, error) {
	spans, err := ScanBlocks(conf)
	if err != nil {
		return Span{}, err
	}
	var hits []Span
	for _, s := range FlattenSpans(spans) {
		if BlockDigest(s.Text(conf)) == ref.Digest {
			hits = append(hits, s)
		}
	}
	switch len(hits) {
	case 0:
		return Span{}, ErrStaleRef
	case 1:
		return hits[0], nil
	}
	// Vários blocos idênticos. O offset do Ref vale como desempate SÓ quando
	// casa exatamente — se o arquivo não mudou de tamanho acima do bloco, ele
	// ainda aponta para o certo. Fora disso, recusa.
	for _, s := range hits {
		if s.Header == ref.Start {
			return s, nil
		}
	}
	return Span{}, ErrAmbiguousRef
}

// ResolveSymlinks devolve o caminho real, sem elo simbólico nenhum.
//
// Existe porque confinar escrita por prefixo de caminho é insuficiente: um
// `sites-enabled/x.conf -> /etc/passwd` passa em qualquer comparação textual e
// falha na vida. Quem valida caminho para ESCREVER resolve primeiro e compara
// depois.
func ResolveSymlinks(path string) (string, error) {
	clean := filepath.Clean(path)
	resolved, err := filepath.EvalSymlinks(clean)
	if err != nil {
		// Arquivo que ainda não existe não é erro de segurança: resolve-se o
		// diretório, que precisa existir, e mantém-se o nome.
		dir, err2 := filepath.EvalSymlinks(filepath.Dir(clean))
		if err2 != nil {
			return "", err
		}
		return filepath.Join(dir, filepath.Base(clean)), nil
	}
	return resolved, nil
}

// AttachRefs preenche o `Ref` de cada vhost do inventário.
//
// O casamento é por ORDEM dentro de cada arquivo, e é exato porque as duas
// varreduras percorrem o mesmo texto na mesma direção: o N-ésimo bloco
// `server` que o lexer acha num arquivo é o N-ésimo vhost que o inventário
// listou daquele arquivo. Blocos desligados não entram em nenhuma das duas
// (são comentário), então as listas não se desalinham.
//
// Os offsets saem do DUMP, não do arquivo no disco, e é por isso que eles são
// só dica: quem resolve é o digest, que é conteúdo e sobrevive ao marcador que
// o dump injeta.
func (inv *Inventory) AttachRefs(dump string) {
	for file, section := range sectionsByFile(dump) {
		spans, err := ScanBlocks(section)
		if err != nil {
			continue
		}
		var servers []Span
		for _, s := range FlattenSpans(spans) {
			if s.Kind == "server" {
				servers = append(servers, s)
			}
		}
		i := 0
		for vi := range inv.Vhosts {
			v := &inv.Vhosts[vi]
			if v.File != file || v.Disabled {
				continue
			}
			if i >= len(servers) {
				break
			}
			span := servers[i]
			i++
			v.Ref = Ref{
				File:   file,
				Kind:   "server",
				Start:  span.Header,
				End:    span.End,
				Digest: BlockDigest(span.Text(section)),
			}.Encode()
		}
	}
}
