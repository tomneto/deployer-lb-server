package nginx

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	// `http {` em nível de bloco, com o espaçamento que aparece na vida real.
	httpBlockRe = regexp.MustCompile(`(?m)^[ \t]*http[ \t]*\{`)
	// Uma diretiva `include`, com o alvo cru — glob, caminho relativo ou
	// variável. Interpretar o alvo é de includeCoversDir.
	includeRe = regexp.MustCompile(`^[ \t]*include[ \t]+([^;]+);`)
)

// Ligar o canal: fazer o `nginx.conf` do host incluir o diretório onde este
// listener escreve.
//
// É o defeito que o painel já sabia NOMEAR e não sabia corrigir: os arquivos
// existem em /etc/nginx/conf.d, o listener os escreve a cada apply, e o
// nginx nunca os lê porque nenhum `include` do nginx.conf aponta para lá.
// Tudo que o painel aplica fica no disco sem efeito, e nada no nginx acusa
// isso — a config é válida, o reload passa, o tráfego segue na config
// escrita à mão.
//
// Como no toggle de pool, esta é a parte PURA: texto entra, texto sai. Backup,
// validação, reload e reversão são do handler, e é lá que mora o risco.

// isGlob diz se o último componente de um include é um padrão, e não um
// arquivo só.
//
// A diferença decide o diagnóstico inteiro: `include conf.d/site.conf` aponta
// para dentro do diretório e NÃO liga o canal — o arquivo que o próximo apply
// escrever continuará invisível. Tratar os dois como "já incluído" faria o
// painel declarar conectado um canal que não está.
func isGlob(pattern string) bool {
	return strings.ContainsAny(pattern, "*?[")
}

// includeCoversDir diz se uma diretiva `include` faz o nginx ler os arquivos
// que este listener escreve em confDir.
//
// Exige as duas coisas: mesmo diretório E um padrão que case com um `.conf`
// qualquer, porque é com esse nome que o apply escreve.
func includeCoversDir(target, prefix, confDir string) bool {
	t := strings.Trim(strings.TrimSpace(target), `"'`)
	if t == "" || strings.Contains(t, "$") {
		// Variável é o nginx resolvendo algo em tempo de execução; adivinhar
		// aqui seria afirmar que o canal está ligado sem ter como saber.
		return false
	}
	if !filepath.IsAbs(t) {
		t = filepath.Join(prefix, t)
	}
	t = filepath.Clean(t)
	if filepath.Dir(t) != strings.TrimRight(filepath.Clean(confDir), "/") {
		return false
	}
	base := filepath.Base(t)
	if !isGlob(base) {
		return false
	}
	ok, err := filepath.Match(base, "qualquer-app.conf")
	return err == nil && ok
}

// httpBlockBody devolve os limites do corpo do bloco `http { ... }`.
//
// Andar pelas chaves a partir da de abertura, e não casar um `}` por regex:
// todo `server`, `upstream` e `location` do arquivo está aninhado aí dentro, e
// a primeira chave fechada encerraria a varredura no lugar errado.
func httpBlockBody(conf string) (start, end int, ok bool) {
	loc := httpBlockRe.FindStringIndex(conf)
	if loc == nil {
		return 0, 0, false
	}
	depth := 0
	for i := loc[1] - 1; i < len(conf); i++ {
		switch conf[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return loc[1], i, true
			}
		}
	}
	return 0, 0, false
}

// ConfDirIncluded diz se o nginx.conf já lê o diretório gerido.
//
// `prefix` é o diretório do próprio nginx.conf, que é como o nginx resolve um
// include relativo.
func ConfDirIncluded(conf, confDir, prefix string) bool {
	if strings.TrimSpace(confDir) == "" {
		return false
	}
	start, end, ok := httpBlockBody(conf)
	if !ok {
		return false
	}
	for _, line := range strings.Split(conf[start:end], "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			// Um include comentado é exatamente o estado que se quer
			// corrigir; lê-lo como ligado seria recusar a correção.
			continue
		}
		m := includeRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		if includeCoversDir(m[1], prefix, confDir) {
			return true
		}
	}
	return false
}

// IncludeResult reporta o que mudou, para o handler distinguir "apliquei" de
// "não havia o que fazer" — a mesma razão de PoolToggleResult.Changed.
type IncludeResult struct {
	Config  string
	Line    string
	Changed bool
}

// AddedIncludeComment marca a linha como escrita pelo painel. Fica no arquivo
// de propósito: quem abrir o nginx.conf a mês de distância precisa saber de
// onde veio a linha sem ter de procurar no histórico do painel.
const AddedIncludeComment = "# include adicionado pelo painel (deployer-lb-server)"

// EnsureConfDirInclude acrescenta `include <confDir>/*.conf;` ao fim do bloco
// http, se ele ainda não estiver lá.
//
// No FIM do bloco, e não no começo: o nginx escolhe o vhost por `server_name`,
// não por ordem, mas em empate o PRIMEIRO declarado vence. Entrar por último
// significa que, se algum domínio colidir com a config escrita à mão, quem
// continua servindo é ela — o estado de hoje, que funciona. A correção liga o
// canal sem trocar o que já responde.
func EnsureConfDirInclude(conf, confDir, prefix string) (IncludeResult, error) {
	res := IncludeResult{Config: conf}
	if strings.TrimSpace(confDir) == "" {
		return res, fmt.Errorf("conf dir is empty")
	}
	_, end, ok := httpBlockBody(conf)
	if !ok {
		return res, fmt.Errorf("nenhum bloco http {} encontrado no nginx.conf")
	}
	if ConfDirIncluded(conf, confDir, prefix) {
		return res, nil
	}

	dir := strings.TrimRight(filepath.Clean(confDir), "/")
	res.Line = fmt.Sprintf("include %s/*.conf;", dir)

	// Antes da linha que fecha o http, preservando a indentação dela — o
	// arquivo é de alguém, e uma linha nossa desalinhada no meio dele é a
	// primeira coisa que faz pensar que o painel estragou algo.
	lineStart := strings.LastIndexByte(conf[:end], '\n') + 1
	indent := conf[lineStart:end]
	if strings.TrimSpace(indent) != "" {
		indent = ""
	}
	block := fmt.Sprintf("%s    %s\n%s    %s\n",
		indent, AddedIncludeComment, indent, res.Line)
	res.Config = conf[:lineStart] + block + conf[lineStart:]
	res.Changed = true
	return res, nil
}
