package nginx

import (
	"strings"
	"testing"
)

const disconnectedConf = `events {}
http {
    include /etc/nginx/mime.types;
    server {
        listen 80;
        server_name legado.exemplo.com;
    }
}
`

func TestEnsureConfDirIncludeAddsTheLineInsideHttp(t *testing.T) {
	res, err := EnsureConfDirInclude(disconnectedConf, "/etc/nginx/conf.d", "/etc/nginx")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("esperava mudança")
	}
	if !strings.Contains(res.Config, "include /etc/nginx/conf.d/*.conf;") {
		t.Fatalf("a linha não entrou:\n%s", res.Config)
	}
	// Dentro do http, e não depois dele: um `include` de vhosts fora do bloco
	// http faz o nginx recusar a config inteira.
	idx := strings.Index(res.Config, "include /etc/nginx/conf.d/*.conf;")
	if idx < 0 || idx > strings.LastIndex(res.Config, "}") {
		t.Fatalf("a linha ficou fora do bloco http:\n%s", res.Config)
	}
	// Por último: em empate de server_name quem vence é quem foi declarado
	// primeiro, e o que já serve tráfego tem de continuar servindo.
	if strings.Index(res.Config, "server_name legado.exemplo.com") > idx {
		t.Fatalf("a linha precisa entrar DEPOIS dos vhosts existentes:\n%s", res.Config)
	}
	if !ConfDirIncluded(res.Config, "/etc/nginx/conf.d", "/etc/nginx") {
		t.Fatal("a mesma sonda que detectou o defeito tem de ver a correção")
	}
}

func TestEnsureConfDirIncludeIsIdempotent(t *testing.T) {
	once, err := EnsureConfDirInclude(disconnectedConf, "/etc/nginx/conf.d", "/etc/nginx")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := EnsureConfDirInclude(once.Config, "/etc/nginx/conf.d", "/etc/nginx")
	if err != nil {
		t.Fatal(err)
	}
	if twice.Changed || twice.Config != once.Config {
		t.Fatal("a segunda chamada não pode escrever nada")
	}
}

func TestConfDirIncludedReadsRelativeAndQuotedIncludes(t *testing.T) {
	cases := map[string]bool{
		`include conf.d/*.conf;`:         true,
		`include "/etc/nginx/conf.d/*";`: true,
		// Espaçamento largo e espaço antes do `;` são válidos para o nginx,
		// e ler isso como "não incluído" mandaria escrever uma linha repetida.
		`  include   /etc/nginx/conf.d/*.conf ;`: true,
		// Um arquivo só não liga o canal: o próximo apply escreve OUTRO nome,
		// e ele seguiria invisível.
		`include /etc/nginx/conf.d/site.conf;`: false,
		// Comentado é o defeito, não a correção.
		`# include /etc/nginx/conf.d/*.conf;`: false,
		// Variável é o nginx resolvendo em runtime; adivinhar seria afirmar.
		`include /etc/nginx/$dir/*.conf;`: false,
		// Diretório parecido não é o mesmo diretório.
		`include /etc/nginx/conf.d.bak/*.conf;`: false,
	}
	for line, want := range cases {
		conf := "events {}\nhttp {\n    " + line + "\n}\n"
		got := ConfDirIncluded(conf, "/etc/nginx/conf.d", "/etc/nginx")
		if got != want {
			t.Errorf("%q: esperava %v, veio %v", line, want, got)
		}
	}
}

// Um include do diretório gerido FORA do http (no `stream`, por exemplo) não
// serve vhost nenhum, e lê-lo como canal ligado faria o painel recusar a
// correção no host que mais precisa dela.
func TestConfDirIncludedIgnoresIncludesOutsideHttp(t *testing.T) {
	conf := `events {}
stream {
    include /etc/nginx/conf.d/*.conf;
}
http {
    server { listen 80; }
}
`
	if ConfDirIncluded(conf, "/etc/nginx/conf.d", "/etc/nginx") {
		t.Fatal("include fora do http não liga o canal")
	}
}

func TestEnsureConfDirIncludeRefusesWithoutAnHttpBlock(t *testing.T) {
	if _, err := EnsureConfDirInclude("events {}\n", "/etc/nginx/conf.d", "/etc/nginx"); err == nil {
		t.Fatal("sem bloco http não há onde incluir, e inventar um seria reescrever a config de alguém")
	}
}

func TestEnsureConfDirIncludeKeepsTheClosingBraceIndentation(t *testing.T) {
	conf := "events {}\nhttp {\n    server { listen 80; }\n}\n"
	res, err := EnsureConfDirInclude(conf, "/etc/nginx/conf.d", "/etc/nginx")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(res.Config, "}\n") {
		t.Fatalf("o fecho do http se perdeu:\n%s", res.Config)
	}
	if !strings.Contains(res.Config, "\n    "+AddedIncludeComment+"\n") {
		t.Fatalf("o comentário de autoria tem de ficar junto da linha:\n%s", res.Config)
	}
}

func TestEnsureConfDirIncludeSurvivesUnbalancedBraceInComment(t *testing.T) {
	// O vhost comentado à unha é o estado normal de um LB escrito à mão — e um
	// `# }` esquecido deixa as chaves comentadas desbalanceadas. A contagem
	// ingênua achava o fim do bloco `http` cedo demais, e o fim do `http` é
	// exatamente onde esta função escreve. A linha ia parar no meio do arquivo.
	conf := `http {
    # server {
    #     listen 80;
    # o fechamento deste comentario foi apagado por alguem

    server {
        listen 80;
        server_name real.example.com;
    }
}
`
	res, err := EnsureConfDirInclude(conf, "/etc/nginx/conf.d", "/etc/nginx")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed {
		t.Fatal("a linha de include precisava ter sido acrescentada")
	}
	// A prova: o include tem de cair DEPOIS do vhost real, no fim do `http`,
	// e não espremido entre o comentario e o server.
	at := indexOf(res.Config, "include /etc/nginx/conf.d/*.conf;")
	srv := indexOf(res.Config, "server_name real.example.com;")
	if at < 0 {
		t.Fatalf("include nao foi escrito:\n%s", res.Config)
	}
	if at < srv {
		t.Fatalf("o include caiu ANTES do vhost real — a chave comentada moveu o fim do http:\n%s", res.Config)
	}
}
