package nginx

import "testing"

// Um fixture com todos os venenos juntos, porque é assim que eles aparecem: a
// config escrita à mão de um LB real tem comentário antigo, regex entre aspas e
// corpo de erro em JSON no mesmo arquivo.
const poisonConf = `http {
    upstream backend_pool {
        server 10.10.0.2:10000;
    }

    # location /antigo {
    #     proxy_pass http://morto;
    # }

    server {
        listen 80;
        server_name api.example.com;

        location ~ "^/v(1|2){1,2}/" {
            proxy_pass http://backend_pool;
        }

        location = /health {
            return 200 '{"status":"ok"}';
        }

        location /quebrado {
            return 503 '{';
            add_header X-Nota "fecha } aqui" always;
            add_header X-Aspa "escapou \" e segue";
            add_header X-Jogo "tem # dentro";
        }
    }
}
`

// offsetOf acha a posição de uma marca única no fixture. Falha o teste quando a
// marca não é única: um teste de offset que casa dois lugares não prova nada.
func offsetOf(t *testing.T, conf, needle string) int {
	t.Helper()
	first := indexOf(conf, needle)
	if first < 0 {
		t.Fatalf("marca %q não existe no fixture", needle)
	}
	if indexOf(conf[first+1:], needle) >= 0 {
		t.Fatalf("marca %q aparece mais de uma vez; o teste não saberia qual", needle)
	}
	return first
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestBraceWalkIgnoresCommentedBrace(t *testing.T) {
	// `# location /antigo {` é o estado em que meio LB vive: alguém desligou
	// uma rota comentando. Contar aquela chave sobe a profundidade e o bloco
	// seguinte nunca fecha no lugar certo.
	open := offsetOf(t, poisonConf, "server {")
	end, err := MatchBrace(poisonConf, open+len("server "))
	if err != nil {
		t.Fatal(err)
	}
	// O `}` do server é o penúltimo do arquivo; depois dele só o do `http`.
	if got := poisonConf[end]; got != '}' {
		t.Fatalf("o fim do bloco caiu em %q, não numa chave", got)
	}
	tail := poisonConf[end:]
	if indexOf(tail, "location") >= 0 {
		t.Fatal("o fim do `server` ficou ANTES de um location: a chave comentada moveu a contagem")
	}
}

func TestBraceWalkIgnoresBraceInsideQuotedRegex(t *testing.T) {
	// O nginx EXIGE aspas quando o parâmetro de location tem chave. O `{1,2}`
	// do quantificador não abre bloco nenhum.
	open := offsetOf(t, poisonConf, `location ~ "^/v(1|2){1,2}/" {`)
	brace := open + len(`location ~ "^/v(1|2){1,2}/" `)
	end, err := MatchBrace(poisonConf, brace)
	if err != nil {
		t.Fatal(err)
	}
	body := poisonConf[brace : end+1]
	if indexOf(body, "proxy_pass") < 0 {
		t.Fatalf("o corpo do location não chegou até o proxy_pass:\n%s", body)
	}
	if indexOf(body, "location = /health") >= 0 {
		t.Fatal("o bloco engoliu o location seguinte: a chave do quantificador foi contada")
	}
}

func TestBraceWalkIgnoresBraceInsideSingleQuotedJSON(t *testing.T) {
	// `return 503 '{';` é chave solta dentro de string — ela não balanceia com
	// nada, e contá-la deixa o arquivo inteiro deslocado a partir dali.
	open := offsetOf(t, poisonConf, "location /quebrado {")
	brace := open + len("location /quebrado ")
	end, err := MatchBrace(poisonConf, brace)
	if err != nil {
		t.Fatal(err)
	}
	if indexOf(poisonConf[brace:end+1], "X-Jogo") < 0 {
		t.Fatal("o bloco fechou antes do fim: a chave dentro da string foi contada")
	}
}

func TestBraceWalkHandlesEscapedQuoteAndHashInsideString(t *testing.T) {
	// Se `\"` fechasse a string, tudo depois dela viraria código e o `#` da
	// linha seguinte comentaria o resto do arquivo.
	blocks, err := ScanBlocks(poisonConf)
	if err != nil {
		t.Fatalf("o fixture inteiro tem de escanear: %v", err)
	}
	if len(blocks) != 1 || blocks[0].Kind != "http" {
		t.Fatalf("esperava um único bloco http no topo, veio %d", len(blocks))
	}
}

func TestScanBlocksReadsNestedStructure(t *testing.T) {
	blocks, err := ScanBlocks(poisonConf)
	if err != nil {
		t.Fatal(err)
	}
	http := blocks[0]
	var server *Span
	for i := range http.Children {
		if http.Children[i].Kind == "server" {
			server = &http.Children[i]
		}
	}
	if server == nil {
		t.Fatal("o bloco server não foi encontrado dentro do http")
	}
	if len(server.Children) != 3 {
		t.Fatalf("o server tem 3 locations; a varredura viu %d", len(server.Children))
	}
}

func TestScanBlocksKeepsQuotedArgumentWhole(t *testing.T) {
	// Quebrar o cabeçalho com strings.Fields mutilaria o padrão, e é o padrão
	// que identifica a rota.
	blocks, _ := ScanBlocks(poisonConf)
	var found string
	var walk func(s Span)
	walk = func(s Span) {
		if s.Kind == "location" && s.Arg(0) == "~" {
			found = s.Arg(1)
		}
		for _, c := range s.Children {
			walk(c)
		}
	}
	for _, b := range blocks {
		walk(b)
	}
	if found != `^/v(1|2){1,2}/` {
		t.Fatalf("o padrão do location saiu mutilado: %q", found)
	}
}

func TestScanBlocksRejectsUnclosedBlock(t *testing.T) {
	// Um fim chutado vira escrita que corta o arquivo no meio. Recusar é a
	// única resposta aceitável.
	if _, err := ScanBlocks("server {\n  listen 80;\n"); err == nil {
		t.Fatal("bloco sem fechamento precisa dar erro, não um fim chutado")
	}
}

func TestMatchBraceRejectsOffsetThatIsNotABrace(t *testing.T) {
	if _, err := MatchBrace(poisonConf, 0); err == nil {
		t.Fatal("offset que não é `{` precisa dar erro")
	}
}

func TestInventoryAndBraceWalkAgreeOnBlockEnd(t *testing.T) {
	// A regra que este arquivo existe para impor: o localizador (inventário) e
	// o editor (varredura) não podem discordar sobre onde um bloco termina.
	// Enquanto discordavam, a tela mostrava um bloco e a escrita cortaria outro.
	inv := BuildInventory("# configuration file /etc/nginx/nginx.conf:\n" + poisonConf)
	if len(inv.Vhosts) != 1 {
		t.Fatalf("o inventário precisa ver 1 vhost no fixture, viu %d", len(inv.Vhosts))
	}
	if got := len(inv.Vhosts[0].Locations); got != 3 {
		t.Fatalf("o inventário viu %d locations e a varredura vê 3 — eles discordam", got)
	}
}
