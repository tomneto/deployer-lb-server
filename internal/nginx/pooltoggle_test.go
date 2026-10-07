package nginx

import "testing"

const toggleConf = `http {
    upstream n8n_pool {
        server 10.10.0.2:11000;
    }
    upstream backend_pool {
        server 10.10.0.2:10000 weight=3 max_fails=2;
        server 10.10.0.3:10000;
        keepalive 16;
    }
    server {
        listen 80;
        location / { proxy_pass http://n8n_pool; }
    }
}
`

func TestSetPoolDownMarksEveryBackend(t *testing.T) {
	res, err := SetPoolDown(toggleConf, "backend_pool", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed != 2 || res.Total != 2 {
		t.Fatalf("esperava 2 de 2, veio %d de %d", res.Changed, res.Total)
	}
	if !contains(res.Config, "server 10.10.0.2:10000 weight=3 max_fails=2 down;") {
		t.Fatalf("os parâmetros existentes precisam sobreviver intactos:\n%s", res.Config)
	}
	// E o outro pool não pode ter sido tocado.
	if !contains(res.Config, "server 10.10.0.2:11000;") {
		t.Fatalf("mexeu no pool errado:\n%s", res.Config)
	}
}

func TestSetPoolDownIsIdempotent(t *testing.T) {
	once, _ := SetPoolDown(toggleConf, "n8n_pool", true)
	twice, err := SetPoolDown(once.Config, "n8n_pool", true)
	if err != nil {
		t.Fatal(err)
	}
	// `Changed == 0` é o que diz ao handler para pular a escrita inteira: um
	// reload que não serve para nada ainda é uma janela em que a config pode
	// não voltar.
	if twice.Changed != 0 {
		t.Fatalf("esperava nenhuma mudança na segunda vez, veio %d", twice.Changed)
	}
	if twice.Config != once.Config {
		t.Fatal("a segunda passada não pode alterar o arquivo")
	}
}

func TestSetPoolDownRoundTrips(t *testing.T) {
	down, _ := SetPoolDown(toggleConf, "backend_pool", true)
	up, err := SetPoolDown(down.Config, "backend_pool", false)
	if err != nil {
		t.Fatal(err)
	}
	if up.Config != toggleConf {
		t.Fatalf("ligar de volta tem de devolver o arquivo original:\n%s", up.Config)
	}
}

// Um backend chamado `downloads.internal` contém "down" e NÃO está fora de
// rotação. Comparar por substring faria o toggle mentir sobre o estado atual.
func TestDownIsMatchedAsAWordNotASubstring(t *testing.T) {
	conf := "upstream p {\n    server downloads.internal:8080;\n}\n"
	res, err := SetPoolDown(conf, "p", true)
	if err != nil {
		t.Fatal(err)
	}
	if res.Changed != 1 {
		t.Fatalf("o backend não estava desabilitado, esperava 1 mudança, veio %d", res.Changed)
	}
	if !contains(res.Config, "server downloads.internal:8080 down;") {
		t.Fatalf("saída inesperada: %s", res.Config)
	}
}

func TestPoolIsDownNeedsEveryBackendDown(t *testing.T) {
	// Um pool com um de dois backends fora ainda está servindo; mostrar o
	// toggle como desligado seria mentira.
	partial := "upstream p {\n    server a:1 down;\n    server b:2;\n}\n"
	if isDown, ok := PoolIsDown(partial, "p"); !ok || isDown {
		t.Fatalf("esperava não-desabilitado, veio isDown=%v ok=%v", isDown, ok)
	}
	full := "upstream p {\n    server a:1 down;\n    server b:2 down;\n}\n"
	if isDown, ok := PoolIsDown(full, "p"); !ok || !isDown {
		t.Fatalf("esperava desabilitado, veio isDown=%v ok=%v", isDown, ok)
	}
}

func TestSetPoolDownRefusesWhatItCannotDo(t *testing.T) {
	if _, err := SetPoolDown(toggleConf, "nao_existe", true); err == nil {
		t.Fatal("upstream ausente precisa ser erro, não silêncio")
	}
	if _, err := SetPoolDown("upstream vazio {\n    keepalive 8;\n}\n", "vazio", true); err == nil {
		t.Fatal("upstream sem server precisa ser erro")
	}
	if _, err := SetPoolDown("upstream aberto {\n    server a:1;\n", "aberto", true); err == nil {
		t.Fatal("bloco não fechado precisa ser erro")
	}
	if _, err := SetPoolDown(toggleConf, "  ", true); err == nil {
		t.Fatal("nome vazio precisa ser erro")
	}
}

// O bloco pode conter chaves aninhadas; parar na primeira `}` cortaria o
// upstream ao meio e corromperia o arquivo.
func TestSetPoolDownWalksNestedBraces(t *testing.T) {
	conf := "upstream p {\n    zone up 64k;\n    server a:1;\n}\nserver {\n    listen 80;\n}\n"
	res, err := SetPoolDown(conf, "p", true)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(res.Config, "listen 80;") {
		t.Fatalf("o resto do arquivo sumiu:\n%s", res.Config)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (func() bool {
		for i := 0; i+len(needle) <= len(haystack); i++ {
			if haystack[i:i+len(needle)] == needle {
				return true
			}
		}
		return false
	})()
}

// O inventário precisa devolver a posição do toggle, senão o painel desenha um
// interruptor que não sabe onde está.
func TestInventoryReportsPoolDownState(t *testing.T) {
	conf := `# configuration file /etc/nginx/nginx.conf:
http {
    upstream desligado {
        server a:1 down;
        server b:2 down;
    }
    upstream parcial {
        server c:3 down;
        server d:4;
    }
    upstream vazio {
        keepalive 8;
    }
}
`
	inv := BuildInventory(conf)
	byName := map[string]Pool{}
	for _, p := range inv.Pools {
		byName[p.Name] = p
	}
	if !byName["desligado"].Down {
		t.Fatal("todos os backends down = pool desabilitado")
	}
	// Um de dois fora ainda está servindo.
	if byName["parcial"].Down {
		t.Fatal("parcial não pode aparecer como desabilitado")
	}
	if byName["vazio"].Down {
		t.Fatal("pool sem backend está vazio, não desabilitado")
	}
	if !byName["parcial"].Servers[0].Down || byName["parcial"].Servers[1].Down {
		t.Fatal("o estado por backend tem de vir junto")
	}
}
