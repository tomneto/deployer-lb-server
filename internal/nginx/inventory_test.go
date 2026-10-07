package nginx

import "testing"

// Um recorte fiel do nginx que serve produção hoje: pools apontando para a
// malha WireGuard, um vhost com location regex para websocket, outro com
// match exato, e um vhost gerido pelo listener ao lado dos escritos à mão.
const inventoryDump = `# configuration file /etc/nginx/nginx.conf:
http {
    upstream backend_pool {
        server 10.10.0.2:10000;
        keepalive 16;
    }
    upstream public_api_pool {
        server 10.10.0.2:10100 max_fails=3;
    }

    server {
        listen 80;
        server_name backend.workspacefy.com;
        include snippets/error-pages.conf;

        location ~ ^/(ws/|workspace/[^/]+/__collab__) {
            proxy_pass http://backend_pool;
            proxy_set_header Upgrade $http_upgrade;
        }

        location / {
            proxy_pass http://backend_pool;
        }
    }

    server {
        listen 80;
        server_name workspacefy.com;

        location = /404.html {
            root /docker;
        }

        location / {
            proxy_pass https://www.workspacefy.com/;
        }
    }
}

# configuration file /etc/nginx/conf.d/app-a.conf:
# managed-by: deployer-lb-server app=app-a revision=7
upstream app_a_pool {
    server 10.10.0.5:8080;
}
server {
    listen 80;
    server_name a.workspacefy.com;
    location / {
        proxy_pass http://app_a_pool;
    }
}
`

func build(t *testing.T) Inventory {
	t.Helper()
	inv := BuildInventory(inventoryDump)
	inv.ResolvePools()
	return inv
}

func TestInventoryFindsEveryPool(t *testing.T) {
	inv := build(t)
	if len(inv.Pools) != 3 {
		t.Fatalf("esperava 3 pools, veio %d: %+v", len(inv.Pools), inv.Pools)
	}
	byName := map[string]Pool{}
	for _, p := range inv.Pools {
		byName[p.Name] = p
	}
	be, ok := byName["backend_pool"]
	if !ok || len(be.Servers) != 1 {
		t.Fatalf("backend_pool mal lido: %+v", be)
	}
	if be.Servers[0].Host != "10.10.0.2" || be.Servers[0].Port != 10000 {
		t.Errorf("backend errado: %+v", be.Servers[0])
	}
	// O que vem depois do endereço é preservado cru em vez de modelado: a
	// tela mostra `max_fails=3` sem esta struct ter de conhecer a diretiva.
	if byName["public_api_pool"].Servers[0].Raw != "max_fails=3" {
		t.Errorf("raw do backend perdido: %+v", byName["public_api_pool"].Servers[0])
	}
}

func TestInventorySeparatesManagedFromHandWritten(t *testing.T) {
	// O ponto da tela: o que o painel escreveu e o que estava lá antes não
	// podem aparecer iguais.
	inv := build(t)
	var managed, legacy int
	for _, v := range inv.Vhosts {
		if v.Managed {
			managed++
			if v.App != "app-a" {
				t.Errorf("app não extraído do header: %+v", v)
			}
		} else {
			legacy++
		}
	}
	if managed != 1 || legacy != 2 {
		t.Fatalf("esperava 1 gerido e 2 legados, veio %d/%d", managed, legacy)
	}
}

func TestInventoryKeepsLocationMatchersVerbatim(t *testing.T) {
	// Operador traduzido errado é bug de roteamento. A tela mostra o que o
	// nginx entende.
	inv := build(t)
	var backend Vhost
	for _, v := range inv.Vhosts {
		if len(v.ServerNames) > 0 && v.ServerNames[0] == "backend.workspacefy.com" {
			backend = v
		}
	}
	if len(backend.Locations) != 2 {
		t.Fatalf("esperava 2 locations, veio %d: %+v", len(backend.Locations), backend.Locations)
	}
	ws := backend.Locations[0]
	if ws.Matcher != "~" {
		t.Errorf("matcher regex perdido: %q", ws.Matcher)
	}
	if !ws.Websocket {
		t.Errorf("header Upgrade não detectado: %+v", ws)
	}
	if ws.Pool != "backend_pool" {
		t.Errorf("location não ligada ao pool: %q", ws.Pool)
	}
}

func TestInventoryHandlesExactMatchAndRoot(t *testing.T) {
	inv := build(t)
	var root Vhost
	for _, v := range inv.Vhosts {
		if len(v.ServerNames) > 0 && v.ServerNames[0] == "workspacefy.com" {
			root = v
		}
	}
	if len(root.Locations) != 2 {
		t.Fatalf("esperava 2 locations: %+v", root.Locations)
	}
	if root.Locations[0].Matcher != "=" || root.Locations[0].Root != "/docker" {
		t.Errorf("match exato com root mal lido: %+v", root.Locations[0])
	}
}

func TestInventoryDoesNotInventPoolsForExternalDestinations(t *testing.T) {
	// `proxy_pass https://www.workspacefy.com/` é um destino, não um pool.
	// Mostrá-lo como pool inventaria um backend que não existe aqui.
	inv := build(t)
	for _, v := range inv.Vhosts {
		for _, l := range v.Locations {
			if l.ProxyPass == "https://www.workspacefy.com/" && l.Pool != "" {
				t.Fatalf("destino externo virou pool: %+v", l)
			}
		}
	}
}

func TestInventoryNeverPanicsOnJunk(t *testing.T) {
	// Degrada para vazio; quem chama ainda tem o texto cru para mostrar.
	for _, junk := range []string{"", "lixo", "server {", "upstream {{{", "}"} {
		inv := BuildInventory(junk)
		inv.ResolvePools()
		_ = inv
	}
}
