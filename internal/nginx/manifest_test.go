package nginx

import "testing"

const managedConfFixture = `# managed-by: deployer-lb-server app=app-a revision=12
## app.example.com
upstream app_a_pool {
    server 10.0.0.2:10010;
    server 10.0.0.3:10010;
    keepalive 16;
    keepalive_timeout 60s;
}

server {
    listen 80;
    server_name app.example.com www.app.example.com;
    location / {
        proxy_pass http://app_a_pool;
    }
}
`

func TestParseManagedConfExtractsAppRevisionDomainsUpstreams(t *testing.T) {
	mc, ok := ParseManagedConf(managedConfFixture)
	if !ok {
		t.Fatal("expected fixture to parse as managed")
	}
	if mc.App != "app-a" {
		t.Fatalf("expected app app-a, got %q", mc.App)
	}
	if mc.Revision != 12 {
		t.Fatalf("expected revision 12, got %d", mc.Revision)
	}
	wantDomains := []string{"app.example.com", "www.app.example.com"}
	if len(mc.Domains) != len(wantDomains) {
		t.Fatalf("expected domains %v, got %v", wantDomains, mc.Domains)
	}
	for i, d := range wantDomains {
		if mc.Domains[i] != d {
			t.Fatalf("expected domains %v, got %v", wantDomains, mc.Domains)
		}
	}
	if len(mc.Upstreams) != 2 {
		t.Fatalf("expected 2 upstreams, got %v", mc.Upstreams)
	}
	if mc.Upstreams[0].Host != "10.0.0.2" || mc.Upstreams[0].Port != 10010 {
		t.Fatalf("unexpected first upstream: %+v", mc.Upstreams[0])
	}
	if mc.Upstreams[1].Host != "10.0.0.3" || mc.Upstreams[1].Port != 10010 {
		t.Fatalf("unexpected second upstream: %+v", mc.Upstreams[1])
	}
}

func TestParseManagedConfRejectsUnmanagedFile(t *testing.T) {
	if _, ok := ParseManagedConf("server {\n    listen 80;\n    server_name hand.example.com;\n}\n"); ok {
		t.Fatal("expected hand-written conf to be rejected")
	}
}

func TestParseManagedConfRejectsCatchAllWithoutApp(t *testing.T) {
	catchAll := `# managed-by: deployer-lb-server (default_server catch-all — D19)
server {
    listen 80 default_server;
    server_name _;
    return 444;
}
`
	if _, ok := ParseManagedConf(catchAll); ok {
		t.Fatal("expected catch-all conf (no app=) to be rejected")
	}
}

func TestParseManagedConfHeaderMustBeFirstLine(t *testing.T) {
	content := "server { listen 80; }\n# managed-by: deployer-lb-server app=x revision=1\n"
	if _, ok := ParseManagedConf(content); ok {
		t.Fatal("expected conf whose header is not the first line to be rejected")
	}
}
