package render

// Exercises the actual shipped template (conf/nginx-app.conf.tmpl, owned by
// plan step B3) through the existing Render/RenderString machinery. This
// file only consumes render's exported API — it does not change any
// core render logic (owned by the B1 agent working in parallel).

import (
	"strings"
	"testing"
)

const templateRelPath = "../../conf/nginx-app.conf.tmpl"

func TestNginxAppTemplate_MatchesPlanExampleBlock(t *testing.T) {
	p := Payload{
		SchemaVersion:  SupportedSchemaVersion,
		Revision:       42,
		IdempotencyKey: "app-a:run-1",
		PipelineRef:    "app-a",
		Repo:           "owner/app-a",
		Domains:        []string{"app-a.workspacefy.com"},
		Exposure:       "external",
		Upstreams:      []Upstream{{IP: "10.10.0.2", Port: 10200}},
		Websocket:      false,
		Cache:          CacheConfig{Enabled: false},
		Timeouts:       Timeouts{Read: 120, Send: 120, Connect: 10},
	}

	out, err := Render(templateRelPath, p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	wantFirst := "# managed-by: deployer-lb-server app=app-a revision=42"
	if got := firstLine(out); got != wantFirst {
		t.Fatalf("first line = %q, want %q", got, wantFirst)
	}

	mustContain := []string{
		"## app-a.workspacefy.com",
		"upstream app_a_pool {",
		"server 10.10.0.2:10200;",
		"keepalive 16;",
		"keepalive_timeout 60s;",
		"listen 80;",
		"server_name app-a.workspacefy.com;",
		"underscores_in_headers on;",
		// Sem isto o nginx aplica o default de 1m e responde 413 nos chunks
		// de 3MB do upload chunked do backend.
		"client_max_body_size 100m;",
		"include snippets/error-pages.conf;",
		"include snippets/cloudflare-real-ip.conf;",
		"proxy_pass http://app_a_pool;",
		"proxy_http_version 1.1;",
		`proxy_set_header Connection "";`,
		"proxy_set_header Host $host;",
		"proxy_set_header X-Real-IP $remote_addr;",
		"proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;",
		"proxy_set_header X-Forwarded-Proto $scheme;",
		"proxy_pass_request_headers on;",
		"proxy_connect_timeout 10s;",
		"proxy_read_timeout 120s;",
		"proxy_send_timeout 120s;",
		"proxy_next_upstream error timeout http_502 http_503 http_504;",
		"proxy_next_upstream_tries 2;",
	}
	for _, want := range mustContain {
		if !strings.Contains(out, want) {
			t.Errorf("rendered output missing %q\n--- full output ---\n%s", want, out)
		}
	}

	mustNotContain := []string{
		"Upgrade $http_upgrade",
		"proxy_cache ",
		"proxy_cache_path",
	}
	for _, unwanted := range mustNotContain {
		if strings.Contains(out, unwanted) {
			t.Errorf("rendered output unexpectedly contains %q (websocket/cache both disabled)\n%s", unwanted, out)
		}
	}
}

func TestNginxAppTemplate_WebsocketVariant(t *testing.T) {
	p := Payload{
		SchemaVersion:  SupportedSchemaVersion,
		Revision:       1,
		IdempotencyKey: "n8n:run-1",
		PipelineRef:    "n8n",
		Repo:           "owner/n8n",
		Domains:        []string{"n8n.workspacefy.com"},
		Exposure:       "external",
		Upstreams:      []Upstream{{IP: "10.10.0.3", Port: 5678}},
		Websocket:      true,
		Cache:          CacheConfig{Enabled: false},
		Timeouts:       Timeouts{Read: 120, Send: 120, Connect: 10},
	}

	out, err := Render(templateRelPath, p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	for _, want := range []string{
		"proxy_set_header Upgrade $http_upgrade;",
		`proxy_set_header Connection "upgrade";`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("websocket variant missing %q\n%s", want, out)
		}
	}
}

func TestNginxAppTemplate_CacheVariant(t *testing.T) {
	p := Payload{
		SchemaVersion:  SupportedSchemaVersion,
		Revision:       1,
		IdempotencyKey: "www:run-1",
		PipelineRef:    "www",
		Repo:           "owner/www",
		Domains:        []string{"www.workspacefy.com"},
		Exposure:       "external",
		Upstreams:      []Upstream{{IP: "10.10.0.4", Port: 8080}},
		Websocket:      false,
		Cache:          CacheConfig{Enabled: true},
		Timeouts:       Timeouts{Read: 60, Send: 60, Connect: 5},
	}

	out, err := Render(templateRelPath, p)
	if err != nil {
		t.Fatalf("Render() error = %v", err)
	}

	for _, want := range []string{
		"proxy_cache_path /var/cache/nginx/www_pool levels=1:2 keys_zone=www_pool_cache:10m",
		"proxy_cache www_pool_cache;",
		"add_header X-Cache-Status $upstream_cache_status;",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("cache variant missing %q\n%s", want, out)
		}
	}
}
