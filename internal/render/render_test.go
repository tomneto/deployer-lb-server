package render

import "testing"

func validPayload() Payload {
	return Payload{
		SchemaVersion:  SupportedSchemaVersion,
		Revision:       42,
		IdempotencyKey: "app-a:run-1",
		PipelineRef:    "app-a",
		Repo:           "owner/app-a",
		Domains:        []string{"app-a.workspacefy.com"},
		Exposure:       "external",
		Upstreams:      []Upstream{{IP: "10.10.0.2", Port: 10200}},
		Websocket:      true,
		Cache:          CacheConfig{Enabled: false},
		Timeouts:       Timeouts{Read: 120, Send: 120, Connect: 10},
	}
}

func TestValidatePayloadValid(t *testing.T) {
	p := validPayload()
	if errs := ValidatePayload(&p); errs != nil {
		t.Fatalf("expected no errors, got %v", errs)
	}
}

func TestValidatePayloadRejectsBadSchemaVersion(t *testing.T) {
	p := validPayload()
	p.SchemaVersion = 99
	errs := ValidatePayload(&p)
	if len(errs) == 0 {
		t.Fatal("expected schema_version error")
	}
}

func TestValidatePayloadRejectsPathTraversalInPipelineRef(t *testing.T) {
	cases := []string{
		"../../etc/passwd",
		"app/../secret",
		"app;rm -rf",
		"App-A",   // uppercase not allowed
		"",        // empty
		"a b",     // space
		"app.conf/../x",
	}
	for _, ref := range cases {
		p := validPayload()
		p.PipelineRef = ref
		errs := ValidatePayload(&p)
		if len(errs) == 0 {
			t.Fatalf("expected pipeline_ref %q to be rejected", ref)
		}
	}
}

func TestValidatePayloadRejectsBadDomain(t *testing.T) {
	p := validPayload()
	p.Domains = []string{"not a domain", "-bad.com", "localhost"}
	errs := ValidatePayload(&p)
	if len(errs) == 0 {
		t.Fatal("expected invalid domains to be rejected")
	}
}

func TestValidatePayloadRejectsEmptyDomains(t *testing.T) {
	p := validPayload()
	p.Domains = nil
	errs := ValidatePayload(&p)
	if len(errs) == 0 {
		t.Fatal("expected empty domains to be rejected")
	}
}

func TestValidatePayloadRejectsBadUpstream(t *testing.T) {
	p := validPayload()
	p.Upstreams = []Upstream{{IP: "not-an-ip", Port: 99999}}
	errs := ValidatePayload(&p)
	if len(errs) < 2 {
		t.Fatalf("expected both ip and port errors, got %v", errs)
	}
}

func TestValidatePayloadRejectsBadExposure(t *testing.T) {
	p := validPayload()
	p.Exposure = "public"
	errs := ValidatePayload(&p)
	if len(errs) == 0 {
		t.Fatal("expected invalid exposure to be rejected")
	}
}

func TestValidatePayloadRejectsBadIdempotencyKey(t *testing.T) {
	p := validPayload()
	p.IdempotencyKey = "has spaces/and?illegal"
	errs := ValidatePayload(&p)
	if len(errs) == 0 {
		t.Fatal("expected invalid idempotency_key to be rejected")
	}
}

func TestConfFileNameDerivesFromPipelineRefOnly(t *testing.T) {
	p := validPayload()
	p.PipelineRef = "app-a"
	p.Repo = "owner/../../etc" // repo is metadata only; must never affect the path
	if got, want := p.ConfFileName(), "app-a.conf"; got != want {
		t.Fatalf("ConfFileName() = %q, want %q", got, want)
	}
}

const testTemplate = `# managed-by: deployer-lb-server app={{.PipelineRef}} revision={{.Revision}}
upstream {{ upstreamName .PipelineRef }} {
{{- range .Upstreams}}
    server {{.IP}}:{{.Port}};
{{- end}}
}
server {
    listen 80;
    server_name {{ join .Domains " " }};
    location / {
        proxy_pass http://{{ upstreamName .PipelineRef }};
    }
}
`

func TestRenderStringProducesManagedHeaderFirstLine(t *testing.T) {
	p := validPayload()
	out, err := RenderString(testTemplate, p)
	if err != nil {
		t.Fatalf("render error: %v", err)
	}
	wantFirst := "# managed-by: deployer-lb-server app=app-a revision=42"
	if got := firstLine(out); got != wantFirst {
		t.Fatalf("first line = %q, want %q", got, wantFirst)
	}
}

func firstLine(s string) string {
	for i, c := range s {
		if c == '\n' {
			return s[:i]
		}
	}
	return s
}

func TestUpstreamNameSanitizesRef(t *testing.T) {
	if got, want := UpstreamName("app-a"), "app_a_pool"; got != want {
		t.Fatalf("UpstreamName() = %q, want %q", got, want)
	}
}
