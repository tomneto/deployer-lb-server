//go:build lb

// Command deployer-lb-server is the "lb" mode of deployer-lb-server: it runs
// on load balancers (hosts with nginx), provisions the host (out of scope
// here — see internal/provision, owned by B4) and serves the apply listener
// contract from pipe-improves.md §2.3: POST /v1/apply, DELETE
// /v1/app/{ref}, GET /v1/status, GET /v1/health.
//
// Build tag `lb` keeps this binary's dependency graph separate from the
// `agent` mode (cmd/agent): building deployer-lb-server never pulls in the
// gopsutil/docker collector code, and vice versa (D5).
package main

import (
	"flag"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/lbserver"
	"github.com/tomneto/deployer-lb-server/internal/nginx"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	var (
		addr         = flag.String("addr", envOr("LB_LISTEN_ADDR", "127.0.0.1:8443"), "listen address (bind to 127.0.0.1 or the wg0 interface, never public — §2.3)")
		token        = flag.String("token", envOr("LB_TOKEN", ""), "shared bearer token")
		secret       = flag.String("secret", envOr("LB_SHARED_SECRET", ""), "HMAC shared secret")
		confDir      = flag.String("conf-dir", envOr("NGINX_CONF_DIR", "/etc/nginx/conf.d"), "nginx conf.d directory this listener manages")
		templatePath = flag.String("template", envOr("NGINX_TEMPLATE_PATH", "/etc/nginx/lb-templates/nginx-app.conf.tmpl"), "path to the nginx-app.conf.tmpl template")
		maxBodyBytes = flag.Int64("max-body-bytes", 64*1024, "max accepted request body size in bytes")
		tsWindow     = flag.Duration("ts-window", 30*time.Second, "allowed clock skew for X-Payload-Ts")
		nonceTTL     = flag.Duration("nonce-ttl", 5*time.Minute, "how long nonces are remembered for replay protection")
	)
	flag.Parse()

	if *token == "" || *secret == "" {
		log.Fatal("deployer-lb-server: --token and --secret (or LB_TOKEN / LB_SHARED_SECRET) are required")
	}

	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)

	srv := lbserver.New(lbserver.Config{
		Token:        *token,
		Secret:       *secret,
		ConfDir:      *confDir,
		TemplatePath: *templatePath,
		MaxBodyBytes: *maxBodyBytes,
		TSWindow:     *tsWindow,
		NonceTTL:     *nonceTTL,
		Runner:       nginx.RealRunner{},
		Logger:       logger,
	})

	mux := http.NewServeMux()
	srv.Routes(mux)

	logger.Printf("deployer-lb-server listening on %s (conf-dir=%s template=%s)", *addr, *confDir, *templatePath)
	if err := http.ListenAndServe(*addr, mux); err != nil {
		log.Fatalf("deployer-lb-server: %v", err)
	}
}
