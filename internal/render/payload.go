// Package render defines the immutable apply payload contract (pipe-improves.md
// §2.2) sent by the backoffice engine to the `lb` listener, its input
// validation (strict regex, applied before any disk write — §2.3 "Validação
// de entrada"), and the text/template rendering of the nginx vhost fragment.
package render

import (
	"fmt"
	"net"
	"regexp"
)

// SupportedSchemaVersion is the only schema_version this listener accepts.
// Bumping the payload contract requires bumping this constant in lockstep
// with the Python-side sender (§2.3: "o listener rejeita com 400 versões que
// não entende").
const SupportedSchemaVersion = 1

// Upstream is one backend pool member. IP is always the target's
// wireguard_ip (D3) and Port is always the pipeline's *stable* port — never
// blue_port/green_port (§2.2 "Invariante de porta").
type Upstream struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Timeouts are proxy_*_timeout values, in seconds.
type Timeouts struct {
	Read    int `json:"read"`
	Send    int `json:"send"`
	Connect int `json:"connect"`
}

// CacheConfig controls proxy_cache injection for static sites.
type CacheConfig struct {
	Enabled bool `json:"enabled"`
}

// RateLimitConfig caps how fast one client address can hit this vhost.
//
// Opt-in, and deliberately so. This template serves live product traffic, and
// a limit sized wrong does not degrade — it returns 429 to real users, which
// is worse than the burst it was meant to absorb. Turning it on is a decision
// per pipeline, made by someone who knows that app's request shape.
//
// The address counted is the one `snippets/cloudflare-real-ip.conf` restores
// (CF-Connecting-IP), not the edge's — without that every request would look
// like it came from a handful of Cloudflare addresses and the limit would
// either never trigger or block everyone at once.
type RateLimitConfig struct {
	Enabled bool `json:"enabled"`
	// Sustained requests per second per address. 0 falls back to the default.
	Rate int `json:"rate"`
	// How many requests may arrive above the rate before any are refused. A
	// single page load pulls dozens of assets at once, so a burst well above
	// the rate is what separates "a browser opening a page" from "a flood".
	Burst int `json:"burst"`
}

// Defaults chosen to be invisible to a human browsing and still cut a flood.
const (
	DefaultRateLimitRate  = 30
	DefaultRateLimitBurst = 60
)

// Resolved returns the config with defaults applied, so the template never
// renders `rate=0r/s` — which nginx accepts and which refuses everything.
func (r RateLimitConfig) Resolved() RateLimitConfig {
	if r.Rate <= 0 {
		r.Rate = DefaultRateLimitRate
	}
	if r.Burst <= 0 {
		r.Burst = DefaultRateLimitBurst
	}
	return r
}

// Payload is the exact JSON body of POST /v1/apply, per pipe-improves.md §2.2.
type Payload struct {
	SchemaVersion  int             `json:"schema_version"`
	Revision       int64           `json:"revision"`
	IdempotencyKey string          `json:"idempotency_key"`
	PipelineRef    string          `json:"pipeline_ref"`
	Repo           string          `json:"repo"`
	Domains        []string        `json:"domains"`
	Exposure       string          `json:"exposure"`
	Upstreams      []Upstream      `json:"upstreams"`
	Websocket      bool            `json:"websocket"`
	Cache          CacheConfig     `json:"cache"`
	RateLimit      RateLimitConfig `json:"rate_limit"`
	Timeouts       Timeouts        `json:"timeouts"`
	CorpOrigin     bool            `json:"corp_origin"`
}

// Regexes are intentionally strict: the pipeline_ref is the *only* input
// used to derive the on-disk filename (conf.d/<pipeline_ref>.conf), which is
// what actually needs path-traversal-proof validation (see decision note in
// ValidatePayload). `repo` and `domains[]` get their own strict validation
// too, per §2.3, even though they aren't used for filesystem paths.
var (
	pipelineRefRe = regexp.MustCompile(`^[a-z0-9_-]{1,100}$`)
	repoRe        = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
	domainRe      = regexp.MustCompile(`^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$`)
	idempotencyRe = regexp.MustCompile(`^[A-Za-z0-9:_.-]{1,200}$`)
)

// ValidatePayload returns a list of human-readable validation errors, or nil
// if the payload is well-formed. It performs no I/O and must be called
// before any disk write happens (§2.3: "antes de qualquer escrita").
//
// Decision (ambiguity in the plan): §2.2's example filename pattern is
// `conf.d/<repo>.conf`, but `repo` is documented as `"owner/app-a"` (contains
// a `/`) — using it verbatim as a filename would itself be a path-traversal
// vector, which is exactly what §2.3 warns against. This implementation
// derives the on-disk filename from `pipeline_ref` (regex `[a-z0-9_-]`, no
// `.`, no `/`) instead, and validates `repo` separately as free-form
// "owner/name" metadata used only for template comments/logs, never for
// paths.
func ValidatePayload(p *Payload) []string {
	var errs []string

	if p.SchemaVersion != SupportedSchemaVersion {
		errs = append(errs, fmt.Sprintf("unsupported schema_version: %d", p.SchemaVersion))
	}
	if p.Revision <= 0 {
		errs = append(errs, "revision must be a positive integer")
	}
	if p.IdempotencyKey == "" || !idempotencyRe.MatchString(p.IdempotencyKey) {
		errs = append(errs, "invalid idempotency_key")
	}
	if !pipelineRefRe.MatchString(p.PipelineRef) {
		errs = append(errs, "invalid pipeline_ref: must match ^[a-z0-9_-]{1,100}$")
	}
	if !repoRe.MatchString(p.Repo) {
		errs = append(errs, "invalid repo: must match ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
	}
	if len(p.Domains) == 0 {
		errs = append(errs, "domains must not be empty")
	}
	for _, d := range p.Domains {
		if !domainRe.MatchString(d) {
			errs = append(errs, fmt.Sprintf("invalid domain: %q", d))
		}
	}
	if p.Exposure != "external" && p.Exposure != "internal" {
		errs = append(errs, `exposure must be "external" or "internal"`)
	}
	if len(p.Upstreams) == 0 {
		errs = append(errs, "upstreams must not be empty")
	}
	for _, u := range p.Upstreams {
		if net.ParseIP(u.IP) == nil {
			errs = append(errs, fmt.Sprintf("invalid upstream ip: %q", u.IP))
		}
		if u.Port < 1 || u.Port > 65535 {
			errs = append(errs, fmt.Sprintf("invalid upstream port: %d", u.Port))
		}
	}
	return errs
}

// ConfFileName returns the safe, validated on-disk filename (without
// directory) for this payload's app. Caller must have already run
// ValidatePayload successfully.
func (p Payload) ConfFileName() string {
	return p.PipelineRef + ".conf"
}
