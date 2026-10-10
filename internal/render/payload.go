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

// SupportedSchemaVersion is the oldest contract this listener still accepts,
// and the version a payload without `locations` is sent as.
//
// Kept as a constant because every existing caller and test names it, and
// because a payload that declares no locations IS a v1 payload — nothing
// about it changed.
const SupportedSchemaVersion = 1

// CurrentSchemaVersion is what a sender uses when it needs a feature this
// listener gained after v1 (today: `locations`).
const CurrentSchemaVersion = 2

// SupportedSchemaVersions is a SET, deliberately, and not a bumped constant.
//
// The hazard being designed away from is not the bump — it is SILENCE. If
// this stayed at 1 and we relied on encoding/json ignoring unknown fields, an
// old listener receiving `locations` would answer 200 {"status":"reloaded"}
// having discarded them: the central would record a successful apply while
// the vhost on disk routed nothing it was told to route. With the set, that
// same payload gets a loud 400 instead.
//
// A 400 is still bad — lb_sync_worker marks it FAILED with no retry — so the
// sender is expected to check GET /v1/health's `capabilities` BEFORE sending
// a payload that needs v2, and to hold it rather than burn it. The 400 is the
// backstop for when that check is skipped, not the mechanism.
//
// Note what is NOT done here: json.Decoder.DisallowUnknownFields. Turning it
// on would make every listener in the fleet reject every future field
// addition, forever, which is the opposite of what tolerant decoding is for.
var SupportedSchemaVersions = map[int]bool{
	SupportedSchemaVersion: true,
	CurrentSchemaVersion:   true,
}

// Capabilities is what GET /v1/health advertises, so a sender can find out
// what this listener understands without having to try and fail.
//
// Plain feature strings, never a version number the caller has to map: they
// leak nothing (the endpoint is unauthenticated) and they stay meaningful
// when versions stop being linear.
func Capabilities() []string {
	return []string{"locations.v1"}
}

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
	// Locations vazio renderiza o `location /` de sempre, byte a byte. Ver
	// locations.go — inclusive por que a validação dele é tão estrita.
	Locations []LocationSpec `json:"locations,omitempty"`
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

	if !SupportedSchemaVersions[p.SchemaVersion] {
		errs = append(errs, fmt.Sprintf("unsupported schema_version: %d", p.SchemaVersion))
	}
	// `locations` é a única coisa que exige v2. Aceitá-lo num payload que se
	// declara v1 deixaria o sender achar que um listener antigo o entenderia —
	// e é justamente esse engano que a versão existe para impedir.
	if len(p.Locations) > 0 && p.SchemaVersion < CurrentSchemaVersion {
		errs = append(errs, fmt.Sprintf(
			"locations require schema_version %d, got %d",
			CurrentSchemaVersion, p.SchemaVersion))
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
	// Um vhost cujas rotas vão TODAS para fora não tem backend deste sistema,
	// e exigir um seria pedir um valor inventado. Sem locations declaradas a
	// rota implícita é o `location /` para o pool, então a regra antiga
	// continua valendo inteira. Quem cobra o caso misto é validateLocations.
	if len(p.Upstreams) == 0 && len(p.Locations) == 0 {
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
	errs = append(errs, validateLocations(p)...)
	return errs
}

// ConfFileName returns the safe, validated on-disk filename (without
// directory) for this payload's app. Caller must have already run
// ValidatePayload successfully.
func (p Payload) ConfFileName() string {
	return p.PipelineRef + ".conf"
}
