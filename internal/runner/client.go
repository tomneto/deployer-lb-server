package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tomneto/deployer-lb-server/internal/hmacauth"
)

// Client speaks the three runner endpoints on the panel.
//
// Two http.Clients, not one, and that is the point of this type: the claim is a
// long-poll and every other call is a short request. Sharing a single timeout
// would mean either a claim that hangs up mid-poll or a log POST that takes
// half a minute to notice the panel is gone.
type Client struct {
	// BaseURL is the panel root, e.g. https://vault.local:6069. A path on it is
	// preserved, so a panel mounted under a prefix works.
	BaseURL string
	// Ref is the target ref registered in the panel; it travels as X-Agent-Id.
	Ref    string
	Secret string

	// ClaimHTTP must have a timeout LARGER than the server's long-poll window,
	// or the runner hangs up at exactly the moment work would have arrived.
	// NewClient enforces that; set it by hand only if you mean it.
	ClaimHTTP *http.Client
	// ShortHTTP is for log and result: fast failure, so a dead panel does not
	// stall a finished command.
	ShortHTTP *http.Client

	// WaitSeconds is what the runner asks the server to hold a claim for.
	WaitSeconds int

	// Now is injectable for tests; nil means time.Now.
	Now func() time.Time

	// Identity, reported on every claim.
	Hostname string
	Version  string
	OS       string
	Arch     string
}

// ClientConfig is the plain-data form of a Client, so the binary's flags map
// onto it without the binary having to reason about the two HTTP clients.
type ClientConfig struct {
	BaseURL      string
	Ref          string
	Secret       string
	Wait         time.Duration
	ClaimMargin  time.Duration
	ShortTimeout time.Duration
	Hostname     string
	Version      string
	OS           string
	Arch         string
	Transport    http.RoundTripper
}

// NewClient builds a Client with the timeout invariant already satisfied: the
// claim client's deadline is the server's hold window PLUS a margin. Getting
// this backwards is the subtle failure this constructor exists to prevent —
// everything works, just never on a busy panel, because the only claims that
// ever return are the empty ones.
func NewClient(cfg ClientConfig) *Client {
	wait := cfg.Wait
	if wait <= 0 {
		wait = 25 * time.Second
	}
	margin := cfg.ClaimMargin
	if margin <= 0 {
		margin = 20 * time.Second
	}
	short := cfg.ShortTimeout
	if short <= 0 {
		short = 15 * time.Second
	}
	// wait_seconds travels as a whole number, so a sub-second window would
	// round down to 0 — which reads on the server as "do not hold this at all"
	// and silently turns the long poll into a busy loop. Round UP: asking the
	// server to hold slightly longer than the client intended is harmless
	// (the client deadline is wait+margin either way); asking for zero is not.
	waitSeconds := int((wait + time.Second - 1) / time.Second)

	return &Client{
		BaseURL:     cfg.BaseURL,
		Ref:         cfg.Ref,
		Secret:      cfg.Secret,
		ClaimHTTP:   &http.Client{Timeout: wait + margin, Transport: cfg.Transport},
		ShortHTTP:   &http.Client{Timeout: short, Transport: cfg.Transport},
		WaitSeconds: waitSeconds,
		Hostname:    cfg.Hostname,
		Version:     cfg.Version,
		OS:          cfg.OS,
		Arch:        cfg.Arch,
	}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

// URLFor joins the panel base with an endpoint path, preserving any prefix the
// base already carries.
func (c *Client) URLFor(path string) (string, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", fmt.Errorf("invalid panel url %q: %w", c.BaseURL, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("invalid panel url %q: want scheme://host", c.BaseURL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + strings.TrimPrefix(path, "/")
	return u.String(), nil
}

// post signs and sends one request. It returns the status and the (bounded)
// body, and an error only for transport failures — status handling is the
// caller's, because 204 means something different on claim than anywhere else.
func (c *Client) post(ctx context.Context, httpc *http.Client, path string, payload any) (int, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, fmt.Errorf("marshal: %w", err)
	}
	endpoint, err := c.URLFor(path)
	if err != nil {
		return 0, nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// The very same scheme the agent uses, down to the header names.
	hmacauth.Apply(req, c.Ref, c.Secret, body, c.now())

	resp, err := httpc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("post %s: %w", path, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, data, nil
}

// Claim long-polls for work.
//
// Three outcomes, and the caller must tell them apart: (cmd, nil) there is work;
// (nil, nil) the poll came back empty — 204, the normal idle case; (nil, err)
// the panel could not be reached or answered badly. Only the third is a
// failure, and even then the loop keeps going.
func (c *Client) Claim(ctx context.Context) (*Command, error) {
	req := ClaimRequest{
		Ref:         c.Ref,
		Hostname:    c.Hostname,
		Version:     c.Version,
		OS:          c.OS,
		Arch:        c.Arch,
		WaitSeconds: c.WaitSeconds,
	}
	status, body, err := c.post(ctx, c.ClaimHTTP, "/deploy/runner/claim", req)
	if err != nil {
		return nil, err
	}
	switch {
	case status == http.StatusNoContent:
		return nil, nil
	case status < 200 || status >= 300:
		return nil, fmt.Errorf("claim returned status %d: %s", status, snippet(body))
	}
	// A 200 with an empty body is the same thing a 204 is; treating it as an
	// error would turn a harmless server quirk into a backoff storm.
	if len(bytes.TrimSpace(body)) == 0 || string(bytes.TrimSpace(body)) == "null" {
		return nil, nil
	}
	var cmd Command
	if err := json.Unmarshal(body, &cmd); err != nil {
		return nil, fmt.Errorf("claim body: %w", err)
	}
	if strings.TrimSpace(cmd.ID) == "" {
		return nil, fmt.Errorf("claim body: command without an id")
	}
	return &cmd, nil
}

// SendLog ships one incremental batch. Best-effort by contract.
func (c *Client) SendLog(ctx context.Context, batch LogBatch) error {
	status, body, err := c.post(ctx, c.ShortHTTP, "/deploy/runner/commands/"+url.PathEscape(batch.CommandID)+"/log", batch)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("log returned status %d: %s", status, snippet(body))
	}
	return nil
}

// SendResult closes a command out. Unlike a log batch this one is retried by
// the loop: losing it means the panel waits for a lease to expire instead of
// learning the command already finished.
func (c *Client) SendResult(ctx context.Context, res Result) error {
	status, body, err := c.post(ctx, c.ShortHTTP, "/deploy/runner/commands/"+url.PathEscape(res.CommandID)+"/result", res)
	if err != nil {
		return err
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("result returned status %d: %s", status, snippet(body))
	}
	return nil
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		return s[:200] + "..."
	}
	return s
}
