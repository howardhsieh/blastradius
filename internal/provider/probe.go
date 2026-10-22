package provider

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// ProbeConfig is the user's opt-in for network probes. The scanner builds
// it from the --probe flags; tests set Transport to stand in for the real
// APIs. There is no flag that can change where a probe connects: the hosts
// come from each prober's ProbeHosts list, --probe-host (GitHub Enterprise)
// and --probe-cluster (kubeconfig cluster names).
type ProbeConfig struct {
	// Hosts are GitHub Enterprise hosts the user allowed with --probe-host.
	Hosts []string
	// Clusters are kubeconfig cluster names the user allowed with --probe-cluster.
	Clusters []string
	// Timeout bounds one probe (one credential, one service). Zero means 10s.
	Timeout time.Duration
	// UserAgent is sent with every request ("blastradius/1.2.3").
	UserAgent string
	// Transport, when set, wraps the transport every probe uses. It is for
	// tests, which reroute requests to httptest servers; the allow-list
	// check runs before it, so a rerouted request still had to be for an
	// allowed host.
	Transport func(next http.RoundTripper) http.RoundTripper
}

// DefaultProbeTimeout bounds a single probe.
const DefaultProbeTimeout = 10 * time.Second

// maxProbeBody caps how much of an API response is read.
const maxProbeBody = 1 << 20

func (c *ProbeConfig) timeout() time.Duration {
	if c == nil || c.Timeout <= 0 {
		return DefaultProbeTimeout
	}
	return c.Timeout
}

func (c *ProbeConfig) allowsHost(h string) bool {
	if c == nil {
		return false
	}
	for _, x := range c.Hosts {
		if strings.EqualFold(strings.TrimSpace(x), h) {
			return true
		}
	}
	return false
}

func (c *ProbeConfig) allowsCluster(name string) bool {
	if c == nil {
		return false
	}
	for _, x := range c.Clusters {
		if x == name {
			return true
		}
	}
	return false
}

// ErrOffline is returned when Probe is called without a ProbeConfig.
var ErrOffline = errors.New("probing is off (no --probe)")

// ErrNotProbed means the credential is of a kind this prober cannot check.
var ErrNotProbed = errors.New("not probed")

// errHostNotAllowed is returned by the allow-list transport. It is a
// programming error if it ever fires in production: it means a prober
// built a URL for a host it did not declare.
type errHostNotAllowed struct{ host string }

func (e errHostNotAllowed) Error() string {
	return fmt.Sprintf("refused to contact %s: not in the probe allow-list", e.host)
}

// allowOnly is an http.RoundTripper that refuses every request whose host
// is not in its list. It wraps the real transport, so no code path in a
// prober can reach another host by mistake.
type allowOnly struct {
	hosts map[string]bool
	next  http.RoundTripper
}

func (a allowOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	h := strings.ToLower(req.URL.Hostname())
	if req.URL.Scheme != "https" || !a.hosts[h] {
		return nil, errHostNotAllowed{host: req.URL.Host}
	}
	return a.next.RoundTrip(req)
}

// client builds the HTTP client for one probe: HTTPS only, hosts restricted
// to allowed, TLS verification on, proxy from the environment, no redirects
// (a redirect could point off the allow-list), bounded by the probe timeout.
func (e *Env) probeClient(allowed []string, tlsConf *tls.Config) *http.Client {
	hosts := map[string]bool{}
	for _, h := range allowed {
		hosts[strings.ToLower(hostOnly(h))] = true
	}
	base := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		TLSClientConfig:       tlsConf,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          4,
		DisableKeepAlives:     true,
	}
	var rt http.RoundTripper = base
	if e.Probe != nil && e.Probe.Transport != nil {
		rt = e.Probe.Transport(rt)
	}
	return &http.Client{
		Transport: allowOnly{hosts: hosts, next: rt},
		Timeout:   e.Probe.timeout(),
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// hostOnly strips a port from "host:port".
func hostOnly(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func (e *Env) userAgent() string {
	if e.Probe != nil && e.Probe.UserAgent != "" {
		return e.Probe.UserAgent
	}
	return "blastradius/dev"
}

// newProbeRequest builds a request with the common headers. The secret is
// added by the caller in whatever header the service wants.
func (e *Env) newProbeRequest(ctx context.Context, method, url string, body io.Reader) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", e.userAgent())
	req.Header.Set("Accept", "application/json")
	return req, nil
}

// doJSON performs the request and decodes a JSON body of at most
// maxProbeBody bytes into v (which may be nil). The returned error never
// contains the response body.
func doJSON(client *http.Client, req *http.Request, v any) (*http.Response, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, redactErr(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxProbeBody))
	if err != nil {
		return resp, fmt.Errorf("reading response: %v", redactErr(err))
	}
	resp.Body = io.NopCloser(strings.NewReader(string(data)))
	if v != nil && resp.StatusCode/100 == 2 {
		if err := json.Unmarshal(data, v); err != nil {
			return resp, fmt.Errorf("HTTP %d with a body that is not the expected JSON", resp.StatusCode)
		}
	}
	return resp, nil
}

// redactErr strips URL user-info and query strings that a transport error
// might echo. Probe URLs never carry secrets, but belt and braces.
func redactErr(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, "?"); i >= 0 {
		msg = msg[:i]
	}
	return errors.New(msg)
}

// statusErr summarises a non-2xx response without its body.
func statusErr(host string, resp *http.Response) error {
	return fmt.Errorf("%s answered HTTP %d", host, resp.StatusCode)
}

// rejected reports whether a status means "the credential is not valid".
func rejected(code int) bool { return code == 401 }

// secretAt re-reads the secret behind c from its Location and Line and
// returns it only if its fingerprint matches the one the scan recorded, so
// a prober can never send a value other than the one that was inventoried.
// The Credential itself never carries the secret; this is the one place
// that reads it back, and the value goes to the prober and nowhere else.
func secretAt(env *Env, c cred.Credential) (string, error) {
	if c.Fingerprint == "" {
		return "", errors.New("no fingerprint recorded")
	}
	if name, ok := strings.CutPrefix(c.Location, "env:"); ok {
		v := env.Getenv(name)
		if v == "" {
			return "", fmt.Errorf("$%s is no longer set", name)
		}
		if cred.Fingerprint(v) != c.Fingerprint {
			return "", fmt.Errorf("$%s changed since the scan", name)
		}
		return strings.TrimSpace(v), nil
	}
	path := env.Expand(c.Location)
	data, _, ok, prob := readFile(path)
	if prob != nil {
		return "", errors.New(prob.Err)
	}
	if !ok {
		return "", errors.New("file is gone")
	}
	text := string(data)
	if c.Line > 0 {
		lines := strings.Split(text, "\n")
		if c.Line > len(lines) {
			return "", errors.New("file changed since the scan")
		}
		// The secret is on the recorded line; the whole file is the
		// fallback for multi-line values.
		if s, ok := matchFingerprint(lines[c.Line-1], c.Fingerprint); ok {
			return s, nil
		}
	}
	if s, ok := matchFingerprint(text, c.Fingerprint); ok {
		return s, nil
	}
	return "", errors.New("secret not found where the scan saw it (file changed?)")
}

var runRe = regexp.MustCompile(`[A-Za-z0-9_.+/~=:@-]{8,}`)

// matchFingerprint returns the substring of text whose fingerprint is fp.
// Candidates are the text itself, each quoted string, each JSON string
// value, and every token-shaped run split at the usual separators.
func matchFingerprint(text, fp string) (string, bool) {
	try := func(s string) (string, bool) {
		s = strings.TrimSpace(s)
		return s, s != "" && cred.Fingerprint(s) == fp
	}
	if s, ok := try(text); ok {
		return s, true
	}
	for _, q := range []string{`"`, `'`} {
		parts := strings.Split(text, q)
		for i := 1; i < len(parts); i += 2 {
			if s, ok := try(parts[i]); ok {
				return s, true
			}
		}
	}
	var walk func(v any) (string, bool)
	walk = func(v any) (string, bool) {
		switch x := v.(type) {
		case string:
			return try(x)
		case map[string]any:
			for _, e := range x {
				if s, ok := walk(e); ok {
					return s, true
				}
			}
		case []any:
			for _, e := range x {
				if s, ok := walk(e); ok {
					return s, true
				}
			}
		}
		return "", false
	}
	if t := strings.TrimSpace(text); strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		var v any
		if json.Unmarshal([]byte(t), &v) == nil {
			if s, ok := walk(v); ok {
				return s, true
			}
		}
	}
	for _, run := range runRe.FindAllString(text, -1) {
		if s, ok := try(run); ok {
			return s, true
		}
		for _, sep := range []string{"=", ":", "@", "//"} {
			if _, after, found := strings.Cut(run, sep); found {
				if s, ok := try(after); ok {
					return s, true
				}
			}
			if before, _, found := strings.Cut(run, sep); found {
				if s, ok := try(before); ok {
					return s, true
				}
			}
		}
		// "user:TOKEN@host", "scheme://user:TOKEN@host" and "scheme://TOKEN@host".
		if at := strings.LastIndex(run, "@"); at > 0 {
			left := run[:at]
			for _, sep := range []string{":", "/"} {
				if i := strings.LastIndex(left, sep); i >= 0 {
					if s, ok := try(left[i+1:]); ok {
						return s, true
					}
				}
			}
		}
	}
	return "", false
}

// scrub removes every occurrence of the given secrets (and their base64
// forms) from the strings a probe returned, so a hostile or broken API
// that echoes the credential back can never put it into a report.
func scrub(r *Reach, secrets ...string) {
	if r == nil {
		return
	}
	clean := func(s string) string {
		for _, sec := range secrets {
			sec = strings.TrimSpace(sec)
			if len(sec) < 4 {
				continue
			}
			for _, form := range []string{sec, base64.StdEncoding.EncodeToString([]byte(sec)), base64.URLEncoding.EncodeToString([]byte(sec))} {
				s = strings.ReplaceAll(s, form, "[redacted]")
			}
			// Even a fragment is a leak: slide 16- then 8-character windows
			// over the secret so nothing longer than 7 characters of it
			// survives. Secrets are short, so this is cheap.
			for _, width := range []int{16, 8} {
				for i := 0; i+width <= len(sec); i++ {
					s = strings.ReplaceAll(s, sec[i:i+width], "[redacted]")
				}
			}
		}
		if len(s) > 200 {
			s = s[:200] + "…"
		}
		return s
	}
	r.Identity = clean(r.Identity)
	r.Summary = clean(r.Summary)
	r.TokenType = clean(r.TokenType)
	r.Host = clean(r.Host)
	for i := range r.Scopes {
		r.Scopes[i] = clean(r.Scopes[i])
	}
	for i := range r.Permissions {
		r.Permissions[i] = clean(r.Permissions[i])
	}
}

// guarded runs fn with the re-read secret, then scrubs the result. Every
// token-style prober goes through it.
func guarded(env *Env, c cred.Credential, fn func(secret string) (*Reach, error)) (*Reach, error) {
	if env.Probe == nil {
		return nil, ErrOffline
	}
	secret, err := secretAt(env, c)
	if err != nil {
		return nil, fmt.Errorf("re-reading the secret: %v", err)
	}
	r, err := fn(secret)
	if r != nil {
		r.ProbedAt = env.Now.UTC().Format(time.RFC3339)
		scrub(r, secret)
	}
	if err != nil {
		err = errors.New(strings.ReplaceAll(err.Error(), secret, "[redacted]"))
	}
	return r, err
}

// Probers returns every provider that can probe, in report order.
func Probers() []Prober {
	var out []Prober
	for _, p := range All() {
		if pr, ok := p.(Prober); ok {
			out = append(out, pr)
		}
	}
	return out
}

// targeter is implemented by probers so the scanner can tell the user
// what --probe is about to contact before any request is made.
type targeter interface {
	// probeTargets returns the hosts Probe would contact for c, or a reason
	// it would not (empty hosts). Both are safe to print.
	probeTargets(env *Env, c cred.Credential) (hosts []string, skip string)
}

// ProbeTargets reports which prober handles c and which hosts it would
// contact. hosts is empty when c is not probed, with skip saying why
// (which may be "" for kinds that are simply not probeable).
func ProbeTargets(env *Env, c cred.Credential) (p Prober, hosts []string, skip string) {
	if c.Fingerprint == "" || c.Expired || c.Protected {
		return nil, nil, ""
	}
	for _, pr := range Probers() {
		t, ok := pr.(targeter)
		if !ok {
			continue
		}
		hosts, skip := t.probeTargets(env, c)
		if len(hosts) > 0 || skip != "" {
			return pr, hosts, skip
		}
	}
	return nil, nil, ""
}

// joinList renders a short, sorted, de-duplicated list for summaries.
func joinList(items []string, max int) string {
	seen := map[string]bool{}
	var out []string
	for _, s := range items {
		if s = strings.TrimSpace(s); s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) > max {
		return strings.Join(out[:max], ", ") + fmt.Sprintf(" (+%d more)", len(out)-max)
	}
	return strings.Join(out, ", ")
}
