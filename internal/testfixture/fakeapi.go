package testfixture

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// FakeAPI stands in for every service --probe talks to. One httptest server
// answers for all of them and dispatches on the Host header the prober set,
// so the probers keep building their real URLs (https://api.github.com/user)
// and the test transport only reroutes the connection. A request for a host
// the fake does not know is an error, which is how the tests prove no probe
// ever leaves the allow-list.
//
// Behaviour is keyed on the shape of the credential presented, so the
// FAKEBLAST fixture drives it without the test knowing the secrets:
//
//	gho_…          GitHub, scopes "repo, read:org, gist, workflow"
//	ghp_…          GitHub, scopes "repo, admin:org"
//	github_pat_…   GitHub fine-grained (no scopes header)
//	ghu_…          GitHub, empty scopes header (read-only)
//	UUID           npm legacy token, listed as automation
//	npm_…          npm, listed as read-only
//	AKIA…          AWS, the account root user
//	ASIA…          AWS assumed role, requires X-Amz-Security-Token
//	sk-ant-/sk-…   Anthropic / OpenAI, live
//	kube Bearer    cluster-admin rules; no Authorization (client cert): read-only
//
// Any secret containing "revoked" is answered 401. Echo makes the fake
// hostile: every identity-like field in every answer is the secret the
// client just presented, so a leak test can check nothing of it reaches a
// report.
type FakeAPI struct {
	srv *httptest.Server

	// Echo turns on the hostile mode described above.
	Echo bool
	// NPMKind overrides the npm token classification: "readonly",
	// "automation", "publish" or "granular" (not listed).
	NPMKind func(token string) string
	// AWSArn overrides the ARN returned for a key ID; "" means reject.
	AWSArn func(keyID string) string
	// KubeRules overrides the SelfSubjectRulesReview rules.
	KubeRules func(bearer string) []map[string]any

	mu       sync.Mutex
	requests []string
	hosts    map[string]int
	// Unexpected records hosts the probers tried that the fake does not serve.
	Unexpected []string
}

// Hosts the fake serves. Kubernetes hosts match the fixture kubeconfig.
var fakeHosts = map[string]bool{
	"api.github.com": true, "ghe.example.com": true, "registry.npmjs.org": true,
	"sts.amazonaws.com": true, "api.anthropic.com": true, "api.openai.com": true,
	"prod.k8s.example.com:6443": true, "eks.example.com": true,
}

// NewFakeAPI starts the server; it stops with the test.
func NewFakeAPI(t *testing.T) *FakeAPI {
	t.Helper()
	f := &FakeAPI{hosts: map[string]int{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

// Transport is the hook for provider.ProbeConfig.Transport: it records the
// host the prober asked for, refuses unknown ones, and reroutes the rest to
// the fake over plain HTTP. The wrapped transport is never used.
func (f *FakeAPI) Transport(http.RoundTripper) http.RoundTripper { return rerouter{f} }

type rerouter struct{ f *FakeAPI }

func (r rerouter) RoundTrip(req *http.Request) (*http.Response, error) {
	f := r.f
	host := req.URL.Host
	f.mu.Lock()
	f.requests = append(f.requests, host+" "+req.URL.Path)
	f.hosts[host]++
	known := fakeHosts[host]
	if !known {
		f.Unexpected = append(f.Unexpected, host)
	}
	f.mu.Unlock()
	if !known {
		return nil, errors.New("fake API: unexpected host " + host)
	}
	if req.URL.Scheme != "https" {
		return nil, errors.New("fake API: probe used " + req.URL.Scheme + ", not https")
	}
	if ua := req.Header.Get("User-Agent"); !strings.HasPrefix(ua, "blastradius/") {
		return nil, errors.New("fake API: User-Agent is " + ua)
	}
	clone := req.Clone(req.Context())
	clone.URL.Scheme = "http"
	clone.URL.Host = strings.TrimPrefix(f.srv.URL, "http://")
	clone.Host = host
	return http.DefaultTransport.RoundTrip(clone)
}

// Requests returns "host path" for every request made so far.
func (f *FakeAPI) Requests() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

// HostCounts returns how many requests each host received.
func (f *FakeAPI) HostCounts() map[string]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int{}
	for k, v := range f.hosts {
		out[k] = v
	}
	return out
}

var uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// presented extracts the credential from the request.
func presented(r *http.Request) string {
	if a := r.Header.Get("Authorization"); a != "" {
		if _, tok, ok := strings.Cut(a, " "); ok && !strings.HasPrefix(a, "AWS4") {
			return tok
		}
		return a
	}
	return r.Header.Get("x-api-key")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func (f *FakeAPI) serve(w http.ResponseWriter, r *http.Request) {
	secret := presented(r)
	if strings.Contains(strings.ToLower(secret), "revoked") {
		writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
		return
	}
	// ident returns the identity to report: the real-looking one, or the
	// secret itself in hostile mode.
	ident := func(s string) string {
		if f.Echo && secret != "" {
			return secret
		}
		return s
	}
	switch r.Host {
	case "api.github.com", "ghe.example.com":
		if secret == "" {
			writeJSON(w, 401, map[string]string{"message": "Requires authentication"})
			return
		}
		switch {
		case strings.HasPrefix(secret, "gho_"):
			w.Header().Set("X-OAuth-Scopes", ident("repo, read:org, gist, workflow"))
		case strings.HasPrefix(secret, "ghp_"):
			w.Header().Set("X-OAuth-Scopes", ident("repo, admin:org"))
		case strings.HasPrefix(secret, "github_pat_"):
			// fine-grained: no header
		case strings.HasPrefix(secret, "ghu_"):
			w.Header().Set("X-OAuth-Scopes", "")
		default:
			writeJSON(w, 401, map[string]string{"message": "Bad credentials"})
			return
		}
		writeJSON(w, 200, map[string]any{"login": ident("alice"), "type": "User"})
	case "registry.npmjs.org":
		if secret == "" {
			writeJSON(w, 401, map[string]string{"error": "unauthenticated"})
			return
		}
		switch r.URL.Path {
		case "/-/whoami":
			writeJSON(w, 200, map[string]string{"username": ident("alice")})
		case "/-/npm/v1/tokens":
			kind := "publish"
			switch {
			case f.NPMKind != nil:
				kind = f.NPMKind(secret)
			case uuidRe.MatchString(secret):
				kind = "automation"
			case strings.HasPrefix(secret, "npm_"):
				kind = "readonly"
			}
			sum := sha512.Sum512([]byte(secret))
			obj := map[string]any{"token": secret[:6], "key": hex.EncodeToString(sum[:]), "readonly": kind == "readonly", "automation": kind == "automation", "created": "2026-01-01T00:00:00.000Z"}
			if f.Echo {
				obj["token"] = secret
			}
			objs := []any{obj}
			if kind == "granular" {
				objs = []any{}
			}
			writeJSON(w, 200, map[string]any{"objects": objs, "total": len(objs)})
		default:
			writeJSON(w, 404, map[string]string{"error": "not found"})
		}
	case "sts.amazonaws.com":
		auth := r.Header.Get("Authorization")
		m := regexp.MustCompile(`^AWS4-HMAC-SHA256 Credential=([A-Z0-9]+)/\d{8}/us-east-1/sts/aws4_request, SignedHeaders=([a-z0-9;-]+), Signature=[0-9a-f]{64}$`).FindStringSubmatch(auth)
		if m == nil || r.Header.Get("X-Amz-Date") == "" || r.Method != http.MethodPost {
			writeJSON(w, 403, map[string]any{"Error": map[string]string{"Code": "IncompleteSignature", "Message": "bad auth header"}})
			return
		}
		keyID := m[1]
		token := r.Header.Get("X-Amz-Security-Token")
		arn := ""
		switch {
		case f.AWSArn != nil:
			arn = f.AWSArn(keyID)
		case strings.HasPrefix(keyID, "AKIA"):
			arn = "arn:aws:iam::123456789012:root"
		case strings.HasPrefix(keyID, "ASIA") && token != "" && strings.Contains(m[2], "x-amz-security-token"):
			arn = "arn:aws:sts::123456789012:assumed-role/Admin/alice"
		}
		if arn == "" {
			writeJSON(w, 403, map[string]any{"Error": map[string]string{"Code": "InvalidClientTokenId", "Message": "The security token included in the request is invalid."}})
			return
		}
		if f.Echo && token != "" {
			arn = token
		}
		writeJSON(w, 200, map[string]any{"GetCallerIdentityResponse": map[string]any{
			"GetCallerIdentityResult": map[string]string{"Account": "123456789012", "Arn": arn, "UserId": "AIDAEXAMPLE"},
			"ResponseMetadata":        map[string]string{"RequestId": "00000000-0000-0000-0000-000000000000"},
		}})
	case "api.anthropic.com", "api.openai.com":
		if secret == "" {
			writeJSON(w, 401, map[string]any{"error": map[string]string{"type": "authentication_error"}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": []map[string]string{{"id": ident("model-a")}, {"id": ident("model-b")}}})
	case "prod.k8s.example.com:6443", "eks.example.com":
		if r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" || r.Method != http.MethodPost {
			writeJSON(w, 404, map[string]string{"message": "not found"})
			return
		}
		var rules []map[string]any
		switch {
		case f.KubeRules != nil:
			rules = f.KubeRules(secret)
		case secret != "":
			rules = []map[string]any{{"verbs": []string{"*"}, "apiGroups": []string{"*"}, "resources": []string{ident("*")}}}
		default:
			rules = []map[string]any{{"verbs": []string{"get", "list", "watch"}, "apiGroups": []string{""}, "resources": []string{"pods", "services"}}}
		}
		writeJSON(w, 201, map[string]any{"kind": "SelfSubjectRulesReview", "status": map[string]any{"resourceRules": rules, "incomplete": false}})
	default:
		writeJSON(w, 500, map[string]string{"error": fmt.Sprintf("fake API has no handler for %s", r.Host)})
	}
}
