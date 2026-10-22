package provider

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/testfixture"
)

// probeEnv is the fixture environment with probing switched on and every
// request rerouted to the fake API.
func probeEnv(t *testing.T, f *testfixture.Fixture, fake *testfixture.FakeAPI, cfg ProbeConfig) *Env {
	t.Helper()
	e := envFor(f)
	cfg.Transport = fake.Transport
	cfg.UserAgent = "blastradius/test"
	e.Probe = &cfg
	return e
}

func mustCollect(t *testing.T, e *Env, id string) []cred.Credential {
	t.Helper()
	for _, p := range All() {
		if p.ID() == id {
			cs, _ := p.Collect(e)
			return cs
		}
	}
	t.Fatalf("no provider %q", id)
	return nil
}

func proberFor(t *testing.T, id string) Prober {
	t.Helper()
	for _, p := range Probers() {
		if p.ID() == id {
			return p
		}
	}
	t.Fatalf("%s is not a Prober", id)
	return nil
}

// TestSecretAtRecoversEveryProbeableSecret: for each fixture credential a
// prober handles, re-reading from Location/Line yields a value with the
// recorded fingerprint, and never anything else.
func TestSecretAtRecoversEveryProbeableSecret(t *testing.T) {
	f := NewFixture(t)
	e := envFor(f)
	e.Probe = &ProbeConfig{Clusters: []string{"prod"}}
	n := 0
	for _, p := range All() {
		cs, _ := p.Collect(e)
		for _, c := range cs {
			pr, hosts, _ := ProbeTargets(e, c)
			if pr == nil || len(hosts) == 0 || c.Service == cred.ServiceKubernetes || c.Service == cred.ServiceAWS {
				continue // AWS and Kubernetes re-read structured material themselves
			}
			s, err := secretAt(e, c)
			if err != nil {
				t.Errorf("%s %s:%d: %v", p.ID(), c.Location, c.Line, err)
				continue
			}
			if cred.Fingerprint(s) != c.Fingerprint {
				t.Errorf("%s %s: wrong secret recovered", p.ID(), c.Location)
			}
			n++
		}
	}
	if n < 10 {
		t.Errorf("only %d probeable secrets recovered", n)
	}
	// A credential whose fingerprint no longer matches the file is refused.
	c := cred.Credential{Location: "~/.npmrc", Line: 1, Fingerprint: "deadbeef"}
	if _, err := secretAt(e, c); err == nil {
		t.Error("secretAt returned a secret whose fingerprint does not match")
	}
	if _, err := secretAt(e, cred.Credential{Location: "env:NOPE", Fingerprint: "deadbeef"}); err == nil {
		t.Error("secretAt returned a value for an unset variable")
	}
}

func TestMatchFingerprint(t *testing.T) {
	tok := "ghp_" + strings.Repeat("x", 36)
	fp := cred.Fingerprint(tok)
	for _, text := range []string{
		tok,
		"  oauth_token: " + tok + "\n",
		"https://alice:" + tok + "@github.com",
		"https://" + tok + "@github.com",
		"//registry.npmjs.org/:_authToken=" + tok,
		"export GH_TOKEN=\"" + tok + "\" # comment",
		"set -gx GH_TOKEN " + tok,
		`{"tokens":{"nested":{"access_token":"` + tok + `"}}}`,
		"machine api.github.com login alice password " + tok,
		"curl -H 'Authorization: Bearer " + tok + "' https://x",
		"echo " + tok + " | gh auth login --with-token",
	} {
		got, ok := matchFingerprint(text, fp)
		if !ok || got != tok {
			t.Errorf("matchFingerprint(%q) = %q, %v", text, got, ok)
		}
	}
	b64 := base64.StdEncoding.EncodeToString([]byte("dave:pw"))
	if got, ok := matchFingerprint("//r.example.com/:_auth="+b64+"\n", cred.Fingerprint(b64)); !ok || got != b64 {
		t.Errorf("base64 with padding: %q %v", got, ok)
	}
	if _, ok := matchFingerprint("nothing here", fp); ok {
		t.Error("matched nothing")
	}
}

func TestAllowListTransport(t *testing.T) {
	// The hook stands in for the network: a request that gets here would
	// have left the machine.
	e := &Env{Now: time0(), Probe: &ProbeConfig{Transport: func(http.RoundTripper) http.RoundTripper {
		return roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return nil, errors.New("reached the network")
		})
	}}}
	client := e.probeClient([]string{"api.github.com", "prod.k8s.example.com:6443"}, nil)
	for _, u := range []string{"https://evil.example.com/user", "https://api.github.com.evil.example.com/", "http://api.github.com/user", "https://ghe.example.com/api/v3/user"} {
		req, _ := http.NewRequest(http.MethodGet, u, nil)
		_, err := client.Do(req)
		var denied errHostNotAllowed
		if !errors.As(err, &denied) {
			t.Errorf("%s: err = %v, want allow-list refusal", u, err)
		}
	}
	// A listed host with a port is matched on the host name.
	req, _ := http.NewRequest(http.MethodGet, "https://prod.k8s.example.com:6443/x", nil)
	if _, err := client.Do(req); err == nil || !strings.Contains(err.Error(), "reached the network") {
		t.Errorf("allowed host: err = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProbeHostsAreDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, p := range Probers() {
		for _, h := range p.ProbeHosts() {
			declared[h] = true
		}
	}
	for _, want := range []string{"api.github.com", "registry.npmjs.org", "sts.amazonaws.com", "api.anthropic.com", "api.openai.com"} {
		if !declared[want] {
			t.Errorf("%s not declared by any prober", want)
		}
	}
	if len(declared) != 5 {
		t.Errorf("unexpected allow-list %v", declared)
	}
	if hosts := proberFor(t, "kubernetes").ProbeHosts(); len(hosts) != 0 {
		t.Errorf("kubernetes must not have a fixed host list, got %v", hosts)
	}
}

func TestProbeGitHub(t *testing.T) {
	f := NewFixture(t)
	fake := testfixture.NewFakeAPI(t)
	e := probeEnv(t, f, fake, ProbeConfig{})
	gh := proberFor(t, "github")
	ctx := context.Background()

	// gh OAuth token: classic scopes.
	tok := find(mustCollect(t, e, "github"), byAccount("alice@github.com"))
	r, err := gh.Probe(ctx, e, *tok)
	if err != nil || !r.Live || r.Identity != "alice" || r.TokenType != "classic" || strings.Join(r.Scopes, ",") != "gist,read:org,repo,workflow" || r.ReadOnly || r.Host != "api.github.com" || r.ProbedAt == "" {
		t.Errorf("oauth = %+v, %v", r, err)
	}
	// netrc ghp_: repo + admin:org.
	pat := find(mustCollect(t, e, "netrc"), byKind("classic-pat"))
	if r, err = gh.Probe(ctx, e, *pat); err != nil || !strings.Contains(r.Summary, "full control") {
		t.Errorf("pat = %+v, %v", r, err)
	}
	// Copilot ghu_: empty scope header means read-only.
	cp := find(mustCollect(t, e, "ai-tools"), func(c cred.Credential) bool { return c.Source == "github-copilot" })
	if r, err = gh.Probe(ctx, e, *cp); err != nil || !r.ReadOnly || !strings.Contains(r.Summary, "no scopes") {
		t.Errorf("copilot = %+v, %v", r, err)
	}
	// Fine-grained PAT: no X-OAuth-Scopes header at all.
	fg := "github_pat_" + strings.Repeat("FAKEBLAST", 10)
	path := filepath.Join(f.Home, ".netrc")
	if err := os.WriteFile(path, []byte("machine api.github.com login fg password "+fg+"\nmachine api.github.com login dead password ghp_revoked"+strings.Repeat("FAKEBLAST", 5)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cs := mustCollect(t, e, "netrc")
	if r, err = gh.Probe(ctx, e, *find(cs, byAccount("fg@api.github.com"))); err != nil || r.TokenType != "fine-grained" || len(r.Scopes) != 0 || !strings.Contains(r.Summary, "fine-grained") {
		t.Errorf("fine-grained = %+v, %v", r, err)
	}
	// Revoked token: 401 is a result, not an error.
	if r, err = gh.Probe(ctx, e, *find(cs, byAccount("dead@api.github.com"))); err != nil || r.Live || !strings.Contains(r.Summary, "rejected") {
		t.Errorf("revoked = %+v, %v", r, err)
	}
	for _, req := range fake.Requests() {
		if !strings.HasPrefix(req, "api.github.com /user") {
			t.Errorf("unexpected request %q", req)
		}
	}
}

func TestProbeGitHubEnterpriseNeedsOptIn(t *testing.T) {
	f := NewFixture(t)
	fake := testfixture.NewFakeAPI(t)
	hosts := filepath.Join(f.Home, ".config", "gh", "hosts.yml")
	tok := "gho_" + strings.Repeat("FAKEBLAST", 5)
	if err := os.WriteFile(hosts, []byte("ghe.example.com:\n    user: bob\n    oauth_token: "+tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gh := proberFor(t, "github")
	e := probeEnv(t, f, fake, ProbeConfig{})
	c := *find(mustCollect(t, e, "github"), byAccount("bob@ghe.example.com"))
	if _, hosts, skip := ProbeTargets(e, c); len(hosts) != 0 || !strings.Contains(skip, "--probe-host ghe.example.com") {
		t.Errorf("without opt-in: hosts %v skip %q", hosts, skip)
	}
	if _, err := gh.Probe(context.Background(), e, c); err == nil || len(fake.Requests()) != 0 {
		t.Errorf("probe without opt-in: err %v, requests %v", err, fake.Requests())
	}
	e = probeEnv(t, f, fake, ProbeConfig{Hosts: []string{"ghe.example.com"}})
	r, err := gh.Probe(context.Background(), e, c)
	if err != nil || !r.Live || r.Host != "ghe.example.com" {
		t.Errorf("with opt-in: %+v %v", r, err)
	}
	if reqs := fake.Requests(); len(reqs) != 1 || reqs[0] != "ghe.example.com /api/v3/user" {
		t.Errorf("requests = %v", reqs)
	}
}

func TestProbeNPM(t *testing.T) {
	f := NewFixture(t)
	fake := testfixture.NewFakeAPI(t)
	e := probeEnv(t, f, fake, ProbeConfig{})
	np := proberFor(t, "npm")
	cs := mustCollect(t, e, "npm")
	ctx := context.Background()
	legacy := find(cs, byKind("legacy-token"))
	r, err := np.Probe(ctx, e, *legacy)
	if err != nil || !r.Live || r.Identity != "alice" || r.TokenType != "automation" || !r.Bypass2FA || r.ReadOnly {
		t.Errorf("legacy = %+v, %v", r, err)
	}
	granular := find(cs, func(c cred.Credential) bool { return strings.Contains(c.Location, "src/app") })
	if r, err = np.Probe(ctx, e, *granular); err != nil || r.TokenType != "read-only" || !r.ReadOnly {
		t.Errorf("npm_ = %+v, %v", r, err)
	}
	fake.NPMKind = func(string) string { return "granular" }
	if r, err = np.Probe(ctx, e, *granular); err != nil || r.TokenType != "granular" || r.ReadOnly || r.Bypass2FA {
		t.Errorf("unlisted = %+v, %v", r, err)
	}
	fake.NPMKind = func(string) string { return "publish" }
	if r, err = np.Probe(ctx, e, *granular); err != nil || r.TokenType != "publish" || !strings.Contains(r.Summary, "publish token") {
		t.Errorf("publish = %+v, %v", r, err)
	}
	// The corporate registry basic-auth entry is not an npmjs token.
	if _, hosts, _ := ProbeTargets(e, *find(cs, byKind("basic-auth"))); len(hosts) != 0 {
		t.Error("basic-auth for another registry must not be probed")
	}
	for _, req := range fake.Requests() {
		if !strings.HasPrefix(req, "registry.npmjs.org /-/") {
			t.Errorf("unexpected request %q", req)
		}
	}
}

func TestProbeAWS(t *testing.T) {
	f := NewFixture(t)
	fake := testfixture.NewFakeAPI(t)
	e := probeEnv(t, f, fake, ProbeConfig{})
	aw := proberFor(t, "aws")
	ctx := context.Background()
	cs := mustCollect(t, e, "aws")
	root := find(cs, byAccount("profile default"))
	r, err := aw.Probe(ctx, e, *root)
	if err != nil || !r.Live || !r.Admin || r.TokenType != "root" || r.Identity != "arn:aws:iam::123456789012:root" || !strings.Contains(r.Summary, "ROOT") {
		t.Errorf("root = %+v, %v", r, err)
	}
	tmp := find(cs, byAccount("profile temp"))
	if r, err = aw.Probe(ctx, e, *tmp); err != nil || !r.Live || r.Admin || r.TokenType != "assumed-role" || !strings.Contains(r.Summary, "role Admin (session alice)") {
		t.Errorf("session = %+v, %v", r, err)
	}
	cache := find(cs, func(c cred.Credential) bool { return c.Source == "aws-cli-cache" })
	if r, err = aw.Probe(ctx, e, *cache); err != nil || !r.Live {
		t.Errorf("cli cache = %+v, %v", r, err)
	}
	// $AWS_SECRET_ACCESS_KEY with an ASIA key but no session token: STS says
	// InvalidClientTokenId, which is a rejection, not an error.
	envKey := find(mustCollect(t, e, "env"), byAccount("AWS_SECRET_ACCESS_KEY"))
	if r, err = aw.Probe(ctx, e, *envKey); err != nil || r.Live || !strings.Contains(r.Summary, "InvalidClientTokenId") {
		t.Errorf("env rejected = %+v, %v", r, err)
	}
	// SSO sessions are not STS credentials and a history line has no key ID.
	if _, hosts, _ := ProbeTargets(e, *find(cs, byKind("sso-access-token"))); len(hosts) != 0 {
		t.Error("sso token must not be probed")
	}
	hist := find(mustCollect(t, e, "shell-history"), byAccount("AWS_SECRET_ACCESS_KEY"))
	if _, hosts, skip := ProbeTargets(e, *hist); len(hosts) != 0 || !strings.Contains(skip, "access key ID") {
		t.Errorf("history: hosts %v skip %q", hosts, skip)
	}
	for _, req := range fake.Requests() {
		if req != "sts.amazonaws.com /" {
			t.Errorf("unexpected request %q", req)
		}
	}
}

func TestProbeAIKeys(t *testing.T) {
	f := NewFixture(t)
	fake := testfixture.NewFakeAPI(t)
	e := probeEnv(t, f, fake, ProbeConfig{})
	ai := proberFor(t, "ai-tools")
	ctx := context.Background()
	envs := mustCollect(t, e, "env")
	a := find(envs, byAccount("ANTHROPIC_API_KEY"))
	r, err := ai.Probe(ctx, e, *a)
	if err != nil || !r.Live || r.Host != "api.anthropic.com" || !strings.Contains(r.Summary, "2 model") {
		t.Errorf("anthropic = %+v, %v", r, err)
	}
	o := find(envs, byAccount("OPENAI_API_KEY"))
	if r, err = ai.Probe(ctx, e, *o); err != nil || !r.Live || r.Host != "api.openai.com" {
		t.Errorf("openai = %+v, %v", r, err)
	}
	// OAuth logins of the CLIs are never sent anywhere.
	for _, c := range mustCollect(t, e, "ai-tools") {
		if _, hosts, _ := ProbeTargets(e, c); len(hosts) != 0 && c.Kind != "api-key" && c.Service != cred.ServiceGitHub {
			t.Errorf("%s/%s would be probed", c.Source, c.Kind)
		}
	}
	for _, req := range fake.Requests() {
		if req != "api.anthropic.com /v1/models" && req != "api.openai.com /v1/models" {
			t.Errorf("unexpected request %q", req)
		}
	}
}

// TestProbeKube runs a real TLS API server with the kubeconfig's CA and
// checks both authentication styles: a bearer token and a client
// certificate. No reroute is involved; the kubeconfig names the server.
func TestProbeKube(t *testing.T) {
	now := time0()
	certPEM, keyPEM := testfixture.SelfSigned(t, "kube-admin", now.AddDate(1, 0, 0))
	var gotCN, gotBearer string
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" || r.Method != http.MethodPost {
			http.Error(w, "not found", 404)
			return
		}
		var body struct {
			Spec struct {
				Namespace string `json:"namespace"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		rules := []map[string]any{{"verbs": []string{"get", "list"}, "apiGroups": []string{""}, "resources": []string{"pods"}}}
		switch {
		case len(r.TLS.PeerCertificates) > 0:
			gotCN = r.TLS.PeerCertificates[0].Subject.CommonName
			rules = []map[string]any{{"verbs": []string{"*"}, "apiGroups": []string{"*"}, "resources": []string{"*"}}}
		case strings.HasPrefix(r.Header.Get("Authorization"), "Bearer "):
			gotBearer = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if strings.Contains(gotBearer, "revoked") {
				http.Error(w, "Unauthorized", 401)
				return
			}
			rules = append(rules, map[string]any{"verbs": []string{"create"}, "apiGroups": []string{""}, "resources": []string{"secrets"}})
		default:
			http.Error(w, "Unauthorized", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"resourceRules": rules, "incomplete": body.Spec.Namespace == "incomplete"}})
	}))
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	home := t.TempDir()
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	tok := "eyJ" + strings.Repeat("FAKEBLAST", 8)
	revoked := "eyJrevoked" + strings.Repeat("FAKEBLAST", 8)
	kubeconfig := "apiVersion: v1\nclusters:\n- cluster:\n    server: " + srv.URL + "\n    certificate-authority-data: " + b64(string(caPEM)) + "\n  name: local\n" +
		"- cluster:\n    server: https://other.example.com\n    insecure-skip-tls-verify: true\n  name: insecure\n" +
		"contexts:\n- context:\n    cluster: local\n    user: admin\n    namespace: kube-system\n  name: a\n" +
		"- context:\n    cluster: local\n    user: sa\n  name: b\n- context:\n    cluster: insecure\n    user: sa\n  name: c\n" +
		"- context:\n    cluster: local\n    user: dead\n  name: d\n" +
		"users:\n- name: admin\n  user:\n    client-certificate-data: " + b64(certPEM) + "\n    client-key-data: " + b64(keyPEM) + "\n" +
		"- name: sa\n  user:\n    token: " + tok + "\n- name: dead\n  user:\n    token: " + revoked + "\n"
	if err := os.MkdirAll(filepath.Join(home, ".kube"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".kube", "config"), []byte(kubeconfig), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &Env{Home: home, Now: now, Getenv: func(string) string { return "" }, Environ: func() []string { return nil }}
	k := proberFor(t, "kubernetes")
	cs := mustCollect(t, e, "kubernetes")
	admin, sa, dead := find(cs, byAccount("admin")), find(cs, byAccount("sa")), find(cs, byAccount("dead"))
	if admin == nil || sa == nil || dead == nil {
		t.Fatalf("collect: %+v", cs)
	}

	// Without --probe-cluster nothing is contacted.
	e.Probe = &ProbeConfig{}
	if _, hosts, skip := ProbeTargets(e, *sa); len(hosts) != 0 || !strings.Contains(skip, "--probe-cluster insecure") && !strings.Contains(skip, "--probe-cluster local") {
		t.Errorf("no opt-in: hosts %v skip %q", hosts, skip)
	}
	if _, err := k.Probe(context.Background(), e, *sa); err == nil || gotBearer != "" {
		t.Errorf("probe without opt-in: %v (bearer sent: %v)", err, gotBearer != "")
	}

	e.Probe = &ProbeConfig{Clusters: []string{"local", "insecure"}}
	r, err := k.Probe(context.Background(), e, *admin)
	if err != nil || !r.Live || !r.Admin || gotCN != "kube-admin" || !strings.Contains(r.Summary, "cluster-admin") || !strings.Contains(strings.Join(r.Permissions, ";"), "local (ns kube-system)") {
		t.Errorf("client cert = %+v, %v (cn %q)", r, err, gotCN)
	}
	r, err = k.Probe(context.Background(), e, *sa)
	if err != nil || !r.Live || r.Admin || r.ReadOnly || gotBearer != tok || !strings.Contains(r.Summary, "write secrets") || !strings.Contains(r.Summary, "read pods") {
		t.Errorf("token = %+v, %v", r, err)
	}
	// The insecure cluster was opted in but is still refused.
	if !strings.Contains(r.Summary, "insecure-skip-tls-verify") {
		t.Errorf("insecure cluster not refused: %s", r.Summary)
	}
	if r, err = k.Probe(context.Background(), e, *dead); err != nil || r.Live || !strings.Contains(r.Summary, "rejected") {
		t.Errorf("revoked = %+v, %v", r, err)
	}
	// A rotated token is not sent: the fingerprint no longer matches.
	gotBearer = ""
	rotated := strings.Replace(kubeconfig, tok, "eyJ"+strings.Repeat("ROTATED00", 8), 1)
	if err := os.WriteFile(filepath.Join(home, ".kube", "config"), []byte(rotated), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := k.Probe(context.Background(), e, *sa); err == nil || gotBearer != "" {
		t.Errorf("rotated token: err %v, sent %q", err, gotBearer)
	}
}

func TestSummariseRules(t *testing.T) {
	s, admin, ro := summariseRules([]kubeRule{{Verbs: []string{"*"}, APIGroups: []string{"*"}, Resources: []string{"*"}}})
	if !admin || ro || !strings.Contains(s, "full control") {
		t.Errorf("admin: %q %v %v", s, admin, ro)
	}
	s, admin, ro = summariseRules([]kubeRule{{Verbs: []string{"get"}, Resources: []string{"pods"}}, {Verbs: []string{"get"}, NonResourceURLs: []string{"/healthz"}}})
	if admin || !ro || s != "read /healthz, pods" && s != "read pods, /healthz" {
		t.Errorf("read-only: %q %v %v", s, admin, ro)
	}
	if s, _, ro = summariseRules(nil); s != "no permissions" || !ro {
		t.Errorf("empty: %q %v", s, ro)
	}
}

// TestScrub: a hostile API that echoes the secret cannot get it into a
// Reach.
func TestScrub(t *testing.T) {
	secret := "ghp_" + strings.Repeat("FAKEBLAST", 5)
	r := &Reach{Identity: secret, Summary: "acts as " + secret + " · scopes: " + secret[4:20], Scopes: []string{secret, "repo"}, Permissions: []string{base64.StdEncoding.EncodeToString([]byte(secret))}}
	scrub(r, secret)
	blob := r.Identity + r.Summary + strings.Join(r.Scopes, "") + strings.Join(r.Permissions, "")
	if strings.Contains(blob, "FAKEBLAST") || strings.Contains(blob, base64.StdEncoding.EncodeToString([]byte(secret))) || r.Scopes[1] != "repo" {
		t.Errorf("scrub left %q", blob)
	}
}

func TestProbeOfflineRefuses(t *testing.T) {
	f := NewFixture(t)
	e := envFor(f) // Probe nil
	c := find(mustCollect(t, e, "github"), byAccount("alice@github.com"))
	if _, err := proberFor(t, "github").Probe(context.Background(), e, *c); !errors.Is(err, ErrOffline) {
		t.Errorf("err = %v, want ErrOffline", err)
	}
}
