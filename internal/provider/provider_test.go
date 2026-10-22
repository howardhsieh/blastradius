package provider

import (
	"runtime"
	"strings"
	"testing"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/testfixture"
)

const marker = testfixture.Marker

// NewFixture is the shared fake home directory.
func NewFixture(t *testing.T) *testfixture.Fixture { return testfixture.NewFixture(t) }

func envFor(f *testfixture.Fixture) *Env {
	return &Env{Home: f.Home, Hostname: "testbox", Now: f.Now, Getenv: f.Getenv, Environ: f.Environment, Dirs: f.Dirs()}
}

func collect(t *testing.T, f *testfixture.Fixture, id string) []cred.Credential {
	t.Helper()
	for _, p := range All() {
		if p.ID() != id {
			continue
		}
		cs, probs := p.Collect(envFor(f))
		for _, pr := range probs {
			t.Errorf("%s: problem %s: %s", id, pr.Location, pr.Err)
		}
		return cs
	}
	t.Fatalf("no provider %q", id)
	return nil
}

func find(cs []cred.Credential, pred func(cred.Credential) bool) *cred.Credential {
	for i := range cs {
		if pred(cs[i]) {
			return &cs[i]
		}
	}
	return nil
}

func byKind(kind string) func(cred.Credential) bool {
	return func(c cred.Credential) bool { return c.Kind == kind }
}

func byAccount(acct string) func(cred.Credential) bool {
	return func(c cred.Credential) bool { return c.Account == acct }
}

func TestNoProviderReturnsASecret(t *testing.T) {
	f := NewFixture(t)
	for _, p := range All() {
		cs, _ := p.Collect(envFor(f))
		for _, c := range cs {
			blob := strings.Join(append([]string{c.Location, c.Account, c.Summary, c.Fingerprint, c.Remediation}, c.Notes...), "\n")
			for _, s := range f.Secrets {
				if strings.Contains(blob, strings.TrimSpace(s)) {
					t.Errorf("%s leaked a fixture secret in %+v", p.ID(), c)
				}
			}
			if strings.Contains(blob, marker) {
				t.Errorf("%s: credential text contains fixture marker: %q", p.ID(), blob)
			}
			if len(c.Fingerprint) != 0 && len(c.Fingerprint) != 8 {
				t.Errorf("%s: fingerprint %q is not 8 hex chars", p.ID(), c.Fingerprint)
			}
		}
	}
}

func TestGitHub(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "github")
	if len(cs) != 2 {
		t.Fatalf("want 2 github credentials (one token, one keyring note), got %d: %+v", len(cs), cs)
	}
	tok := find(cs, byAccount("alice@github.com"))
	if tok == nil || tok.Kind != "oauth-token" || tok.Severity != cred.High || tok.Fingerprint == "" || tok.Lifetime != cred.LongTerm {
		t.Errorf("token = %+v", tok)
	}
	kr := find(cs, byAccount("bob@ghe.example.com"))
	if kr == nil || !kr.Protected || kr.Severity != cred.Low || kr.Fingerprint != "" {
		t.Errorf("keyring entry = %+v", kr)
	}
}

func TestGitCredentialsAndNetrc(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "git-credentials")
	if len(cs) != 3 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	if gh := find(cs, byAccount("alice@github.com")); gh == nil || gh.Service != cred.ServiceGitHub || gh.Kind != "oauth-token" {
		t.Errorf("github entry = %+v", gh)
	}
	if gl := find(cs, byAccount("gitlab.com")); gl == nil || gl.Service != cred.ServiceGitLab || gl.Kind != "personal-access-token" {
		t.Errorf("gitlab token-as-user entry = %+v", gl)
	}
	if o := find(cs, byAccount("carol@git.example.com")); o == nil || o.Severity != cred.Medium {
		t.Errorf("generic entry = %+v", o)
	}
	nr := collect(t, f, "netrc")
	if len(nr) != 2 {
		t.Fatalf("netrc got %d: %+v", len(nr), nr)
	}
	if p := find(nr, byAccount("alice@api.github.com")); p == nil || p.Kind != "classic-pat" {
		t.Errorf("netrc github = %+v", p)
	}
	if p := find(nr, byAccount("__token__@upload.pypi.org")); p == nil || p.Service != cred.ServicePyPI {
		t.Errorf("netrc pypi = %+v", p)
	}
}

func TestNPM(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "npm")
	if len(cs) != 3 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	if l := find(cs, byKind("legacy-token")); l == nil || l.Severity != cred.Critical || l.AgeDays == nil || *l.AgeDays != 400 {
		t.Errorf("legacy = %+v", l)
	}
	if b := find(cs, byKind("basic-auth")); b == nil || b.Account != "dave@registry.corp.example.com" || b.Service != cred.ServiceGeneric {
		t.Errorf("basic = %+v", b)
	}
	if p := find(cs, func(c cred.Credential) bool { return strings.Contains(c.Location, "src/app") }); p == nil || p.Kind != "access-token" || !strings.Contains(strings.Join(p.Notes, " "), "project-level") {
		t.Errorf("project npmrc = %+v", p)
	}
}

func TestPyPI(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "pypi")
	if len(cs) != 3 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	if p := find(cs, byAccount("pypi")); p == nil || p.Kind != "api-token" || p.Severity != cred.High {
		t.Errorf("pypi = %+v", p)
	}
	if p := find(cs, byAccount("alice@testpypi")); p == nil || p.Severity != cred.Medium {
		t.Errorf("testpypi = %+v", p)
	}
	if p := find(cs, byKind("index-url-password")); p == nil || p.Account != "pypi.corp.example.com" {
		t.Errorf("pip.conf = %+v", p)
	}
}

func TestAWS(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "aws")
	lt := find(cs, byAccount("profile default"))
	if lt == nil || lt.Kind != "access-key" || lt.Severity != cred.Critical || lt.Lifetime != cred.LongTerm || *lt.AgeDays != 500 {
		t.Fatalf("long-term = %+v", lt)
	}
	notes := strings.Join(lt.Notes, "|")
	if !strings.Contains(notes, "role profiles: admin") || !strings.Contains(notes, "ap-northeast-1") {
		t.Errorf("notes = %q", notes)
	}
	if tmp := find(cs, byAccount("profile temp")); tmp == nil || tmp.Kind != "session-key" || tmp.Lifetime != cred.ShortTerm || tmp.Severity != cred.Medium {
		t.Errorf("temp = %+v", tmp)
	}
	sso := find(cs, func(c cred.Credential) bool { return c.Kind == "sso-access-token" && !c.Expired })
	if sso == nil || sso.Account != "corp.awsapps.com" || sso.ExpiresAt != "2026-10-22T20:00:00Z" || sso.Severity != cred.Medium {
		t.Errorf("sso = %+v", sso)
	}
	if old := find(cs, func(c cred.Credential) bool { return c.Kind == "sso-access-token" && c.Expired }); old == nil || old.Severity != cred.Low {
		t.Errorf("expired sso = %+v", old)
	}
	if cli := find(cs, func(c cred.Credential) bool { return c.Source == "aws-cli-cache" }); cli == nil || cli.Account != "Admin (account 1234…9012)" || cli.Expired {
		t.Errorf("cli cache = %+v", cli)
	}
}

func TestGCloud(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "gcp")
	if adc := find(cs, byKind("user-refresh-token")); adc == nil || adc.Account != "alice@example.com" || adc.Severity != cred.High {
		t.Errorf("adc = %+v", adc)
	}
	if sa := find(cs, byKind("service-account-key")); sa == nil || sa.Account != "deploy@demo-123.iam.gserviceaccount.com" || sa.Severity != cred.Critical {
		t.Errorf("sa = %+v", sa)
	}
	if db := find(cs, byKind("credential-store")); db == nil || !strings.Contains(strings.Join(db.Notes, ""), "1 stored refresh token") {
		t.Errorf("db = %+v", db)
	}
}

func TestAzure(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "azure")
	if len(cs) != 2 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	if c := find(cs, byKind("token-cache")); c == nil || c.Account != "alice@example.com" || c.Severity != cred.High || !strings.Contains(c.Notes[0], "2 subscription") {
		t.Errorf("cache = %+v", c)
	}
	if c := find(cs, byKind("service-principal-secret")); c == nil || c.Severity != cred.Critical || !strings.HasPrefix(c.Account, "11111111") {
		t.Errorf("sp = %+v", c)
	}
}

func TestDocker(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "docker")
	if len(cs) != 2 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	if c := find(cs, byKind("registry-basic-auth")); c == nil || c.Account != "alice@index.docker.io" || c.Severity != cred.High {
		t.Errorf("auth = %+v", c)
	}
	if c := find(cs, byKind("credential-store")); c == nil || c.Account != "osxkeychain" || c.Severity != cred.Info || !strings.Contains(c.Notes[0], "ghcr.io") {
		t.Errorf("store = %+v", c)
	}
}

func TestKube(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "kubernetes")
	if len(cs) != 4 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	admin := find(cs, byAccount("admin"))
	if admin == nil || admin.Kind != "client-certificate" || admin.Severity != cred.High || admin.Expired || admin.ExpiresAt == "" {
		t.Fatalf("admin = %+v", admin)
	}
	n := strings.Join(admin.Notes, "|")
	if !strings.Contains(n, "kube-admin (system:masters)") || !strings.Contains(n, "prod-admin → prod.k8s.example.com:6443 (ns kube-system) [current]") {
		t.Errorf("admin notes = %q", n)
	}
	if old := find(cs, byAccount("old")); old == nil || !old.Expired || old.Severity != cred.Low || !strings.Contains(strings.Join(old.Notes, ""), "not referenced") {
		t.Errorf("old = %+v", old)
	}
	if sa := find(cs, byAccount("sa-token")); sa == nil || sa.Kind != "static-token" || !strings.Contains(strings.Join(sa.Notes, ""), "JWT") {
		t.Errorf("sa = %+v", sa)
	}
	if ex := find(cs, byAccount("eks-user")); ex == nil || ex.Kind != "exec-plugin" || ex.Severity != cred.Low || ex.Fingerprint != "" || !strings.Contains(ex.Summary, "aws eks get-token") {
		t.Errorf("exec = %+v", ex)
	}
}

func TestSSH(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "ssh")
	plain := find(cs, func(c cred.Credential) bool { return strings.HasSuffix(c.Location, "id_ed25519") })
	if plain == nil || plain.Protected || plain.Severity != cred.High || plain.Account != "alice@laptop" || !strings.Contains(plain.Summary, "ssh-ed25519") {
		t.Fatalf("plain = %+v", plain)
	}
	if n := strings.Join(plain.Notes, "|"); !strings.Contains(n, "default identity") || !strings.Contains(n, "used for hosts: *") {
		t.Errorf("plain notes = %q", n)
	}
	enc := find(cs, func(c cred.Credential) bool { return strings.HasSuffix(c.Location, "id_rsa") })
	if enc == nil || !enc.Protected || enc.Severity != cred.Low || !strings.Contains(enc.Summary, "ssh-rsa") || !strings.Contains(strings.Join(enc.Notes, "|"), "github.com") {
		t.Errorf("enc = %+v", enc)
	}
	pemk := find(cs, func(c cred.Credential) bool { return strings.HasSuffix(c.Location, "legacy.pem") })
	if pemk == nil || !pemk.Protected {
		t.Errorf("pem = %+v", pemk)
	} else if runtime.GOOS != "windows" && !strings.Contains(strings.Join(pemk.Notes, "|"), "0644") {
		// Unix file modes are meaningless on Windows (every file reads 0666),
		// so the permissions note is only asserted off Windows.
		t.Errorf("pem perms note = %+v", pemk)
	}
	if dk := find(cs, func(c cred.Credential) bool { return strings.HasSuffix(c.Location, "deploy_key") }); dk == nil || dk.Protected || !strings.Contains(strings.Join(dk.Notes, "|"), "bastion") {
		t.Errorf("deploy key = %+v", dk)
	}
	if fa := find(cs, byKind("agent-forwarding")); fa == nil || fa.Account != "bastion" || fa.Severity != cred.Low || fa.Line != 5 {
		t.Errorf("forward agent = %+v", fa)
	}
	if find(cs, func(c cred.Credential) bool {
		return strings.Contains(c.Location, "known_hosts") || strings.HasSuffix(c.Location, ".pub")
	}) != nil {
		t.Error("non-key files reported")
	}
}

func TestAITools(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "ai-tools")
	want := map[string]string{"claude-code": cred.ServiceAnthropic, "codex-cli": cred.ServiceOpenAI, "github-copilot": cred.ServiceGitHub, "gemini-cli": cred.ServiceGoogleAI, "huggingface-cli": cred.ServiceHuggingFace}
	for src, svc := range want {
		if c := find(cs, func(c cred.Credential) bool { return c.Source == src }); c == nil || c.Service != svc || c.Fingerprint == "" {
			t.Errorf("%s = %+v", src, c)
		}
	}
	if n := len(cs); n != 6 {
		t.Errorf("want 6 (codex has key + login), got %d", n)
	}
	if cp := find(cs, func(c cred.Credential) bool { return c.Source == "github-copilot" }); cp.Account != "alice@github.com" {
		t.Errorf("copilot account = %q", cp.Account)
	}
}

func TestEnvVars(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "env")
	got := map[string]cred.Credential{}
	for _, c := range cs {
		got[c.Location] = c
	}
	for _, name := range []string{"env:ANTHROPIC_API_KEY", "env:OPENAI_API_KEY", "env:NPM_TOKEN", "env:GH_TOKEN", "env:AWS_SECRET_ACCESS_KEY"} {
		if _, ok := got[name]; !ok {
			t.Errorf("missing %s in %+v", name, cs)
		}
	}
	for _, name := range []string{"env:MY_SERVICE_TOKEN", "env:SSH_AUTH_SOCK", "env:PATH", "env:AWS_ACCESS_KEY_ID"} {
		if _, ok := got[name]; ok {
			t.Errorf("%s should not be reported", name)
		}
	}
	if a := got["env:AWS_SECRET_ACCESS_KEY"]; a.Kind != "session-key" || a.Lifetime != cred.ShortTerm {
		t.Errorf("ASIA pair should be short-term: %+v", a)
	}
	if o := got["env:OPENAI_API_KEY"]; o.Service != cred.ServiceOpenAI {
		t.Errorf("bare sk- key = %+v", o)
	}
}

func TestShellRC(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "shell-rc")
	if len(cs) != 3 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	if find(cs, byAccount("GITHUB_TOKEN")) != nil {
		t.Error("dynamic $(...) value must be skipped")
	}
	if s := find(cs, byAccount("STRIPE_SECRET_KEY")); s == nil || s.Service != cred.ServiceStripe || s.Severity != cred.Critical || s.Line != 4 {
		t.Errorf("stripe = %+v", s)
	}
	if o := find(cs, byAccount("OPENAI_API_KEY")); o == nil || !strings.Contains(o.Location, "config.fish") {
		t.Errorf("fish = %+v", o)
	}
}

func TestShellHistory(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "shell-history")
	if len(cs) != 4 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	aws := find(cs, byAccount("AWS_SECRET_ACCESS_KEY"))
	if aws == nil || aws.Line != 1 || aws.Severity != cred.High || !strings.Contains(strings.Join(aws.Notes, ""), "appears 2 times") {
		t.Errorf("aws = %+v", aws)
	}
	if b := find(cs, byKind("bearer-token")); b == nil || b.Line != 3 {
		t.Errorf("bearer = %+v", b)
	}
	if n := find(cs, func(c cred.Credential) bool { return c.Service == cred.ServiceNPM }); n == nil || n.Line != 4 {
		t.Errorf("npm flag = %+v", n)
	}
	if g := find(cs, func(c cred.Credential) bool { return c.Service == cred.ServiceGitHub }); g == nil || g.Kind != "classic-pat" || g.Line != 6 {
		t.Errorf("ghp in pipe = %+v", g)
	}
}

func TestDotenv(t *testing.T) {
	f := NewFixture(t)
	cs := collect(t, f, "dotenv")
	if len(cs) != 3 {
		t.Fatalf("got %d: %+v", len(cs), cs)
	}
	if d := find(cs, byAccount("DATABASE_URL")); d == nil || d.Service != cred.ServiceDatabase || *d.AgeDays != 200 {
		t.Errorf("db = %+v", d)
	}
	if o := find(cs, byAccount("OPENAI_API_KEY")); o == nil || o.Line != 2 {
		t.Errorf("openai = %+v", o)
	}
	if s := find(cs, byAccount("SLACK_BOT_TOKEN")); s == nil || !strings.Contains(s.Location, ".env.production") {
		t.Errorf("slack = %+v", s)
	}
	for _, c := range cs {
		if strings.Contains(c.Location, "node_modules") || c.Account == "SESSION_SECRET" || c.Account == "STRIPE_SECRET_KEY" || c.Account == "API_SECRET" {
			t.Errorf("should have been skipped: %+v", c)
		}
	}
	// No --dir: nothing is walked.
	e := envFor(f)
	e.Dirs = nil
	if cs, _ := (dotenv{}).Collect(e); len(cs) != 0 {
		t.Errorf("without dirs got %+v", cs)
	}
}

func TestMissingHomeIsQuiet(t *testing.T) {
	e := &Env{Home: t.TempDir(), Now: time0(), Getenv: func(string) string { return "" }, Environ: func() []string { return nil }}
	for _, p := range All() {
		cs, probs := p.Collect(e)
		if len(cs) != 0 || len(probs) != 0 {
			t.Errorf("%s on empty home: %+v %+v", p.ID(), cs, probs)
		}
	}
}

func TestInspectKey(t *testing.T) {
	for _, tc := range []struct {
		body             string
		isKey, encrypted bool
		keyType          string
	}{
		{testfixture.OpenSSHKey("ssh-ed25519", false), true, false, "ssh-ed25519"},
		{testfixture.OpenSSHKey("ssh-rsa", true), true, true, "ssh-rsa"},
		{"-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n", true, true, "PKCS#8"},
		{"-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n", true, false, "PKCS#8"},
		{"-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n", true, false, "PEM EC"},
		{"PuTTY-User-Key-File-3: ssh-ed25519\nEncryption: aes256-cbc\n", true, true, "ssh-ed25519"},
		{"ssh-ed25519 AAAA alice@laptop\n", false, false, ""},
		{"# ssh config\nHost x\n", false, false, ""},
	} {
		k, ok := inspectKey([]byte(tc.body))
		if ok != tc.isKey || (ok && (k.encrypted != tc.encrypted || k.keyType != tc.keyType)) {
			t.Errorf("inspectKey(%.30q) = %+v, %v; want key=%v enc=%v type=%s", tc.body, k, ok, tc.isKey, tc.encrypted, tc.keyType)
		}
	}
}

func TestParseAssignment(t *testing.T) {
	for _, tc := range []struct{ in, k, v string }{
		{`export FOO="bar baz" # c`, "FOO", "bar baz"},
		{`FOO='x'`, "FOO", "x"},
		{`set -gx FOO value`, "FOO", "value"},
		{`FOO=plain # comment`, "FOO", "plain"},
		{`# FOO=x`, "", ""},
		{`echo hi`, "", ""},
		{`1BAD=x`, "", ""},
	} {
		k, v, ok := parseAssignment(tc.in)
		if (tc.k == "") == ok || k != tc.k || v != tc.v {
			t.Errorf("parseAssignment(%q) = %q %q %v", tc.in, k, v, ok)
		}
	}
}
