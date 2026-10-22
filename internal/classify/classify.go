// Package classify recognises what kind of secret a value is from its shape
// (token prefixes) or from the name of the variable that holds it. It never
// returns the value it was given.
package classify

import (
	"regexp"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// Result describes a recognised secret.
type Result struct {
	Service  string
	Kind     string
	Lifetime cred.Lifetime
	Severity cred.Severity
	// Label is a short human description such as "GitHub classic PAT".
	Label string
}

type prefixRule struct {
	prefix string
	minLen int
	Result
}

// Token prefixes, most specific first.
var prefixRules = []prefixRule{
	{"github_pat_", 30, Result{cred.ServiceGitHub, "fine-grained-pat", cred.LongTerm, cred.Medium, "GitHub fine-grained PAT"}},
	{"ghp_", 30, Result{cred.ServiceGitHub, "classic-pat", cred.LongTerm, cred.High, "GitHub classic PAT"}},
	{"gho_", 30, Result{cred.ServiceGitHub, "oauth-token", cred.LongTerm, cred.High, "GitHub OAuth token"}},
	{"ghu_", 30, Result{cred.ServiceGitHub, "user-to-server-token", cred.ShortTerm, cred.Medium, "GitHub user-to-server token"}},
	{"ghs_", 30, Result{cred.ServiceGitHub, "installation-token", cred.ShortTerm, cred.Medium, "GitHub App installation token"}},
	{"ghr_", 30, Result{cred.ServiceGitHub, "refresh-token", cred.LongTerm, cred.Medium, "GitHub refresh token"}},
	{"glpat-", 20, Result{cred.ServiceGitLab, "personal-access-token", cred.LongTerm, cred.High, "GitLab PAT"}},
	{"npm_", 30, Result{cred.ServiceNPM, "access-token", cred.LongTerm, cred.High, "npm access token"}},
	{"pypi-", 40, Result{cred.ServicePyPI, "api-token", cred.LongTerm, cred.High, "PyPI API token"}},
	{"AKIA", 20, Result{cred.ServiceAWS, "access-key", cred.LongTerm, cred.Critical, "AWS long-term access key"}},
	{"ASIA", 20, Result{cred.ServiceAWS, "session-key", cred.ShortTerm, cred.Medium, "AWS temporary access key"}},
	{"sk-ant-", 20, Result{cred.ServiceAnthropic, "api-key", cred.LongTerm, cred.High, "Anthropic API key"}},
	{"sk-proj-", 20, Result{cred.ServiceOpenAI, "api-key", cred.LongTerm, cred.High, "OpenAI project API key"}},
	{"sk_live_", 20, Result{cred.ServiceStripe, "secret-key", cred.LongTerm, cred.Critical, "Stripe live secret key"}},
	{"rk_live_", 20, Result{cred.ServiceStripe, "restricted-key", cred.LongTerm, cred.High, "Stripe live restricted key"}},
	{"sk_test_", 20, Result{cred.ServiceStripe, "test-key", cred.LongTerm, cred.Low, "Stripe test key"}},
	{"xoxb-", 20, Result{cred.ServiceSlack, "bot-token", cred.LongTerm, cred.High, "Slack bot token"}},
	{"xoxp-", 20, Result{cred.ServiceSlack, "user-token", cred.LongTerm, cred.High, "Slack user token"}},
	{"xoxa-", 20, Result{cred.ServiceSlack, "app-token", cred.LongTerm, cred.High, "Slack app token"}},
	{"xoxr-", 20, Result{cred.ServiceSlack, "refresh-token", cred.LongTerm, cred.High, "Slack refresh token"}},
	{"hf_", 30, Result{cred.ServiceHuggingFace, "access-token", cred.LongTerm, cred.Medium, "Hugging Face token"}},
	{"AIza", 35, Result{cred.ServiceGoogleAI, "api-key", cred.LongTerm, cred.Medium, "Google API key"}},
	{"ya29.", 20, Result{cred.ServiceGCP, "access-token", cred.ShortTerm, cred.Medium, "Google OAuth access token"}},
	{"1//", 20, Result{cred.ServiceGCP, "refresh-token", cred.LongTerm, cred.High, "Google OAuth refresh token"}},
	{"dop_v1_", 30, Result{cred.ServiceGeneric, "api-token", cred.LongTerm, cred.High, "DigitalOcean token"}},
	{"SG.", 40, Result{cred.ServiceGeneric, "api-key", cred.LongTerm, cred.High, "SendGrid API key"}},
	// A bare "sk-" is OpenAI's older key format; it needs the length check
	// because "sk-" also starts plenty of harmless strings.
	{"sk-", 40, Result{cred.ServiceOpenAI, "api-key", cred.LongTerm, cred.High, "OpenAI API key"}},
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	jwtRe  = regexp.MustCompile(`^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
)

// Token recognises a secret from its shape alone.
func Token(value string) (Result, bool) {
	value = strings.TrimSpace(value)
	for _, r := range prefixRules {
		if strings.HasPrefix(value, r.prefix) && len(value) >= r.minLen {
			return r.Result, true
		}
	}
	if strings.HasPrefix(value, "-----BEGIN") && strings.Contains(value, "PRIVATE KEY") {
		return Result{cred.ServiceGeneric, "private-key", cred.LongTerm, cred.Critical, "private key"}, true
	}
	if jwtRe.MatchString(value) {
		return Result{cred.ServiceGeneric, "jwt", cred.ShortTerm, cred.Medium, "JSON Web Token"}, true
	}
	return Result{}, false
}

// IsLegacyNPMToken reports whether a value has the UUID shape of a legacy
// npm token, which never expires and bypasses 2FA.
func IsLegacyNPMToken(value string) bool { return uuidRe.MatchString(strings.TrimSpace(value)) }

type nameRule struct {
	match func(string) bool
	Result
}

func exact(names ...string) func(string) bool {
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	return func(s string) bool { return set[s] }
}

func suffix(suf string) func(string) bool {
	return func(s string) bool { return strings.HasSuffix(s, suf) }
}

func contains(sub string) func(string) bool {
	return func(s string) bool { return strings.Contains(s, sub) }
}

// Variable names that carry a known service's secret.
var nameRules = []nameRule{
	{exact("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_API_KEY"), Result{cred.ServiceAnthropic, "api-key", cred.LongTerm, cred.High, "Anthropic API key"}},
	{exact("OPENAI_API_KEY", "OPENAI_ADMIN_KEY"), Result{cred.ServiceOpenAI, "api-key", cred.LongTerm, cred.High, "OpenAI API key"}},
	{exact("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_API_KEY"), Result{cred.ServiceGoogleAI, "api-key", cred.LongTerm, cred.Medium, "Google AI API key"}},
	{exact("OPENROUTER_API_KEY", "GROQ_API_KEY", "MISTRAL_API_KEY", "DEEPSEEK_API_KEY", "XAI_API_KEY", "TOGETHER_API_KEY", "COHERE_API_KEY", "PERPLEXITY_API_KEY", "REPLICATE_API_TOKEN", "FIREWORKS_API_KEY"), Result{cred.ServiceGeneric, "ai-api-key", cred.LongTerm, cred.Medium, "AI provider API key"}},
	{exact("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACEHUB_API_TOKEN"), Result{cred.ServiceHuggingFace, "access-token", cred.LongTerm, cred.Medium, "Hugging Face token"}},
	{exact("GH_TOKEN", "GITHUB_TOKEN", "GITHUB_PAT", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN", "HOMEBREW_GITHUB_API_TOKEN"), Result{cred.ServiceGitHub, "token", cred.LongTerm, cred.High, "GitHub token"}},
	{exact("GITLAB_TOKEN", "GITLAB_PRIVATE_TOKEN", "CI_JOB_TOKEN"), Result{cred.ServiceGitLab, "token", cred.LongTerm, cred.High, "GitLab token"}},
	{exact("NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_AUTH_TOKEN"), Result{cred.ServiceNPM, "access-token", cred.LongTerm, cred.High, "npm token"}},
	{exact("TWINE_PASSWORD", "PYPI_TOKEN", "PYPI_API_TOKEN", "UV_PUBLISH_TOKEN", "POETRY_PYPI_TOKEN_PYPI", "FLIT_PASSWORD"), Result{cred.ServicePyPI, "api-token", cred.LongTerm, cred.High, "PyPI publish credential"}},
	{exact("AWS_SECRET_ACCESS_KEY"), Result{cred.ServiceAWS, "access-key", cred.LongTerm, cred.Critical, "AWS secret access key"}},
	{exact("AWS_SESSION_TOKEN"), Result{cred.ServiceAWS, "session-token", cred.ShortTerm, cred.Medium, "AWS session token"}},
	{exact("AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET"), Result{cred.ServiceAzure, "client-secret", cred.LongTerm, cred.Critical, "Azure service principal secret"}},
	{exact("GOOGLE_CREDENTIALS", "GCP_SERVICE_ACCOUNT_KEY", "GCLOUD_SERVICE_KEY"), Result{cred.ServiceGCP, "service-account-key", cred.LongTerm, cred.Critical, "GCP service account key"}},
	{exact("DOCKER_PASSWORD", "DOCKER_TOKEN", "DOCKERHUB_TOKEN", "REGISTRY_PASSWORD", "GHCR_TOKEN"), Result{cred.ServiceDocker, "registry-password", cred.LongTerm, cred.High, "container registry credential"}},
	{exact("KUBE_TOKEN", "KUBERNETES_TOKEN"), Result{cred.ServiceKubernetes, "token", cred.LongTerm, cred.High, "Kubernetes token"}},
	{exact("STRIPE_SECRET_KEY", "STRIPE_API_KEY"), Result{cred.ServiceStripe, "secret-key", cred.LongTerm, cred.Critical, "Stripe secret key"}},
	{exact("SLACK_TOKEN", "SLACK_BOT_TOKEN", "SLACK_USER_TOKEN", "SLACK_APP_TOKEN", "SLACK_WEBHOOK_URL"), Result{cred.ServiceSlack, "token", cred.LongTerm, cred.High, "Slack token"}},
	{exact("DATABASE_URL", "DB_PASSWORD", "POSTGRES_PASSWORD", "MYSQL_ROOT_PASSWORD", "MYSQL_PASSWORD", "MONGODB_URI", "MONGO_URL", "REDIS_URL", "REDIS_PASSWORD", "PGPASSWORD"), Result{cred.ServiceDatabase, "database-credential", cred.LongTerm, cred.Medium, "database credential"}},
}

// Generic secret-looking names.
var genericNameRules = []nameRule{
	{suffix("_PRIVATE_KEY"), Result{cred.ServiceGeneric, "private-key", cred.LongTerm, cred.High, "private key"}},
	{suffix("_SECRET_KEY"), Result{cred.ServiceGeneric, "secret-key", cred.LongTerm, cred.Medium, "secret key"}},
	{suffix("_SECRET_ACCESS_KEY"), Result{cred.ServiceGeneric, "secret-key", cred.LongTerm, cred.Medium, "secret key"}},
	{suffix("_CLIENT_SECRET"), Result{cred.ServiceGeneric, "client-secret", cred.LongTerm, cred.Medium, "OAuth client secret"}},
	{suffix("_API_KEY"), Result{cred.ServiceGeneric, "api-key", cred.LongTerm, cred.Medium, "API key"}},
	{suffix("_ACCESS_TOKEN"), Result{cred.ServiceGeneric, "access-token", cred.Unknown, cred.Medium, "access token"}},
	{suffix("_REFRESH_TOKEN"), Result{cred.ServiceGeneric, "refresh-token", cred.LongTerm, cred.Medium, "refresh token"}},
	{suffix("_AUTH_TOKEN"), Result{cred.ServiceGeneric, "token", cred.LongTerm, cred.Medium, "auth token"}},
	{suffix("_TOKEN"), Result{cred.ServiceGeneric, "token", cred.Unknown, cred.Medium, "token"}},
	{suffix("_SECRET"), Result{cred.ServiceGeneric, "secret", cred.LongTerm, cred.Medium, "secret"}},
	{suffix("_KEY"), Result{cred.ServiceGeneric, "key", cred.LongTerm, cred.Medium, "key"}},
	{contains("PASSWORD"), Result{cred.ServiceGeneric, "password", cred.LongTerm, cred.Medium, "password"}},
	{contains("PASSWD"), Result{cred.ServiceGeneric, "password", cred.LongTerm, cred.Medium, "password"}},
	{suffix("_CREDENTIALS"), Result{cred.ServiceGeneric, "credential", cred.LongTerm, cred.Medium, "credential"}},
	{suffix("_DSN"), Result{cred.ServiceDatabase, "database-credential", cred.LongTerm, cred.Medium, "database DSN"}},
}

// Names that end in _KEY or _TOKEN but hold nothing secret.
var benignNames = map[string]bool{
	"SSH_AUTH_SOCK": true, "GPG_TTY": true, "PUBLIC_KEY": true, "SSH_PUBLIC_KEY": true,
	"CSRF_TOKEN": true, "XSRF_TOKEN": true, "TERM_SESSION_ID": true, "VSCODE_GIT_IPC_HANDLE": true,
	"GPG_KEY_ID": true, "SIGNING_KEY_ID": true, "AWS_ACCESS_KEY_ID": true, "AZURE_CLIENT_ID": true,
	"AWS_PROFILE": true, "KEY_LAYOUT": true, "XDG_SESSION_KEY": true, "APP_KEY_ID": true,
}

// IsSecretName reports whether an environment variable name looks like it
// holds a secret.
func IsSecretName(name string) bool {
	if benignNames[name] {
		return false
	}
	for _, r := range nameRules {
		if r.match(name) {
			return true
		}
	}
	for _, r := range genericNameRules {
		if r.match(name) {
			return true
		}
	}
	return false
}

// Var classifies a name=value pair. It reports false when the name does not
// look secret-bearing or the value is obviously a placeholder.
func Var(name, value string) (Result, bool) {
	name = strings.ToUpper(strings.TrimSpace(name))
	value = strings.TrimSpace(value)
	if benignNames[name] || IsPlaceholder(value) {
		return Result{}, false
	}
	// Names that are only public identifiers.
	if strings.HasPrefix(name, "NEXT_PUBLIC_") || strings.HasPrefix(name, "VITE_") || strings.HasPrefix(name, "REACT_APP_") || strings.HasPrefix(name, "PUBLIC_") {
		if r, ok := Token(value); ok {
			r.Severity = min(r.Severity, cred.Medium)
			return r, true
		}
		return Result{}, false
	}
	if res, ok := Token(value); ok {
		// Clerk issues sk_live_/sk_test_ keys in Stripe's format; only call
		// it Stripe when the variable name agrees.
		if res.Service == cred.ServiceStripe && !strings.Contains(name, "STRIPE") {
			res.Service, res.Kind = cred.ServiceGeneric, "secret-key"
			res.Label = strings.Replace(res.Label, "Stripe", "Stripe-format", 1)
		}
		// A recognised token shape wins over the variable name, but a
		// service-specific name may refine a generic shape.
		if res.Service == cred.ServiceGeneric {
			for _, r := range nameRules {
				if r.match(name) {
					return r.Result, true
				}
			}
		}
		return res, true
	}
	for _, r := range nameRules {
		if r.match(name) {
			res := r.Result
			if res.Service == cred.ServiceDatabase && !URLHasPassword(value) && !looksLikePassword(name) {
				// DATABASE_URL without a password is not a credential.
				return Result{}, false
			}
			return res, true
		}
	}
	for _, r := range genericNameRules {
		if r.match(name) {
			return r.Result, true
		}
	}
	if URLHasPassword(value) {
		return Result{cred.ServiceGeneric, "url-with-password", cred.LongTerm, cred.Medium, "URL with embedded password"}, true
	}
	return Result{}, false
}

func looksLikePassword(name string) bool {
	return strings.Contains(name, "PASSWORD") || strings.Contains(name, "PASSWD")
}

var placeholderRe = regexp.MustCompile(`(?i)^(?:<.*>|\$\{?[A-Z_][A-Z0-9_]*\}?|\$\(.*\)|` + "`.*`" + `|your[-_ ].*|change[-_ ]?me.*|replace[-_ ]?me.*|x{3,}|\*{3,}|\.{3,}|todo|tbd|fixme|placeholder|example|dummy|redacted|secret|password|none|null|undefined|true|false|0+)$`)

// IsPlaceholder reports whether a value is clearly not a real secret: empty,
// too short, a template reference or a well-known dummy.
func IsPlaceholder(value string) bool {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`)
	if len(value) < 8 {
		return true
	}
	if placeholderRe.MatchString(value) {
		return true
	}
	lower := strings.ToLower(value)
	for _, w := range []string{"your-", "your_", "<your", "example.com", "changeme", "xxxxxxxx", "replace-with", "insert-", "placeholder", "dummy", "{{", "${"} {
		if strings.Contains(lower, w) {
			return true
		}
	}
	return false
}

var urlCredRe = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*://[^/@\s:]+:([^@\s]+)@`)

// URLHasPassword reports whether a URL carries user:password@ credentials.
func URLHasPassword(value string) bool {
	m := urlCredRe.FindStringSubmatch(strings.TrimSpace(value))
	return m != nil && !IsPlaceholder(m[1])
}

// URLPassword extracts the password part of a user:password@ URL, or "".
func URLPassword(value string) string {
	m := urlCredRe.FindStringSubmatch(strings.TrimSpace(value))
	if m == nil {
		return ""
	}
	return m[1]
}
