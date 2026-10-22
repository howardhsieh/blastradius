package scan

import (
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// adviceRule maps a credential to a remediation. Rules are matched in
// order; the first whose match function returns true wins.
type adviceRule struct {
	key    string
	match  func(c cred.Credential) bool
	title  string
	detail string
}

func is(service string, kinds ...string) func(cred.Credential) bool {
	return func(c cred.Credential) bool {
		if c.Service != service {
			return false
		}
		if len(kinds) == 0 {
			return true
		}
		for _, k := range kinds {
			if c.Kind == k {
				return true
			}
		}
		return false
	}
}

func source(src string) func(cred.Credential) bool {
	return func(c cred.Credential) bool { return c.Source == src }
}

var adviceRules = []adviceRule{
	// Reach-based rules come first: a probe answer is more specific than
	// the credential's shape.
	{"revoked", func(c cred.Credential) bool { return probed(c, func(r *cred.Reach) bool { return !r.Live }) },
		"Delete credentials the service no longer accepts",
		"The probe got a 401 for these. They cannot be used, but they clutter the machine and hide live ones; remove the file or line. If you did not revoke them yourself, treat the account as having been through a rotation and check its audit log."},
	{"aws-root", func(c cred.Credential) bool {
		return c.Service == cred.ServiceAWS && probed(c, func(r *cred.Reach) bool { return r.Admin })
	},
		"Delete the ROOT access key now and lock the root user behind hardware MFA",
		"sts:GetCallerIdentity says this key is the account root user: no IAM policy limits it, it can close the account and delete every backup. In the console as root: Security credentials → Access keys → Deactivate, then Delete; enable a hardware MFA device; create an IAM Identity Center or IAM user for daily work. Review CloudTrail for the key's history."},
	{"npm-automation", func(c cred.Credential) bool {
		return c.Service == cred.ServiceNPM && probed(c, func(r *cred.Reach) bool { return r.Bypass2FA })
	},
		"Revoke the npm automation token: it publishes without 2FA",
		"An automation token is meant for CI, not a laptop; whoever copies it can publish to every package you own with no second factor, which is exactly how Shai-Hulud spread. Revoke it at npmjs.com → Access Tokens, publish from CI with trusted publishing (OIDC), and keep only a read-only or granular token locally."},
	{"aws-long-term", is(cred.ServiceAWS, "access-key"),
		"Rotate the long-term AWS access key and move the profile to short-lived credentials",
		"Create a new key only if you must, then delete the old one in IAM. Better: `aws configure sso` (IAM Identity Center) or `aws sts assume-role` behind MFA, so what sits on disk expires within hours."},
	{"gcp-sa-key", is(cred.ServiceGCP, "service-account-key"),
		"Delete the service-account key file and disable the key in IAM",
		"Service-account keys never expire. Use `gcloud auth application-default login` for local work, or workload identity federation for automation, and set the iam.disableServiceAccountKeyCreation org policy."},
	{"azure-sp", is(cred.ServiceAzure, "service-principal-secret", "service-principal-certificate"),
		"Rotate the service principal secret and stop logging in with it from a laptop",
		"Reset the credential in Entra ID (App registrations → Certificates & secrets), run `az logout`, and use `az login` with your user identity plus PIM for elevated roles."},
	{"npm-legacy", is(cred.ServiceNPM, "legacy-token"),
		"Revoke the legacy npm token today",
		"Legacy (UUID) tokens never expire and skip 2FA; they are exactly what the Shai-Hulud worm used to publish itself. Revoke it at npmjs.com → Access Tokens, then create a granular token limited to the packages you publish, with an expiry and 2FA required for publish."},
	{"registry-auth", func(c cred.Credential) bool { return c.Source == "npmrc" && c.Service != cred.ServiceNPM },
		"Replace the _auth / _password entry in .npmrc with a scoped registry token",
		"Private registries (Artifactory, GitHub Packages, Verdaccio) all issue per-user tokens with an expiry; a base64 user:password line is your account password on disk."},
	{"npm", is(cred.ServiceNPM),
		"Replace the npm token with a granular token (package-scoped, expiring) and require 2FA for publish",
		"At npmjs.com → Access Tokens → Generate New Token → Granular: pick the packages, set read-only unless you publish from this machine, set an expiry, and keep 'bypass 2FA' off. Better still, publish from CI with trusted publishing (OIDC) and keep no publish token on the laptop."},
	{"pypi", is(cred.ServicePyPI),
		"Scope or remove the PyPI upload token",
		"Project-scoped tokens with 2FA on the account limit the blast radius; trusted publishing from GitHub Actions removes the need for a token on disk altogether."},
	{"github-oauth", is(cred.ServiceGitHub, "oauth-token", "classic-pat", "token"),
		"Narrow the GitHub token: fine-grained PAT with an expiry, or re-login to gh with fewer scopes",
		"Classic tokens and gh's default OAuth grant cover every repository you can write to. Revoke it at github.com → Settings → Developer settings, then use a fine-grained PAT scoped to the repositories you need (`gh auth login --with-token`) or `gh auth refresh --remove-scopes workflow,gist`. Keep it out of GH_TOKEN in your shell rc."},
	{"git-store", source("git-credentials"),
		"Stop using credential.helper=store",
		"Delete the plaintext file and switch to a keychain-backed helper: `git config --global credential.helper osxkeychain` (macOS), `manager` (Windows) or `libsecret` (Linux). Rotate the password or token that was in it."},
	{"netrc", source("netrc"),
		"Move .netrc secrets to a credential helper or short-lived tokens, and rotate them",
		"~/.netrc is plaintext and read by curl, pip and git alike. Prefer per-tool keychain helpers; where a tool insists on .netrc, keep it 0600 and use a token scoped to that one job."},
	{"ssh-nopass", func(c cred.Credential) bool {
		return c.Service == cred.ServiceSSH && c.Kind == "private-key" && !c.Protected
	},
		"Add a passphrase to the SSH key and load it through ssh-agent",
		"`ssh-keygen -p -o -a 64 -f <key>` encrypts the key in place; `ssh-add --apple-use-keychain <key>` (macOS) or a hardware key (`ssh-keygen -t ed25519-sk`) keeps the private material out of reach of a file-copying stealer. Rotate the key on servers and GitHub if it may already be copied."},
	{"ssh-forward", is(cred.ServiceSSH, "agent-forwarding"),
		"Turn off ForwardAgent, or restrict it to hosts you fully trust",
		"Use `ProxyJump` instead of agent forwarding for bastions, and add `AddKeysToAgent confirm` so each signature needs a click."},
	{"docker-plain", is(cred.ServiceDocker, "registry-basic-auth", "registry-password"),
		"Run `docker logout` and configure a credential store",
		"Set `\"credsStore\": \"osxkeychain\"` (or `pass`, `wincred`, `desktop`) in ~/.docker/config.json, log in again, and rotate the registry password or token. Prefer per-registry access tokens over your account password."},
	{"kube-static", is(cred.ServiceKubernetes, "static-token", "client-certificate", "basic-auth", "token-file", "auth-provider"),
		"Replace static kubeconfig credentials with an exec plugin or OIDC",
		"Cloud clusters issue short-lived tokens through `aws eks update-kubeconfig`, `gke-gcloud-auth-plugin` or `kubelogin`. For self-hosted clusters use OIDC. Rotate or delete the service account / certificate that is in the file now."},
	{"gcp-user", is(cred.ServiceGCP, "user-refresh-token", "credential-store"),
		"Revoke gcloud refresh tokens you do not need, and re-authenticate only where required",
		"`gcloud auth revoke --all` and `gcloud auth application-default revoke` invalidate the stored refresh tokens. Keep one login per machine, and prefer impersonating a least-privilege service account (`--impersonate-service-account`) over a broad user identity."},
	{"azure-cache", is(cred.ServiceAzure, "token-cache"),
		"Log out of the Azure CLI when not in use, and keep the token cache encrypted",
		"`az logout` clears the cache. On Linux install a keyring so MSAL encrypts the cache; set `az config set core.encrypt_token_cache=true` where supported."},
	{"ai-keys", func(c cred.Credential) bool {
		switch c.Service {
		case cred.ServiceAnthropic, cred.ServiceOpenAI, cred.ServiceGoogleAI, cred.ServiceHuggingFace:
			return true
		}
		return c.Kind == "ai-api-key"
	},
		"Rotate AI provider API keys, set spend limits, and stop exporting them globally",
		"Create workspace-scoped keys with a monthly budget in the provider console, delete the old one, and load the key per project (`op run`, direnv with a secret backend, or a `.envrc` that reads the keychain) instead of `export` in ~/.zshrc."},
	{"env-global", source("process-env"),
		"Remove secrets from the global environment",
		"Anything exported in your shell is handed to every program, including `npm install` scripts. Load tokens only inside the project that needs them, or use the tool's own credential store (`gh auth`, `aws configure sso`)."},
	{"shell-rc", source("shell-rc"),
		"Take literal secrets out of shell start-up files",
		"Replace `export NAME=value` with a lookup at use time: `export NAME=$(security find-generic-password -ws name)` on macOS, `op read`, or `pass`. Then rotate the value, because the file has been readable all along."},
	{"history", source("shell-history"),
		"Scrub the history file and rotate what was in it",
		"Delete the lines (`fc -R` after editing, or `history -c`) and set `setopt HIST_IGNORE_SPACE` / `HISTCONTROL=ignorespace` so a leading space keeps a command out of history. Treat every token that appeared as compromised."},
	{"dotenv", source("dotenv"),
		"Move project secrets out of .env files, or at least out of the tree",
		"Use a secret manager (`op run --env-file`, doppler, direnv + sops) so the plaintext never sits in the working copy; add `.env*` to a global gitignore; rotate anything that has lived in a .env file for months."},
	{"database", is(cred.ServiceDatabase),
		"Rotate database passwords found on this machine and prefer IAM/short-lived auth",
		"Cloud databases support IAM authentication (RDS, Cloud SQL) or short-lived certificates; for others, keep the password in the OS keychain or a secret manager."},
	{"short-lived", func(c cred.Credential) bool { return c.Lifetime == cred.ShortTerm },
		"Short-lived credentials: let them expire, and protect the login that mints them",
		"Session keys, SSO tokens and exec-plugin logins stop working on their own. Make sure the identity behind them (your SSO user, your cloud login) requires phishing-resistant MFA, and log out when you finish a session on a shared machine."},
	{"generic", func(c cred.Credential) bool { return true },
		"Rotate the remaining secrets and keep them in a credential store",
		"Any secret readable as a plain file is one `cat` away for malware running as you. Prefer the tool's own keychain-backed store, short-lived credentials, or hardware-backed keys."},
}

// Rule is one remediation rule as seen from outside the package: the SARIF
// reporter publishes the list as the tool's rules and tags every finding
// with the one that matched.
type Rule struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
}

// InventoryRule is the rule attached to credentials that need no
// remediation (expired, informational, already protected) so that every
// row still appears in a SARIF log.
var InventoryRule = Rule{ID: "inventory", Title: "Credential inventoried, no action needed",
	Detail: "The credential is expired, informational or already protected (for example a passphrase-protected SSH key); it is listed so the inventory is complete."}

// Rules returns every remediation rule in matching order, plus InventoryRule.
func Rules() []Rule {
	out := make([]Rule, 0, len(adviceRules)+1)
	for _, r := range adviceRules {
		out = append(out, Rule{ID: r.key, Title: r.title, Detail: r.detail})
	}
	return append(out, InventoryRule)
}

// RuleFor returns the rule that matched a credential.
func RuleFor(c cred.Credential) Rule {
	if !needsAdvice(c) {
		return InventoryRule
	}
	for _, r := range adviceRules {
		if r.match(c) {
			return Rule{ID: r.key, Title: r.title, Detail: r.detail}
		}
	}
	return InventoryRule
}

// remediationFor returns the one-line advice title for a credential.
func remediationFor(c cred.Credential) string {
	if !needsAdvice(c) {
		return ""
	}
	for _, r := range adviceRules {
		if r.match(c) {
			return r.title
		}
	}
	return ""
}

// needsAdvice is false for credentials that are expired, informational, or
// already protected well enough (a passphrase-protected key).
func needsAdvice(c cred.Credential) bool {
	if c.Expired || c.Severity == cred.Info {
		return false
	}
	if c.Protected && c.Severity <= cred.Low {
		return false
	}
	return true
}

// advise groups credentials by remediation and orders the groups by the
// worst credential they cover, then by how many they cover.
func advise(cs []cred.Credential) []Advice {
	type group struct {
		rule  adviceRule
		worst cred.Severity
		ids   []string
	}
	groups := map[string]*group{}
	var order []string
	for _, c := range cs {
		if !needsAdvice(c) {
			continue
		}
		for _, r := range adviceRules {
			if !r.match(c) {
				continue
			}
			g, ok := groups[r.key]
			if !ok {
				g = &group{rule: r}
				groups[r.key] = g
				order = append(order, r.key)
			}
			g.ids = append(g.ids, c.ID)
			if c.Severity > g.worst {
				g.worst = c.Severity
			}
			break
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		a, b := groups[order[i]], groups[order[j]]
		if a.worst != b.worst {
			return a.worst > b.worst
		}
		return len(a.ids) > len(b.ids)
	})
	out := []Advice{}
	for i, k := range order {
		g := groups[k]
		out = append(out, Advice{Priority: i + 1, Severity: g.worst, Title: g.rule.title, Detail: g.rule.detail, Credentials: g.ids})
	}
	return out
}

// ServicesLine renders a compact "github, npm, aws" list.
func ServicesLine(r *Result) string { return strings.Join(r.Services, ", ") }
