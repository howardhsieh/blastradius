package provider

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/yamlite"
)

// github reads the GitHub CLI's hosts.yml. Tokens in GH_TOKEN/GITHUB_TOKEN
// are picked up by the process-environment collector and merged by
// fingerprint.
type github struct{}

func (github) ID() string { return "github" }
func (github) Describe() string {
	return "GitHub CLI login (~/.config/gh/hosts.yml); GH_TOKEN / GITHUB_TOKEN via the environment collector"
}

func ghConfigDir(env *Env) string {
	if d := env.Getenv("GH_CONFIG_DIR"); d != "" {
		return d
	}
	if d := env.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "gh")
	}
	if a := env.Getenv("APPDATA"); a != "" && env.Getenv("HOME") == "" {
		return filepath.Join(a, "GitHub CLI")
	}
	return env.Path(".config", "gh")
}

func (github) Collect(env *Env) ([]cred.Credential, []Problem) {
	path := filepath.Join(ghConfigDir(env), "hosts.yml")
	data, info, ok, prob := readFile(path)
	if prob != nil {
		return nil, []Problem{*prob}
	}
	if !ok {
		return nil, nil
	}
	doc, err := yamlite.Parse(data)
	if err != nil {
		return nil, []Problem{{Location: env.Display(path), Err: "parse: " + err.Error()}}
	}
	var out []cred.Credential
	for _, host := range doc.Map {
		seen := map[string]bool{}
		add := func(user, token string, line int) {
			fp := cred.Fingerprint(token)
			if fp == "" || seen[fp] {
				return
			}
			seen[fp] = true
			c := cred.Credential{
				Service: cred.ServiceGitHub, Kind: "oauth-token", Source: "gh-cli",
				Location: env.Display(path), Line: line, Account: user + "@" + host.Key,
				Fingerprint: fp, Lifetime: cred.LongTerm, Severity: cred.High, AgeDays: ageDays(env, info),
			}
			label := "GitHub CLI OAuth token"
			if r, ok := classify.Token(token); ok && r.Service == cred.ServiceGitHub {
				c.Kind, c.Lifetime, c.Severity, label = r.Kind, r.Lifetime, r.Severity, r.Label
			}
			c.Summary = fmt.Sprintf("%s for %s on %s", label, user, host.Key)
			if c.Kind == "oauth-token" {
				c.Notes = append(c.Notes, "gh auth login grants repo, read:org, gist and workflow by default: full read/write on every repository you can push to")
			}
			if worldReadable(info) {
				c.Notes = append(c.Notes, "file is readable by other users")
			}
			out = append(out, c)
		}
		user := host.Val.Str("user")
		if tok := host.Val.Str("oauth_token"); tok != "" {
			add(user, tok, host.Val.Get("oauth_token").Line)
		}
		if users := host.Val.Get("users"); users != nil {
			for _, u := range users.Map {
				if tok := u.Val.Str("oauth_token"); tok != "" {
					add(u.Key, tok, u.Val.Get("oauth_token").Line)
				}
			}
		}
		if len(seen) == 0 && user != "" {
			out = append(out, cred.Credential{
				Service: cred.ServiceGitHub, Kind: "oauth-token", Source: "gh-cli",
				Location: env.Display(path), Line: host.Line, Account: user + "@" + host.Key,
				Lifetime: cred.LongTerm, Severity: cred.Low, Protected: true,
				Summary: fmt.Sprintf("GitHub CLI is logged in as %s on %s; the token is in the OS keyring", user, host.Key),
				Notes:   []string{"a process running as you can still ask the keyring for it (macOS prompts; Linux secret-service usually does not)"},
			})
		}
	}
	return out, nil
}

// serviceForGitHost maps a git remote host to a service.
func serviceForGitHost(host string) (service, kind string, sev cred.Severity) {
	h := strings.ToLower(host)
	switch {
	case h == "github.com" || h == "api.github.com" || strings.HasSuffix(h, ".github.com"):
		return cred.ServiceGitHub, "token", cred.High
	case h == "gitlab.com" || strings.Contains(h, "gitlab"):
		return cred.ServiceGitLab, "token", cred.High
	case strings.Contains(h, "bitbucket"):
		return cred.ServiceGeneric, "git-password", cred.High
	case h == "registry.npmjs.org":
		return cred.ServiceNPM, "access-token", cred.High
	case h == "upload.pypi.org" || h == "pypi.org" || h == "test.pypi.org":
		return cred.ServicePyPI, "api-token", cred.High
	}
	return cred.ServiceGeneric, "password", cred.Medium
}
