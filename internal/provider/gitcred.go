package provider

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// gitCredentials reads the plaintext store written by
// `git config credential.helper store`.
type gitCredentials struct{}

func (gitCredentials) ID() string { return "git-credentials" }
func (gitCredentials) Describe() string {
	return "git credential.helper=store files (~/.git-credentials, ~/.config/git/credentials)"
}

func (gitCredentials) Collect(env *Env) ([]cred.Credential, []Problem) {
	var out []cred.Credential
	var probs []Problem
	paths := []string{env.Path(".git-credentials")}
	if x := env.Getenv("XDG_CONFIG_HOME"); x != "" {
		paths = append(paths, x+"/git/credentials")
	} else {
		paths = append(paths, env.Path(".config", "git", "credentials"))
	}
	for _, path := range paths {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			u, err := url.Parse(line)
			if err != nil || u.User == nil {
				continue
			}
			user := u.User.Username()
			secret, hasPass := u.User.Password()
			if !hasPass {
				// "https://TOKEN@host": the user part is the secret.
				secret, user = user, ""
			}
			if secret == "" {
				continue
			}
			service, kind, sev := serviceForGitHost(u.Host)
			label := "git password"
			if r, ok := classify.Token(secret); ok {
				service, kind, sev, label = r.Service, r.Kind, r.Severity, r.Label
			} else if service != cred.ServiceGeneric {
				label = service + " credential"
			}
			account := u.Host
			if user != "" {
				account = user + "@" + u.Host
			}
			out = append(out, cred.Credential{
				Service: service, Kind: kind, Source: "git-credentials",
				Location: env.Display(path), Line: i + 1, Account: account,
				Fingerprint: cred.Fingerprint(secret), Lifetime: cred.LongTerm, Severity: sev,
				AgeDays: ageDays(env, info),
				Summary: fmt.Sprintf("%s stored in plaintext for %s", label, account),
				Notes:   []string{"credential.helper=store keeps the password readable by any process running as you"},
			})
		}
	}
	return out, probs
}
