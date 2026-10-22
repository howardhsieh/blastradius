package provider

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

const githubAPIHost = "api.github.com"

// ProbeHosts: GitHub.com's API. GitHub Enterprise hosts found in hosts.yml
// are contacted only when the user names them with --probe-host.
func (github) ProbeHosts() []string { return []string{githubAPIHost} }

var githubTokenKinds = map[string]bool{
	"oauth-token": true, "classic-pat": true, "fine-grained-pat": true, "token": true,
	"user-to-server-token": true,
}

// githubHost extracts the GitHub host a credential belongs to from its
// account label ("alice@ghe.example.com") or defaults to github.com.
func githubHost(c cred.Credential) string {
	host := "github.com"
	if _, h, ok := strings.Cut(c.Account, "@"); ok && strings.Contains(h, ".") {
		host = strings.ToLower(h)
	}
	if host == githubAPIHost || strings.HasSuffix(host, ".github.com") {
		host = "github.com"
	}
	return host
}

func (github) probeTargets(env *Env, c cred.Credential) ([]string, string) {
	if c.Service != cred.ServiceGitHub || !githubTokenKinds[c.Kind] {
		return nil, ""
	}
	host := githubHost(c)
	if host == "github.com" {
		return []string{githubAPIHost}, ""
	}
	if env.Probe.allowsHost(host) {
		return []string{host}, ""
	}
	return nil, fmt.Sprintf("GitHub Enterprise host %s is not probed; pass --probe-host %s to allow it", host, host)
}

// Probe asks GET /user who the token is and reads X-OAuth-Scopes. Classic
// tokens and gh OAuth tokens report their scopes there; fine-grained PATs
// report none, because GitHub does not expose a fine-grained token's
// permissions to the token itself.
func (g github) Probe(ctx context.Context, env *Env, c cred.Credential) (*Reach, error) {
	hosts, skip := g.probeTargets(env, c)
	if len(hosts) == 0 {
		if skip != "" {
			return nil, fmt.Errorf("%s", skip)
		}
		return nil, ErrNotProbed
	}
	host := hosts[0]
	return guarded(env, c, func(secret string) (*Reach, error) {
		url := "https://" + host + "/user"
		if host != githubAPIHost {
			url = "https://" + host + "/api/v3/user"
		}
		req, err := env.newProbeRequest(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		var user struct {
			Login string `json:"login"`
			Type  string `json:"type"`
		}
		resp, err := doJSON(env.probeClient(hosts, nil), req, &user)
		if err != nil {
			return nil, err
		}
		r := &Reach{Host: host}
		if rejected(resp.StatusCode) {
			r.Summary = fmt.Sprintf("rejected by %s (HTTP %d): revoked or expired", host, resp.StatusCode)
			return r, nil
		}
		if resp.StatusCode/100 != 2 {
			return nil, statusErr(host, resp)
		}
		r.Live = true
		r.Identity = user.Login
		scopesHeader, hasScopes := resp.Header[http.CanonicalHeaderKey("X-OAuth-Scopes")]
		switch {
		case c.Kind == "fine-grained-pat" || !hasScopes:
			// No X-OAuth-Scopes header at all: GitHub omits it only for
			// fine-grained tokens and GitHub App tokens.
			r.TokenType = "fine-grained"
		default:
			r.TokenType = "classic"
			for _, part := range strings.Split(strings.Join(scopesHeader, ","), ",") {
				if s := strings.TrimSpace(part); s != "" {
					r.Scopes = append(r.Scopes, s)
				}
			}
			sort.Strings(r.Scopes)
			r.ReadOnly = githubScopesReadOnly(r.Scopes)
		}
		r.Summary = "acts as " + r.Identity
		switch {
		case r.TokenType == "fine-grained":
			r.Summary += " · fine-grained token: GitHub does not report its permissions to the token; check Settings → Developer settings"
		case len(r.Scopes) == 0:
			r.Summary += " · no scopes: public read access only"
			r.ReadOnly = true
		default:
			r.Summary += " · scopes: " + strings.Join(r.Scopes, ", ")
			if githubFullControl(r.Scopes) {
				r.Summary += " · full control of every repository and organisation this user administers"
			} else if r.ReadOnly {
				r.Summary += " · read-only"
			}
		}
		return r, nil
	})
}

// githubScopesReadOnly reports whether a classic scope list grants no
// write access anywhere.
func githubScopesReadOnly(scopes []string) bool {
	for _, s := range scopes {
		switch {
		case strings.HasPrefix(s, "read:"):
		case s == "user:email", s == "user:follow", s == "public_repo:read":
		default:
			return false
		}
	}
	return true
}

// githubFullControl reports the classic combination that lets a stealer
// push to every repository and administer organisations.
func githubFullControl(scopes []string) bool {
	has := map[string]bool{}
	for _, s := range scopes {
		has[s] = true
	}
	return has["repo"] && has["admin:org"]
}
