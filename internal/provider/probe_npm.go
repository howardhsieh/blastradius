package provider

import (
	"context"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

const npmRegistryHost = "registry.npmjs.org"

// ProbeHosts: the public npm registry only. Tokens for other registries
// are not probed.
func (npm) ProbeHosts() []string { return []string{npmRegistryHost} }

func (npm) probeTargets(env *Env, c cred.Credential) ([]string, string) {
	if c.Service != cred.ServiceNPM {
		return nil, ""
	}
	switch c.Kind {
	case "access-token", "legacy-token":
	default:
		return nil, ""
	}
	return []string{npmRegistryHost}, ""
}

// Probe asks /-/whoami for the user name, then /-/npm/v1/tokens for the
// token's own entry: read-only, automation (publishes without 2FA) or
// publish. Granular tokens are not listed by that endpoint and are
// reported as such.
func (n npm) Probe(ctx context.Context, env *Env, c cred.Credential) (*Reach, error) {
	if hosts, _ := n.probeTargets(env, c); len(hosts) == 0 {
		return nil, ErrNotProbed
	}
	host := npmRegistryHost
	return guarded(env, c, func(secret string) (*Reach, error) {
		client := env.probeClient([]string{host}, nil)
		get := func(path string, v any) (*http.Response, error) {
			req, err := env.newProbeRequest(ctx, http.MethodGet, "https://"+host+path, nil)
			if err != nil {
				return nil, err
			}
			req.Header.Set("Authorization", "Bearer "+secret)
			return doJSON(client, req, v)
		}
		var who struct {
			Username string `json:"username"`
		}
		resp, err := get("/-/whoami", &who)
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
		r.Identity = who.Username
		r.Summary = "acts as " + r.Identity

		var list struct {
			Objects []struct {
				Token      string `json:"token"`
				Key        string `json:"key"`
				ReadOnly   bool   `json:"readonly"`
				Automation bool   `json:"automation"`
			} `json:"objects"`
		}
		resp, err = get("/-/npm/v1/tokens?perPage=100", &list)
		if err != nil {
			r.Summary += " · token type unknown (token list unavailable)"
			return r, nil
		}
		if resp.StatusCode/100 != 2 {
			r.Summary += fmt.Sprintf(" · token type unknown (token list answered HTTP %d)", resp.StatusCode)
			return r, nil
		}
		sum := sha512.Sum512([]byte(secret))
		key := hex.EncodeToString(sum[:])
		found := false
		for _, o := range list.Objects {
			if (o.Key != "" && strings.EqualFold(o.Key, key)) || (len(o.Token) >= 6 && strings.HasPrefix(secret, strings.TrimRight(o.Token, "…."))) {
				found = true
				switch {
				case o.ReadOnly:
					r.TokenType, r.ReadOnly = "read-only", true
				case o.Automation:
					r.TokenType, r.Bypass2FA = "automation", true
				default:
					r.TokenType = "publish"
				}
				break
			}
		}
		switch {
		case !found:
			r.TokenType = "granular"
			r.Summary += " · not in the classic token list: a granular token (permissions are set per package at npmjs.com)"
		case r.ReadOnly:
			r.Summary += " · read-only token"
		case r.Bypass2FA:
			r.Summary += " · automation token: publishes to every package of this user without 2FA"
		default:
			r.Summary += " · publish token (2FA applies if the account requires it)"
		}
		return r, nil
	})
}
