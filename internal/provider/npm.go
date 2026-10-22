package provider

import (
	"encoding/base64"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// npm reads the user .npmrc and any project .npmrc under --dir.
type npm struct{}

func (npm) ID() string { return "npm" }
func (npm) Describe() string {
	return "~/.npmrc and project .npmrc files (_authToken, _auth, _password); NPM_TOKEN via the environment collector"
}

func (npm) Collect(env *Env) ([]cred.Credential, []Problem) {
	paths := []string{env.EnvOr("NPM_CONFIG_USERCONFIG", env.Path(".npmrc"))}
	if len(env.Dirs) > 0 {
		walkDirs(env.Dirs, 5, 50000, func(path string, d fs.DirEntry) bool {
			if d.Name() == ".npmrc" {
				paths = append(paths, path)
			}
			return true
		})
	}
	var out []cred.Credential
	var probs []Problem
	for _, path := range paths {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		out = append(out, npmrc(env, path, info, string(data))...)
	}
	return out, probs
}

func npmrc(env *Env, path string, info fs.FileInfo, text string) []cred.Credential {
	var out []cred.Credential
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue
		}
		key, val := strings.TrimSpace(line[:eq]), unquoteValue(line[eq+1:])
		registry := "registry.npmjs.org"
		field := key
		if strings.HasPrefix(key, "//") {
			if c := strings.LastIndex(key, ":"); c > 0 {
				registry, field = hostOf(key[2:c]), key[c+1:]
			}
		}
		if val == "" || strings.HasPrefix(val, "${") {
			continue // referenced from the environment, not stored here
		}
		c := cred.Credential{
			Service: cred.ServiceNPM, Source: "npmrc", Location: env.Display(path), Line: i + 1,
			Account: registry, Lifetime: cred.LongTerm, AgeDays: ageDays(env, info),
		}
		if registry != "registry.npmjs.org" {
			c.Service = cred.ServiceGeneric
			if strings.Contains(registry, "github") {
				c.Service = cred.ServiceGitHub
			}
		}
		switch field {
		case "_authToken":
			c.Fingerprint = cred.Fingerprint(val)
			switch {
			case classify.IsLegacyNPMToken(val):
				c.Kind, c.Severity = "legacy-token", cred.Critical
				c.Summary = "Legacy npm token for " + registry + ": never expires and is not covered by 2FA"
			case strings.HasPrefix(val, "npm_"):
				c.Kind, c.Severity = "access-token", cred.High
				c.Summary = "npm access token for " + registry
				c.Notes = append(c.Notes, "classic and granular tokens share the npm_ prefix; whether it can publish cannot be told offline")
			default:
				c.Kind, c.Severity = "access-token", cred.High
				c.Summary = "Registry auth token for " + registry
				if r, ok := classify.Token(val); ok {
					c.Service, c.Kind, c.Severity, c.Lifetime = r.Service, r.Kind, r.Severity, r.Lifetime
					c.Summary = r.Label + " used as registry token for " + registry
				}
			}
		case "_auth":
			c.Kind, c.Severity = "basic-auth", cred.High
			c.Fingerprint = cred.Fingerprint(val)
			if dec, err := base64.StdEncoding.DecodeString(val); err == nil {
				if u, _, ok := strings.Cut(string(dec), ":"); ok {
					c.Account = u + "@" + registry
				}
			}
			c.Summary = "Base64 user:password for " + registry
		case "_password":
			c.Kind, c.Severity = "password", cred.High
			c.Fingerprint = cred.Fingerprint(val)
			c.Summary = "Registry password for " + registry
		default:
			continue
		}
		if filepath.Dir(path) != env.Home {
			c.Notes = append(c.Notes, "project-level .npmrc: easy to commit by accident")
		}
		out = append(out, c)
	}
	return out
}
