package provider

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// docker reads Docker and Podman registry auth files.
type docker struct{}

func (docker) ID() string { return "docker" }
func (docker) Describe() string {
	return "~/.docker/config.json and containers/auth.json (plaintext auth entries, credential stores)"
}

func (docker) Collect(env *Env) ([]cred.Credential, []Problem) {
	paths := []string{filepath.Join(env.EnvOr("DOCKER_CONFIG", env.Path(".docker")), "config.json")}
	if r := env.Getenv("REGISTRY_AUTH_FILE"); r != "" {
		paths = append(paths, r)
	}
	if x := env.Getenv("XDG_RUNTIME_DIR"); x != "" {
		paths = append(paths, filepath.Join(x, "containers", "auth.json"))
	}
	paths = append(paths, env.Path(".config", "containers", "auth.json"))
	var out []cred.Credential
	var probs []Problem
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		var f struct {
			Auths map[string]struct {
				Auth          string `json:"auth"`
				Username      string `json:"username"`
				Password      string `json:"password"`
				IdentityToken string `json:"identitytoken"`
				RegistryToken string `json:"registrytoken"`
			} `json:"auths"`
			CredsStore  string            `json:"credsStore"`
			CredHelpers map[string]string `json:"credHelpers"`
		}
		if json.Unmarshal(data, &f) != nil {
			probs = append(probs, Problem{Location: env.Display(path), Err: "not valid JSON"})
			continue
		}
		var stored []string
		regs := make([]string, 0, len(f.Auths))
		for r := range f.Auths {
			regs = append(regs, r)
		}
		sort.Strings(regs)
		for _, reg := range regs {
			a := f.Auths[reg]
			host := hostOf(reg)
			c := cred.Credential{
				Service: cred.ServiceDocker, Source: "docker-config", Location: env.Display(path),
				Account: host, Lifetime: cred.LongTerm, AgeDays: ageDays(env, info),
			}
			if strings.Contains(host, "ghcr.io") || strings.Contains(host, "docker.pkg.github.com") {
				c.Service = cred.ServiceGitHub
			}
			switch {
			case a.Auth != "":
				c.Kind, c.Severity = "registry-basic-auth", cred.High
				c.Fingerprint = cred.Fingerprint(a.Auth)
				if dec, err := base64.StdEncoding.DecodeString(a.Auth); err == nil {
					if u, _, ok := strings.Cut(string(dec), ":"); ok && u != "" {
						c.Account = u + "@" + host
					}
				}
				c.Summary = "Plaintext registry login for " + host + ": whoever has it can push images under your name"
			case a.Password != "":
				c.Kind, c.Severity = "registry-password", cred.High
				c.Fingerprint = cred.Fingerprint(a.Password)
				if a.Username != "" {
					c.Account = a.Username + "@" + host
				}
				c.Summary = "Plaintext registry password for " + host
			case a.IdentityToken != "":
				c.Kind, c.Severity, c.Lifetime = "identity-token", cred.Medium, cred.ShortTerm
				c.Fingerprint = cred.Fingerprint(a.IdentityToken)
				c.Summary = "Registry identity token for " + host
			case a.RegistryToken != "":
				c.Kind, c.Severity, c.Lifetime = "registry-token", cred.Medium, cred.ShortTerm
				c.Fingerprint = cred.Fingerprint(a.RegistryToken)
				c.Summary = "Registry bearer token for " + host
			default:
				stored = append(stored, host)
				continue
			}
			out = append(out, c)
		}
		if f.CredsStore != "" || len(f.CredHelpers) > 0 {
			store := f.CredsStore
			if store == "" {
				for _, h := range f.CredHelpers {
					store = h
					break
				}
			}
			c := cred.Credential{
				Service: cred.ServiceDocker, Kind: "credential-store", Source: "docker-config",
				Location: env.Display(path), Account: store, Lifetime: cred.LongTerm, Severity: cred.Info,
				Protected: true, AgeDays: ageDays(env, info),
				Summary: fmt.Sprintf("Registry logins kept in the %q credential helper, not in this file", store),
			}
			if len(stored) > 0 {
				c.Notes = append(c.Notes, "registries: "+strings.Join(stored, ", "))
			}
			out = append(out, c)
		}
	}
	return out, probs
}
