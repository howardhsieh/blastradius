package provider

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// azure reads the Azure CLI's token caches and service principal store.
type azure struct{}

func (azure) ID() string { return "azure" }
func (azure) Describe() string {
	return "~/.azure (msal_token_cache.json/.bin, accessTokens.json, service_principal_entries.json, azureProfile.json)"
}

func (azure) Collect(env *Env) ([]cred.Credential, []Problem) {
	var out []cred.Credential
	var probs []Problem
	dir := env.EnvOr("AZURE_CONFIG_DIR", env.Path(".azure"))

	// Profile: who is logged in, how many subscriptions. Labels only.
	account, subs := "", 0
	if data, _, ok, _ := readFile(filepath.Join(dir, "azureProfile.json")); ok {
		var p struct {
			Subscriptions []struct {
				User struct {
					Name string `json:"name"`
				} `json:"user"`
				IsDefault bool `json:"isDefault"`
			} `json:"subscriptions"`
		}
		// The file may start with a UTF-8 BOM.
		if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
			data = data[3:]
		}
		if json.Unmarshal(data, &p) == nil {
			subs = len(p.Subscriptions)
			for _, s := range p.Subscriptions {
				if account == "" || s.IsDefault {
					account = s.User.Name
				}
			}
		}
	}
	note := ""
	if subs > 0 {
		note = fmt.Sprintf("%d subscription(s) visible to this login", subs)
	}

	type cache struct {
		name, kind, summary string
		sev                 cred.Severity
		protected           bool
	}
	for _, f := range []cache{
		{"msal_token_cache.json", "token-cache", "Azure CLI MSAL token cache in plaintext: refresh tokens for every tenant you logged in to", cred.High, false},
		{"accessTokens.json", "token-cache", "Legacy Azure CLI token store (ADAL) in plaintext", cred.High, false},
		{"msal_token_cache.bin", "token-cache", "Azure CLI MSAL token cache, encrypted with the OS data-protection API", cred.Low, true},
	} {
		path := filepath.Join(dir, f.name)
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok || len(data) <= 2 {
			continue
		}
		c := cred.Credential{
			Service: cred.ServiceAzure, Kind: f.kind, Source: "azure-cli", Location: env.Display(path),
			Account: account, Fingerprint: cred.FingerprintBytes(data), Lifetime: cred.LongTerm,
			Severity: f.sev, Protected: f.protected, AgeDays: ageDays(env, info), Summary: f.summary,
		}
		if note != "" {
			c.Notes = append(c.Notes, note)
		}
		out = append(out, c)
	}

	path := filepath.Join(dir, "service_principal_entries.json")
	if data, info, ok, prob := readFile(path); prob != nil {
		probs = append(probs, *prob)
	} else if ok {
		var entries []struct {
			Client      string `json:"client_id"`
			Tenant      string `json:"tenant"`
			Secret      string `json:"client_secret"`
			Certificate string `json:"certificate"`
		}
		if json.Unmarshal(data, &entries) == nil {
			for _, e := range entries {
				c := cred.Credential{
					Service: cred.ServiceAzure, Source: "azure-cli", Location: env.Display(path),
					Account: e.Client + "@" + e.Tenant, Lifetime: cred.LongTerm, AgeDays: ageDays(env, info),
				}
				switch {
				case e.Secret != "":
					c.Kind, c.Severity = "service-principal-secret", cred.Critical
					c.Fingerprint = cred.Fingerprint(e.Secret)
					c.Summary = "Service principal client secret stored by `az login --service-principal`"
				case e.Certificate != "":
					c.Kind, c.Severity = "service-principal-certificate", cred.High
					c.Fingerprint = cred.Fingerprint(e.Certificate)
					c.Summary = "Service principal certificate path stored by the Azure CLI"
				default:
					continue
				}
				out = append(out, c)
			}
		}
	}
	return out, probs
}
