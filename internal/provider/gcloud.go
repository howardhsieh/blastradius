package provider

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// gcloud reads Application Default Credentials, legacy per-account
// credentials, GOOGLE_APPLICATION_CREDENTIALS and the gcloud credential
// database.
type gcloud struct{}

func (gcloud) ID() string { return "gcp" }
func (gcloud) Describe() string {
	return "~/.config/gcloud (application_default_credentials.json, legacy_credentials, credentials.db) and GOOGLE_APPLICATION_CREDENTIALS"
}

func gcloudDir(env *Env) string {
	if d := env.Getenv("CLOUDSDK_CONFIG"); d != "" {
		return d
	}
	if a := env.Getenv("APPDATA"); a != "" && env.Getenv("HOME") == "" {
		return filepath.Join(a, "gcloud")
	}
	return env.Path(".config", "gcloud")
}

func (gcloud) Collect(env *Env) ([]cred.Credential, []Problem) {
	var out []cred.Credential
	var probs []Problem
	dir := gcloudDir(env)

	// Active account/project, for labels only.
	account, project := "", ""
	if data, _, ok, _ := readFile(filepath.Join(dir, "active_config")); ok {
		name := strings.TrimSpace(string(data))
		if data, _, ok, _ := readFile(filepath.Join(dir, "configurations", "config_"+name)); ok {
			for _, s := range parseINI(data) {
				if s.Name == "core" {
					account, project = s.Get("account"), s.Get("project")
				}
			}
		}
	}

	paths := []string{filepath.Join(dir, "application_default_credentials.json")}
	legacy, _ := filepath.Glob(filepath.Join(dir, "legacy_credentials", "*", "adc.json"))
	paths = append(paths, legacy...)
	if p := env.Getenv("GOOGLE_APPLICATION_CREDENTIALS"); p != "" {
		paths = append(paths, p)
	}
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
			Type           string `json:"type"`
			RefreshToken   string `json:"refresh_token"`
			ClientEmail    string `json:"client_email"`
			PrivateKey     string `json:"private_key"`
			PrivateKeyID   string `json:"private_key_id"`
			ProjectID      string `json:"project_id"`
			QuotaProjectID string `json:"quota_project_id"`
			Audience       string `json:"audience"`
		}
		if json.Unmarshal(data, &f) != nil {
			probs = append(probs, Problem{Location: env.Display(path), Err: "not valid JSON"})
			continue
		}
		c := cred.Credential{Service: cred.ServiceGCP, Source: "gcloud", Location: env.Display(path), AgeDays: ageDays(env, info)}
		if strings.Contains(path, "legacy_credentials") {
			c.Account = filepath.Base(filepath.Dir(path))
		}
		switch f.Type {
		case "authorized_user":
			c.Kind, c.Lifetime, c.Severity = "user-refresh-token", cred.LongTerm, cred.High
			c.Fingerprint = cred.Fingerprint(f.RefreshToken)
			if c.Account == "" && account != "" {
				c.Account = account
			}
			c.Summary = "Google user refresh token (Application Default Credentials): acts as you in every project until revoked"
			if f.QuotaProjectID != "" {
				c.Notes = append(c.Notes, "quota project "+f.QuotaProjectID)
			}
		case "service_account":
			c.Kind, c.Lifetime, c.Severity = "service-account-key", cred.LongTerm, cred.Critical
			c.Fingerprint = cred.Fingerprint(f.PrivateKey)
			c.Account = f.ClientEmail
			c.Summary = "Service account private key for " + f.ClientEmail + ": works from anywhere, never expires"
			if f.ProjectID != "" {
				c.Notes = append(c.Notes, "project "+f.ProjectID)
			}
		case "external_account":
			c.Kind, c.Lifetime, c.Severity = "workload-identity-config", cred.ShortTerm, cred.Info
			c.Account = hostOf(f.Audience)
			c.Summary = "Workload identity federation config (no long-lived secret inside)"
		case "impersonated_service_account":
			c.Kind, c.Lifetime, c.Severity = "impersonation-config", cred.LongTerm, cred.High
			c.Fingerprint = cred.FingerprintBytes(data)
			c.Summary = "Service-account impersonation config wrapping a source credential"
		default:
			continue
		}
		if project != "" && f.ProjectID == "" {
			c.Notes = append(c.Notes, "active gcloud project "+project)
		}
		out = append(out, c)
	}

	// credentials.db holds the refresh token of every `gcloud auth login`.
	if data, info, ok, prob := readFile(filepath.Join(dir, "credentials.db")); prob != nil {
		probs = append(probs, *prob)
	} else if ok && len(data) > 0 {
		c := cred.Credential{
			Service: cred.ServiceGCP, Kind: "credential-store", Source: "gcloud",
			Location: env.Display(filepath.Join(dir, "credentials.db")), Account: account,
			Fingerprint: cred.FingerprintBytes(data), Lifetime: cred.LongTerm, Severity: cred.High,
			AgeDays: ageDays(env, info),
			Summary: "gcloud credential database: refresh tokens for every account you ran `gcloud auth login` with, in an unencrypted SQLite file",
		}
		if n := strings.Count(string(data), `"refresh_token"`); n > 0 {
			c.Notes = append(c.Notes, itoa(n)+" stored refresh token(s)")
		}
		out = append(out, c)
	}
	return out, probs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
