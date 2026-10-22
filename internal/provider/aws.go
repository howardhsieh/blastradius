package provider

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// aws reads the shared credentials file, the config file (for context) and
// the SSO / CLI token caches.
type aws struct{}

func (aws) ID() string { return "aws" }
func (aws) Describe() string {
	return "~/.aws/credentials, ~/.aws/config, ~/.aws/sso/cache, ~/.aws/cli/cache; AWS_SECRET_ACCESS_KEY via the environment collector"
}

func (aws) Collect(env *Env) ([]cred.Credential, []Problem) {
	var out []cred.Credential
	var probs []Problem
	credPath := env.EnvOr("AWS_SHARED_CREDENTIALS_FILE", env.Path(".aws", "credentials"))
	confPath := env.EnvOr("AWS_CONFIG_FILE", env.Path(".aws", "config"))

	// Config: region per profile, and which profiles assume roles from which.
	region := map[string]string{}
	roleUsers := map[string][]string{}
	ssoProfiles := 0
	if data, _, ok, prob := readFile(confPath); prob != nil {
		probs = append(probs, *prob)
	} else if ok {
		for _, s := range parseINI(data) {
			name := strings.TrimPrefix(s.Name, "profile ")
			if r := s.Get("region"); r != "" {
				region[name] = r
			}
			if src := s.Get("source_profile"); src != "" && s.Has("role_arn") {
				roleUsers[src] = append(roleUsers[src], name)
			}
			if s.Has("sso_start_url") || s.Has("sso_session") {
				ssoProfiles++
			}
		}
	}

	if data, info, ok, prob := readFile(credPath); prob != nil {
		probs = append(probs, *prob)
	} else if ok {
		for _, s := range parseINI(data) {
			secret := s.Get("aws_secret_access_key")
			if secret == "" {
				continue
			}
			keyID := s.Get("aws_access_key_id")
			c := cred.Credential{
				Service: cred.ServiceAWS, Source: "aws-credentials", Location: env.Display(credPath),
				Line: s.Line, Account: "profile " + s.Name, Fingerprint: cred.Fingerprint(secret),
				AgeDays: ageDays(env, info),
			}
			prefix := ""
			if len(keyID) >= 4 {
				prefix = keyID[:4]
			}
			switch {
			case prefix == "ASIA" || s.Has("aws_session_token"):
				c.Kind, c.Lifetime, c.Severity = "session-key", cred.ShortTerm, cred.Medium
				c.Summary = fmt.Sprintf("Temporary AWS credentials (%s…) in profile %q", prefix, s.Name)
			case prefix == "AKIA":
				c.Kind, c.Lifetime, c.Severity = "access-key", cred.LongTerm, cred.Critical
				c.Summary = fmt.Sprintf("Long-term IAM access key (AKIA…) in profile %q, %s", s.Name, ageNote(c.AgeDays))
				c.Notes = append(c.Notes, "an IAM user key works from anywhere, needs no MFA from the CLI, and stays valid until rotated")
			default:
				c.Kind, c.Lifetime, c.Severity = "access-key", cred.Unknown, cred.High
				c.Summary = fmt.Sprintf("AWS access key in profile %q", s.Name)
			}
			if r := region[s.Name]; r != "" {
				c.Notes = append(c.Notes, "default region "+r)
			}
			if users := roleUsers[s.Name]; len(users) > 0 {
				sort.Strings(users)
				c.Notes = append(c.Notes, "source credential for role profiles: "+strings.Join(users, ", "))
			}
			if worldReadable(info) {
				c.Notes = append(c.Notes, "file is readable by other users")
			}
			out = append(out, c)
		}
	}

	// SSO token cache.
	ssoDir := filepath.Join(filepath.Dir(confPath), "sso", "cache")
	entries, _ := filepath.Glob(filepath.Join(ssoDir, "*.json"))
	for _, path := range entries {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		var f struct {
			AccessToken  string `json:"accessToken"`
			RefreshToken string `json:"refreshToken"`
			ExpiresAt    string `json:"expiresAt"`
			StartURL     string `json:"startUrl"`
			Region       string `json:"region"`
			ClientSecret string `json:"clientSecret"`
		}
		if json.Unmarshal(data, &f) != nil {
			continue
		}
		switch {
		case f.AccessToken != "":
			c := cred.Credential{
				Service: cred.ServiceAWS, Kind: "sso-access-token", Source: "aws-sso-cache",
				Location: env.Display(path), Account: hostOf(f.StartURL), Fingerprint: cred.Fingerprint(f.AccessToken),
				Lifetime: cred.ShortTerm, Severity: cred.Medium, AgeDays: ageDays(env, info),
			}
			c.ExpiresAt, c.Expired, _ = expiry(env, f.ExpiresAt)
			c.Summary = "IAM Identity Center session for " + hostOf(f.StartURL)
			if c.Expired {
				c.Severity = cred.Low
				c.Summary += " (expired)"
			} else {
				c.Summary += ": every role this login can assume, until it expires"
			}
			if f.RefreshToken != "" {
				c.Notes = append(c.Notes, "includes a refresh token, so the session outlives the access token")
				if !c.Expired {
					c.Severity = cred.High
				}
			}
			out = append(out, c)
		case f.ClientSecret != "":
			out = append(out, cred.Credential{
				Service: cred.ServiceAWS, Kind: "sso-client-registration", Source: "aws-sso-cache",
				Location: env.Display(path), Account: hostOf(f.StartURL), Fingerprint: cred.Fingerprint(f.ClientSecret),
				Lifetime: cred.ShortTerm, Severity: cred.Info, AgeDays: ageDays(env, info),
				Summary: "OIDC client registration for the SSO device flow (not a login by itself)",
			})
		}
	}

	// CLI cache of assumed-role credentials.
	cliDir := filepath.Join(filepath.Dir(confPath), "cli", "cache")
	entries, _ = filepath.Glob(filepath.Join(cliDir, "*.json"))
	for _, path := range entries {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		var f struct {
			Credentials struct {
				AccessKeyID     string `json:"AccessKeyId"`
				SecretAccessKey string `json:"SecretAccessKey"`
				Expiration      string `json:"Expiration"`
			} `json:"Credentials"`
			AssumedRoleUser struct {
				Arn string `json:"Arn"`
			} `json:"AssumedRoleUser"`
		}
		if json.Unmarshal(data, &f) != nil || f.Credentials.SecretAccessKey == "" {
			continue
		}
		c := cred.Credential{
			Service: cred.ServiceAWS, Kind: "session-key", Source: "aws-cli-cache",
			Location: env.Display(path), Account: roleName(f.AssumedRoleUser.Arn), Fingerprint: cred.Fingerprint(f.Credentials.SecretAccessKey),
			Lifetime: cred.ShortTerm, Severity: cred.Medium, AgeDays: ageDays(env, info),
		}
		c.ExpiresAt, c.Expired, _ = expiry(env, f.Credentials.Expiration)
		c.Summary = "Cached temporary credentials for " + c.Account
		if c.Expired {
			c.Severity = cred.Low
			c.Summary += " (expired)"
		}
		out = append(out, c)
	}
	return out, probs
}

// roleName shortens arn:aws:sts::123456789012:assumed-role/Name/session to
// "Name (account 1234…9012)".
func roleName(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	acct := parts[4]
	if len(acct) == 12 {
		acct = acct[:4] + "…" + acct[8:]
	}
	res := strings.Split(parts[5], "/")
	name := res[0]
	if len(res) > 1 {
		name = res[1]
	}
	return fmt.Sprintf("%s (account %s)", name, acct)
}
