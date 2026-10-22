package provider

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// aiTools reads the credential files of AI coding assistants: Claude Code,
// OpenAI Codex CLI, GitHub Copilot, Gemini CLI and the Hugging Face hub.
// API keys exported as environment variables are found by the environment
// and shell-rc collectors.
type aiTools struct{}

func (aiTools) ID() string { return "ai-tools" }
func (aiTools) Describe() string {
	return "~/.claude/.credentials.json, ~/.codex/auth.json, ~/.config/github-copilot/*.json, ~/.gemini/oauth_creds.json, ~/.cache/huggingface/token"
}

func (aiTools) Collect(env *Env) ([]cred.Credential, []Problem) {
	var out []cred.Credential
	var probs []Problem
	read := func(path string) ([]byte, *int, bool) {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			return nil, nil, false
		}
		return data, ageDays(env, info), true
	}

	// Claude Code OAuth (Linux/Windows keep it on disk; macOS uses the keychain).
	claudeDir := env.EnvOr("CLAUDE_CONFIG_DIR", env.Path(".claude"))
	if data, age, ok := read(filepath.Join(claudeDir, ".credentials.json")); ok {
		var f struct {
			OAuth struct {
				AccessToken  string `json:"accessToken"`
				RefreshToken string `json:"refreshToken"`
				ExpiresAt    int64  `json:"expiresAt"`
			} `json:"claudeAiOauth"`
		}
		if json.Unmarshal(data, &f) == nil && (f.OAuth.AccessToken != "" || f.OAuth.RefreshToken != "") {
			secret := f.OAuth.RefreshToken
			kind := "oauth-refresh-token"
			if secret == "" {
				secret, kind = f.OAuth.AccessToken, "oauth-access-token"
			}
			out = append(out, cred.Credential{
				Service: cred.ServiceAnthropic, Kind: kind, Source: "claude-code",
				Location:    env.Display(filepath.Join(claudeDir, ".credentials.json")),
				Fingerprint: cred.Fingerprint(secret), Lifetime: cred.LongTerm, Severity: cred.High, AgeDays: age,
				Summary: "Claude Code login: can use your Claude subscription or API account",
			})
		}
	}

	// OpenAI Codex CLI.
	codexDir := env.EnvOr("CODEX_HOME", env.Path(".codex"))
	if data, age, ok := read(filepath.Join(codexDir, "auth.json")); ok {
		var f struct {
			APIKey string `json:"OPENAI_API_KEY"`
			Tokens struct {
				AccessToken  string `json:"access_token"`
				RefreshToken string `json:"refresh_token"`
				AccountID    string `json:"account_id"`
			} `json:"tokens"`
		}
		if json.Unmarshal(data, &f) == nil {
			loc := env.Display(filepath.Join(codexDir, "auth.json"))
			if f.APIKey != "" {
				out = append(out, cred.Credential{
					Service: cred.ServiceOpenAI, Kind: "api-key", Source: "codex-cli", Location: loc,
					Fingerprint: cred.Fingerprint(f.APIKey), Lifetime: cred.LongTerm, Severity: cred.High, AgeDays: age,
					Summary: "OpenAI API key stored by the Codex CLI: billable API access",
				})
			}
			if f.Tokens.RefreshToken != "" || f.Tokens.AccessToken != "" {
				secret, kind := f.Tokens.RefreshToken, "oauth-refresh-token"
				if secret == "" {
					secret, kind = f.Tokens.AccessToken, "oauth-access-token"
				}
				out = append(out, cred.Credential{
					Service: cred.ServiceOpenAI, Kind: kind, Source: "codex-cli", Location: loc, Account: f.Tokens.AccountID,
					Fingerprint: cred.Fingerprint(secret), Lifetime: cred.LongTerm, Severity: cred.High, AgeDays: age,
					Summary: "ChatGPT login used by the Codex CLI",
				})
			}
		}
	}

	// GitHub Copilot: apps.json / hosts.json hold a GitHub OAuth token.
	copilotDir := env.Path(".config", "github-copilot")
	if x := env.Getenv("XDG_CONFIG_HOME"); x != "" {
		copilotDir = filepath.Join(x, "github-copilot")
	}
	for _, name := range []string{"apps.json", "hosts.json"} {
		path := filepath.Join(copilotDir, name)
		data, age, ok := read(path)
		if !ok {
			continue
		}
		var f map[string]struct {
			User  string `json:"user"`
			Token string `json:"oauth_token"`
		}
		if json.Unmarshal(data, &f) != nil {
			continue
		}
		for key, v := range f {
			if v.Token == "" {
				continue
			}
			host := key
			if i := strings.IndexByte(host, ':'); i > 0 {
				host = host[:i]
			}
			out = append(out, cred.Credential{
				Service: cred.ServiceGitHub, Kind: "oauth-token", Source: "github-copilot", Location: env.Display(path),
				Account: v.User + "@" + host, Fingerprint: cred.Fingerprint(v.Token), Lifetime: cred.LongTerm,
				Severity: cred.High, AgeDays: age,
				Summary: "GitHub Copilot OAuth token for " + v.User + ": a GitHub user token, not just Copilot access",
			})
		}
	}

	// Gemini CLI.
	if data, age, ok := read(env.Path(".gemini", "oauth_creds.json")); ok {
		var f struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		}
		if json.Unmarshal(data, &f) == nil && (f.RefreshToken != "" || f.AccessToken != "") {
			secret, kind := f.RefreshToken, "oauth-refresh-token"
			if secret == "" {
				secret, kind = f.AccessToken, "oauth-access-token"
			}
			out = append(out, cred.Credential{
				Service: cred.ServiceGoogleAI, Kind: kind, Source: "gemini-cli", Location: env.Display(env.Path(".gemini", "oauth_creds.json")),
				Fingerprint: cred.Fingerprint(secret), Lifetime: cred.LongTerm, Severity: cred.High, AgeDays: age,
				Summary: "Google OAuth token stored by the Gemini CLI",
			})
		}
	}

	// Hugging Face hub token.
	hfPath := env.EnvOr("HF_TOKEN_PATH", filepath.Join(env.EnvOr("HF_HOME", env.Path(".cache", "huggingface")), "token"))
	if data, age, ok := read(hfPath); ok && strings.TrimSpace(string(data)) != "" {
		out = append(out, cred.Credential{
			Service: cred.ServiceHuggingFace, Kind: "access-token", Source: "huggingface-cli", Location: env.Display(hfPath),
			Fingerprint: cred.Fingerprint(string(data)), Lifetime: cred.LongTerm, Severity: cred.Medium, AgeDays: age,
			Summary: "Hugging Face hub token: can push to your models and datasets",
		})
	}
	return out, probs
}
