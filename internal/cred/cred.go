// Package cred defines the credential record shared by providers, the
// scanner and the reporters.
//
// A Credential never holds secret material. Providers hash the secret the
// moment they read it and keep only the first 8 hex characters of the
// SHA-256 digest, which is enough to tell two tokens apart and to recognise
// the same token in several places, but not enough to use it.
package cred

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Severity ranks what an attacker who copies this credential gains.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < Info || s > Critical {
		return "unknown"
	}
	return severityNames[s]
}

func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// ParseSeverity converts a name such as "high" into a Severity.
func ParseSeverity(v string) (Severity, error) {
	for i, n := range severityNames {
		if strings.EqualFold(v, n) {
			return Severity(i), nil
		}
	}
	return Info, fmt.Errorf("unknown severity %q (want info, low, medium, high or critical)", v)
}

// Lifetime says whether a credential keeps working until someone revokes
// it, or expires on its own.
type Lifetime string

const (
	LongTerm  Lifetime = "long-term"
	ShortTerm Lifetime = "short-term"
	Unknown   Lifetime = "unknown"
)

// Services a credential unlocks. Week-2 network probes dispatch on these.
const (
	ServiceGitHub      = "github"
	ServiceGitLab      = "gitlab"
	ServiceNPM         = "npm"
	ServicePyPI        = "pypi"
	ServiceAWS         = "aws"
	ServiceGCP         = "gcp"
	ServiceAzure       = "azure"
	ServiceDocker      = "docker"
	ServiceKubernetes  = "kubernetes"
	ServiceSSH         = "ssh"
	ServiceAnthropic   = "anthropic"
	ServiceOpenAI      = "openai"
	ServiceGoogleAI    = "google-ai"
	ServiceHuggingFace = "huggingface"
	ServiceSlack       = "slack"
	ServiceStripe      = "stripe"
	ServiceDatabase    = "database"
	ServiceGeneric     = "generic"
)

// Credential is one secret found on the machine, described without the
// secret itself.
type Credential struct {
	// ID is assigned by the scanner (for example "aws-2") so remediation
	// advice can refer back to a row.
	ID string `json:"id"`
	// Service is what the credential unlocks: "github", "aws", "ssh" ...
	Service string `json:"service"`
	// Kind is the shape of the secret: "oauth-token", "access-key",
	// "private-key" ...
	Kind string `json:"kind"`
	// Source is the collector that found it: "gh-cli", "shell-history" ...
	Source string `json:"source"`
	// Location is a file path (with the home directory shortened to "~")
	// or "env:NAME" for a process environment variable.
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
	// AlsoIn lists other locations where the same secret was found.
	AlsoIn []string `json:"also_in,omitempty"`
	// Account is a non-secret identifier: a user name, profile, e-mail,
	// registry or cluster. Never a token, password or key ID.
	Account string `json:"account,omitempty"`
	// Fingerprint is the first 8 hex characters of SHA-256(secret).
	Fingerprint string   `json:"fingerprint,omitempty"`
	Lifetime    Lifetime `json:"lifetime"`
	// AgeDays is how long ago the file holding the secret was last
	// modified, when that says something about the key's age.
	AgeDays   *int   `json:"age_days,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Expired   bool   `json:"expired,omitempty"`
	// Protected is true for secrets that need a second factor to use,
	// such as a passphrase-protected SSH key.
	Protected   bool     `json:"protected,omitempty"`
	Severity    Severity `json:"severity"`
	Summary     string   `json:"summary"`
	Notes       []string `json:"notes,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
}

// Fingerprint returns the first 8 hex characters of SHA-256(secret), or
// "" for an empty secret. Leading and trailing whitespace is ignored so the
// same token matches whether it came from a file or an environment variable.
func Fingerprint(secret string) string {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:4])
}

// FingerprintBytes hashes raw bytes, for key files whose whole content is
// the secret.
func FingerprintBytes(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:4])
}

// Days converts a day count to the optional form used by AgeDays.
func Days(n int) *int { return &n }
