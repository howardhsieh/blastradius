package scan

import (
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// refine adjusts a credential's severity from what the probe learned. The
// offline severity says what the credential's format allows; the probe
// says what this one actually does. Rules:
//
//   - rejected by the service: LOW, because a revoked token on disk is a
//     clean-up item, not an exposure;
//   - GitHub classic token with repo + admin:org: stays HIGH and says so;
//   - GitHub classic token whose scopes are all read-only: MEDIUM;
//   - GitHub fine-grained PAT: stays MEDIUM (GitHub does not reveal its
//     permissions to the token, so "read-only" cannot be confirmed);
//   - npm read-only token: MEDIUM; npm automation token (publishes without
//     2FA): CRITICAL; publish token: unchanged;
//   - AWS key whose ARN is the account root: CRITICAL;
//   - Kubernetes credential with * on * (cluster-admin): CRITICAL; one
//     confirmed read-only: MEDIUM.
//
// Expired, protected and unprobed credentials are left alone.
func refine(c *cred.Credential) {
	r := c.Reach
	if r == nil {
		return
	}
	if !r.Live {
		c.Severity = cred.Low
		c.Notes = append(c.Notes, "the service rejected this credential; it is dead weight, delete it (and rotate if you did not revoke it yourself)")
		return
	}
	switch c.Service {
	case cred.ServiceGitHub:
		switch {
		case r.TokenType == "fine-grained":
			if c.Severity > cred.Medium {
				c.Severity = cred.Medium
			}
		case hasAll(r.Scopes, "repo", "admin:org"):
			if c.Severity < cred.High {
				c.Severity = cred.High
			}
			c.Notes = append(c.Notes, "probe: repo + admin:org means a stealer could push to every repository and change organisation membership and settings")
		case r.ReadOnly:
			if c.Severity > cred.Medium {
				c.Severity = cred.Medium
			}
			c.Notes = append(c.Notes, "probe: scopes are read-only, so a stealer could read but not push")
		}
	case cred.ServiceNPM:
		switch r.TokenType {
		case "read-only":
			if c.Severity > cred.Medium {
				c.Severity = cred.Medium
			}
			c.Notes = append(c.Notes, "probe: read-only token, cannot publish")
		case "automation":
			c.Severity = cred.Critical
			c.Notes = append(c.Notes, "probe: automation token, publishes without a second factor: this is the Shai-Hulud shape")
		}
	case cred.ServiceAWS:
		if r.Admin {
			c.Severity = cred.Critical
			c.Notes = append(c.Notes, "probe: this key belongs to the account ROOT user")
		}
	case cred.ServiceKubernetes:
		switch {
		case r.Admin:
			c.Severity = cred.Critical
			c.Notes = append(c.Notes, "probe: cluster-admin on at least one cluster")
		case r.ReadOnly:
			if c.Severity > cred.Medium {
				c.Severity = cred.Medium
			}
			c.Notes = append(c.Notes, "probe: read-only on every probed cluster")
		}
	}
}

func hasAll(list []string, want ...string) bool {
	have := map[string]bool{}
	for _, s := range list {
		have[strings.TrimSpace(s)] = true
	}
	for _, w := range want {
		if !have[w] {
			return false
		}
	}
	return true
}

// probed reports whether the credential has reach of the given shape; used
// by advice rules.
func probed(c cred.Credential, f func(r *cred.Reach) bool) bool {
	return c.Reach != nil && f(c.Reach)
}
