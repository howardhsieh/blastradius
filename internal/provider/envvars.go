package provider

import (
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// envVars inspects the process environment: whatever is exported here is
// readable by every program you start, including an npm postinstall script.
type envVars struct{}

func (envVars) ID() string { return "env" }
func (envVars) Describe() string {
	return "process environment (GH_TOKEN, NPM_TOKEN, AWS_SECRET_ACCESS_KEY, ANTHROPIC_API_KEY, OPENAI_API_KEY, *_TOKEN, *_SECRET ...)"
}

func (envVars) Collect(env *Env) ([]cred.Credential, []Problem) {
	if env.Environ == nil {
		return nil, nil
	}
	vars := env.Environ()
	sort.Strings(vars)
	var out []cred.Credential
	hasKeyID := false
	for _, kv := range vars {
		if strings.HasPrefix(kv, "AWS_ACCESS_KEY_ID=") {
			hasKeyID = true
		}
	}
	for _, kv := range vars {
		name, value, ok := strings.Cut(kv, "=")
		if !ok || !classify.IsSecretName(name) {
			continue
		}
		r, ok := classify.Var(name, value)
		if !ok {
			continue
		}
		c := cred.Credential{
			Service: r.Service, Kind: r.Kind, Source: "process-env", Location: "env:" + name, Account: name,
			Fingerprint: cred.Fingerprint(value), Lifetime: r.Lifetime, Severity: r.Severity,
			Summary: r.Label + " exported as $" + name,
			Notes:   []string{"inherited by every process you start: a malicious postinstall script or editor extension reads it without touching a file"},
		}
		if name == "AWS_SECRET_ACCESS_KEY" {
			if hasKeyID {
				for _, kv := range vars {
					if id, ok := strings.CutPrefix(kv, "AWS_ACCESS_KEY_ID="); ok && strings.HasPrefix(id, "ASIA") {
						c.Kind, c.Lifetime, c.Severity = "session-key", cred.ShortTerm, cred.Medium
						c.Summary = "Temporary AWS credentials exported in the environment"
					}
				}
			}
		}
		out = append(out, c)
	}
	return out, nil
}
