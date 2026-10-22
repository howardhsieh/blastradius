package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/howardhsieh/blastradius/internal/cred"
)

const (
	anthropicAPIHost = "api.anthropic.com"
	openaiAPIHost    = "api.openai.com"
)

// ProbeHosts: the model-list endpoints of Anthropic and OpenAI. These are
// the cheapest read-only calls each API offers; no completion is ever
// requested, so a probe costs nothing.
func (aiTools) ProbeHosts() []string { return []string{anthropicAPIHost, openaiAPIHost} }

func (aiTools) probeTargets(env *Env, c cred.Credential) ([]string, string) {
	if c.Kind != "api-key" {
		return nil, "" // OAuth logins of the CLIs are not probed
	}
	switch c.Service {
	case cred.ServiceAnthropic:
		return []string{anthropicAPIHost}, ""
	case cred.ServiceOpenAI:
		return []string{openaiAPIHost}, ""
	}
	return nil, ""
}

// Probe confirms the key is live with GET /v1/models. The APIs expose no
// permission model to the key itself, so the result is live / rejected.
func (a aiTools) Probe(ctx context.Context, env *Env, c cred.Credential) (*Reach, error) {
	hosts, _ := a.probeTargets(env, c)
	if len(hosts) == 0 {
		return nil, ErrNotProbed
	}
	host := hosts[0]
	return guarded(env, c, func(secret string) (*Reach, error) {
		req, err := env.newProbeRequest(ctx, http.MethodGet, "https://"+host+"/v1/models", nil)
		if err != nil {
			return nil, err
		}
		if host == anthropicAPIHost {
			req.Header.Set("x-api-key", secret)
			req.Header.Set("anthropic-version", "2023-06-01")
		} else {
			req.Header.Set("Authorization", "Bearer "+secret)
		}
		var models struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		resp, err := doJSON(env.probeClient(hosts, nil), req, &models)
		if err != nil {
			return nil, err
		}
		r := &Reach{Host: host}
		if rejected(resp.StatusCode) {
			r.Summary = fmt.Sprintf("rejected by %s (HTTP %d): revoked or invalid", host, resp.StatusCode)
			return r, nil
		}
		if resp.StatusCode/100 != 2 {
			return nil, statusErr(host, resp)
		}
		r.Live = true
		r.TokenType = "api-key"
		r.Summary = fmt.Sprintf("live key: %s lists %d model(s) for it; usage is billed to the account", host, len(models.Data))
		return r, nil
	})
}
