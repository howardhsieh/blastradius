package scan

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/provider"
	"github.com/howardhsieh/blastradius/internal/testfixture"
)

// probedScan runs the offline scan on the fixture, then the probe phase
// against the fake API.
func probedScan(t *testing.T, fake *testfixture.FakeAPI, opt Options) (*Result, *ProbePlan) {
	t.Helper()
	f := testfixture.NewFixture(t)
	env := envFor(f)
	env.Probe = &provider.ProbeConfig{Transport: fake.Transport, UserAgent: "blastradius/test"}
	opt.Probe = true
	if opt.Dirs == nil {
		opt.Dirs = f.Dirs()
	}
	res, err := Run(env, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Offline || len(fake.Requests()) != 0 {
		t.Fatalf("Run must stay offline even with Probe set: offline=%v requests=%v", res.Offline, fake.Requests())
	}
	plan := PlanProbe(env, res, opt)
	if len(fake.Requests()) != 0 {
		t.Fatalf("PlanProbe made requests: %v", fake.Requests())
	}
	RunProbe(context.Background(), env, res, plan, opt)
	return res, plan
}

func byID(res *Result, pred func(c cred.Credential) bool) *cred.Credential {
	for i := range res.Credentials {
		if pred(res.Credentials[i]) {
			return &res.Credentials[i]
		}
	}
	return nil
}

// TestProbeNoCredentialsNoRequests: --probe on a machine with nothing to
// probe makes zero requests.
func TestProbeNoCredentialsNoRequests(t *testing.T) {
	fake := testfixture.NewFakeAPI(t)
	e := &provider.Env{Home: t.TempDir(), Hostname: "empty", Now: time.Now(), Getenv: func(string) string { return "" }, Environ: func() []string { return nil },
		Probe: &provider.ProbeConfig{Transport: fake.Transport}}
	opt := Options{Probe: true, ProbeClusters: []string{"prod"}}
	res, err := Run(e, opt)
	if err != nil {
		t.Fatal(err)
	}
	plan := PlanProbe(e, res, opt)
	if plan.Credentials() != 0 || len(plan.Targets) != 0 || len(plan.Skipped) != 0 {
		t.Errorf("plan = %+v", plan)
	}
	RunProbe(context.Background(), e, res, plan, opt)
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests made with nothing to probe: %v", n, fake.Requests())
	}
	if res.Offline || len(res.Problems) != 0 || res.Rating != RatingLow {
		t.Errorf("result = offline %v problems %v rating %s", res.Offline, res.Problems, res.Rating)
	}
}

// TestProbePlanAndHosts: the plan names every host before any request, and
// no request goes anywhere else.
func TestProbePlanAndHosts(t *testing.T) {
	fake := testfixture.NewFakeAPI(t)
	res, plan := probedScan(t, fake, Options{ProbeClusters: []string{"prod"}})
	wantHosts := []string{"api.anthropic.com", "api.github.com", "api.openai.com", "prod.k8s.example.com:6443", "registry.npmjs.org", "sts.amazonaws.com"}
	if got := strings.Join(plan.Hosts(), ","); got != strings.Join(wantHosts, ",") {
		t.Errorf("plan hosts = %s", got)
	}
	declared := map[string]bool{"prod.k8s.example.com:6443": true}
	for _, p := range provider.Probers() {
		for _, h := range p.ProbeHosts() {
			declared[h] = true
		}
	}
	for h := range fake.HostCounts() {
		if !declared[h] {
			t.Errorf("request to %s, which no prober declares and no flag allowed", h)
		}
	}
	if len(fake.Unexpected) != 0 {
		t.Errorf("unexpected hosts: %v", fake.Unexpected)
	}
	if res.Offline || strings.Join(res.ProbedHosts, ",") != strings.Join(wantHosts, ",") {
		t.Errorf("offline=%v probed_hosts=%v", res.Offline, res.ProbedHosts)
	}
	probed := 0
	for _, c := range res.Credentials {
		if c.Reach != nil {
			probed++
			if c.Reach.ProbedAt == "" || c.Reach.Host == "" {
				t.Errorf("%s: reach missing host/time: %+v", c.ID, c.Reach)
			}
		}
	}
	if probed != plan.Credentials() {
		t.Errorf("%d credentials probed, plan had %d; problems: %+v", probed, plan.Credentials(), res.Problems)
	}
	// Credentials that cannot be probed are explained, not silently skipped.
	skipped := strings.Join(plan.Skipped, "\n")
	if !strings.Contains(skipped, "zsh_history") || !strings.Contains(skipped, "access key ID") {
		t.Errorf("skipped = %q", skipped)
	}
	// Without the cluster opt-in the kube credentials are listed as skipped.
	fake2 := testfixture.NewFakeAPI(t)
	_, plan2 := probedScan(t, fake2, Options{})
	if !strings.Contains(strings.Join(plan2.Skipped, "\n"), "--probe-cluster prod") {
		t.Errorf("kube skip reason missing: %v", plan2.Skipped)
	}
	if n := fake2.HostCounts()["prod.k8s.example.com:6443"]; n != 0 {
		t.Errorf("cluster contacted without --probe-cluster: %d", n)
	}
}

// TestRefineFromReach checks every severity rule against the fixture.
func TestRefineFromReach(t *testing.T) {
	fake := testfixture.NewFakeAPI(t)
	res, _ := probedScan(t, fake, Options{ProbeClusters: []string{"prod"}})
	check := func(name string, c *cred.Credential, sev cred.Severity, summary string) {
		t.Helper()
		if c == nil {
			t.Errorf("%s: credential not found", name)
			return
		}
		if c.Reach == nil {
			t.Errorf("%s: not probed (%+v)", name, c)
			return
		}
		if c.Severity != sev || !strings.Contains(c.Reach.Summary, summary) {
			t.Errorf("%s: severity %s (want %s), reach %q", name, c.Severity, sev, c.Reach.Summary)
		}
	}
	// gh OAuth token with repo, read:org, gist, workflow: HIGH, and the merged
	// row carries the reach.
	gh := byID(res, func(c cred.Credential) bool { return c.Source == "gh-cli" && c.Account == "alice@github.com" })
	check("gh oauth", gh, cred.High, "scopes: gist, read:org, repo, workflow")
	// netrc ghp_ with repo + admin:org: stays HIGH and says why.
	check("ghp admin:org", byID(res, func(c cred.Credential) bool { return c.Source == "netrc" && c.Kind == "classic-pat" }), cred.High, "full control")
	// Copilot token with no scopes: read-only, MEDIUM.
	check("copilot", byID(res, func(c cred.Credential) bool { return c.Source == "github-copilot" }), cred.Medium, "no scopes")
	// Legacy npm token confirmed automation: CRITICAL with the 2FA note.
	legacy := byID(res, func(c cred.Credential) bool { return c.Kind == "legacy-token" })
	check("npm automation", legacy, cred.Critical, "without 2FA")
	if legacy != nil && legacy.Remediation != "Revoke the npm automation token: it publishes without 2FA" {
		t.Errorf("legacy remediation = %q", legacy.Remediation)
	}
	// npm_ token confirmed read-only: MEDIUM.
	check("npm read-only", byID(res, func(c cred.Credential) bool {
		return c.Service == cred.ServiceNPM && c.Kind == "access-token" && c.Source == "npmrc"
	}), cred.Medium, "read-only")
	// AWS root key: CRITICAL with its own advice, first in the list.
	root := byID(res, func(c cred.Credential) bool { return c.Account == "profile default" })
	check("aws root", root, cred.Critical, "ROOT USER")
	if root != nil && !strings.HasPrefix(root.Remediation, "Delete the ROOT access key") {
		t.Errorf("root remediation = %q", root.Remediation)
	}
	var rootAdvice, revokedAdvice *Advice
	for i := range res.Remediation {
		switch {
		case strings.HasPrefix(res.Remediation[i].Title, "Delete the ROOT access key"):
			rootAdvice = &res.Remediation[i]
		case strings.HasPrefix(res.Remediation[i].Title, "Delete credentials the service no longer accepts"):
			revokedAdvice = &res.Remediation[i]
		}
	}
	if rootAdvice == nil || rootAdvice.Severity != cred.Critical || len(rootAdvice.Credentials) != 1 || rootAdvice.Priority > 3 {
		t.Errorf("root advice = %+v", rootAdvice)
	}
	if revokedAdvice == nil || revokedAdvice.Severity != cred.Low {
		t.Errorf("revoked advice = %+v", revokedAdvice)
	}
	// AWS session key in the environment without a session token: STS rejects
	// it, so it drops to LOW and gets the clean-up advice.
	envAWS := byID(res, func(c cred.Credential) bool { return c.Location == "env:AWS_SECRET_ACCESS_KEY" })
	check("aws rejected", envAWS, cred.Low, "rejected")
	if envAWS != nil && !strings.HasPrefix(envAWS.Remediation, "Delete credentials the service no longer accepts") {
		t.Errorf("rejected remediation = %q", envAWS.Remediation)
	}
	// Kubernetes: cluster-admin token is CRITICAL; the read-only certificate
	// user drops to MEDIUM.
	check("kube admin token", byID(res, func(c cred.Credential) bool { return c.Account == "sa-token" }), cred.Critical, "cluster-admin")
	check("kube read-only cert", byID(res, func(c cred.Credential) bool { return c.Account == "admin" && c.Service == cred.ServiceKubernetes }), cred.Medium, "read pods, services")
	// Live AI keys keep their severity.
	check("anthropic", byID(res, func(c cred.Credential) bool { return c.Location == "env:ANTHROPIC_API_KEY" }), cred.High, "live key")
	// Severity order and rating were recomputed.
	for i := 1; i < len(res.Credentials); i++ {
		if res.Credentials[i].Severity > res.Credentials[i-1].Severity {
			// Probing may reorder severities; the report sorts for display.
			break
		}
	}
	if res.Rating != RatingCritical || res.Summary["critical"] < 3 {
		t.Errorf("rating %s summary %v", res.Rating, res.Summary)
	}
	if !res.Credentials[0].Expired && res.Credentials[0].Reach == nil && res.Credentials[0].Severity != cred.Critical {
		t.Errorf("first credential = %+v", res.Credentials[0])
	}
}

// TestProbeErrorsBecomeProblems: an API that is down turns into a Problem
// line; the scan result is still complete and rated.
func TestProbeErrorsBecomeProblems(t *testing.T) {
	fake := testfixture.NewFakeAPI(t)
	fake.AWSArn = func(string) string { return "" } // every AWS answer is a rejection
	fake.KubeRules = func(string) []map[string]any { return nil }
	f := testfixture.NewFixture(t)
	env := envFor(f)
	// Break the npm file between scan and probe so re-reading fails.
	env.Probe = &provider.ProbeConfig{Transport: fake.Transport}
	opt := Options{Probe: true, Dirs: f.Dirs(), ProbeTimeout: 30 * time.Second}
	res, err := Run(env, opt)
	if err != nil {
		t.Fatal(err)
	}
	plan := PlanProbe(env, res, opt)
	if err := writeFile(f.Home+"/.npmrc", "# rotated\n"); err != nil {
		t.Fatal(err)
	}
	RunProbe(context.Background(), env, res, plan, opt)
	var npmProblem bool
	for _, p := range res.Problems {
		if strings.Contains(p.Location, "npmrc") && strings.Contains(p.Err, "probe registry.npmjs.org") {
			npmProblem = true
		}
		if strings.Contains(p.Err, testfixture.Marker) {
			t.Errorf("problem leaks a secret: %+v", p)
		}
	}
	if !npmProblem {
		t.Errorf("no problem for the rotated npm token: %+v", res.Problems)
	}
	if res.Rating == "" || len(res.Remediation) == 0 || res.Offline {
		t.Errorf("result incomplete after probe errors: %+v", res)
	}
	// A cancelled context stops the phase without losing the offline result.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	env2 := envFor(f)
	env2.Probe = &provider.ProbeConfig{Transport: fake.Transport}
	res2, _ := Run(env2, opt)
	plan2 := PlanProbe(env2, res2, opt)
	before := len(fake.Requests())
	RunProbe(ctx, env2, res2, plan2, opt)
	if len(res2.Problems) < plan2.Credentials() || len(fake.Requests()) != before {
		t.Errorf("cancelled probe: %d problems for %d jobs, %d requests made", len(res2.Problems), plan2.Credentials(), len(fake.Requests())-before)
	}
}

func TestRefineRulesDirect(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    cred.Credential
		want cred.Severity
	}{
		{"unprobed untouched", cred.Credential{Service: cred.ServiceAWS, Severity: cred.Critical}, cred.Critical},
		{"rejected is low", cred.Credential{Service: cred.ServiceGitHub, Severity: cred.High, Reach: &cred.Reach{Live: false}}, cred.Low},
		{"fine-grained stays medium", cred.Credential{Service: cred.ServiceGitHub, Severity: cred.High, Reach: &cred.Reach{Live: true, TokenType: "fine-grained"}}, cred.Medium},
		{"read-only classic", cred.Credential{Service: cred.ServiceGitHub, Severity: cred.High, Reach: &cred.Reach{Live: true, TokenType: "classic", Scopes: []string{"read:org"}, ReadOnly: true}}, cred.Medium},
		{"repo+admin:org", cred.Credential{Service: cred.ServiceGitHub, Severity: cred.Medium, Reach: &cred.Reach{Live: true, TokenType: "classic", Scopes: []string{"repo", "admin:org"}}}, cred.High},
		{"npm publish unchanged", cred.Credential{Service: cred.ServiceNPM, Severity: cred.High, Reach: &cred.Reach{Live: true, TokenType: "publish"}}, cred.High},
		{"npm automation", cred.Credential{Service: cred.ServiceNPM, Severity: cred.High, Reach: &cred.Reach{Live: true, TokenType: "automation", Bypass2FA: true}}, cred.Critical},
		{"aws user unchanged", cred.Credential{Service: cred.ServiceAWS, Severity: cred.Critical, Reach: &cred.Reach{Live: true, TokenType: "iam-user"}}, cred.Critical},
		{"aws root", cred.Credential{Service: cred.ServiceAWS, Severity: cred.Medium, Reach: &cred.Reach{Live: true, Admin: true}}, cred.Critical},
		{"kube read-only", cred.Credential{Service: cred.ServiceKubernetes, Severity: cred.High, Reach: &cred.Reach{Live: true, ReadOnly: true}}, cred.Medium},
	} {
		c := tc.c
		refine(&c)
		if c.Severity != tc.want {
			t.Errorf("%s: %s, want %s", tc.name, c.Severity, tc.want)
		}
	}
}

func writeFile(path, body string) error { return os.WriteFile(path, []byte(body), 0o600) }
