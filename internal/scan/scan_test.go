package scan

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/provider"
	"github.com/howardhsieh/blastradius/internal/testfixture"
)

func envFor(f *testfixture.Fixture) *provider.Env {
	return &provider.Env{Home: f.Home, Hostname: "testbox", Now: f.Now, Getenv: f.Getenv, Environ: f.Environment}
}

func mustRun(t *testing.T, f *testfixture.Fixture, opt Options) *Result {
	t.Helper()
	if opt.Dirs == nil {
		opt.Dirs = f.Dirs()
	}
	res, err := Run(envFor(f), opt)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestFullScan(t *testing.T) {
	f := testfixture.NewFixture(t)
	res := mustRun(t, f, Options{})
	if res.Rating != RatingCritical || res.Score != 100 {
		t.Errorf("rating %s score %d", res.Rating, res.Score)
	}
	if len(res.Problems) != 0 {
		t.Errorf("problems: %+v", res.Problems)
	}
	if len(res.Providers) != len(provider.All()) {
		t.Errorf("providers run: %v", res.Providers)
	}
	for _, s := range []string{"github", "npm", "aws", "gcp", "ssh", "anthropic", "kubernetes"} {
		if !contains(res.Services, s) {
			t.Errorf("service %s missing from %v", s, res.Services)
		}
	}
	// Every credential has an ID, and IDs are unique.
	ids := map[string]bool{}
	for _, c := range res.Credentials {
		if c.ID == "" || ids[c.ID] {
			t.Errorf("bad or duplicate id %q", c.ID)
		}
		ids[c.ID] = true
		if needsAdvice(c) && c.Remediation == "" {
			t.Errorf("%s has no remediation", c.ID)
		}
	}
	// Sorted by severity, worst first.
	for i := 1; i < len(res.Credentials); i++ {
		if res.Credentials[i].Severity > res.Credentials[i-1].Severity {
			t.Errorf("not sorted at %d", i)
		}
	}
	// Advice exists, is ordered, and the first item is about a critical credential.
	if len(res.Remediation) == 0 || res.Remediation[0].Severity != cred.Critical || res.Remediation[0].Priority != 1 {
		t.Fatalf("remediation = %+v", res.Remediation)
	}
	for i := 1; i < len(res.Remediation); i++ {
		if res.Remediation[i].Severity > res.Remediation[i-1].Severity {
			t.Errorf("advice not ordered at %d", i)
		}
		if res.Remediation[i].Priority != i+1 {
			t.Errorf("priority at %d = %d", i, res.Remediation[i].Priority)
		}
	}
	// Every non-expired, non-info credential is covered by exactly one advice.
	covered := map[string]int{}
	for _, a := range res.Remediation {
		for _, id := range a.Credentials {
			covered[id]++
		}
	}
	for _, c := range res.Credentials {
		want := 1
		if !needsAdvice(c) {
			want = 0
		}
		if covered[c.ID] != want {
			t.Errorf("%s covered by %d advice entries, want %d", c.ID, covered[c.ID], want)
		}
	}
}

// The gh token is in hosts.yml twice, in .git-credentials and in $GH_TOKEN:
// one secret, one row, three "also in" locations.
func TestMergeSameSecret(t *testing.T) {
	f := testfixture.NewFixture(t)
	res := mustRun(t, f, Options{})
	var gh []cred.Credential
	for _, c := range res.Credentials {
		if c.Service == cred.ServiceGitHub && c.Source == "gh-cli" && c.Account == "alice@github.com" {
			gh = append(gh, c)
		}
	}
	if len(gh) != 1 {
		t.Fatalf("want one merged row, got %d: %+v", len(gh), gh)
	}
	if len(gh[0].AlsoIn) != 2 || !strings.Contains(strings.Join(gh[0].AlsoIn, ","), "env:GH_TOKEN") {
		t.Errorf("also_in = %v", gh[0].AlsoIn)
	}
	if !strings.Contains(gh[0].Notes[0], "2 other place") {
		t.Errorf("notes = %v", gh[0].Notes)
	}
}

func TestOptions(t *testing.T) {
	f := testfixture.NewFixture(t)
	res := mustRun(t, f, Options{SkipEnv: true})
	for _, c := range res.Credentials {
		if c.Source == "process-env" || strings.HasPrefix(c.Location, "env:") || contains(c.AlsoIn, "env:GH_TOKEN") {
			t.Errorf("env scanned despite SkipEnv: %+v", c)
		}
	}
	res = mustRun(t, f, Options{Providers: []string{"ssh"}})
	if len(res.Providers) != 1 {
		t.Errorf("providers = %v", res.Providers)
	}
	for _, c := range res.Credentials {
		if c.Service != cred.ServiceSSH {
			t.Errorf("unexpected %+v", c)
		}
	}
	if res.Rating != RatingHigh {
		t.Errorf("ssh-only rating = %s", res.Rating)
	}
}

func TestEmptyHome(t *testing.T) {
	e := &provider.Env{Home: t.TempDir(), Hostname: "empty", Now: testfixture.NewFixture(t).Now, Getenv: func(string) string { return "" }, Environ: func() []string { return nil }}
	res, err := Run(e, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Rating != RatingLow || res.Score != 0 || len(res.Credentials) != 0 || len(res.Remediation) != 0 {
		t.Errorf("empty home: %+v", res)
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), `"credentials": []`) && !strings.Contains(buf.String(), `"credentials":[]`) {
		t.Errorf("credentials should encode as an empty array: %s", buf.String())
	}
}

func TestRate(t *testing.T) {
	for _, tc := range []struct {
		sev    []cred.Severity
		rating string
		score  int
	}{
		{nil, RatingLow, 0},
		{[]cred.Severity{cred.Low}, RatingLow, 2},
		{[]cred.Severity{cred.Medium, cred.Low}, RatingModerate, 10},
		{[]cred.Severity{cred.High}, RatingHigh, 20},
		{[]cred.Severity{cred.Critical, cred.High, cred.High, cred.High}, RatingCritical, 100},
	} {
		var cs []cred.Credential
		for _, s := range tc.sev {
			cs = append(cs, cred.Credential{Severity: s})
		}
		score, rating := Rate(cs)
		if rating != tc.rating || score != tc.score {
			t.Errorf("Rate(%v) = %d %s, want %d %s", tc.sev, score, rating, tc.score, tc.rating)
		}
	}
	// Expired credentials do not count.
	if s, r := Rate([]cred.Credential{{Severity: cred.Critical, Expired: true}}); s != 0 || r != RatingLow {
		t.Errorf("expired counted: %d %s", s, r)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
