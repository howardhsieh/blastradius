package report

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/provider"
	"github.com/howardhsieh/blastradius/internal/scan"
	"github.com/howardhsieh/blastradius/internal/testfixture"
)

func fullScan(t *testing.T) (*testfixture.Fixture, *scan.Result) {
	t.Helper()
	f := testfixture.NewFixture(t)
	env := &provider.Env{Home: f.Home, Hostname: "testbox", Now: f.Now, Getenv: f.Getenv, Environ: f.Environment}
	res, err := scan.Run(env, scan.Options{Dirs: f.Dirs()})
	if err != nil {
		t.Fatal(err)
	}
	return f, res
}

// probedScan runs the offline scan and then the probe phase against the
// fake API. With echo, the fake is hostile: every identity, scope, ARN and
// rule it returns is the secret the probe just presented.
func probedScan(t *testing.T, echo bool) (*testfixture.Fixture, *scan.Result) {
	t.Helper()
	f := testfixture.NewFixture(t)
	fake := testfixture.NewFakeAPI(t)
	fake.Echo = echo
	env := &provider.Env{Home: f.Home, Hostname: "testbox", Now: f.Now, Getenv: f.Getenv, Environ: f.Environment,
		Probe: &provider.ProbeConfig{Transport: fake.Transport, UserAgent: "blastradius/test"}}
	opt := scan.Options{Dirs: f.Dirs(), Probe: true, ProbeClusters: []string{"prod"}}
	res, err := scan.Run(env, opt)
	if err != nil {
		t.Fatal(err)
	}
	plan := scan.PlanProbe(env, res, opt)
	scan.RunProbe(context.Background(), env, res, plan, opt)
	probed := 0
	for _, c := range res.Credentials {
		if c.Reach != nil {
			probed++
		}
	}
	if probed < 10 {
		t.Fatalf("only %d credentials probed; problems: %+v", probed, res.Problems)
	}
	return f, res
}

// TestNoSecretInAnyOutput is the contract of the tool: whatever the
// fixture home contains, neither report format may contain any secret, any
// encoding of it that appears in the files, or the fixture marker. It runs
// for the offline scan, for a probed scan, and for a probed scan against a
// hostile API that echoes every secret back in every field.
func TestNoSecretInAnyOutput(t *testing.T) {
	t.Run("offline", func(t *testing.T) {
		f, res := fullScan(t)
		assertNoSecret(t, f, res)
	})
	t.Run("probed", func(t *testing.T) {
		f, res := probedScan(t, false)
		assertNoSecret(t, f, res)
	})
	t.Run("hostile-api", func(t *testing.T) {
		f, res := probedScan(t, true)
		assertNoSecret(t, f, res)
		// The scrubber left a trace, so the hostile answers really arrived.
		var js bytes.Buffer
		if err := JSON(&js, res, "test"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(js.String(), "[redacted]") {
			t.Error("hostile answers were not scrubbed (or never arrived)")
		}
	})
}

func assertNoSecret(t *testing.T, f *testfixture.Fixture, res *scan.Result) {
	t.Helper()
	var table, verbose, js bytes.Buffer
	if err := Table(&table, res, TableOptions{MinSeverity: cred.Info}); err != nil {
		t.Fatal(err)
	}
	if err := Table(&verbose, res, TableOptions{MinSeverity: cred.Info, Verbose: true, Color: true}); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, res, "test"); err != nil {
		t.Fatal(err)
	}
	var sarif bytes.Buffer
	if err := SARIF(&sarif, res, "test"); err != nil {
		t.Fatal(err)
	}
	// Reach fields are part of the contract too: dump them on their own so a
	// leak there is attributed to probing.
	var reach bytes.Buffer
	for _, c := range res.Credentials {
		if c.Reach != nil {
			if err := json.NewEncoder(&reach).Encode(c.Reach); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, p := range res.Problems {
		reach.WriteString(p.Location + " " + p.Err + "\n")
	}
	if len(f.Secrets) < 40 {
		t.Fatalf("fixture only has %d secrets; the leak test needs the full set", len(f.Secrets))
	}
	for name, out := range map[string]string{"table": table.String(), "verbose": verbose.String(), "json": js.String(), "sarif": sarif.String(), "reach": reach.String()} {
		if strings.Contains(out, testfixture.Marker) {
			t.Errorf("%s output contains the fixture marker:\n%s", name, out)
		}
		for _, s := range f.Secrets {
			s = strings.TrimSpace(s)
			for _, form := range []string{s, base64.StdEncoding.EncodeToString([]byte(s)), strings.ReplaceAll(s, "\n", `\n`)} {
				if strings.Contains(out, form) {
					t.Errorf("%s output contains a fixture secret (%.12s…)", name, form)
				}
			}
			// Even a substantial substring is a leak.
			if len(s) > 24 && strings.Contains(out, s[4:20]) {
				t.Errorf("%s output contains part of a fixture secret (%.12s…)", name, s)
			}
		}
	}
}

func TestTable(t *testing.T) {
	_, res := fullScan(t)
	var buf bytes.Buffer
	if err := Table(&buf, res, TableOptions{MinSeverity: cred.High}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"CRITICAL", "testbox", "exposure 100/100", "[CRITICAL]", "~/.aws/credentials:1", "sha256:", "long-term", "Do first:", "1. [CRITICAL]", "also in env:GH_TOKEN"} {
		if !strings.Contains(out, want) {
			t.Errorf("table missing %q:\n%s", want, out)
		}
	}
	// Rows are "[LOW]      service"; the advice list may still mention lower
	// severities because it summarises the whole machine.
	if strings.Contains(out, "[LOW]     ") || strings.Contains(out, "[MEDIUM]  ") || strings.Contains(out, "\x1b[") {
		t.Errorf("low/medium rows or colour shown despite options:\n%s", out)
	}
	buf.Reset()
	if err := Table(&buf, res, TableOptions{MinSeverity: cred.Info, Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "[INFO]") || !strings.Contains(buf.String(), "IAM Identity Center") {
		t.Errorf("verbose/info table:\n%s", buf.String())
	}
}

func TestTableWithReach(t *testing.T) {
	_, res := probedScan(t, false)
	var buf bytes.Buffer
	if err := Table(&buf, res, TableOptions{MinSeverity: cred.Low}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"probed ", " against 6 hosts", "↳ acts as alice · scopes: gist, read:org, repo, workflow", "api.github.com · probed 2026-10-22T12:00:00Z", "↳ ROOT USER of account 123456789012", "↳ rejected by sts.amazonaws.com", "cluster-admin", "Delete the ROOT access key", "Delete credentials the service no longer accepts"} {
		if !strings.Contains(out, want) {
			t.Errorf("probed table missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "offline scan") {
		t.Error("probed table still says offline")
	}
}

func TestJSONWithReach(t *testing.T) {
	_, res := probedScan(t, false)
	var buf bytes.Buffer
	if err := JSON(&buf, res, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Offline     bool     `json:"offline"`
		ProbedHosts []string `json:"probed_hosts"`
		Credentials []struct {
			ID    string `json:"id"`
			Reach *struct {
				Host      string   `json:"host"`
				Live      bool     `json:"live"`
				Identity  string   `json:"identity"`
				TokenType string   `json:"token_type"`
				Scopes    []string `json:"scopes"`
				Summary   string   `json:"summary"`
				ProbedAt  string   `json:"probed_at"`
			} `json:"reach"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Offline || len(doc.ProbedHosts) != 6 {
		t.Errorf("offline %v hosts %v", doc.Offline, doc.ProbedHosts)
	}
	var withReach, classic int
	for _, c := range doc.Credentials {
		if c.Reach == nil {
			continue
		}
		withReach++
		if c.Reach.ProbedAt != "2026-10-22T12:00:00Z" || c.Reach.Summary == "" || c.Reach.Host == "" {
			t.Errorf("%s reach = %+v", c.ID, c.Reach)
		}
		if c.Reach.TokenType == "classic" && len(c.Reach.Scopes) > 0 && c.Reach.Identity == "alice" {
			classic++
		}
	}
	if withReach < 10 || classic == 0 {
		t.Errorf("with reach %d, classic %d", withReach, classic)
	}
	for _, bad := range []string{`"token":`, `"password":`, `"secret":`, `"private_key":`, `"value":`, `"key":`} {
		if strings.Contains(strings.ToLower(buf.String()), bad) {
			t.Errorf("json has a %s field", bad)
		}
	}
}

func TestSARIF(t *testing.T) {
	for _, probed := range []bool{false, true} {
		var res *scan.Result
		if probed {
			_, res = probedScan(t, false)
		} else {
			_, res = fullScan(t)
		}
		var buf bytes.Buffer
		if err := SARIF(&buf, res, "1.2.3"); err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Schema  string `json:"$schema"`
			Version string `json:"version"`
			Runs    []struct {
				Tool struct {
					Driver struct {
						Name    string `json:"name"`
						Version string `json:"version"`
						Rules   []struct {
							ID               string `json:"id"`
							ShortDescription struct {
								Text string `json:"text"`
							} `json:"shortDescription"`
						} `json:"rules"`
					} `json:"driver"`
				} `json:"tool"`
				Results []struct {
					RuleID    string `json:"ruleId"`
					Level     string `json:"level"`
					Message   struct{ Text string }
					Locations []struct {
						PhysicalLocation struct {
							ArtifactLocation struct{ URI string }
							Region           *struct{ StartLine int }
						} `json:"physicalLocation"`
					} `json:"locations"`
					Properties          map[string]string `json:"properties"`
					PartialFingerprints map[string]string `json:"partialFingerprints"`
				} `json:"results"`
				Properties map[string]string `json:"properties"`
			} `json:"runs"`
		}
		if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if doc.Version != "2.1.0" || !strings.Contains(doc.Schema, "sarif-2.1.0") || len(doc.Runs) != 1 {
			t.Fatalf("sarif envelope = %+v", doc)
		}
		run := doc.Runs[0]
		if run.Tool.Driver.Name != "blastradius" || run.Tool.Driver.Version != "1.2.3" || len(run.Tool.Driver.Rules) < 20 {
			t.Errorf("driver = %+v", run.Tool.Driver)
		}
		if run.Properties["rating"] != "CRITICAL" || run.Properties["host"] != "testbox" || run.Properties["offline"] != fmt.Sprint(!probed) {
			t.Errorf("run properties = %v", run.Properties)
		}
		if len(run.Results) != len(res.Credentials) {
			t.Fatalf("%d results for %d credentials", len(run.Results), len(res.Credentials))
		}
		ruleIDs := map[string]bool{}
		for _, r := range run.Tool.Driver.Rules {
			ruleIDs[r.ID] = true
		}
		levels := map[string]int{}
		for i, r := range run.Results {
			c := res.Credentials[i]
			if !ruleIDs[r.RuleID] {
				t.Errorf("result %d uses undeclared rule %q", i, r.RuleID)
			}
			levels[r.Level]++
			if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI == "" {
				t.Errorf("result %d has no location: %+v", i, r)
			}
			if c.Line > 0 && (r.Locations[0].PhysicalLocation.Region == nil || r.Locations[0].PhysicalLocation.Region.StartLine != c.Line) {
				t.Errorf("result %d line = %+v, want %d", i, r.Locations[0].PhysicalLocation.Region, c.Line)
			}
			if r.Properties["service"] != c.Service || r.Properties["severity"] != c.Severity.String() {
				t.Errorf("result %d properties = %v", i, r.Properties)
			}
			if c.Fingerprint != "" && r.PartialFingerprints["secretSha256Prefix/v1"] != c.Fingerprint {
				t.Errorf("result %d fingerprint = %v", i, r.PartialFingerprints)
			}
			if c.Reach != nil && (r.Properties["probe_host"] == "" || !strings.Contains(r.Message.Text, "probe:")) {
				t.Errorf("result %d lost its reach: %+v", i, r)
			}
			if !strings.Contains(r.Message.Text, strings.ToUpper(c.Severity.String())) {
				t.Errorf("result %d message = %q", i, r.Message.Text)
			}
		}
		if levels["error"] == 0 || levels["warning"] == 0 || levels["note"] == 0 {
			t.Errorf("levels = %v", levels)
		}
		if probed && run.Properties["probed_hosts"] == "" {
			t.Errorf("probed run has no probed_hosts: %v", run.Properties)
		}
		// Environment variables are env: URIs, files keep the ~/ form.
		var envSeen, fileSeen bool
		for _, r := range run.Results {
			uri := r.Locations[0].PhysicalLocation.ArtifactLocation.URI
			if strings.HasPrefix(uri, "env:") {
				envSeen = true
			}
			if strings.HasPrefix(uri, "~/") {
				fileSeen = true
			}
		}
		if !envSeen || !fileSeen {
			t.Errorf("uris: env %v file %v", envSeen, fileSeen)
		}
	}
	// The inventory rule covers rows that need no action.
	if scan.RuleFor(cred.Credential{Severity: cred.Info}).ID != scan.InventoryRule.ID {
		t.Error("info credential should map to the inventory rule")
	}
}

func TestJSON(t *testing.T) {
	_, res := fullScan(t)
	var buf bytes.Buffer
	if err := JSON(&buf, res, "1.2.3"); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Tool        string `json:"tool"`
		Version     string `json:"version"`
		Rating      string `json:"rating"`
		Offline     bool   `json:"offline"`
		Credentials []struct {
			ID          string   `json:"id"`
			Service     string   `json:"service"`
			Fingerprint string   `json:"fingerprint"`
			Severity    string   `json:"severity"`
			Lifetime    string   `json:"lifetime"`
			AlsoIn      []string `json:"also_in"`
		} `json:"credentials"`
		Remediation []struct {
			Priority    int      `json:"priority"`
			Credentials []string `json:"credentials"`
		} `json:"remediation"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Tool != "blastradius" || doc.Version != "1.2.3" || doc.Rating != "CRITICAL" || !doc.Offline || len(doc.Credentials) == 0 || len(doc.Remediation) == 0 {
		t.Errorf("json = %+v", doc)
	}
	if doc.Credentials[0].Severity != "critical" || doc.Credentials[0].ID == "" {
		t.Errorf("first credential = %+v", doc.Credentials[0])
	}
	// No key named like a secret may exist anywhere in the document.
	for _, bad := range []string{`"token":`, `"password":`, `"secret":`, `"private_key":`, `"value":`} {
		if strings.Contains(strings.ToLower(buf.String()), bad) {
			t.Errorf("json has a %s field", bad)
		}
	}
}
