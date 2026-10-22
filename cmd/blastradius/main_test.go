package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/howardhsieh/blastradius/internal/testfixture"
)

func TestCLI(t *testing.T) {
	f := testfixture.NewFixture(t)
	// The CLI reads the real process environment; keep it out of the way so
	// the test is deterministic and never reports the developer's own keys.
	run := func(args ...string) (int, string, string) {
		var out, errb bytes.Buffer
		code := run(append([]string{"scan", "--home", f.Home, "--no-env", "--no-color"}, args...), &out, &errb)
		return code, out.String(), errb.String()
	}
	code, out, _ := run("--dir", f.Dirs()[0])
	if code != 0 || !strings.Contains(out, "CRITICAL") || strings.Contains(out, testfixture.Marker) {
		t.Errorf("default scan: code %d\n%s", code, out)
	}
	code, out, _ = run("-f", "json", "--fail-on", "high")
	if code != 1 {
		t.Errorf("--fail-on high should exit 1, got %d", code)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil || doc["rating"] != "CRITICAL" {
		t.Errorf("json output: %v %v", err, doc["rating"])
	}
	code, out, _ = run("-f", "sarif")
	var sarif struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []map[string]any `json:"results"`
		} `json:"runs"`
	}
	if code != 0 || json.Unmarshal([]byte(out), &sarif) != nil || sarif.Version != "2.1.0" || len(sarif.Runs) != 1 || len(sarif.Runs[0].Results) == 0 || strings.Contains(out, testfixture.Marker) {
		t.Errorf("sarif output: code %d\n%.300s", code, out)
	}
	if code, _, _ = run("--provider", "ssh", "--fail-on", "critical"); code != 0 {
		t.Errorf("ssh only should not be critical: %d", code)
	}
	path := filepath.Join(t.TempDir(), "r.json")
	if code, _, _ = run("-f", "json", "-o", path); code != 0 {
		t.Errorf("-o: %d", code)
	}
	if st, err := os.Stat(path); err != nil || st.Size() == 0 {
		t.Errorf("report not written: %v", err)
	}
	for _, bad := range [][]string{{"--probe-host", "ghe.example.com"}, {"--probe-cluster", "prod"}, {"--probe", "--probe-timeout", "0s"}, {"-f", "xml"}, {"--min-severity", "loud"}, {"--fail-on", "maybe"}, {"--provider", "nope"}, {"extra"}} {
		if code, _, errs := run(bad...); code != 2 || errs == "" {
			t.Errorf("%v should exit 2 with a message, got %d %q", bad, code, errs)
		}
	}
}

// TestProbeCLI drives --probe end to end against the fake API: the consent
// list is printed before any request, the JSON carries reach, and nothing
// goes to a host the probers do not declare.
func TestProbeCLI(t *testing.T) {
	fake := testfixture.NewFakeAPI(t)
	probeTransport = fake.Transport
	t.Cleanup(func() { probeTransport = nil })
	f := testfixture.NewFixture(t)

	// Nothing to probe: the consent message says so and no request is made.
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--home", t.TempDir(), "--no-env", "--probe", "-f", "json"}, &out, &errb); code != 0 || !strings.Contains(errb.String(), "nothing to probe, no request will be made") {
		t.Errorf("empty home: code %d stderr %q", code, errb.String())
	}
	if n := len(fake.Requests()); n != 0 {
		t.Errorf("%d requests for an empty home", n)
	}

	out.Reset()
	errb.Reset()
	code := run([]string{"scan", "--home", f.Home, "--no-env", "--no-color", "--probe", "--probe-cluster", "prod", "--dir", f.Dirs()[0], "-f", "json"}, &out, &errb)
	if code != 0 {
		t.Fatalf("probe scan: code %d stderr %s", code, errb.String())
	}
	consent := errb.String()
	for _, want := range []string{"will send", "api.github.com", "registry.npmjs.org", "sts.amazonaws.com", "api.anthropic.com", "api.openai.com", "prod.k8s.example.com:6443", "github credential", "not probed:"} {
		if !strings.Contains(consent, want) {
			t.Errorf("consent output missing %q:\n%s", want, consent)
		}
	}
	if strings.Contains(consent, testfixture.Marker) || strings.Contains(out.String(), testfixture.Marker) {
		t.Error("output contains the fixture marker")
	}
	var doc struct {
		Offline     bool     `json:"offline"`
		ProbedHosts []string `json:"probed_hosts"`
		Credentials []struct {
			Reach map[string]any `json:"reach"`
		} `json:"credentials"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	probed := 0
	for _, c := range doc.Credentials {
		if c.Reach != nil {
			probed++
		}
	}
	if doc.Offline || len(doc.ProbedHosts) != 6 || probed < 10 {
		t.Errorf("json: offline %v hosts %v probed %d", doc.Offline, doc.ProbedHosts, probed)
	}
	if len(fake.Unexpected) != 0 {
		t.Errorf("requests to undeclared hosts: %v", fake.Unexpected)
	}
	for _, r := range fake.Requests() {
		if !strings.HasPrefix(r, "blastradius") && !strings.HasPrefix(r, "api.") && !strings.HasPrefix(r, "registry.") && !strings.HasPrefix(r, "sts.") && !strings.HasPrefix(r, "prod.") {
			t.Errorf("unexpected request %q", r)
		}
	}
	// Table output shows the reach line under the row.
	out.Reset()
	errb.Reset()
	if code := run([]string{"scan", "--home", f.Home, "--no-env", "--no-color", "--probe", "--probe-cluster", "prod"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "↳ acts as alice") || !strings.Contains(out.String(), "probed ") {
		t.Errorf("table: code %d\n%s", code, out.String())
	}
}

func TestOtherCommands(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"providers"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "shell-history") || !strings.Contains(out.String(), "probe: api.github.com") || !strings.Contains(out.String(), "--probe-cluster NAME") || !strings.Contains(out.String(), "sts.amazonaws.com") {
		t.Errorf("providers: %d %s", code, out.String())
	}
	out.Reset()
	if code := run([]string{"version"}, &out, &errb); code != 0 || !strings.HasPrefix(out.String(), "blastradius ") {
		t.Errorf("version: %d %s", code, out.String())
	}
	if code := run(nil, &out, &errb); code != 2 {
		t.Errorf("no args: %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "unknown command") {
		t.Errorf("bogus: %d", code)
	}
}
