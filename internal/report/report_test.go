package report

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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

// TestNoSecretInAnyOutput is the contract of the tool: whatever the
// fixture home contains, neither report format may contain any secret, any
// encoding of it that appears in the files, or the fixture marker.
func TestNoSecretInAnyOutput(t *testing.T) {
	f, res := fullScan(t)
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
	if len(f.Secrets) < 40 {
		t.Fatalf("fixture only has %d secrets; the leak test needs the full set", len(f.Secrets))
	}
	for name, out := range map[string]string{"table": table.String(), "verbose": verbose.String(), "json": js.String()} {
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
