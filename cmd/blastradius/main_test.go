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
	for _, bad := range [][]string{{"--probe"}, {"-f", "xml"}, {"--min-severity", "loud"}, {"--fail-on", "maybe"}, {"--provider", "nope"}, {"extra"}} {
		if code, _, errs := run(bad...); code != 2 || errs == "" {
			t.Errorf("%v should exit 2 with a message, got %d %q", bad, code, errs)
		}
	}
}

func TestOtherCommands(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"providers"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "shell-history") {
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
