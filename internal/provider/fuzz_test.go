package provider

import (
	"strings"
	"testing"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// The parsers in this package read files a stealer or a malicious
// repository could have written: INI, dotenv/shell assignments, .npmrc,
// history lines. None of them may panic or hang on arbitrary input.

func FuzzParseINI(f *testing.F) {
	for _, s := range []string{
		"",
		"[default]\naws_access_key_id = AKIA\naws_secret_access_key = x\n",
		"[profile a]\nregion=us-east-1\ns3 =\n  max_concurrent_requests = 10\n",
		"no section = here\n[unterminated\nk=v\n",
		"[]\n=\n:\n[ ]\n",
		strings.Repeat("[s]\n", 5000),
		strings.Repeat("k="+strings.Repeat("v", 2000)+"\n", 100),
		"\xff\xfe[\x00]\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, s := range parseINI(data) {
			_ = s.Get("aws_secret_access_key")
			_ = s.Has("region")
		}
	})
}

func FuzzParseAssignment(f *testing.F) {
	for _, s := range []string{
		"", "export A=b", "set -gx A b", "setenv A b", "A=\"quoted # not comment\" # comment",
		"A='single", "export =x", "A B=c", "export A=$(cmd)", "A=`cmd`", "\x00=\x00",
		strings.Repeat("A", 10000) + "=" + strings.Repeat("b", 10000),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		if k, v, ok := parseAssignment(line); ok {
			if k == "" || !validVarName(k) {
				t.Fatalf("accepted bad name %q", k)
			}
			_ = dynamicValue(v)
			_ = unquoteValue(v)
		}
		_ = historyCommand(line)
	})
}

func FuzzNpmrc(f *testing.F) {
	for _, s := range []string{
		"",
		"//registry.npmjs.org/:_authToken=npm_x\n",
		"//r.example.com/:_auth=ZGF2ZTpwdw==\n_password=x\n",
		"//host:port/path/:_authToken=${TOKEN}\n",
		"=\n//:\n//:_authToken=\n; comment\n# comment\n",
		strings.Repeat("//a/:_authToken=b\n", 3000),
	} {
		f.Add(s)
	}
	e := &Env{Home: "/home/fuzz", Now: time0(), Getenv: func(string) string { return "" }}
	f.Fuzz(func(t *testing.T, text string) {
		for _, c := range npmrc(e, "/home/fuzz/.npmrc", nil, text) {
			if c.Fingerprint == "" && c.Kind != "" {
				t.Fatalf("credential without fingerprint: %+v", c)
			}
			if strings.Contains(c.Summary, "_authToken=") {
				t.Fatalf("summary echoes the line: %q", c.Summary)
			}
		}
	})
}

// FuzzMatchFingerprint: the secret re-reader must never panic on an
// arbitrary file and must only ever return a value with the asked-for
// fingerprint.
func FuzzMatchFingerprint(f *testing.F) {
	tok := "ghp_" + strings.Repeat("x", 36)
	for _, s := range []string{
		"", tok, "https://a:" + tok + "@h", `{"a":{"b":"` + tok + `"}}`, "[" + tok + "]", "'" + tok, `"`,
		strings.Repeat("=", 5000), strings.Repeat("{", 5000), "\xff\x00" + tok,
	} {
		f.Add(s, cred.Fingerprint(tok))
		f.Add(s, "00000000")
	}
	f.Fuzz(func(t *testing.T, text, fp string) {
		if got, ok := matchFingerprint(text, fp); ok && cred.Fingerprint(got) != fp {
			t.Fatalf("returned %q whose fingerprint is not %q", got, fp)
		}
	})
}

// FuzzScrub: whatever the service returned, no 8+ character run of the
// secret survives scrubbing.
func FuzzScrub(f *testing.F) {
	secret := "npm_" + strings.Repeat("FAKEBLAST", 4)
	for _, s := range []string{"", secret, "acts as " + secret, secret[3:19], strings.Repeat(secret, 3), "unrelated alice"} {
		f.Add(s, secret)
	}
	f.Fuzz(func(t *testing.T, text, sec string) {
		r := &Reach{Identity: text, Summary: text, Scopes: []string{text}, Permissions: []string{text}}
		scrub(r, sec)
		if len(sec) < 8 {
			return
		}
		for _, field := range []string{r.Identity, r.Summary, r.Scopes[0], r.Permissions[0]} {
			for i := 0; i+8 <= len(sec); i++ {
				if strings.Contains(field, sec[i:i+8]) {
					t.Fatalf("fragment %q survived in %q", sec[i:i+8], field)
				}
			}
		}
	})
}
