package yamlite

import (
	"strings"
	"testing"
)

// FuzzParse throws arbitrary bytes at the parser. kubeconfig and hosts.yml
// are attacker-influenced files (a malicious repository can ship a
// kubeconfig, a stealer can rewrite one), so the contract is that Parse
// never panics, always terminates, and either returns a tree or an error.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"",
		"---\n",
		kubeconfig,
		"github.com:\n    user: alice\n    oauth_token: gho_x\n    users:\n        alice:\n            oauth_token: gho_x\n",
		"a: 1\nb:\n  - x\n  - y: z\n    w: |\n      block\n      text\n  - 'q: uoted'\n",
		"- - - deep\n",
		"key: \"unterminated\n",
		"k: v\n\tbad: tab\n",
		"a:\n  b:\n c: misaligned\n",
		"x: >-\n  folded\n  text\n\ny: [flow, seq]\nz: {flow: map}\n",
		strings.Repeat("- ", 2000) + "x\n",
		strings.Repeat("a:\n ", 500),
		"k: v # comment\n# full line\n...\n",
		"\xff\xfe\x00 not utf8: \x01\n",
		strings.Repeat("x", 1<<16) + ": y\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		n, err := Parse(data)
		if err == nil && n == nil {
			t.Fatal("nil node without error")
		}
		if n != nil {
			// Accessors must be safe on whatever came back.
			_ = n.Str("anything")
			_ = n.Get("users").Get("user").Str("token")
			for _, kv := range n.Map {
				_ = kv.Val.String()
			}
			for _, s := range n.Seq {
				_ = s.Str("name")
			}
		}
	})
}
