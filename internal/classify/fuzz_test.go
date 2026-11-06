package classify

import (
	"strings"
	"testing"
)

// FuzzVar: the classifier sees every environment variable and every line
// of every .env and shell file. It must never panic and must never return
// a Result for a placeholder.
func FuzzVar(f *testing.F) {
	for _, tc := range [][2]string{
		{"GH_TOKEN", "ghp_" + strings.Repeat("x", 36)},
		{"DATABASE_URL", "postgres://u:p@h/db"},
		{"DATABASE_URL", "postgres://h/db"},
		{"NEXT_PUBLIC_KEY", "AKIA" + strings.Repeat("A", 16)},
		{"STRIPE_SECRET_KEY", "sk_live_" + strings.Repeat("x", 24)},
		{"X", "${VAR}"},
		{"", ""},
		{strings.Repeat("A", 1000) + "_TOKEN", strings.Repeat("b", 100000)},
		{"PASSWORD", "changeme"},
		{"K\x00EY", "\xff\xfe"},
	} {
		f.Add(tc[0], tc[1])
	}
	f.Fuzz(func(t *testing.T, name, value string) {
		if r, ok := Var(name, value); ok {
			if r.Service == "" || r.Kind == "" || r.Label == "" {
				t.Fatalf("incomplete result %+v for %q", r, name)
			}
			if IsPlaceholder(value) {
				t.Fatalf("classified a placeholder: %q=%q", name, value)
			}
		}
		_, _ = Token(value)
		_ = IsSecretName(name)
		_ = IsLegacyNPMToken(value)
		_ = URLHasPassword(value)
		_ = URLPassword(value)
	})
}
