package provider

import (
	"path/filepath"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// shellRC finds secrets written literally into shell start-up files.
type shellRC struct{}

func (shellRC) ID() string { return "shell-rc" }
func (shellRC) Describe() string {
	return "~/.zshrc, ~/.zshenv, ~/.bashrc, ~/.bash_profile, ~/.profile, fish config: literal `export NAME=secret` lines"
}

func (shellRC) Collect(env *Env) ([]cred.Credential, []Problem) {
	files := []string{".zshrc", ".zshenv", ".zprofile", ".zlogin", ".bashrc", ".bash_profile", ".bash_login", ".profile", ".envrc", ".env"}
	var paths []string
	for _, f := range files {
		paths = append(paths, env.Path(f))
	}
	if z := env.Getenv("ZDOTDIR"); z != "" && z != env.Home {
		for _, f := range []string{".zshrc", ".zshenv", ".zprofile"} {
			paths = append(paths, filepath.Join(z, f))
		}
	}
	fishDir := env.Path(".config", "fish")
	if x := env.Getenv("XDG_CONFIG_HOME"); x != "" {
		fishDir = filepath.Join(x, "fish")
	}
	paths = append(paths, filepath.Join(fishDir, "config.fish"))
	if m, _ := filepath.Glob(filepath.Join(fishDir, "conf.d", "*.fish")); len(m) > 0 {
		paths = append(paths, m...)
	}
	var out []cred.Credential
	var probs []Problem
	for _, path := range paths {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		for i, line := range strings.Split(string(data), "\n") {
			name, value, ok := parseAssignment(line)
			if !ok || dynamicValue(value) || !classify.IsSecretName(name) {
				continue
			}
			r, ok := classify.Var(name, value)
			if !ok {
				continue
			}
			out = append(out, cred.Credential{
				Service: r.Service, Kind: r.Kind, Source: "shell-rc", Location: env.Display(path), Line: i + 1,
				Account: name, Fingerprint: cred.Fingerprint(value), Lifetime: r.Lifetime, Severity: r.Severity,
				AgeDays: ageDays(env, info),
				Summary: r.Label + " written literally in " + filepath.Base(path) + " as " + name,
				Notes:   []string{"loaded into every shell and inherited by everything started from one"},
			})
		}
	}
	return out, probs
}
