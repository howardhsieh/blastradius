package provider

import (
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// dotenv scans .env files under the directories given with --dir.
type dotenv struct{}

func (dotenv) ID() string { return "dotenv" }
func (dotenv) Describe() string {
	return ".env, .env.* and *.env files under --dir (skips node_modules, .git, vendor, build output)"
}

func isDotenv(name string) bool {
	return name == ".env" || strings.HasPrefix(name, ".env.") || strings.HasSuffix(name, ".env")
}

func (dotenv) Collect(env *Env) ([]cred.Credential, []Problem) {
	if len(env.Dirs) == 0 {
		return nil, nil
	}
	var out []cred.Credential
	var probs []Problem
	truncated := walkDirs(env.Dirs, 8, 200000, func(path string, d fs.DirEntry) bool {
		if !isDotenv(d.Name()) {
			return true
		}
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			return true
		}
		example := strings.Contains(d.Name(), "example") || strings.Contains(d.Name(), "sample") || strings.Contains(d.Name(), "template")
		for i, line := range strings.Split(string(data), "\n") {
			name, value, ok := parseAssignment(line)
			if !ok || dynamicValue(value) || !classify.IsSecretName(strings.ToUpper(name)) {
				continue
			}
			r, ok := classify.Var(name, value)
			if !ok {
				continue
			}
			c := cred.Credential{
				Service: r.Service, Kind: r.Kind, Source: "dotenv", Location: env.Display(path), Line: i + 1,
				Account: name, Fingerprint: cred.Fingerprint(value), Lifetime: r.Lifetime, Severity: r.Severity,
				AgeDays: ageDays(env, info),
				Summary: r.Label + " in " + filepath.Base(filepath.Dir(path)) + "/" + d.Name() + " as " + name,
			}
			if example {
				c.Notes = append(c.Notes, "an example file that holds a real-looking value: it is probably committed")
			}
			if r.Service == cred.ServiceGeneric || r.Service == cred.ServiceDatabase {
				c.Notes = append(c.Notes, "project secret; reach is limited to that service")
			}
			out = append(out, c)
		}
		return true
	})
	if truncated {
		probs = append(probs, Problem{Location: strings.Join(env.Dirs, ","), Err: "file limit reached; not every .env file was read"})
	}
	return out, probs
}
