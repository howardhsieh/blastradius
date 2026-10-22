package provider

import (
	"fmt"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// pypi reads ~/.pypirc and pip.conf index URLs with embedded passwords.
type pypi struct{}

func (pypi) ID() string { return "pypi" }
func (pypi) Describe() string {
	return "~/.pypirc (twine/flit/poetry upload tokens) and pip.conf index URLs with passwords"
}

func (pypi) Collect(env *Env) ([]cred.Credential, []Problem) {
	var out []cred.Credential
	var probs []Problem

	path := env.EnvOr("PYPIRC", env.Path(".pypirc"))
	if data, info, ok, prob := readFile(path); prob != nil {
		probs = append(probs, *prob)
	} else if ok {
		for _, s := range parseINI(data) {
			pw := s.Get("password")
			if pw == "" || s.Name == "distutils" {
				continue
			}
			user := s.Get("username")
			c := cred.Credential{
				Service: cred.ServicePyPI, Kind: "password", Source: "pypirc",
				Location: env.Display(path), Line: s.Line, Account: s.Name,
				Fingerprint: cred.Fingerprint(pw), Lifetime: cred.LongTerm, Severity: cred.High,
				AgeDays: ageDays(env, info),
			}
			if user == "__token__" || strings.HasPrefix(pw, "pypi-") {
				c.Kind = "api-token"
			}
			if user != "" && user != "__token__" {
				c.Account = user + "@" + s.Name
			}
			c.Summary = fmt.Sprintf("PyPI %s for repository %q: can upload releases of your packages", c.Kind, s.Name)
			if s.Name == "testpypi" || strings.Contains(s.Get("repository"), "test.pypi.org") {
				c.Severity = cred.Medium
				c.Summary = "TestPyPI " + c.Kind + " (test index only)"
			}
			out = append(out, c)
		}
	}

	confs := []string{env.Path(".config", "pip", "pip.conf"), env.Path(".pip", "pip.conf"), env.Path("Library", "Application Support", "pip", "pip.conf")}
	if x := env.Getenv("XDG_CONFIG_HOME"); x != "" {
		confs = append([]string{x + "/pip/pip.conf"}, confs...)
	}
	if p := env.Getenv("PIP_CONFIG_FILE"); p != "" {
		confs = append([]string{p}, confs...)
	}
	for _, path := range confs {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		for _, s := range parseINI(data) {
			for _, k := range s.Keys {
				if k.Key != "index-url" && k.Key != "extra-index-url" && k.Key != "trusted-host" {
					continue
				}
				for _, u := range strings.Fields(k.Value) {
					if pw := classify.URLPassword(u); pw != "" {
						out = append(out, cred.Credential{
							Service: cred.ServiceGeneric, Kind: "index-url-password", Source: "pip-conf",
							Location: env.Display(path), Line: k.Line, Account: hostOf(u),
							Fingerprint: cred.Fingerprint(pw), Lifetime: cred.LongTerm, Severity: cred.Medium,
							AgeDays: ageDays(env, info),
							Summary: "Password embedded in pip " + k.Key + " for " + hostOf(u),
						})
					}
				}
			}
		}
	}
	return out, probs
}
