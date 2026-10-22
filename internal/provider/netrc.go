package provider

import (
	"fmt"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// netrc reads ~/.netrc, used by curl, pip, git and many SDKs.
type netrc struct{}

func (netrc) ID() string       { return "netrc" }
func (netrc) Describe() string { return "~/.netrc / ~/_netrc (curl, pip, git, Heroku ...)" }

func (netrc) Collect(env *Env) ([]cred.Credential, []Problem) {
	paths := []string{env.Path(".netrc"), env.Path("_netrc")}
	if p := env.Getenv("NETRC"); p != "" {
		paths = append([]string{p}, paths...)
	}
	var out []cred.Credential
	var probs []Problem
	seen := map[string]bool{}
	for _, path := range paths {
		if seen[path] {
			continue
		}
		seen[path] = true
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		// Tokenise: "machine HOST login USER password PASS" may span lines.
		type tok struct {
			s    string
			line int
		}
		var toks []tok
		for i, l := range strings.Split(string(data), "\n") {
			if t := strings.TrimSpace(l); strings.HasPrefix(t, "#") {
				continue
			}
			for _, f := range strings.Fields(l) {
				toks = append(toks, tok{f, i + 1})
			}
		}
		var machine, login, password string
		var line int
		flush := func() {
			if password == "" {
				return
			}
			service, kind, sev := serviceForGitHost(machine)
			label := "password"
			if r, ok := classify.Token(password); ok {
				service, kind, sev, label = r.Service, r.Kind, r.Severity, r.Label
			} else if service != cred.ServiceGeneric {
				label = service + " credential"
			}
			account := machine
			if login != "" {
				account = login + "@" + machine
			}
			out = append(out, cred.Credential{
				Service: service, Kind: kind, Source: "netrc",
				Location: env.Display(path), Line: line, Account: account,
				Fingerprint: cred.Fingerprint(password), Lifetime: cred.LongTerm, Severity: sev,
				AgeDays: ageDays(env, info),
				Summary: fmt.Sprintf("%s for %s in .netrc", label, account),
			})
			machine, login, password = "", "", ""
		}
		for i := 0; i < len(toks); i++ {
			switch toks[i].s {
			case "machine", "default":
				flush()
				line = toks[i].line
				if toks[i].s == "default" {
					machine = "default"
				} else if i+1 < len(toks) {
					i++
					machine = toks[i].s
				}
			case "login", "account":
				if i+1 < len(toks) {
					i++
					login = toks[i].s
				}
			case "password":
				if i+1 < len(toks) {
					i++
					password = toks[i].s
				}
			case "macdef":
				// A macro runs to the next blank line; skip its body.
				for i+1 < len(toks) && toks[i+1].line == toks[i].line {
					i++
				}
			}
		}
		flush()
	}
	return out, probs
}
