package provider

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/howardhsieh/blastradius/internal/classify"
	"github.com/howardhsieh/blastradius/internal/cred"
)

// shellHistory finds secrets that were typed on the command line and are
// now sitting in a history file.
type shellHistory struct{}

func (shellHistory) ID() string { return "shell-history" }
func (shellHistory) Describe() string {
	return "~/.zsh_history, ~/.bash_history, fish history, $HISTFILE: `export X_TOKEN=...`, known token shapes, Authorization headers"
}

const historyTail = 8 << 20

var (
	assignRe = regexp.MustCompile(`(?:^|[\s;&|(])(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)=(["']?)([^\s"';&|)]+)`)
	tokenRe  = regexp.MustCompile(`(?:^|[^A-Za-z0-9_-])(github_pat_[A-Za-z0-9_]{60,}|gh[pousr]_[A-Za-z0-9]{36,}|npm_[A-Za-z0-9]{36}|pypi-[A-Za-z0-9_-]{50,}|AKIA[0-9A-Z]{16}|sk-ant-[A-Za-z0-9_-]{30,}|sk-proj-[A-Za-z0-9_-]{30,}|xox[abpr]-[A-Za-z0-9-]{10,}|glpat-[A-Za-z0-9_-]{20,}|hf_[A-Za-z0-9]{30,}|AIza[0-9A-Za-z_-]{35}|sk_live_[A-Za-z0-9]{20,}|dop_v1_[a-f0-9]{64})`)
	bearerRe = regexp.MustCompile(`(?i)authorization:\s*(?:bearer|token|basic)\s+([A-Za-z0-9._~+/=-]{16,})`)
	flagRe   = regexp.MustCompile(`--?(?:token|password|passwd|api-key|apikey|secret)[= ]+["']?([^\s"']{8,})`)
)

func (shellHistory) Collect(env *Env) ([]cred.Credential, []Problem) {
	paths := []string{env.Path(".zsh_history"), env.Path(".bash_history"), env.Path(".history"), env.Path(".sh_history"), env.Path(".zhistory"),
		env.Path(".local", "share", "fish", "fish_history")}
	if h := env.Getenv("HISTFILE"); h != "" {
		paths = append([]string{h}, paths...)
	}
	var out []cred.Credential
	var probs []Problem
	seenFile := map[string]bool{}
	for _, path := range paths {
		if seenFile[path] {
			continue
		}
		seenFile[path] = true
		text, info, ok, prob := readTail(path, historyTail)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok {
			continue
		}
		type hit struct {
			c     *cred.Credential
			count int
		}
		byFP := map[string]*hit{}
		var order []string
		record := func(line int, secret string, r classify.Result, account string) {
			fp := cred.Fingerprint(secret)
			if fp == "" {
				return
			}
			if h, ok := byFP[fp]; ok {
				h.count++
				return
			}
			sev := min(r.Severity, cred.High) // the value may be stale; still a copy on disk
			c := &cred.Credential{
				Service: r.Service, Kind: r.Kind, Source: "shell-history", Location: env.Display(path), Line: line,
				Account: account, Fingerprint: fp, Lifetime: r.Lifetime, Severity: sev, AgeDays: ageDays(env, info),
				Summary: r.Label + " on the command line, kept in " + filepath.Base(path),
			}
			byFP[fp] = &hit{c: c, count: 1}
			order = append(order, fp)
		}
		for i, line := range strings.Split(text, "\n") {
			cmd := historyCommand(line)
			if cmd == "" {
				continue
			}
			for _, m := range assignRe.FindAllStringSubmatch(cmd, -1) {
				name, value := m[1], m[3]
				if !classify.IsSecretName(strings.ToUpper(name)) || dynamicValue(value) {
					continue
				}
				if r, ok := classify.Var(name, value); ok {
					record(i+1, value, r, name)
				}
			}
			for _, m := range tokenRe.FindAllStringSubmatch(cmd, -1) {
				if r, ok := classify.Token(m[1]); ok {
					record(i+1, m[1], r, "")
				}
			}
			for _, m := range bearerRe.FindAllStringSubmatch(cmd, -1) {
				r, ok := classify.Token(m[1])
				if !ok {
					r = classify.Result{Service: cred.ServiceGeneric, Kind: "bearer-token", Lifetime: cred.Unknown, Severity: cred.Medium, Label: "Authorization header"}
				}
				record(i+1, m[1], r, "")
			}
			for _, m := range flagRe.FindAllStringSubmatch(cmd, -1) {
				if classify.IsPlaceholder(m[1]) || dynamicValue(m[1]) {
					continue
				}
				r, ok := classify.Token(m[1])
				if !ok {
					r = classify.Result{Service: cred.ServiceGeneric, Kind: "cli-flag-secret", Lifetime: cred.Unknown, Severity: cred.Medium, Label: "secret given as a --token/--password flag"}
				}
				record(i+1, m[1], r, "")
			}
		}
		for _, fp := range order {
			h := byFP[fp]
			if h.count > 1 {
				h.c.Notes = append(h.c.Notes, fmt.Sprintf("appears %d times", h.count))
			}
			h.c.Notes = append(h.c.Notes, "history files are the first thing credential stealers grep")
			out = append(out, *h.c)
		}
	}
	return out, probs
}

// historyCommand strips zsh extended-history and fish prefixes.
func historyCommand(line string) string {
	if strings.HasPrefix(line, ": ") {
		if i := strings.IndexByte(line, ';'); i > 0 {
			return line[i+1:]
		}
	}
	if strings.HasPrefix(line, "- cmd: ") {
		return line[len("- cmd: "):]
	}
	if strings.HasPrefix(line, "  when:") || strings.HasPrefix(line, "  paths:") {
		return ""
	}
	return line
}

// readTail returns the last n bytes of a file.
func readTail(path string, n int64) (string, os.FileInfo, bool, *Problem) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil, false, nil
		}
		return "", nil, false, &Problem{Location: path, Err: errString(err)}
	}
	if !info.Mode().IsRegular() {
		return "", nil, false, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return "", nil, false, &Problem{Location: path, Err: errString(err)}
	}
	defer f.Close()
	if info.Size() > n {
		if _, err := f.Seek(-n, io.SeekEnd); err != nil {
			return "", nil, false, &Problem{Location: path, Err: errString(err)}
		}
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return "", nil, false, &Problem{Location: path, Err: errString(err)}
	}
	return string(data), info, true, nil
}
