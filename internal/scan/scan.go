// Package scan runs every provider, merges credentials that turn out to be
// the same secret, rates the machine and builds prioritised remediation.
package scan

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/provider"
)

// Ratings, from best to worst.
const (
	RatingLow      = "LOW"
	RatingModerate = "MODERATE"
	RatingHigh     = "HIGH"
	RatingCritical = "CRITICAL"
)

// Options controls a scan.
type Options struct {
	// Dirs are project directories to search for .env files and .npmrc.
	Dirs []string
	// SkipEnv leaves the process environment alone (CI runners).
	SkipEnv bool
	// Providers restricts the scan to these provider IDs (empty = all).
	Providers []string
}

// Advice is one remediation step, covering one or more credentials.
type Advice struct {
	Priority    int           `json:"priority"`
	Severity    cred.Severity `json:"severity"`
	Title       string        `json:"title"`
	Detail      string        `json:"detail"`
	Credentials []string      `json:"credentials"`
}

// Result is the outcome of scanning one machine.
type Result struct {
	Host        string                `json:"host"`
	ScannedAt   string                `json:"scanned_at"`
	Rating      string                `json:"rating"`
	Score       int                   `json:"score"`
	Summary     map[string]int        `json:"summary"`
	Services    []string              `json:"services"`
	Credentials []cred.Credential     `json:"credentials"`
	Remediation []Advice              `json:"remediation"`
	Problems    []provider.Problem    `json:"problems,omitempty"`
	Providers   []string              `json:"providers_run"`
	Dirs        []string              `json:"dirs_searched,omitempty"`
	Offline     bool                  `json:"offline"`
	counts      map[cred.Severity]int `json:"-"`
}

// Run scans the machine described by env.
func Run(env *provider.Env, opt Options) (*Result, error) {
	if env == nil {
		var err error
		if env, err = provider.Default(); err != nil {
			return nil, err
		}
	}
	env.Dirs = opt.Dirs
	if opt.SkipEnv {
		env.Environ = func() []string { return nil }
	}
	only := map[string]bool{}
	for _, p := range opt.Providers {
		only[p] = true
	}
	res := &Result{Host: env.Hostname, ScannedAt: env.Now.UTC().Format(time.RFC3339), Offline: true, Dirs: opt.Dirs}
	var all []cred.Credential
	for _, p := range provider.All() {
		if len(only) > 0 && !only[p.ID()] {
			continue
		}
		res.Providers = append(res.Providers, p.ID())
		cs, probs := p.Collect(env)
		for i := range probs {
			probs[i].Location = env.Display(probs[i].Location)
		}
		all = append(all, cs...)
		res.Problems = append(res.Problems, probs...)
	}
	all = merge(all)
	sortCredentials(all)
	for i := range all {
		all[i].ID = fmt.Sprintf("%s-%d", all[i].Service, i+1)
		all[i].Remediation = remediationFor(all[i])
	}
	if all == nil {
		all = []cred.Credential{}
	}
	res.Credentials = all
	res.Summary = map[string]int{}
	res.counts = map[cred.Severity]int{}
	services := map[string]bool{}
	for _, c := range all {
		res.Summary[c.Severity.String()]++
		res.counts[c.Severity]++
		services[c.Service] = true
	}
	for s := range services {
		res.Services = append(res.Services, s)
	}
	sort.Strings(res.Services)
	res.Score, res.Rating = Rate(all)
	res.Remediation = advise(all)
	return res, nil
}

// Counts returns how many credentials have each severity.
func (r *Result) Counts() map[cred.Severity]int { return r.counts }

// merge folds credentials that share a fingerprint into one record: the
// same token in hosts.yml, .git-credentials and $GH_TOKEN is one secret
// in three places.
func merge(in []cred.Credential) []cred.Credential {
	byFP := map[string]int{}
	var out []cred.Credential
	for _, c := range in {
		if c.Fingerprint == "" {
			out = append(out, c)
			continue
		}
		key := c.Service + "|" + c.Fingerprint
		if c.Service == cred.ServiceGeneric {
			key = c.Fingerprint
		}
		i, ok := byFP[key]
		if !ok {
			byFP[key] = len(out)
			out = append(out, c)
			continue
		}
		m := &out[i]
		loc := c.Location
		if c.Line > 0 {
			loc = fmt.Sprintf("%s:%d", c.Location, c.Line)
		}
		m.AlsoIn = append(m.AlsoIn, loc)
		if c.Severity > m.Severity {
			m.Severity = c.Severity
		}
		if m.Account == "" {
			m.Account = c.Account
		}
		if m.Kind == "token" && c.Kind != "token" && c.Kind != "" {
			m.Kind = c.Kind
		}
		for _, n := range c.Notes {
			if !containsString(m.Notes, n) {
				m.Notes = append(m.Notes, n)
			}
		}
	}
	for i := range out {
		if n := len(out[i].AlsoIn); n > 0 {
			out[i].Notes = append([]string{fmt.Sprintf("the same secret is stored in %d other place(s)", n)}, out[i].Notes...)
		}
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortCredentials(cs []cred.Credential) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Service != b.Service {
			return a.Service < b.Service
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Line < b.Line
	})
}

var weights = map[cred.Severity]int{cred.Low: 2, cred.Medium: 8, cred.High: 20, cred.Critical: 40}

// Rate turns the credential list into a 0-100 exposure score and a rating.
// The rating follows the worst credential; the score adds up what an
// attacker would walk away with, capped at 100.
func Rate(cs []cred.Credential) (score int, rating string) {
	worst := cred.Info
	for _, c := range cs {
		if c.Expired {
			continue
		}
		score += weights[c.Severity]
		if c.Severity > worst {
			worst = c.Severity
		}
	}
	if score > 100 {
		score = 100
	}
	switch {
	case worst >= cred.Critical:
		rating = RatingCritical
	case worst == cred.High:
		rating = RatingHigh
	case worst == cred.Medium:
		rating = RatingModerate
	default:
		rating = RatingLow
	}
	return score, rating
}

// ParseRating converts a rating name to its rank (LOW=0 ... CRITICAL=3).
func ParseRating(s string) (int, error) {
	for i, r := range []string{RatingLow, RatingModerate, RatingHigh, RatingCritical} {
		if strings.EqualFold(s, r) {
			return i, nil
		}
	}
	return 0, fmt.Errorf("unknown rating %q (want low, moderate, high or critical)", s)
}

// RatingRank returns the rank of a rating string.
func RatingRank(s string) int {
	r, _ := ParseRating(s)
	return r
}
