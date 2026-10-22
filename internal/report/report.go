// Package report renders scan results as a terminal table or JSON. Neither
// format can contain a secret: the Credential type never carries one.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/scan"
)

// TableOptions controls terminal output.
type TableOptions struct {
	Color       bool
	MinSeverity cred.Severity
	// Verbose prints the full remediation detail under each advice line.
	Verbose bool
}

const (
	reset = "\x1b[0m"
	bold  = "\x1b[1m"
	dim   = "\x1b[2m"
)

var sevColor = map[cred.Severity]string{
	cred.Critical: "\x1b[1;91m",
	cred.High:     "\x1b[31m",
	cred.Medium:   "\x1b[33m",
	cred.Low:      "\x1b[36m",
	cred.Info:     dim,
}

// 256-colour badges: terminal themes restyle the basic 16 colours.
var ratingColor = map[string]string{
	scan.RatingCritical: "\x1b[1;38;5;231;48;5;160m",
	scan.RatingHigh:     "\x1b[1;38;5;231;48;5;202m",
	scan.RatingModerate: "\x1b[1;38;5;232;48;5;214m",
	scan.RatingLow:      "\x1b[1;38;5;232;48;5;34m",
}

var ratingLine = map[string]string{
	scan.RatingCritical: "A credential stealer running as you would get long-term cloud, registry or signing access. Rotate the CRITICAL items now.",
	scan.RatingHigh:     "A stealer would get write access to source, packages or infrastructure through long-lived tokens that sit in plaintext.",
	scan.RatingModerate: "What a stealer would find is short-lived or narrowly scoped. Tidy the MODERATE items when convenient.",
	scan.RatingLow:      "Nothing long-lived in plaintext was found. blastradius only reads the well-known locations; it does not prove the machine is clean.",
}

// Table writes a human-readable report.
func Table(w io.Writer, r *scan.Result, opt TableOptions) error {
	paint := func(code, s string) string {
		if !opt.Color {
			return s
		}
		return code + s + reset
	}
	n := len(r.Credentials)
	mode := "offline scan"
	if !r.Offline {
		probed := 0
		for _, c := range r.Credentials {
			if c.Reach != nil {
				probed++
			}
		}
		mode = fmt.Sprintf("probed %d credential%s against %d host%s", probed, plural(probed), len(r.ProbedHosts), plural(len(r.ProbedHosts)))
	}
	fmt.Fprintf(w, "\n %s  %s   exposure %d/100   %d credential%s across %d service%s   %s\n\n",
		paint(ratingColor[r.Rating], " "+r.Rating+" "), paint(bold, r.Host), r.Score,
		n, plural(n), len(r.Services), plural(len(r.Services)), paint(dim, mode))

	shown := 0
	for _, c := range r.Credentials {
		if c.Severity < opt.MinSeverity {
			continue
		}
		shown++
		loc := c.Location
		if c.Line > 0 {
			loc = fmt.Sprintf("%s:%d", c.Location, c.Line)
		}
		label := fmt.Sprintf("[%s]", strings.ToUpper(c.Severity.String()))
		fmt.Fprintf(w, " %s %s  %s\n", paint(sevColor[c.Severity], fmt.Sprintf("%-10s", label)), paint(bold, c.Service), paint(dim, loc))
		fmt.Fprintf(w, "            %s\n", c.Summary)
		var attrs []string
		if c.Account != "" {
			attrs = append(attrs, c.Account)
		}
		if c.Fingerprint != "" {
			attrs = append(attrs, "sha256:"+c.Fingerprint)
		}
		if c.Lifetime != "" && c.Lifetime != cred.Unknown {
			attrs = append(attrs, string(c.Lifetime))
		}
		if c.Expired {
			attrs = append(attrs, "expired")
		} else if c.ExpiresAt != "" {
			attrs = append(attrs, "expires "+c.ExpiresAt)
		}
		if c.AgeDays != nil && c.Lifetime == cred.LongTerm && *c.AgeDays >= 90 {
			attrs = append(attrs, fmt.Sprintf("%d days old", *c.AgeDays))
		}
		if len(attrs) > 0 {
			fmt.Fprintf(w, "            %s\n", paint(dim, "→ "+strings.Join(attrs, "  ·  ")))
		}
		if c.Reach != nil {
			code := sevColor[c.Severity]
			if !c.Reach.Live {
				code = dim
			}
			fmt.Fprintf(w, "            %s\n", paint(code, "↳ "+reachLine(c.Reach)))
		}
		for _, note := range c.Notes {
			fmt.Fprintf(w, "            %s\n", paint(dim, "  "+note))
		}
		for _, also := range c.AlsoIn {
			fmt.Fprintf(w, "            %s\n", paint(dim, "  also in "+also))
		}
		fmt.Fprintln(w)
	}
	if shown == 0 {
		fmt.Fprintf(w, " No credentials at or above %s severity.\n\n", opt.MinSeverity)
	}

	counts := r.Counts()
	var parts []string
	for s := cred.Critical; s >= cred.Info; s-- {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, " %s\n", strings.Join(parts, ", "))
	}
	fmt.Fprintf(w, " %s\n", ratingLine[r.Rating])

	if len(r.Remediation) > 0 {
		fmt.Fprintf(w, "\n %s\n", paint(bold, "Do first:"))
		for _, a := range r.Remediation {
			fmt.Fprintf(w, "  %d. %s %s\n", a.Priority, paint(sevColor[a.Severity], fmt.Sprintf("[%s]", strings.ToUpper(a.Severity.String()))), a.Title)
			fmt.Fprintf(w, "     %s\n", paint(dim, strings.Join(a.Credentials, ", ")))
			if opt.Verbose {
				fmt.Fprintf(w, "     %s\n", wrap(a.Detail, 90, "     "))
			}
		}
	}
	if len(r.Problems) > 0 {
		heading := "Not read:"
		if !r.Offline {
			heading = "Not read or not probed:"
		}
		fmt.Fprintf(w, "\n %s\n", paint(dim, heading))
		for _, p := range r.Problems {
			fmt.Fprintf(w, "  %s\n", paint(dim, p.Location+": "+p.Err))
		}
	}
	_, err := fmt.Fprintln(w)
	return err
}

// reachLine renders what the probe learned: "acts as alice · scopes: repo,
// read:org · probed 2026-10-22T12:00:00Z".
func reachLine(r *cred.Reach) string {
	s := r.Summary
	if s == "" {
		s = "acts as " + r.Identity
	}
	if r.Host != "" {
		s += " · " + r.Host
	}
	return s + " · probed " + r.ProbedAt
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	var b strings.Builder
	col := 0
	for i, w := range words {
		if col+len(w)+1 > width && col > 0 {
			b.WriteString("\n" + indent)
			col = 0
		} else if i > 0 {
			b.WriteByte(' ')
			col++
		}
		b.WriteString(w)
		col += len(w)
	}
	return b.String()
}

// JSON writes the result as indented JSON.
func JSON(w io.Writer, r *scan.Result, version string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Tool    string `json:"tool"`
		Version string `json:"version"`
		*scan.Result
	}{"blastradius", version, r})
}
