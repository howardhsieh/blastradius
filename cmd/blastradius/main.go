// Command blastradius answers one question about the machine it runs on:
// if a credential stealer ran here as you today, what could it reach?
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
	"strings"
	"time"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/provider"
	"github.com/howardhsieh/blastradius/internal/report"
	"github.com/howardhsieh/blastradius/internal/scan"
)

// version is set at build time with -ldflags "-X main.version=..." by
// GoReleaser; `go install ...@vX.Y.Z` builds carry it in the module info.
var version = "dev"

func init() {
	if version != "dev" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = strings.TrimPrefix(bi.Main.Version, "v")
	}
}

const usage = `blastradius — what could an attacker reach from this machine?

Usage:
  blastradius scan [flags]      Inventory the credentials on this machine (offline)
  blastradius providers         List providers, the files each one reads and
                                the API hosts --probe may contact
  blastradius version           Print the version

Flags (scan):
  -f, --format table|json       Output format (default table)
  -o, --output FILE             Write the report to FILE instead of stdout
      --dir PATH                Also search PATH for .env files and project .npmrc;
                                repeatable or comma-separated
      --provider ID             Run only these providers; repeatable or comma-separated
      --min-severity SEVERITY   Hide table rows below this severity:
                                info, low, medium, high, critical (default low)
      --fail-on RATING          Exit 1 if the rating is at least this bad:
                                none, moderate, high, critical (default none)
      --no-env                  Do not inspect the process environment
      --home DIR                Treat DIR as the home directory (for a copied profile)
  -v, --verbose                 Print the full remediation text
      --no-color                Disable colored output

Flags (scan --probe, opt-in network lookups):
      --probe                   After the offline scan, ask each service what the
                                credentials found can actually do (identity, scopes,
                                token type) and refine the severities. The hosts
                                that will be contacted are printed first.
      --probe-host HOST         Also probe a GitHub Enterprise host from hosts.yml;
                                repeatable
      --probe-cluster NAME      Also probe this kubeconfig cluster (its API server
                                is not on the fixed allow-list); repeatable
      --probe-timeout DURATION  Bound for the whole probe phase (default 60s)

Without --probe the scan never contacts the network. With it, each secret is
sent only to its own service's official API host, over HTTPS, and only the
service's answer (who you are, what you may do) is kept. Nothing ever prints
a secret; every entry shows the first 8 hex characters of its SHA-256 instead.

Exit codes: 0 ok, 1 rating at or above --fail-on, 2 error.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:], stdout, stderr)
	case "providers":
		for _, p := range provider.All() {
			fmt.Fprintf(stdout, "%-16s %s\n", p.ID(), p.Describe())
			if pr, ok := p.(provider.Prober); ok {
				fmt.Fprintf(stdout, "%-16s %s\n", "", "probe: "+probeHostsLine(pr))
			}
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, "blastradius", version)
		return 0
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	}
	fmt.Fprintf(stderr, "blastradius: unknown command %q\n\n%s", args[0], usage)
	return 2
}

// probeTransport lets tests stand in for the real APIs. There is no flag or
// environment variable that sets it: a probe can only ever reach the hosts
// the probers declare.
var probeTransport func(http.RoundTripper) http.RoundTripper

// probeHostsLine renders a prober's allow-list for `providers`.
func probeHostsLine(p provider.Prober) string {
	hosts := p.ProbeHosts()
	switch p.ID() {
	case "github":
		return strings.Join(hosts, ", ") + " (GitHub Enterprise hosts only with --probe-host)"
	case "kubernetes":
		return "no fixed host; each cluster's API server only with --probe-cluster NAME"
	}
	return strings.Join(hosts, ", ")
}

type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }
func (l *listFlag) Set(v string) error {
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			*l = append(*l, p)
		}
	}
	return nil
}

func cmdScan(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("blastradius", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var (
		format, output, failOn, minSev, home string
		noColor, noEnv, verbose, probe       bool
		dirs, providers                      listFlag
		probeHosts, probeClusters            listFlag
		probeTimeout                         time.Duration
	)
	fs.StringVar(&format, "format", "table", "")
	fs.StringVar(&format, "f", "table", "")
	fs.StringVar(&output, "output", "", "")
	fs.StringVar(&output, "o", "", "")
	fs.StringVar(&failOn, "fail-on", "none", "")
	fs.StringVar(&minSev, "min-severity", "low", "")
	fs.StringVar(&home, "home", "", "")
	fs.BoolVar(&noColor, "no-color", false, "")
	fs.BoolVar(&noEnv, "no-env", false, "")
	fs.BoolVar(&verbose, "verbose", false, "")
	fs.BoolVar(&verbose, "v", false, "")
	fs.BoolVar(&probe, "probe", false, "")
	fs.Var(&dirs, "dir", "")
	fs.Var(&providers, "provider", "")
	fs.Var(&probeHosts, "probe-host", "")
	fs.Var(&probeClusters, "probe-cluster", "")
	fs.DurationVar(&probeTimeout, "probe-timeout", scan.DefaultProbeTimeout, "")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "blastradius: %v\n\n%s", err, usage)
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "blastradius: scan takes no positional arguments (did you mean --dir %s?)\n", fs.Arg(0))
		return 2
	}
	if !probe && (len(probeHosts) > 0 || len(probeClusters) > 0) {
		fmt.Fprintln(stderr, "blastradius: --probe-host and --probe-cluster only make sense together with --probe")
		return 2
	}
	if probeTimeout <= 0 {
		fmt.Fprintln(stderr, "blastradius: --probe-timeout must be positive")
		return 2
	}
	if format != "table" && format != "json" {
		fmt.Fprintf(stderr, "blastradius: unknown format %q\n", format)
		return 2
	}
	showSev, err := cred.ParseSeverity(minSev)
	if err != nil {
		fmt.Fprintln(stderr, "blastradius:", err)
		return 2
	}
	failRank := -1
	if failOn != "none" {
		if failRank, err = scan.ParseRating(failOn); err != nil {
			fmt.Fprintln(stderr, "blastradius:", err)
			return 2
		}
	}
	known := map[string]bool{}
	for _, p := range provider.All() {
		known[p.ID()] = true
	}
	for _, p := range providers {
		if !known[p] {
			fmt.Fprintf(stderr, "blastradius: unknown provider %q (see `blastradius providers`)\n", p)
			return 2
		}
	}

	env, err := provider.Default()
	if err != nil {
		fmt.Fprintln(stderr, "blastradius:", err)
		return 2
	}
	if home != "" {
		env.Home = home
	}
	opt := scan.Options{Dirs: dirs, SkipEnv: noEnv, Providers: providers,
		Probe: probe, ProbeHosts: probeHosts, ProbeClusters: probeClusters, ProbeTimeout: probeTimeout}
	res, err := scan.Run(env, opt)
	if err != nil {
		fmt.Fprintln(stderr, "blastradius:", err)
		return 2
	}
	if probe {
		env.Probe = &provider.ProbeConfig{UserAgent: "blastradius/" + version, Transport: probeTransport}
		plan := scan.PlanProbe(env, res, opt)
		printConsent(stderr, plan)
		scan.RunProbe(context.Background(), env, res, plan, opt)
	}

	out := stdout
	if output != "" {
		f, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(stderr, "blastradius:", err)
			return 2
		}
		defer f.Close()
		out = f
	}
	switch format {
	case "json":
		err = report.JSON(out, res, version)
	default:
		color := !noColor && output == "" && os.Getenv("NO_COLOR") == "" && isTerminal(stdout)
		err = report.Table(out, res, report.TableOptions{Color: color, MinSeverity: showSev, Verbose: verbose})
	}
	if err != nil && !errors.Is(err, io.ErrClosedPipe) {
		fmt.Fprintln(stderr, "blastradius:", err)
		return 2
	}
	if failRank >= 0 && scan.RatingRank(res.Rating) >= failRank {
		return 1
	}
	return 0
}

// printConsent tells the user exactly what --probe is about to contact,
// before the first request leaves the machine.
func printConsent(w io.Writer, plan *scan.ProbePlan) {
	if plan.Credentials() == 0 {
		fmt.Fprintln(w, "blastradius: --probe: nothing to probe, no request will be made")
	} else {
		n := plan.Credentials()
		fmt.Fprintf(w, "blastradius: --probe will send %d credential%s to the following hosts over HTTPS and keep only the answer:\n", n, plural(n))
		for _, t := range plan.Targets {
			fmt.Fprintf(w, "  %-28s %d %s credential%s\n", t.Host, t.Count, t.Service, plural(t.Count))
		}
	}
	for _, s := range plan.Skipped {
		fmt.Fprintf(w, "  not probed: %s\n", s)
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
