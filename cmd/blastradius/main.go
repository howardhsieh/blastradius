// Command blastradius answers one question about the machine it runs on:
// if a credential stealer ran here as you today, what could it reach?
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

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
  blastradius providers         List providers and the files each one reads
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

The scan never contacts the network and never prints a secret; every entry
shows the first 8 hex characters of the SHA-256 of the secret instead.

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
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(stderr, "blastradius: %v\n\n%s", err, usage)
		return 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(stderr, "blastradius: scan takes no positional arguments (did you mean --dir %s?)\n", fs.Arg(0))
		return 2
	}
	if probe {
		fmt.Fprintln(stderr, "blastradius: --probe (online permission lookups) is not implemented in this version; the scan is offline")
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
	res, err := scan.Run(env, scan.Options{Dirs: dirs, SkipEnv: noEnv, Providers: providers})
	if err != nil {
		fmt.Fprintln(stderr, "blastradius:", err)
		return 2
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

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}
