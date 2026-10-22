// Package provider holds one collector per credential store. Every
// collector works offline: it reads files under the home directory and the
// process environment, hashes any secret it finds and keeps the hash only.
//
// Network probes ("what can this token actually do?") are a separate,
// optional capability. A provider that supports them implements Prober;
// the scanner only calls Probe when the user passes --probe, and only
// against the official API hosts the provider lists.
package provider

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// Env describes the machine being scanned. Tests point Home at a temporary
// directory and supply a fake environment.
type Env struct {
	Home     string
	Hostname string
	Now      time.Time
	Getenv   func(string) string
	Environ  func() []string
	// Dirs are project directories to search for .env files and .npmrc.
	Dirs []string
	// Probe configures the optional network probes. Nil means offline; the
	// scanner only sets it when the user passed --probe.
	Probe *ProbeConfig
}

// Default returns an Env for the current user.
func Default() (*Env, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	return &Env{Home: home, Hostname: host, Now: time.Now(), Getenv: os.Getenv, Environ: os.Environ}, nil
}

// Path joins parts under the home directory.
func (e *Env) Path(parts ...string) string {
	return filepath.Join(append([]string{e.Home}, parts...)...)
}

// Expand reverses Display: "~/x" becomes an absolute path under Home.
func (e *Env) Expand(p string) string {
	if p == "~" {
		return e.Home
	}
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return e.Path(filepath.FromSlash(rest))
	}
	return p
}

// Display shortens a path under the home directory to "~/...".
func (e *Env) Display(p string) string {
	if rel, err := filepath.Rel(e.Home, p); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
		return "~/" + filepath.ToSlash(rel)
	}
	if p == e.Home {
		return "~"
	}
	return p
}

// EnvOr returns the value of an environment variable, or def when unset.
func (e *Env) EnvOr(name, def string) string {
	if v := e.Getenv(name); v != "" {
		return v
	}
	return def
}

// Problem is a non-fatal error met while collecting, such as an unreadable
// file. It never contains file content.
type Problem struct {
	Location string `json:"location"`
	Err      string `json:"error"`
}

// Provider collects credentials of one store or service.
type Provider interface {
	// ID names the provider: "github", "aws", "shell-history" ...
	ID() string
	// Describe lists what the provider inspects, for `blastradius providers`.
	Describe() string
	// Collect inventories credentials without touching the network.
	Collect(env *Env) ([]cred.Credential, []Problem)
}

// Reach is what a probe learned a credential can do. It lives in package
// cred so a Credential can carry it; the alias keeps the Prober interface
// readable.
type Reach = cred.Reach

// Prober is implemented by providers that can ask the service what a
// credential is allowed to do. Not used by `scan` without --probe.
type Prober interface {
	Provider
	// ProbeHosts is the closed list of API hosts Probe may contact.
	ProbeHosts() []string
	// Probe checks one credential against the service. It receives the
	// credential's location so it can re-read the secret itself; the
	// Credential record never carries it. Implementations send the secret
	// only to hosts in ProbeHosts (or, for GitHub Enterprise and
	// Kubernetes, hosts the user named explicitly), and never put it in the
	// Reach, the error or a log line.
	Probe(ctx context.Context, env *Env, c cred.Credential) (*Reach, error)
}

// All returns every provider in report order.
func All() []Provider {
	return []Provider{
		github{}, gitCredentials{}, netrc{}, npm{}, pypi{}, aws{}, gcloud{}, azure{},
		docker{}, kube{}, ssh{}, aiTools{}, envVars{}, shellRC{}, shellHistory{}, dotenv{},
	}
}
