package provider

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/yamlite"
)

// kube reads kubeconfig files and reports every user entry that carries a
// static credential, plus the contexts (clusters) each one reaches.
type kube struct{}

func (kube) ID() string { return "kubernetes" }
func (kube) Describe() string {
	return "kubeconfig files ($KUBECONFIG or ~/.kube/config): static tokens, client certificates, auth-providers, exec plugins"
}

func (kube) Collect(env *Env) ([]cred.Credential, []Problem) {
	var paths []string
	if kc := env.Getenv("KUBECONFIG"); kc != "" {
		for _, p := range filepath.SplitList(kc) {
			if strings.HasPrefix(p, "~/") {
				p = env.Path(p[2:])
			}
			if p != "" {
				paths = append(paths, p)
			}
		}
	} else {
		paths = []string{env.Path(".kube", "config")}
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
		doc, err := yamlite.Parse(data)
		if err != nil {
			probs = append(probs, Problem{Location: env.Display(path), Err: "parse: " + err.Error()})
			continue
		}
		out = append(out, kubeconfig(env, path, info, doc)...)
	}
	return out, probs
}

func kubeconfig(env *Env, path string, info os.FileInfo, doc *yamlite.Node) []cred.Credential {
	servers := map[string]string{}
	if cl := doc.Get("clusters"); cl != nil {
		for _, c := range cl.Seq {
			servers[c.Str("name")] = hostOf(c.Get("cluster").Str("server"))
		}
	}
	current := doc.Str("current-context")
	contexts := map[string][]string{} // user -> descriptions
	if cx := doc.Get("contexts"); cx != nil {
		for _, c := range cx.Seq {
			ctx := c.Get("context")
			desc := c.Str("name")
			if s := servers[ctx.Str("cluster")]; s != "" {
				desc += " → " + s
			}
			if ns := ctx.Str("namespace"); ns != "" {
				desc += " (ns " + ns + ")"
			}
			if c.Str("name") == current {
				desc += " [current]"
			}
			contexts[ctx.Str("user")] = append(contexts[ctx.Str("user")], desc)
		}
	}
	var out []cred.Credential
	users := doc.Get("users")
	if users == nil {
		return nil
	}
	for _, u := range users.Seq {
		name := u.Str("name")
		user := u.Get("user")
		if user == nil {
			continue
		}
		c := cred.Credential{
			Service: cred.ServiceKubernetes, Source: "kubeconfig", Location: env.Display(path), Line: u.Line,
			Account: name, Lifetime: cred.LongTerm, AgeDays: ageDays(env, info),
		}
		switch {
		case user.Str("token") != "":
			c.Kind, c.Severity = "static-token", cred.High
			c.Fingerprint = cred.Fingerprint(user.Str("token"))
			c.Summary = fmt.Sprintf("Static bearer token for user %q", name)
			if strings.HasPrefix(user.Str("token"), "eyJ") {
				c.Notes = append(c.Notes, "looks like a service-account JWT; legacy SA tokens never expire")
			}
		case user.Str("tokenFile") != "":
			c.Kind, c.Severity = "token-file", cred.High
			if data, _, ok, _ := readFile(user.Str("tokenFile")); ok {
				c.Fingerprint = cred.Fingerprint(string(data))
			}
			c.Summary = fmt.Sprintf("Bearer token file for user %q", name)
		case user.Str("client-key-data") != "" || user.Str("client-key") != "":
			c.Kind, c.Severity = "client-certificate", cred.High
			if kd := user.Str("client-key-data"); kd != "" {
				c.Fingerprint = cred.Fingerprint(kd)
			} else if data, _, ok, _ := readFile(user.Str("client-key")); ok {
				c.Fingerprint = cred.FingerprintBytes(data)
			}
			c.Summary = fmt.Sprintf("Client certificate and private key for user %q", name)
			certData := user.Str("client-certificate-data")
			if certData == "" {
				if data, _, ok, _ := readFile(user.Str("client-certificate")); ok {
					certData = base64.StdEncoding.EncodeToString(data)
				}
			}
			if subj, exp, expired, ok := parseClientCert(env, certData); ok {
				c.Notes = append(c.Notes, "certificate subject "+subj)
				c.ExpiresAt, c.Expired = exp, expired
				if expired {
					c.Severity = cred.Low
					c.Summary += " (certificate expired)"
				}
			}
		case user.Str("password") != "":
			c.Kind, c.Severity = "basic-auth", cred.High
			c.Fingerprint = cred.Fingerprint(user.Str("password"))
			c.Summary = fmt.Sprintf("Basic-auth password for user %q", name)
		case user.Get("auth-provider") != nil:
			ap := user.Get("auth-provider")
			cfg := ap.Get("config")
			c.Kind, c.Severity = "auth-provider", cred.High
			secret := cfg.Str("refresh-token")
			if secret == "" {
				secret = cfg.Str("access-token")
				c.Lifetime = cred.ShortTerm
				c.Severity = cred.Medium
			}
			if secret == "" {
				secret = cfg.Str("id-token")
			}
			c.Fingerprint = cred.Fingerprint(secret)
			c.Summary = fmt.Sprintf("Deprecated %s auth-provider for user %q with cached tokens", ap.Str("name"), name)
			if cfg.Str("client-secret") != "" {
				c.Notes = append(c.Notes, "includes the OIDC client secret")
			}
		case user.Get("exec") != nil:
			ex := user.Get("exec")
			c.Kind, c.Severity, c.Lifetime = "exec-plugin", cred.Low, cred.ShortTerm
			cmd := ex.Str("command")
			var args []string
			if a := ex.Get("args"); a != nil {
				for _, n := range a.Seq {
					args = append(args, n.String())
				}
			}
			c.Summary = fmt.Sprintf("User %q gets short-lived tokens from `%s`", name, strings.TrimSpace(cmd+" "+strings.Join(args, " ")))
			switch {
			case strings.Contains(cmd, "aws"):
				c.Notes = append(c.Notes, "reach depends on the AWS credentials on this machine")
			case strings.Contains(cmd, "gcloud") || strings.Contains(cmd, "gke"):
				c.Notes = append(c.Notes, "reach depends on the gcloud credentials on this machine")
			case strings.Contains(cmd, "kubelogin") || strings.Contains(cmd, "az"):
				c.Notes = append(c.Notes, "reach depends on the Azure login on this machine")
			}
		default:
			continue
		}
		if cx := contexts[name]; len(cx) > 0 {
			sort.Strings(cx)
			c.Notes = append(c.Notes, "contexts: "+strings.Join(cx, "; "))
		} else {
			c.Notes = append(c.Notes, "not referenced by any context")
		}
		out = append(out, c)
	}
	return out
}

// parseClientCert extracts the subject and expiry of a base64 PEM certificate.
func parseClientCert(env *Env, b64 string) (subject, expires string, expired, ok bool) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return "", "", false, false
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", "", false, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", "", false, false
	}
	subject = cert.Subject.CommonName
	if len(cert.Subject.Organization) > 0 {
		subject += " (" + strings.Join(cert.Subject.Organization, ",") + ")"
	}
	return subject, cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"), env.Now.After(cert.NotAfter), true
}
