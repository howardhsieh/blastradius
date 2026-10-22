package provider

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/yamlite"
)

// ProbeHosts is empty for Kubernetes on purpose: cluster API servers are
// whatever the kubeconfig says, so there is no fixed list to vet. Each
// cluster must be named with --probe-cluster NAME before it is contacted.
func (kube) ProbeHosts() []string { return nil }

var kubeProbeKinds = map[string]bool{"static-token": true, "client-certificate": true, "token-file": true}

// kubeTarget is one cluster a kubeconfig user can reach.
type kubeTarget struct {
	cluster, server, namespace string
	caData                     []byte
	insecure                   bool
}

// kubeTargetsFor lists the clusters the contexts of user c point at, with
// the user's raw entry so the prober can load the credential.
func kubeTargetsFor(env *Env, c cred.Credential) (user *yamlite.Node, targets []kubeTarget, err error) {
	data, _, ok, prob := readFile(env.Expand(c.Location))
	if prob != nil {
		return nil, nil, errors.New(prob.Err)
	}
	if !ok {
		return nil, nil, errors.New("kubeconfig is gone")
	}
	doc, err := yamlite.Parse(data)
	if err != nil {
		return nil, nil, errors.New("kubeconfig no longer parses")
	}
	clusters := map[string]kubeTarget{}
	if cl := doc.Get("clusters"); cl != nil {
		for _, n := range cl.Seq {
			cc := n.Get("cluster")
			t := kubeTarget{cluster: n.Str("name"), server: cc.Str("server"), insecure: cc.Str("insecure-skip-tls-verify") == "true"}
			if ca := cc.Str("certificate-authority-data"); ca != "" {
				t.caData, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(ca))
			} else if p := cc.Str("certificate-authority"); p != "" {
				if strings.HasPrefix(p, "~/") {
					p = env.Path(p[2:])
				}
				t.caData, _, _, _ = readFile(p)
			}
			clusters[t.cluster] = t
		}
	}
	if us := doc.Get("users"); us != nil {
		for _, u := range us.Seq {
			if u.Str("name") == c.Account {
				user = u.Get("user")
			}
		}
	}
	if user == nil {
		return nil, nil, errors.New("user entry is gone from the kubeconfig")
	}
	seen := map[string]bool{}
	if cx := doc.Get("contexts"); cx != nil {
		for _, n := range cx.Seq {
			ctx := n.Get("context")
			if ctx.Str("user") != c.Account {
				continue
			}
			t, ok := clusters[ctx.Str("cluster")]
			if !ok || seen[t.cluster] {
				continue
			}
			seen[t.cluster] = true
			t.namespace = ctx.Str("namespace")
			if t.namespace == "" {
				t.namespace = "default"
			}
			targets = append(targets, t)
		}
	}
	sort.Slice(targets, func(i, j int) bool { return targets[i].cluster < targets[j].cluster })
	return user, targets, nil
}

func (kube) probeTargets(env *Env, c cred.Credential) ([]string, string) {
	if c.Service != cred.ServiceKubernetes || !kubeProbeKinds[c.Kind] {
		return nil, ""
	}
	_, targets, err := kubeTargetsFor(env, c)
	if err != nil {
		return nil, "kubeconfig: " + err.Error()
	}
	var hosts, skipped []string
	for _, t := range targets {
		if env.Probe.allowsCluster(t.cluster) {
			if u, err := url.Parse(t.server); err == nil {
				hosts = append(hosts, u.Host)
			}
		} else {
			skipped = append(skipped, t.cluster)
		}
	}
	if len(hosts) == 0 {
		if len(skipped) == 0 {
			return nil, "kubeconfig user is not referenced by any context"
		}
		return nil, fmt.Sprintf("cluster(s) %s not probed; pass --probe-cluster %s to allow", joinList(skipped, 5), skipped[0])
	}
	return hosts, ""
}

// Probe posts a SelfSubjectRulesReview to each allowed cluster the user's
// contexts point at and summarises the rules that come back.
func (k kube) Probe(ctx context.Context, env *Env, c cred.Credential) (*Reach, error) {
	hosts, skip := k.probeTargets(env, c)
	if len(hosts) == 0 {
		if skip != "" {
			return nil, errors.New(skip)
		}
		return nil, ErrNotProbed
	}
	if env.Probe == nil {
		return nil, ErrOffline
	}
	user, targets, err := kubeTargetsFor(env, c)
	if err != nil {
		return nil, err
	}
	// Load the credential and check it is the one the scan fingerprinted.
	var bearer string
	var secrets []string
	var clientCert *tls.Certificate
	switch c.Kind {
	case "static-token":
		bearer = user.Str("token")
	case "token-file":
		data, _, ok, _ := readFile(user.Str("tokenFile"))
		if !ok {
			return nil, errors.New("token file is gone")
		}
		bearer = string(data)
	case "client-certificate":
		keyPEM := []byte(user.Str("client-key-data"))
		if len(keyPEM) > 0 {
			if cred.Fingerprint(string(keyPEM)) != c.Fingerprint {
				return nil, errors.New("client key changed since the scan")
			}
			keyPEM, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyPEM)))
			if err != nil {
				return nil, errors.New("client-key-data is not base64")
			}
		} else {
			keyPEM, _, _, _ = readFile(user.Str("client-key"))
			if cred.FingerprintBytes(keyPEM) != c.Fingerprint {
				return nil, errors.New("client key changed since the scan")
			}
		}
		certPEM := []byte(user.Str("client-certificate-data"))
		if len(certPEM) > 0 {
			certPEM, _ = base64.StdEncoding.DecodeString(strings.TrimSpace(string(certPEM)))
		} else {
			certPEM, _, _, _ = readFile(user.Str("client-certificate"))
		}
		pair, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, errors.New("client certificate and key do not load")
		}
		clientCert = &pair
		secrets = append(secrets, string(keyPEM), user.Str("client-key-data"))
	}
	if bearer != "" {
		bearer = strings.TrimSpace(bearer)
		if cred.Fingerprint(bearer) != c.Fingerprint {
			return nil, errors.New("token changed since the scan")
		}
		secrets = append(secrets, bearer)
	}

	r := &Reach{ProbedAt: env.Now.UTC().Format("2006-01-02T15:04:05Z"), Identity: "kubeconfig user " + c.Account, ReadOnly: true}
	defer scrub(r, secrets...)
	var errs []string
	var reached []string
	live := false
	for _, t := range targets {
		if !env.Probe.allowsCluster(t.cluster) {
			continue
		}
		if t.insecure {
			errs = append(errs, t.cluster+": kubeconfig sets insecure-skip-tls-verify; blastradius does not turn TLS verification off")
			continue
		}
		u, err := url.Parse(t.server)
		if err != nil || u.Scheme != "https" {
			errs = append(errs, t.cluster+": server is not an https URL")
			continue
		}
		tlsConf := &tls.Config{MinVersion: tls.VersionTLS12}
		if len(t.caData) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(t.caData) {
				errs = append(errs, t.cluster+": certificate-authority-data does not parse")
				continue
			}
			tlsConf.RootCAs = pool
		}
		if clientCert != nil {
			tlsConf.Certificates = []tls.Certificate{*clientCert}
		}
		rules, incomplete, status, err := selfSubjectRules(ctx, env, u, tlsConf, bearer, t.namespace)
		if err != nil {
			errs = append(errs, t.cluster+": "+err.Error())
			continue
		}
		if rejected(status) {
			r.Permissions = append(r.Permissions, t.cluster+": rejected (HTTP 401)")
			continue
		}
		live = true
		reached = append(reached, u.Host)
		summary, admin, readOnly := summariseRules(rules)
		if incomplete {
			summary += " (list incomplete)"
		}
		r.Permissions = append(r.Permissions, fmt.Sprintf("%s (ns %s): %s", t.cluster, t.namespace, summary))
		if admin {
			r.Admin = true
		}
		if !readOnly {
			r.ReadOnly = false
		}
	}
	r.Live = live
	r.Host = joinList(reached, 5)
	if !live {
		r.ReadOnly = false
	}
	if !live && len(errs) > 0 && len(r.Permissions) == 0 {
		return nil, errors.New(strings.Join(errs, "; "))
	}
	switch {
	case !live:
		r.Summary = "rejected by every allowed cluster: token or certificate no longer accepted"
	case r.Admin:
		r.Summary = "acts as " + c.Account + " · cluster-admin: " + strings.Join(r.Permissions, "; ")
	default:
		r.Summary = "acts as " + c.Account + " · " + strings.Join(r.Permissions, "; ")
	}
	if len(errs) > 0 {
		r.Summary += " · not reached: " + strings.Join(errs, "; ")
	}
	return r, nil
}

type kubeRule struct {
	Verbs           []string `json:"verbs"`
	APIGroups       []string `json:"apiGroups"`
	Resources       []string `json:"resources"`
	NonResourceURLs []string `json:"nonResourceURLs"`
}

// selfSubjectRules performs the review and returns the rules.
func selfSubjectRules(ctx context.Context, env *Env, server *url.URL, tlsConf *tls.Config, bearer, namespace string) ([]kubeRule, bool, int, error) {
	body, _ := json.Marshal(map[string]any{
		"apiVersion": "authorization.k8s.io/v1",
		"kind":       "SelfSubjectRulesReview",
		"spec":       map[string]string{"namespace": namespace},
	})
	endpoint := *server
	endpoint.Path = strings.TrimSuffix(endpoint.Path, "/") + "/apis/authorization.k8s.io/v1/selfsubjectrulesreviews"
	req, err := env.newProbeRequest(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(body))
	if err != nil {
		return nil, false, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	var out struct {
		Status struct {
			ResourceRules    []kubeRule `json:"resourceRules"`
			NonResourceRules []kubeRule `json:"nonResourceRules"`
			Incomplete       bool       `json:"incomplete"`
		} `json:"status"`
	}
	resp, err := doJSON(env.probeClient([]string{server.Host}, tlsConf), req, &out)
	if err != nil {
		return nil, false, 0, err
	}
	if rejected(resp.StatusCode) {
		return nil, false, resp.StatusCode, nil
	}
	if resp.StatusCode/100 != 2 {
		return nil, false, resp.StatusCode, statusErr(server.Host, resp)
	}
	return append(out.Status.ResourceRules, out.Status.NonResourceRules...), out.Status.Incomplete, resp.StatusCode, nil
}

var kubeWriteVerbs = map[string]bool{"create": true, "update": true, "patch": true, "delete": true, "deletecollection": true, "*": true, "impersonate": true, "bind": true, "escalate": true}

// summariseRules turns a rule list into one line and two flags.
func summariseRules(rules []kubeRule) (summary string, admin, readOnly bool) {
	readOnly = true
	star := func(l []string) bool {
		for _, s := range l {
			if s == "*" {
				return true
			}
		}
		return false
	}
	var writes, reads []string
	for _, r := range rules {
		if star(r.Verbs) && star(r.Resources) && star(r.APIGroups) {
			return "* on * (full control)", true, false
		}
		write := false
		for _, v := range r.Verbs {
			if kubeWriteVerbs[v] {
				write = true
			}
		}
		names := append(append([]string{}, r.Resources...), r.NonResourceURLs...)
		if write {
			readOnly = false
			writes = append(writes, names...)
		} else {
			reads = append(reads, names...)
		}
	}
	var parts []string
	if len(writes) > 0 {
		parts = append(parts, "write "+joinList(writes, 6))
	}
	if len(reads) > 0 {
		parts = append(parts, "read "+joinList(reads, 6))
	}
	if len(parts) == 0 {
		return "no permissions", false, true
	}
	return strings.Join(parts, "; "), false, readOnly
}
