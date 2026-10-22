package provider

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// ssh inspects private keys under ~/.ssh (passphrase or not, without
// decrypting anything) and the hosts in ~/.ssh/config that use them.
type ssh struct{}

func (ssh) ID() string { return "ssh" }
func (ssh) Describe() string {
	return "~/.ssh private keys (passphrase detection, key type, permissions) and ~/.ssh/config hosts / agent forwarding"
}

type sshHost struct {
	names        []string
	identities   []string
	forwardAgent bool
	line         int
}

func (ssh) Collect(env *Env) ([]cred.Credential, []Problem) {
	dir := env.Path(".ssh")
	var out []cred.Credential
	var probs []Problem

	hosts, cfgProbs := sshConfig(env, filepath.Join(dir, "config"), 0)
	probs = append(probs, cfgProbs...)

	// Which hosts use which identity file; hosts with no IdentityFile use
	// the default identities.
	byIdentity := map[string][]string{}
	var defaultHosts []string
	for _, h := range hosts {
		if len(h.identities) == 0 {
			defaultHosts = append(defaultHosts, h.names...)
			continue
		}
		for _, id := range h.identities {
			byIdentity[id] = append(byIdentity[id], h.names...)
		}
	}

	candidates := map[string]bool{}
	if entries, err := os.ReadDir(dir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			n := e.Name()
			switch {
			case strings.HasSuffix(n, ".pub"), n == "config", n == "known_hosts", n == "known_hosts.old",
				n == "authorized_keys", n == "environment", n == "rc", strings.HasPrefix(n, "known_hosts"):
				continue
			}
			candidates[filepath.Join(dir, n)] = true
		}
	} else if !os.IsNotExist(err) {
		probs = append(probs, Problem{Location: env.Display(dir), Err: errString(err)})
	}
	for id := range byIdentity {
		candidates[id] = true
	}
	paths := make([]string, 0, len(candidates))
	for p := range candidates {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		data, info, ok, prob := readFile(path)
		if prob != nil {
			probs = append(probs, *prob)
		}
		if !ok || info.Size() > 64<<10 {
			continue
		}
		k, isKey := inspectKey(data)
		if !isKey {
			continue
		}
		c := cred.Credential{
			Service: cred.ServiceSSH, Kind: "private-key", Source: "ssh", Location: env.Display(path),
			Fingerprint: cred.FingerprintBytes(data), Lifetime: cred.LongTerm, AgeDays: ageDays(env, info),
			Protected: k.encrypted,
		}
		label := k.keyType
		if label == "" {
			label = k.format
		}
		if comment := pubComment(path + ".pub"); comment != "" {
			c.Account = comment
		}
		switch {
		case k.unknown:
			c.Severity = cred.Medium
			c.Summary = fmt.Sprintf("%s private key; could not tell whether it has a passphrase", label)
		case k.encrypted:
			c.Severity = cred.Low
			c.Summary = fmt.Sprintf("%s private key, passphrase-protected", label)
		default:
			c.Severity = cred.High
			c.Summary = fmt.Sprintf("%s private key with NO passphrase: copying the file is enough to use it", label)
		}
		if k.format == "pem" && k.encrypted {
			c.Notes = append(c.Notes, "legacy PEM encryption (MD5-derived key); convert with ssh-keygen -p -o")
		}
		var usedBy []string
		if u := byIdentity[path]; len(u) > 0 {
			usedBy = append(usedBy, u...)
		}
		base := filepath.Base(path)
		if strings.HasPrefix(base, "id_") && !strings.Contains(base, ".") {
			if len(defaultHosts) > 0 {
				usedBy = append(usedBy, defaultHosts...)
			}
			c.Notes = append(c.Notes, "default identity: offered to every host without an explicit IdentityFile")
		}
		if len(usedBy) > 0 {
			sort.Strings(usedBy)
			c.Notes = append(c.Notes, "used for hosts: "+strings.Join(dedupeStrings(usedBy), ", "))
		}
		if unixPermsMeaningful() && info.Mode().Perm()&0o077 != 0 {
			c.Notes = append(c.Notes, fmt.Sprintf("permissions %04o: readable by other users", info.Mode().Perm()))
		}
		out = append(out, c)
	}

	// Agent forwarding lets a compromised server use your keys.
	for _, h := range hosts {
		if !h.forwardAgent {
			continue
		}
		sev := cred.Low
		for _, n := range h.names {
			if n == "*" {
				sev = cred.Medium
			}
		}
		out = append(out, cred.Credential{
			Service: cred.ServiceSSH, Kind: "agent-forwarding", Source: "ssh-config",
			Location: env.Display(filepath.Join(dir, "config")), Line: h.line, Account: strings.Join(h.names, " "),
			Lifetime: cred.ShortTerm, Severity: sev,
			Summary: "ForwardAgent yes for " + strings.Join(h.names, ", ") + ": root on that server can sign with your keys while you are connected",
		})
	}
	return out, probs
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// sshConfig parses Host blocks, following Include up to a small depth.
func sshConfig(env *Env, path string, depth int) ([]sshHost, []Problem) {
	data, _, ok, prob := readFile(path)
	if prob != nil {
		return nil, []Problem{*prob}
	}
	if !ok || depth > 3 {
		return nil, nil
	}
	var hosts []sshHost
	var probs []Problem
	var cur *sshHost
	expand := func(p string) string {
		p = strings.Trim(p, `"`)
		p = strings.ReplaceAll(p, "%d", env.Home)
		if strings.HasPrefix(p, "~/") {
			p = env.Path(p[2:])
		}
		if !filepath.IsAbs(p) {
			p = env.Path(".ssh", p)
		}
		return p
	}
	for i, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(strings.Replace(t, "=", " ", 1))
		if len(f) < 2 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "host":
			hosts = append(hosts, sshHost{names: f[1:], line: i + 1})
			cur = &hosts[len(hosts)-1]
		case "match":
			cur = nil
		case "identityfile":
			if cur != nil {
				cur.identities = append(cur.identities, expand(f[1]))
			}
		case "forwardagent":
			if cur != nil && strings.EqualFold(f[1], "yes") {
				cur.forwardAgent = true
			}
		case "include":
			for _, pat := range f[1:] {
				matches, _ := filepath.Glob(expand(pat))
				for _, m := range matches {
					h, p := sshConfig(env, m, depth+1)
					hosts = append(hosts, h...)
					probs = append(probs, p...)
					cur = nil
				}
			}
		}
	}
	return hosts, probs
}

type keyInfo struct {
	format    string // openssh, pem, pkcs8, putty
	keyType   string // ssh-ed25519, ssh-rsa ...
	kdf       string
	encrypted bool
	unknown   bool // could not parse; passphrase status undetermined
}

// inspectKey recognises a private key file and whether it is encrypted,
// without decrypting it.
func inspectKey(data []byte) (keyInfo, bool) {
	s := string(data)
	switch {
	case strings.HasPrefix(s, "PuTTY-User-Key-File-"):
		k := keyInfo{format: "putty"}
		for _, l := range strings.Split(s, "\n") {
			if strings.HasPrefix(l, "PuTTY-User-Key-File-") {
				if _, v, ok := strings.Cut(l, ": "); ok {
					k.keyType = strings.TrimSpace(v)
				}
			}
			if strings.HasPrefix(l, "Encryption:") {
				k.encrypted = strings.TrimSpace(strings.TrimPrefix(l, "Encryption:")) != "none"
			}
		}
		return k, true
	case strings.Contains(s, "-----BEGIN OPENSSH PRIVATE KEY-----"):
		k := keyInfo{format: "openssh"}
		body := between(s, "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----")
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
		if err != nil || !bytes.HasPrefix(raw, []byte("openssh-key-v1\x00")) {
			k.unknown = true
			return k, true
		}
		r := raw[len("openssh-key-v1\x00"):]
		cipher, r, ok1 := sshString(r)
		kdf, r, ok2 := sshString(r)
		_, r, ok3 := sshString(r) // kdfoptions
		if !ok1 || !ok2 || !ok3 || len(r) < 4 {
			return k, true
		}
		k.kdf = string(kdf)
		k.encrypted = string(cipher) != "none"
		r = r[4:] // number of keys
		if pub, _, ok := sshString(r); ok {
			if kt, _, ok := sshString(pub); ok {
				k.keyType = string(kt)
			}
		}
		return k, true
	case strings.Contains(s, "-----BEGIN ENCRYPTED PRIVATE KEY-----"):
		return keyInfo{format: "pkcs8", keyType: "PKCS#8", encrypted: true}, true
	case strings.Contains(s, "-----BEGIN PRIVATE KEY-----"):
		return keyInfo{format: "pkcs8", keyType: "PKCS#8"}, true
	case strings.Contains(s, "PRIVATE KEY-----"):
		k := keyInfo{format: "pem"}
		for _, kt := range []string{"RSA", "DSA", "EC", "OPENSSH"} {
			if strings.Contains(s, "-----BEGIN "+kt+" PRIVATE KEY-----") {
				k.keyType = "PEM " + kt
			}
		}
		k.encrypted = strings.Contains(s, "Proc-Type: 4,ENCRYPTED") || strings.Contains(s, "DEK-Info:")
		return k, true
	}
	return keyInfo{}, false
}

func between(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	s = s[i+len(a):]
	if j := strings.Index(s, b); j >= 0 {
		s = s[:j]
	}
	return s
}

// sshString reads a length-prefixed string from an SSH wire buffer.
func sshString(b []byte) (val, rest []byte, ok bool) {
	if len(b) < 4 {
		return nil, b, false
	}
	n := binary.BigEndian.Uint32(b)
	if uint64(n) > uint64(len(b)-4) {
		return nil, b, false
	}
	return b[4 : 4+n], b[4+n:], true
}

// pubComment returns the comment of a public key file ("user@host").
func pubComment(path string) string {
	data, _, ok, _ := readFile(path)
	if !ok {
		return ""
	}
	f := strings.Fields(strings.SplitN(string(data), "\n", 2)[0])
	if len(f) >= 3 {
		return strings.Join(f[2:], " ")
	}
	return ""
}
