// Package testfixture builds a fake home directory full of clearly-invalid
// credentials so every layer of blastradius can be tested against the same
// files, and so one test can assert that no fixture secret ever reaches a
// report. Every secret contains the marker FAKEBLAST; none works anywhere.
// It is imported by _test.go files only and is not linked into the binary.
package testfixture

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Every fixture secret carries the marker FAKEBLAST so a leak is easy to
// grep for, and none of them is a real credential: the token bodies are
// made of the marker repeated, not random material.
// Marker is embedded in every fixture secret.
const Marker = "FAKEBLAST"

const marker = Marker

func pad(prefix string, n int) string {
	s := prefix
	for len(s) < n {
		s += marker
	}
	return s[:n]
}

// Fixture is the fake home directory plus every secret written into it.
type Fixture struct {
	Home    string
	Secrets []string
	Environ []string
	Env     map[string]string
	Now     time.Time
	Dir     string // project directory for --dir
}

func (f *Fixture) write(t *testing.T, rel string, body string, mode os.FileMode, age time.Duration) string {
	t.Helper()
	p := filepath.Join(f.Home, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	if age > 0 {
		mt := f.Now.Add(-age)
		if err := os.Chtimes(p, mt, mt); err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func (f *Fixture) secret(s string) string {
	f.Secrets = append(f.Secrets, s)
	return s
}

// NewFixture builds a home directory that exercises every provider.
func NewFixture(t *testing.T) *Fixture {
	t.Helper()
	f := &Fixture{Home: t.TempDir(), Now: time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC), Env: map[string]string{}}
	f.Dir = filepath.Join(f.Home, "src", "app")
	day := 24 * time.Hour

	ghTok := f.secret(pad("gho_", 40))
	f.write(t, ".config/gh/hosts.yml", "github.com:\n    user: alice\n    oauth_token: "+ghTok+"\n    git_protocol: https\n    users:\n        alice:\n            oauth_token: "+ghTok+"\nghe.example.com:\n    user: bob\n", 0o600, 0)
	// Same token again in .git-credentials and in the environment: must merge.
	f.write(t, ".git-credentials", "https://alice:"+ghTok+"@github.com\nhttps://"+f.secret(pad("glpat-", 26))+"@gitlab.com\nhttps://carol:"+f.secret("FAKEBLASTgitpw1234")+"@git.example.com/x\n", 0o600, 0)
	f.Environ = append(f.Environ, "GH_TOKEN="+ghTok)

	f.write(t, ".netrc", "machine api.github.com\n  login alice\n  password "+f.secret(pad("ghp_", 40))+"\nmachine upload.pypi.org login __token__ password "+f.secret(pad("pypi-", 60))+"\n", 0o600, 0)

	legacy := f.secret("00000000-0000-4000-8000-000000000000")
	f.write(t, ".npmrc", "//registry.npmjs.org/:_authToken="+legacy+"\n//npm.pkg.github.com/:_authToken=${NPM_TOKEN}\n//registry.corp.example.com/:_auth="+f.secret(base64.StdEncoding.EncodeToString([]byte("dave:FAKEBLASTnpmpw")))+"\n", 0o600, 400*day)
	f.write(t, "src/app/.npmrc", "//registry.npmjs.org/:_authToken="+f.secret(pad("npm_", 40))+"\n", 0o644, 0)

	f.write(t, ".pypirc", "[distutils]\nindex-servers = pypi testpypi\n\n[pypi]\nusername = __token__\npassword = "+f.secret(pad("pypi-", 70))+"\n\n[testpypi]\nusername = alice\npassword = "+f.secret("FAKEBLASTtestpypi")+"\n", 0o600, 0)
	f.write(t, ".config/pip/pip.conf", "[global]\nindex-url = https://alice:"+f.secret("FAKEBLASTpippw99")+"@pypi.corp.example.com/simple\n", 0o600, 0)

	awsSecret := f.secret(pad("", 40))
	f.write(t, ".aws/credentials", "[default]\naws_access_key_id = AKIAFAKEBLAST0000001\naws_secret_access_key = "+awsSecret+"\n\n[temp]\naws_access_key_id = ASIAFAKEBLAST0000002\naws_secret_access_key = "+f.secret(pad("tmp", 40))+"\naws_session_token = "+f.secret(pad("FQoGZXIvYXdzE", 120))+"\n", 0o600, 500*day)
	f.write(t, ".aws/config", "[default]\nregion = ap-northeast-1\n\n[profile admin]\nrole_arn = arn:aws:iam::123456789012:role/Admin\nsource_profile = default\n\n[profile sso]\nsso_start_url = https://corp.awsapps.com/start\nsso_region = us-east-1\n", 0o600, 0)
	f.write(t, ".aws/sso/cache/aaaa.json", `{"startUrl":"https://corp.awsapps.com/start","region":"us-east-1","accessToken":"`+f.secret(pad("eyJfakesso", 80))+`","expiresAt":"2026-10-22T20:00:00Z"}`, 0o600, 0)
	f.write(t, ".aws/sso/cache/bbbb.json", `{"startUrl":"https://old.awsapps.com/start","accessToken":"`+f.secret(pad("eyJoldsso", 80))+`","expiresAt":"2025-01-01T00:00:00Z"}`, 0o600, 0)
	f.write(t, ".aws/cli/cache/cccc.json", `{"Credentials":{"AccessKeyId":"ASIAFAKEBLAST0000003","SecretAccessKey":"`+f.secret(pad("cli", 40))+`","SessionToken":"x","Expiration":"2026-10-22T13:00:00Z"},"AssumedRoleUser":{"Arn":"arn:aws:sts::123456789012:assumed-role/Admin/alice"}}`, 0o600, 0)

	f.write(t, ".config/gcloud/active_config", "default", 0o600, 0)
	f.write(t, ".config/gcloud/configurations/config_default", "[core]\naccount = alice@example.com\nproject = demo-123\n", 0o600, 0)
	f.write(t, ".config/gcloud/application_default_credentials.json", `{"client_id":"x.apps.googleusercontent.com","client_secret":"d-FAKE","refresh_token":"`+f.secret(pad("1//0gFAKEBLAST", 60))+`","type":"authorized_user","quota_project_id":"demo-123"}`, 0o600, 0)
	saKey := f.secret("-----BEGIN PRIVATE KEY-----\n" + pad("", 64) + "\n-----END PRIVATE KEY-----\n")
	sa := f.write(t, "keys/sa.json", `{"type":"service_account","project_id":"demo-123","private_key_id":"abc","private_key":"`+strings.ReplaceAll(saKey, "\n", `\n`)+`","client_email":"deploy@demo-123.iam.gserviceaccount.com"}`, 0o600, 0)
	f.Env["GOOGLE_APPLICATION_CREDENTIALS"] = sa
	f.write(t, ".config/gcloud/credentials.db", "SQLite format 3\x00"+`{"refresh_token": "`+f.secret(pad("1//0hFAKEBLAST", 60))+`"}`, 0o600, 0)

	f.write(t, ".azure/azureProfile.json", "\xef\xbb\xbf"+`{"subscriptions":[{"id":"s1","user":{"name":"alice@example.com"},"isDefault":true},{"id":"s2","user":{"name":"alice@example.com"}}]}`, 0o600, 0)
	f.write(t, ".azure/msal_token_cache.json", `{"RefreshToken":{"k":{"secret":"`+f.secret(pad("0.AXFAKEBLAST", 80))+`"}}}`, 0o600, 0)
	f.write(t, ".azure/service_principal_entries.json", `[{"client_id":"11111111-1111-1111-1111-111111111111","tenant":"t1","client_secret":"`+f.secret(pad("sp~", 40))+`"}]`, 0o600, 0)

	dockerAuth := f.secret(base64.StdEncoding.EncodeToString([]byte("alice:FAKEBLASTdockerpw")))
	f.Secrets = append(f.Secrets, "FAKEBLASTdockerpw")
	f.write(t, ".docker/config.json", `{"auths":{"https://index.docker.io/v1/":{"auth":"`+dockerAuth+`"},"ghcr.io":{}},"credsStore":"osxkeychain"}`, 0o600, 0)

	certPEM, keyPEM := selfSigned(t, "kube-admin", f.Now.Add(365*day))
	expiredPEM, expiredKey := selfSigned(t, "old-admin", f.Now.Add(-day))
	kubeTok := f.secret(pad("eyJhbGciOiJSUzI1NiIsImtpZCI6IkZBS0UifQ.eyJzdWIiOiJGQUtFQkxBU1QifQ.", 120))
	f.Secrets = append(f.Secrets, keyPEM, expiredKey)
	f.write(t, ".kube/config", `apiVersion: v1
kind: Config
clusters:
- cluster:
    server: https://prod.k8s.example.com:6443
  name: prod
- cluster:
    server: https://eks.example.com
  name: eks
contexts:
- context:
    cluster: prod
    user: admin
    namespace: kube-system
  name: prod-admin
- context:
    cluster: eks
    user: eks-user
  name: eks
- context:
    cluster: prod
    user: sa-token
  name: prod-sa
current-context: prod-admin
users:
- name: admin
  user:
    client-certificate-data: `+base64.StdEncoding.EncodeToString([]byte(certPEM))+`
    client-key-data: `+base64.StdEncoding.EncodeToString([]byte(keyPEM))+`
- name: old
  user:
    client-certificate-data: `+base64.StdEncoding.EncodeToString([]byte(expiredPEM))+`
    client-key-data: `+base64.StdEncoding.EncodeToString([]byte(expiredKey))+`
- name: sa-token
  user:
    token: `+kubeTok+`
- name: eks-user
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      command: aws
      args:
        - eks
        - get-token
        - --cluster-name
        - eks
`, 0o600, 0)

	plain := OpenSSHKey("ssh-ed25519", false)
	enc := OpenSSHKey("ssh-rsa", true)
	pemEnc := "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,FAKEBLAST\n\n" + pad("", 64) + "\n-----END RSA PRIVATE KEY-----\n"
	f.Secrets = append(f.Secrets, plain, enc, pemEnc)
	f.write(t, ".ssh/id_ed25519", plain, 0o600, 800*day)
	f.write(t, ".ssh/id_ed25519.pub", "ssh-ed25519 AAAAC3FAKE alice@laptop\n", 0o644, 0)
	f.write(t, ".ssh/id_rsa", enc, 0o600, 0)
	f.write(t, ".ssh/legacy.pem", pemEnc, 0o644, 0)
	f.write(t, ".ssh/known_hosts", "github.com ssh-ed25519 AAAA\n", 0o600, 0)
	f.write(t, ".ssh/config", "Host github.com\n  User git\n  IdentityFile ~/.ssh/id_rsa\n\nHost bastion\n  HostName bastion.example.com\n  ForwardAgent yes\n  IdentityFile ~/.ssh/deploy_key\n\nHost *\n  AddKeysToAgent yes\n", 0o600, 0)
	f.write(t, ".ssh/deploy_key", OpenSSHKey("ecdsa-sha2-nistp256", false), 0o600, 0)
	f.Secrets = append(f.Secrets, OpenSSHKey("ecdsa-sha2-nistp256", false))

	f.write(t, ".claude/.credentials.json", `{"claudeAiOauth":{"accessToken":"`+f.secret(pad("sk-ant-oat01-", 60))+`","refreshToken":"`+f.secret(pad("sk-ant-ort01-", 60))+`","expiresAt":1800000000000}}`, 0o600, 0)
	f.write(t, ".codex/auth.json", `{"OPENAI_API_KEY":"`+f.secret(pad("sk-proj-", 60))+`","tokens":{"access_token":"a","refresh_token":"`+f.secret(pad("rt_", 40))+`","account_id":"acct_1"}}`, 0o600, 0)
	f.write(t, ".config/github-copilot/apps.json", `{"github.com:Iv1.abc":{"user":"alice","oauth_token":"`+f.secret(pad("ghu_", 40))+`"}}`, 0o600, 0)
	f.write(t, ".gemini/oauth_creds.json", `{"access_token":"ya29.x","refresh_token":"`+f.secret(pad("1//0iFAKEBLAST", 60))+`"}`, 0o600, 0)
	f.write(t, ".cache/huggingface/token", f.secret(pad("hf_", 40))+"\n", 0o600, 0)

	f.Environ = append(f.Environ,
		"ANTHROPIC_API_KEY="+f.secret(pad("sk-ant-api03-", 60)),
		"OPENAI_API_KEY="+f.secret(pad("sk-", 51)),
		"NPM_TOKEN="+f.secret(pad("npm_", 40)),
		"AWS_ACCESS_KEY_ID=ASIAFAKEBLAST0000004",
		"AWS_SECRET_ACCESS_KEY="+f.secret(pad("envaws", 40)),
		"MY_SERVICE_TOKEN=changeme",
		"SSH_AUTH_SOCK=/tmp/agent.sock",
		"PATH=/usr/bin",
		"HOME="+f.Home,
	)
	f.write(t, ".zshrc", "export PATH=$PATH:/opt/bin\nexport ANTHROPIC_API_KEY=\""+f.secret(pad("sk-ant-api03-rc", 60))+"\"\nexport GITHUB_TOKEN=$(security find-generic-password -ws gh)\nexport STRIPE_SECRET_KEY='"+f.secret(pad("sk_live_", 40))+"' # billing\n", 0o644, 0)
	f.write(t, ".config/fish/config.fish", "set -gx OPENAI_API_KEY "+f.secret(pad("sk-proj-fish", 60))+"\n", 0o644, 0)

	f.write(t, ".zsh_history", ": 1700000000:0;export AWS_SECRET_ACCESS_KEY="+f.secret(pad("histaws", 40))+"\n: 1700000001:0;ls -la\n: 1700000002:0;curl -H 'Authorization: Bearer "+f.secret(pad("histbearer", 40))+"' https://api.example.com\n: 1700000003:0;npm publish --token "+f.secret(pad("npm_hist", 40))+"\n: 1700000004:0;export AWS_SECRET_ACCESS_KEY="+pad("histaws", 40)+"\n: 1700000005:0;echo "+f.secret(pad("ghp_hist", 40))+" | gh auth login --with-token\n", 0o600, 0)

	f.write(t, "src/app/.env", "DATABASE_URL=postgres://app:"+f.secret("FAKEBLASTdbpw123")+"@db.internal:5432/app\nOPENAI_API_KEY="+f.secret(pad("sk-proj-dotenv", 60))+"\nPORT=3000\nNEXT_PUBLIC_API_URL=https://api.example.com\nSESSION_SECRET=\"${SESSION_SECRET}\"\nSTRIPE_SECRET_KEY=sk_test_placeholder\n", 0o644, 200*day)
	f.write(t, "src/app/.env.example", "OPENAI_API_KEY=your-key-here\nAPI_SECRET=xxxxxxxx\n", 0o644, 0)
	f.write(t, "src/app/node_modules/pkg/.env", "SKIPPED_TOKEN="+pad("skipped", 40)+"\n", 0o644, 0)
	f.write(t, "src/app/sub/.env.production", "SLACK_BOT_TOKEN="+f.secret(pad("xoxb-", 40))+"\n", 0o644, 0)
	return f
}

// Getenv looks a variable up in the fixture environment.
func (f *Fixture) Getenv(k string) string {
	if v, ok := f.Env[k]; ok {
		return v
	}
	for _, kv := range f.Environ {
		if name, val, ok := strings.Cut(kv, "="); ok && name == k {
			return val
		}
	}
	return ""
}

// Environment returns a copy of the fixture process environment.
func (f *Fixture) Environment() []string { return append([]string(nil), f.Environ...) }

// Dirs returns the project directory to pass as --dir.
func (f *Fixture) Dirs() []string { return []string{filepath.Join(f.Home, "src")} }

// OpenSSHKey builds a syntactically valid openssh-key-v1 private key file
// whose private section is filler, not key material.
func OpenSSHKey(keyType string, encrypted bool) string {
	str := func(s string) []byte {
		b := make([]byte, 4+len(s))
		binary.BigEndian.PutUint32(b, uint32(len(s)))
		copy(b[4:], s)
		return b
	}
	var blob []byte
	blob = append(blob, []byte("openssh-key-v1\x00")...)
	if encrypted {
		blob = append(blob, str("aes256-ctr")...)
		blob = append(blob, str("bcrypt")...)
		blob = append(blob, str(string(str(pad("", 16)))+"\x00\x00\x00\x10")...)
	} else {
		blob = append(blob, str("none")...)
		blob = append(blob, str("none")...)
		blob = append(blob, str("")...)
	}
	blob = append(blob, 0, 0, 0, 1)
	pub := append(str(keyType), str(pad(marker+keyType, 32))...)
	blob = append(blob, str(string(pub))...)
	blob = append(blob, str(pad("private"+keyType, 96))...)
	b64 := base64.StdEncoding.EncodeToString(blob)
	var lines []string
	for len(b64) > 70 {
		lines = append(lines, b64[:70])
		b64 = b64[70:]
	}
	lines = append(lines, b64)
	return "-----BEGIN OPENSSH PRIVATE KEY-----\n" + strings.Join(lines, "\n") + "\n-----END OPENSSH PRIVATE KEY-----\n"
}

// selfSigned returns a throw-away certificate and key in PEM.
func selfSigned(t *testing.T, cn string, notAfter time.Time) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"system:masters"}},
		NotBefore:    notAfter.Add(-2 * 365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kd, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kd}))
	return certPEM, keyPEM
}
