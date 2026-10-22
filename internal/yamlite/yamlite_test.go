package yamlite

import "testing"

const kubeconfig = `apiVersion: v1
kind: Config
# a comment
clusters:
- cluster:
    server: https://1.2.3.4:6443
    certificate-authority-data: QUJD
  name: prod
contexts:
- context:
    cluster: prod
    user: admin
    namespace: kube-system
  name: prod-admin
current-context: prod-admin
users:
- name: admin
  user:
    token: "tok with: colon"
- name: exec-user
  user:
    exec:
      command: aws
      args:
        - eks
        - get-token
      env: null
- name: cert
  user:
    client-key-data: |
      line1
      line2
`

func TestKubeconfig(t *testing.T) {
	n, err := Parse([]byte(kubeconfig))
	if err != nil {
		t.Fatal(err)
	}
	if n.Str("current-context") != "prod-admin" {
		t.Errorf("current-context = %q", n.Str("current-context"))
	}
	users := n.Get("users")
	if users == nil || users.Kind != Seq || len(users.Seq) != 3 {
		t.Fatalf("users = %+v", users)
	}
	if users.Seq[0].Str("name") != "admin" || users.Seq[0].Get("user").Str("token") != "tok with: colon" {
		t.Errorf("user 0 = %+v", users.Seq[0])
	}
	ex := users.Seq[1].Get("user").Get("exec")
	if ex.Str("command") != "aws" || len(ex.Get("args").Seq) != 2 || ex.Get("args").Seq[1].String() != "get-token" {
		t.Errorf("exec = %+v", ex)
	}
	if got := users.Seq[2].Get("user").Str("client-key-data"); got != "line1\nline2" {
		t.Errorf("block scalar = %q", got)
	}
	ctx := n.Get("contexts").Seq[0].Get("context")
	if ctx.Str("namespace") != "kube-system" || n.Get("clusters").Seq[0].Get("cluster").Str("server") != "https://1.2.3.4:6443" {
		t.Errorf("context/cluster parse failed")
	}
}

func TestGHHosts(t *testing.T) {
	src := "github.com:\n    user: alice\n    oauth_token: gho_x # inline\n    git_protocol: https\n    users:\n        alice:\n            oauth_token: gho_x\nghe.example.com:\n    user: bob\n"
	n, err := Parse([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Map) != 2 || n.Get("github.com").Str("oauth_token") != "gho_x" || n.Get("github.com").Get("users").Get("alice").Str("oauth_token") != "gho_x" {
		t.Errorf("parsed %+v", n)
	}
	if n.Get("ghe.example.com").Str("user") != "bob" {
		t.Error("second host missing")
	}
}

func TestEdgeCases(t *testing.T) {
	n, err := Parse([]byte("---\nempty:\nquoted: 'it''s'\nurl: http://x/y:z\nlist:\n- a\n- b\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n.Get("empty") == nil || n.Get("empty").String() != "" {
		t.Error("empty value")
	}
	if n.Str("quoted") != "it's" || n.Str("url") != "http://x/y:z" {
		t.Errorf("quoted=%q url=%q", n.Str("quoted"), n.Str("url"))
	}
	if l := n.Get("list"); l == nil || len(l.Seq) != 2 || l.Seq[1].String() != "b" {
		t.Errorf("list = %+v", l)
	}
	if _, err := Parse([]byte("a:\n\tb: 1\n")); err == nil {
		t.Error("tabs should fail")
	}
}
