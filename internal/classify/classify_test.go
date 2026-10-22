package classify

import (
	"testing"

	"github.com/howardhsieh/blastradius/internal/cred"
)

func long(prefix string, n int) string {
	s := prefix
	for len(s) < n {
		s += "FAKEBLAST"
	}
	return s[:n]
}

func TestToken(t *testing.T) {
	for _, tc := range []struct {
		v       string
		service string
		ok      bool
	}{
		{long("ghp_", 40), cred.ServiceGitHub, true},
		{long("github_pat_", 80), cred.ServiceGitHub, true},
		{long("npm_", 40), cred.ServiceNPM, true},
		{long("AKIA", 20), cred.ServiceAWS, true},
		{long("sk-ant-api03-", 60), cred.ServiceAnthropic, true},
		{long("sk-proj-", 60), cred.ServiceOpenAI, true},
		{long("sk-", 51), cred.ServiceOpenAI, true},
		{"sk-short", "", false},
		{long("xoxb-", 30), cred.ServiceSlack, true},
		{"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2ln", cred.ServiceGeneric, true},
		{"hello world", "", false},
	} {
		r, ok := Token(tc.v)
		if ok != tc.ok || (ok && r.Service != tc.service) {
			t.Errorf("Token(%.20q) = %+v %v, want %s %v", tc.v, r, ok, tc.service, tc.ok)
		}
	}
	if !IsLegacyNPMToken("00000000-0000-4000-8000-000000000000") || IsLegacyNPMToken(long("npm_", 40)) {
		t.Error("legacy npm detection")
	}
}

func TestVar(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		service     string
		ok          bool
	}{
		{"ANTHROPIC_API_KEY", long("sk-ant-", 40), cred.ServiceAnthropic, true},
		{"GH_TOKEN", "FAKEBLASTnotprefixed", cred.ServiceGitHub, true},
		{"MY_API_KEY", "FAKEBLASTvalue1", cred.ServiceGeneric, true},
		{"MY_API_KEY", "changeme", "", false},
		{"MY_API_KEY", "${MY_API_KEY}", "", false},
		{"MY_API_KEY", "<your-key>", "", false},
		{"MY_API_KEY", "short", "", false},
		{"DATABASE_URL", "postgres://u:FAKEBLASTpw@h/db", cred.ServiceDatabase, true},
		{"DATABASE_URL", "postgres://h/db", "", false},
		{"NEXT_PUBLIC_API_URL", "https://api.example.com/v1", "", false},
		{"NEXT_PUBLIC_KEY", long("sk-ant-", 40), cred.ServiceAnthropic, true},
		{"AWS_ACCESS_KEY_ID", "AKIAFAKEBLAST0000001", "", false},
		{"SSH_AUTH_SOCK", "/tmp/agent.sock.FAKEBLAST", "", false},
		{"PORT", "30000000", "", false},
		{"SOME_URL", "https://user:FAKEBLASTpw@host/", cred.ServiceGeneric, true},
		{"STRIPE_SECRET_KEY", long("sk_live_", 40), cred.ServiceStripe, true},
		{"CLERK_SECRET_KEY", long("sk_live_", 40), cred.ServiceGeneric, true},
	} {
		r, ok := Var(tc.name, tc.value)
		if ok != tc.ok || (ok && r.Service != tc.service) {
			t.Errorf("Var(%s, %.20q) = %+v %v, want %s %v", tc.name, tc.value, r, ok, tc.service, tc.ok)
		}
	}
}

func TestIsSecretName(t *testing.T) {
	for name, want := range map[string]bool{
		"GH_TOKEN": true, "FOO_SECRET": true, "DB_PASSWORD": true, "X_API_KEY": true,
		"PATH": false, "SSH_AUTH_SOCK": false, "AWS_ACCESS_KEY_ID": false, "EDITOR": false, "CSRF_TOKEN": false,
	} {
		if IsSecretName(name) != want {
			t.Errorf("IsSecretName(%s) = %v", name, !want)
		}
	}
}
