package provider

import (
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"
)

// The example key pair from the AWS documentation. It is not a working
// credential (every AWS document uses it); the test vectors below are the
// published ones plus signatures generated with botocore for the exact
// request blastradius sends. The session-key case uses a deliberately
// short key ID: the ID is not part of the signature, and a 20-character
// ASIA… string trips GitHub secret scanning even for the documented example.
const (
	exampleKeyID  = "AKIAIOSFODNN7EXAMPLE"
	exampleSecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

// TestSigningKeyVector is the "Examples of how to derive a signing key"
// vector from the Signature Version 4 documentation.
func TestSigningKeyVector(t *testing.T) {
	s := sigv4{secretKey: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", region: "us-east-1", service: "iam"}
	got := hex.EncodeToString(s.signingKey("20120215"))
	if want := "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"; got != want {
		t.Errorf("signing key = %s, want %s", got, want)
	}
}

func stsRequest(t *testing.T) (*http.Request, []byte) {
	t.Helper()
	body := []byte("Action=GetCallerIdentity&Version=2011-06-15")
	req, err := http.NewRequest(http.MethodPost, "https://sts.amazonaws.com/", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("User-Agent", "blastradius/test")
	req.Header.Set("Accept", "application/json")
	return req, body
}

// TestGetCallerIdentitySignature compares against signatures produced by
// botocore's SigV4Auth for the same request at the same instant, for a
// long-term key and for session credentials.
func TestGetCallerIdentitySignature(t *testing.T) {
	now := time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, keyID, token, signedHeaders, signature string
	}{
		{"long-term", exampleKeyID, "", "content-type;host;x-amz-content-sha256;x-amz-date",
			"6382ceea3780ebc88ef45808bd3a4d064cfe39cc7dc7ea8973d77f4bfb6dfc1d"},
		{"session", "ASIAEXAMPLE", "FQoGZXIvYXdzEBYaDExampleSessionToken", "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
			"00fbf3537b8e2cb19afa7a44b26d34cd263692587a733ff8a151e4f485b0e2e9"},
	} {
		req, body := stsRequest(t)
		sigv4{accessKeyID: tc.keyID, secretKey: exampleSecret, sessionToken: tc.token, region: "us-east-1", service: "sts"}.sign(req, body, now)
		want := "AWS4-HMAC-SHA256 Credential=" + tc.keyID + "/20261022/us-east-1/sts/aws4_request, SignedHeaders=" + tc.signedHeaders + ", Signature=" + tc.signature
		if got := req.Header.Get("Authorization"); got != want {
			t.Errorf("%s:\n got %s\nwant %s", tc.name, got, want)
		}
		if got := req.Header.Get("X-Amz-Date"); got != "20261022T120000Z" {
			t.Errorf("%s: X-Amz-Date = %s", tc.name, got)
		}
		if tc.token != "" && req.Header.Get("X-Amz-Security-Token") != tc.token {
			t.Errorf("%s: session token header missing", tc.name)
		}
	}
}

func TestCanonicalQuery(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://sts.amazonaws.com/?Version=2011-06-15&Action=Get%20Caller&b=2&a=~x", nil)
	canonical, _ := canonicalRequest(req, "h")
	if !strings.Contains(canonical, "\nAction=Get%20Caller&Version=2011-06-15&a=~x&b=2\n") {
		t.Errorf("canonical query wrong:\n%s", canonical)
	}
}
