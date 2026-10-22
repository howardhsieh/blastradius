package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
)

// stsHost is the global STS endpoint. It accepts every commercial-partition
// key, which keeps the allow-list to one host; GovCloud and China keys are
// rejected here and show up as "rejected", which the summary notes.
const stsHost = "sts.amazonaws.com"

// ProbeHosts: STS only. GetCallerIdentity needs no permission and reveals
// nothing but the caller's own account, user and ARN.
func (aws) ProbeHosts() []string { return []string{stsHost} }

// awsKeyPair is the material a STS call needs. It is read back from the
// file or environment at probe time and never stored.
type awsKeyPair struct {
	keyID, secret, session string
}

func (aws) probeTargets(env *Env, c cred.Credential) ([]string, string) {
	if c.Service != cred.ServiceAWS {
		return nil, ""
	}
	switch c.Kind {
	case "access-key", "session-key":
	default:
		return nil, "" // SSO tokens and OIDC registrations are not STS credentials
	}
	switch c.Source {
	case "aws-credentials", "process-env", "aws-cli-cache":
		return []string{stsHost}, ""
	}
	return nil, "AWS secret without its access key ID (found in " + c.Source + "); only ~/.aws/credentials, the CLI cache and the environment are probed"
}

// awsPairAt re-reads the key pair behind c and checks the secret's
// fingerprint against the scan.
func awsPairAt(env *Env, c cred.Credential) (awsKeyPair, error) {
	var p awsKeyPair
	switch c.Source {
	case "process-env":
		p = awsKeyPair{keyID: env.Getenv("AWS_ACCESS_KEY_ID"), secret: env.Getenv("AWS_SECRET_ACCESS_KEY"), session: env.Getenv("AWS_SESSION_TOKEN")}
	case "aws-credentials":
		data, _, ok, prob := readFile(env.Expand(c.Location))
		if prob != nil {
			return p, errors.New(prob.Err)
		}
		if !ok {
			return p, errors.New("file is gone")
		}
		for _, s := range parseINI(data) {
			if s.Line == c.Line || "profile "+s.Name == c.Account {
				p = awsKeyPair{keyID: s.Get("aws_access_key_id"), secret: s.Get("aws_secret_access_key"), session: s.Get("aws_session_token")}
				break
			}
		}
	case "aws-cli-cache":
		data, _, ok, prob := readFile(env.Expand(c.Location))
		if prob != nil {
			return p, errors.New(prob.Err)
		}
		if !ok {
			return p, errors.New("file is gone")
		}
		var f struct {
			Credentials struct {
				AccessKeyID     string `json:"AccessKeyId"`
				SecretAccessKey string `json:"SecretAccessKey"`
				SessionToken    string `json:"SessionToken"`
			} `json:"Credentials"`
		}
		if err := json.Unmarshal(data, &f); err != nil {
			return p, errors.New("file changed since the scan")
		}
		p = awsKeyPair{keyID: f.Credentials.AccessKeyID, secret: f.Credentials.SecretAccessKey, session: f.Credentials.SessionToken}
	default:
		return p, ErrNotProbed
	}
	if p.keyID == "" || p.secret == "" {
		return p, errors.New("access key ID or secret missing")
	}
	if cred.Fingerprint(p.secret) != c.Fingerprint {
		return p, errors.New("secret changed since the scan")
	}
	return p, nil
}

var xmlCodeRe = regexp.MustCompile(`<Code>([A-Za-z0-9.]+)</Code>`)

// Probe calls sts:GetCallerIdentity, the one AWS API every credential may
// call, and reports the account, the ARN and whether it is the root user.
func (a aws) Probe(ctx context.Context, env *Env, c cred.Credential) (*Reach, error) {
	hosts, skip := a.probeTargets(env, c)
	if len(hosts) == 0 {
		if skip != "" {
			return nil, errors.New(skip)
		}
		return nil, ErrNotProbed
	}
	if env.Probe == nil {
		return nil, ErrOffline
	}
	pair, err := awsPairAt(env, c)
	if err != nil {
		return nil, fmt.Errorf("re-reading the key pair: %v", err)
	}
	body := "Action=GetCallerIdentity&Version=2011-06-15"
	req, err := env.newProbeRequest(ctx, http.MethodPost, "https://"+stsHost+"/", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	sigv4{accessKeyID: pair.keyID, secretKey: pair.secret, sessionToken: pair.session, region: "us-east-1", service: "sts"}.sign(req, []byte(body), env.Now)

	var out struct {
		Response struct {
			Result struct {
				Account string `json:"Account"`
				Arn     string `json:"Arn"`
				UserID  string `json:"UserId"`
			} `json:"GetCallerIdentityResult"`
		} `json:"GetCallerIdentityResponse"`
	}
	resp, err := doJSON(env.probeClient(hosts, nil), req, &out)
	r := &Reach{Host: stsHost, ProbedAt: env.Now.UTC().Format("2006-01-02T15:04:05Z")}
	defer scrub(r, pair.secret, pair.session)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		code := stsErrorCode(resp)
		switch code {
		case "InvalidClientTokenId", "SignatureDoesNotMatch", "ExpiredToken", "AuthFailure", "UnrecognizedClientException", "InvalidSignatureException":
			r.Summary = fmt.Sprintf("rejected by %s (%s): deleted, deactivated or expired", stsHost, code)
			return r, nil
		}
		if code != "" {
			return nil, fmt.Errorf("%s answered HTTP %d (%s)", stsHost, resp.StatusCode, code)
		}
		return nil, statusErr(stsHost, resp)
	}
	res := out.Response.Result
	r.Live = true
	r.Identity = res.Arn
	r.TokenType = awsPrincipalType(res.Arn)
	r.Admin = r.TokenType == "root"
	r.Summary = fmt.Sprintf("acts as %s in account %s", awsPrincipalName(res.Arn), res.Account)
	if r.Admin {
		r.Summary = fmt.Sprintf("ROOT USER of account %s: unrestricted control of everything in it", res.Account)
	}
	return r, nil
}

// stsErrorCode pulls the error code out of a JSON or XML STS error body.
func stsErrorCode(resp *http.Response) string {
	if resp.Body == nil {
		return ""
	}
	var buf strings.Builder
	data := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(data)
		buf.Write(data[:n])
		if err != nil || buf.Len() > 64*1024 {
			break
		}
	}
	body := buf.String()
	var js struct {
		Error struct {
			Code string `json:"Code"`
		} `json:"Error"`
	}
	if json.Unmarshal([]byte(body), &js) == nil && js.Error.Code != "" {
		return js.Error.Code
	}
	if m := xmlCodeRe.FindStringSubmatch(body); m != nil {
		return m[1]
	}
	return ""
}

// awsPrincipalType classifies an ARN: root, user, assumed-role, federated-user.
func awsPrincipalType(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return "unknown"
	}
	res := parts[5]
	switch {
	case res == "root":
		return "root"
	case strings.HasPrefix(res, "user/"):
		return "iam-user"
	case strings.HasPrefix(res, "assumed-role/"):
		return "assumed-role"
	case strings.HasPrefix(res, "federated-user/"):
		return "federated-user"
	}
	return filepath.Base(res)
}

// awsPrincipalName renders "user alice" / "role Admin (session alice)".
func awsPrincipalName(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) < 6 {
		return arn
	}
	res := strings.Split(parts[5], "/")
	switch {
	case res[0] == "root":
		return "the root user"
	case res[0] == "user" && len(res) > 1:
		return "IAM user " + res[len(res)-1]
	case res[0] == "assumed-role" && len(res) > 2:
		return "role " + res[1] + " (session " + res[2] + ")"
	case res[0] == "assumed-role" && len(res) > 1:
		return "role " + res[1]
	}
	return parts[5]
}
