package provider

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// sigv4 is a minimal AWS Signature Version 4 signer for a single
// POST-with-form-body request, written against the standard library so the
// tool keeps zero dependencies. It covers what sts:GetCallerIdentity needs:
// a fixed path, no query string, a handful of headers.
type sigv4 struct {
	accessKeyID, secretKey, sessionToken string
	region, service                      string
}

// hmacSHA256 is the building block of the signing-key chain.
func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// signingKey derives kSigning for a date (YYYYMMDD).
func (s sigv4) signingKey(date string) []byte {
	k := hmacSHA256([]byte("AWS4"+s.secretKey), date)
	k = hmacSHA256(k, s.region)
	k = hmacSHA256(k, s.service)
	return hmacSHA256(k, "aws4_request")
}

// canonicalRequest builds the canonical request and the signed-header
// list for req. Header values are trimmed and lower-cased by name; the
// query string is sorted and re-encoded.
func canonicalRequest(req *http.Request, bodyHash string) (canonical, signedHeaders string) {
	names := make([]string, 0, len(req.Header)+1)
	values := map[string]string{}
	for k, v := range req.Header {
		lk := strings.ToLower(k)
		switch lk {
		case "user-agent", "accept", "authorization", "content-length", "accept-encoding":
			continue
		}
		names = append(names, lk)
		values[lk] = strings.Join(trimAll(v), ",")
	}
	host := req.Host
	if host == "" {
		host = req.URL.Host
	}
	names = append(names, "host")
	values["host"] = host
	sort.Strings(names)
	var hdr strings.Builder
	for _, n := range names {
		hdr.WriteString(n + ":" + values[n] + "\n")
	}
	signedHeaders = strings.Join(names, ";")
	path := req.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	canonical = strings.Join([]string{
		req.Method, path, canonicalQuery(req.URL.Query()), hdr.String(), signedHeaders, bodyHash,
	}, "\n")
	return canonical, signedHeaders
}

func trimAll(v []string) []string {
	out := make([]string, len(v))
	for i, s := range v {
		out[i] = strings.Join(strings.Fields(s), " ")
	}
	return out
}

// canonicalQuery sorts parameters by name then value, RFC 3986 encoded.
func canonicalQuery(q url.Values) string {
	type kv struct{ k, v string }
	var pairs []kv
	for k, vs := range q {
		for _, v := range vs {
			pairs = append(pairs, kv{awsEscape(k), awsEscape(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

// awsEscape percent-encodes everything but the RFC 3986 unreserved set.
func awsEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		default:
			b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
		}
	}
	return b.String()
}

// stringToSign builds the SigV4 string to sign from the canonical request.
func (s sigv4) stringToSign(amzDate, canonical string) (stringToSign, scope string) {
	scope = amzDate[:8] + "/" + s.region + "/" + s.service + "/aws4_request"
	return strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, sha256Hex([]byte(canonical))}, "\n"), scope
}

// sign adds X-Amz-Date, X-Amz-Content-Sha256, X-Amz-Security-Token (for
// session credentials) and Authorization to req. body is the exact request
// body; now is the signing time.
func (s sigv4) sign(req *http.Request, body []byte, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	bodyHash := sha256Hex(body)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("X-Amz-Content-Sha256", bodyHash)
	if s.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", s.sessionToken)
	}
	canonical, signedHeaders := canonicalRequest(req, bodyHash)
	sts, scope := s.stringToSign(amzDate, canonical)
	sig := hex.EncodeToString(hmacSHA256(s.signingKey(amzDate[:8]), sts))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+s.accessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+sig)
}
