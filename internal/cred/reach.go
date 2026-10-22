package cred

// Reach is what an online probe (--probe) learned a credential can do. It
// is attached to a Credential only when the user opted in, and like the
// rest of the record it never carries the secret: every string in it is
// scrubbed against the secret that was sent before the record is kept.
type Reach struct {
	// Host is the API host that answered.
	Host string `json:"host"`
	// Live is false when the service rejected the credential (revoked,
	// expired or otherwise invalid).
	Live bool `json:"live"`
	// Identity is who the service says the credential acts as: a login,
	// an ARN, a registry user name.
	Identity string `json:"identity,omitempty"`
	// TokenType is the service's own classification where it has one:
	// "classic", "fine-grained", "read-only", "automation", "publish" ...
	TokenType string `json:"token_type,omitempty"`
	// Scopes are OAuth scopes reported by the service (GitHub classic tokens).
	Scopes []string `json:"scopes,omitempty"`
	// Permissions summarise what the credential may do when the service
	// reports rules rather than scopes (Kubernetes).
	Permissions []string `json:"permissions,omitempty"`
	// ReadOnly is true when the service confirmed the credential cannot write.
	ReadOnly bool `json:"read_only,omitempty"`
	// Bypass2FA is true for npm automation tokens, which publish without a
	// second factor.
	Bypass2FA bool `json:"bypass_2fa,omitempty"`
	// Admin is true when the credential is the account root or a
	// cluster-admin equivalent.
	Admin bool `json:"admin,omitempty"`
	// Summary is one line for the report: "acts as alice · scopes: repo".
	Summary string `json:"summary"`
	// ProbedAt is when the probe ran (RFC 3339, UTC).
	ProbedAt string `json:"probed_at"`
}
