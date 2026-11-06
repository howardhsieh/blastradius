package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/howardhsieh/blastradius/internal/cred"
	"github.com/howardhsieh/blastradius/internal/scan"
)

// SARIF 2.1.0, the format GitHub code scanning and most security dashboards
// ingest. One result per credential, one rule per remediation; the run
// carries the machine's rating. Like every other format it holds
// fingerprints and metadata only.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool         `json:"tool"`
	Results    []sarifResult     `json:"results"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	Name             string       `json:"name"`
	ShortDescription sarifMessage `json:"shortDescription"`
	FullDescription  sarifMessage `json:"fullDescription"`
	Help             sarifMessage `json:"help"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	Level      string            `json:"level"`
	Message    sarifMessage      `json:"message"`
	Locations  []sarifLocation   `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
	// PartialFingerprints lets code scanning track the same credential
	// across uploads; it is the scan's own sha256[:8], not a new hash.
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI         string        `json:"uri"`
	Description *sarifMessage `json:"description,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

func sarifLevel(s cred.Severity) string {
	switch {
	case s >= cred.High:
		return "error"
	case s == cred.Medium:
		return "warning"
	default:
		return "note"
	}
}

// sarifURI turns a credential location into an artifact URI. Paths keep
// the "~/" shortening; environment variables become "env:NAME", which is a
// valid URI with scheme "env".
func sarifURI(loc string) string {
	if strings.HasPrefix(loc, "env:") {
		return loc
	}
	return strings.ReplaceAll(loc, " ", "%20")
}

// SARIF writes the result as a SARIF 2.1.0 log.
func SARIF(w io.Writer, r *scan.Result, version string) error {
	var rules []sarifRule
	for _, rl := range scan.Rules() {
		rules = append(rules, sarifRule{
			ID: rl.ID, Name: rl.ID,
			ShortDescription: sarifMessage{rl.Title},
			FullDescription:  sarifMessage{rl.Detail},
			Help:             sarifMessage{rl.Detail},
		})
	}
	results := []sarifResult{}
	for _, c := range r.Credentials {
		loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: sarifURI(c.Location)}}
		if c.Line > 0 {
			loc.Region = &sarifRegion{StartLine: c.Line}
		}
		if c.Source != "" {
			loc.ArtifactLocation.Description = &sarifMessage{"found by the " + c.Source + " collector"}
		}
		msg := fmt.Sprintf("[%s] %s: %s", strings.ToUpper(c.Severity.String()), c.Service, c.Summary)
		if c.Reach != nil {
			msg += " — probe: " + c.Reach.Summary
		}
		if c.Remediation != "" {
			msg += " — " + c.Remediation
		}
		props := map[string]string{
			"service": c.Service, "kind": c.Kind, "severity": c.Severity.String(), "lifetime": string(c.Lifetime),
		}
		if c.Account != "" {
			props["account"] = c.Account
		}
		if c.ExpiresAt != "" {
			props["expires_at"] = c.ExpiresAt
		}
		if c.Expired {
			props["expired"] = "true"
		}
		if c.Protected {
			props["protected"] = "true"
		}
		if len(c.AlsoIn) > 0 {
			props["also_in"] = strings.Join(c.AlsoIn, ", ")
		}
		if c.Reach != nil {
			props["probe_host"] = c.Reach.Host
			props["probe_live"] = fmt.Sprint(c.Reach.Live)
			if c.Reach.Identity != "" {
				props["probe_identity"] = c.Reach.Identity
			}
			if c.Reach.TokenType != "" {
				props["probe_token_type"] = c.Reach.TokenType
			}
			if len(c.Reach.Scopes) > 0 {
				props["probe_scopes"] = strings.Join(c.Reach.Scopes, ", ")
			}
		}
		res := sarifResult{
			RuleID: scan.RuleFor(c).ID, Level: sarifLevel(c.Severity), Message: sarifMessage{msg},
			Locations: []sarifLocation{{loc}}, Properties: props,
		}
		if c.Fingerprint != "" {
			res.PartialFingerprints = map[string]string{"secretSha256Prefix/v1": c.Fingerprint}
		}
		results = append(results, res)
	}
	runProps := map[string]string{
		"host": r.Host, "rating": r.Rating, "score": fmt.Sprint(r.Score), "scanned_at": r.ScannedAt,
		"offline": fmt.Sprint(r.Offline),
	}
	if len(r.ProbedHosts) > 0 {
		runProps["probed_hosts"] = strings.Join(r.ProbedHosts, ", ")
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "blastradius", Version: version,
				InformationURI: "https://github.com/howardhsieh/blastradius", Rules: rules,
			}},
			Results:    results,
			Properties: runProps,
		}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}
