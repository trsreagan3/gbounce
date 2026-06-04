// Package compliance maps observed cross-bouncer audit activity to security/
// compliance framework controls. Faithful Go port of iam-jit's Python
// compliance/mapping.py + overlay.py: same 5 frameworks, same 24-control
// catalog, same 9 mapping rules + match regexes, same honest "evidence
// on-ramp, NOT a certification" disclaimer + partial-coverage disclosure.
//
// It is an EVIDENCE ON-RAMP, not a certification — see Disclaimer.
package compliance

import (
	"regexp"
	"sort"

	"github.com/trsreagan3/gbounce/internal/crossbouncer"
)

// Framework is one compliance framework + its display metadata.
type Framework struct {
	ID      string
	Name    string
	Version string
}

// Frameworks is the ordered set, matching mapping.FRAMEWORKS.
var Frameworks = []Framework{
	{"owasp", "OWASP Agentic AI Top 10", "2026"},
	{"mitre", "MITRE ATT&CK (Enterprise)", "ATT&CK Enterprise"},
	{"nist", "NIST SP 800-53", "Rev. 5"},
	{"soc2", "SOC 2 Trust Services Criteria", "TSC 2017 (rev. 2022)"},
	{"eu-ai-act", "EU AI Act", "Regulation (EU) 2024/1689"},
}

// control is a catalog entry: tag -> {framework, title}.
type control struct {
	framework string
	title     string
}

// catalog is the 24-control catalog, keyed by tag (mapping.CONTROL_CATALOG).
var catalog = map[string]control{
	"OWASP-AGENTIC-T01": {"owasp", "Excessive Agency / Permissions"},
	"OWASP-AGENTIC-T02": {"owasp", "Privilege Compromise / Escalation"},
	"OWASP-AGENTIC-T05": {"owasp", "Cascading / Unbounded Action Risk"},
	"OWASP-AGENTIC-T06": {"owasp", "Sensitive Data / Resource Exposure"},
	"OWASP-AGENTIC-T08": {"owasp", "Insufficient Monitoring / Traceability"},
	"MITRE-T1078":       {"mitre", "Valid Accounts"},
	"MITRE-T1098":       {"mitre", "Account Manipulation"},
	"MITRE-T1548":       {"mitre", "Abuse Elevation Control Mechanism"},
	"MITRE-T1530":       {"mitre", "Data from Cloud Storage"},
	"MITRE-T1485":       {"mitre", "Data Destruction"},
	"MITRE-T1110":       {"mitre", "Brute Force"},
	"NIST-AC-2":         {"nist", "Account Management"},
	"NIST-AC-3":         {"nist", "Access Enforcement"},
	"NIST-AC-6":         {"nist", "Least Privilege"},
	"NIST-AU-2":         {"nist", "Event Logging"},
	"NIST-AU-12":        {"nist", "Audit Record Generation"},
	"NIST-SI-4":         {"nist", "System Monitoring"},
	"SOC2-CC6.1":        {"soc2", "Logical Access Security Controls"},
	"SOC2-CC6.3":        {"soc2", "Access Based on Least Privilege / Roles"},
	"SOC2-CC6.6":        {"soc2", "Protection Against External Threats"},
	"SOC2-CC7.2":        {"soc2", "Anomaly / Security Event Monitoring"},
	"SOC2-CC7.3":        {"soc2", "Evaluation of Security Events"},
	"EU-AI-ACT-ART12":   {"eu-ai-act", "Record-Keeping / Logging"},
	"EU-AI-ACT-ART14":   {"eu-ai-act", "Human Oversight"},
	"EU-AI-ACT-ART15":   {"eu-ai-act", "Accuracy, Robustness & Cybersecurity"},
}

// match-signal kinds (mapping.SIGNAL_*).
type signal int

const (
	sigAny signal = iota
	sigAllow
	sigDeny
	sigActionRE
	sigAnomalous
	sigMFAGated
)

type rule struct {
	id       string
	sig      signal
	pattern  *regexp.Regexp // only for sigActionRE
	controls []string
	category string
}

// The match regexes — ported verbatim from mapping.py (RE2-compatible).
var (
	privEscRE       = regexp.MustCompile(`(?:iam:(?:Put.*Policy|Attach.*Policy|PutRolePolicy|CreateAccessKey|UpdateAssumeRolePolicy|CreatePolicyVersion|SetDefaultPolicyVersion|AddUserToGroup|CreateLoginProfile|UpdateLoginProfile)|sts:AssumeRole.*|iam:PassRole|.*:(?:create|update|patch).*(?:clusterrolebinding|rolebinding|clusterrole)|(?:sql|postgres|mysql):.*(?:GRANT|ALTER\s+ROLE|CREATE\s+ROLE|ALTER\s+USER))`)
	destructiveRE   = regexp.MustCompile(`(?:.*:(?:Delete|Terminate|Destroy|Purge|RemovePermission)|.*:(?:delete|deletecollection)|(?:sql|postgres|mysql):.*(?:DROP|TRUNCATE|DELETE\s+FROM)|(?:DELETE|PUT)$)`)
	sensitiveReadRE = regexp.MustCompile(`(?:secretsmanager:GetSecretValue|ssm:GetParameter.*|kms:Decrypt|s3:GetObject|s3:ListBucket|dynamodb:(?:Scan|Query|GetItem|BatchGetItem)|.*:(?:get|list|watch).*secret|(?:sql|postgres|mysql):.*SELECT)`)
)

// rules is the 9-rule mapping table (mapping.MAPPING_RULES).
var rules = []rule{
	{"audit_traceability", sigAny, nil, []string{"OWASP-AGENTIC-T08", "NIST-AU-2", "NIST-AU-12", "SOC2-CC6.1", "EU-AI-ACT-ART12"}, "audit/traceability"},
	{"access_enforced_allow", sigAllow, nil, []string{"NIST-AC-3", "SOC2-CC6.1"}, "access-enforcement"},
	{"least_privilege_deny", sigDeny, nil, []string{"OWASP-AGENTIC-T01", "NIST-AC-3", "NIST-AC-6", "SOC2-CC6.3", "EU-AI-ACT-ART14"}, "least-privilege"},
	{"privilege_escalation", sigActionRE, privEscRE, []string{"OWASP-AGENTIC-T02", "MITRE-T1098", "MITRE-T1548", "NIST-AC-2", "NIST-AC-6", "SOC2-CC6.6", "EU-AI-ACT-ART15"}, "privilege-escalation"},
	{"destructive_action", sigActionRE, destructiveRE, []string{"OWASP-AGENTIC-T05", "MITRE-T1485", "NIST-AC-6", "EU-AI-ACT-ART15"}, "destructive-action"},
	{"sensitive_read", sigActionRE, sensitiveReadRE, []string{"OWASP-AGENTIC-T06", "MITRE-T1530", "NIST-AC-6"}, "sensitive-data-access"},
	{"valid_accounts", sigAny, nil, []string{"MITRE-T1078"}, "valid-accounts"},
	{"anomaly_monitoring", sigAnomalous, nil, []string{"NIST-SI-4", "SOC2-CC7.2", "SOC2-CC7.3", "MITRE-T1110"}, "anomaly-monitoring"},
	{"mfa_gated", sigMFAGated, nil, []string{"SOC2-CC6.6"}, "mfa"},
}

// Disclaimer — verbatim from overlay.py _DISCLAIMER.
const Disclaimer = "This overlay maps ONLY the agent activity observed in the iam-jit " +
	"audit log for this session+window to the framework controls that activity TOUCHES. " +
	"It is a compliance EVIDENCE ON-RAMP, NOT a certification — evidence of technical-control " +
	"exercise, NOT a compliance certification and NOT a proof of completeness. " +
	"iam-jit-the-company holds no third-party attestations at v1.0 " +
	"(see docs/compliance/COMPLIANCE-MAPPING.md). Audit gaps, short windows, or unreachable " +
	"bouncers can omit real activity; per-framework controls outside the observable audit " +
	"surface are out of scope (see each framework's partial_coverage_note)."

// Output shapes (JSON tags match the Python overlay).

type ControlTouched struct {
	Control    string `json:"control"`
	Title      string `json:"title"`
	Framework  string `json:"framework"`
	EventCount int    `json:"event_count"`
}

type ControlNotTouched struct {
	Control string `json:"control"`
	Title   string `json:"title"`
}

type FrameworkCoverage struct {
	Framework            string              `json:"framework"`
	Name                 string              `json:"name"`
	Version              string              `json:"version"`
	ControlsTouched      []ControlTouched    `json:"controls_touched"`
	ControlsTouchedCount int                 `json:"controls_touched_count"`
	ControlsInCatalog    int                 `json:"controls_in_catalog"`
	ControlsNotTouched   []ControlNotTouched `json:"controls_not_touched"`
	PartialCoverageNote  string              `json:"partial_coverage_note"`
}

type OverlayEntry struct {
	Action         string   `json:"action"`
	Verdict        string   `json:"verdict"`
	Protocol       string   `json:"protocol"`
	Resources      []string `json:"resources"`
	ComplianceTags []string `json:"compliance_tags"`
	Categories     []string `json:"categories"`
}

type Result struct {
	SessionID       string              `json:"session_id"`
	EventsAnalyzed  int                 `json:"events_analyzed"`
	FrameworkFilter string              `json:"framework_filter,omitempty"`
	Overlay         []OverlayEntry      `json:"overlay"`
	Coverage        []FrameworkCoverage `json:"coverage"`
	IsPartial       bool                `json:"is_partial"`
	PartialReasons  []string            `json:"partial_reasons"`
	Disclaimer      string              `json:"disclaimer"`
	Notes           []string            `json:"notes"`
}

// BuildOverlay maps the events to framework controls. notes is the fan-out
// coverage map (bouncer -> "" | error); a non-empty note marks partial.
func BuildOverlay(sessionID string, events []crossbouncer.Event, frameworkFilter string, notes map[string]string) Result {
	controlCount := map[string]int{} // tag -> # events touching it
	overlay := make([]OverlayEntry, 0, len(events))
	analyzed := 0

	for _, ev := range events {
		if ev.IsHeartbeat() {
			continue
		}
		analyzed++
		verdict := ev.Verdict()
		hasVerdict := verdict == "allow" || verdict == "deny"
		action := ev.Action()

		tagSet := map[string]bool{}
		catSet := map[string]bool{}
		for _, r := range rules {
			fired := false
			switch r.sig {
			case sigAny:
				fired = hasVerdict
			case sigAllow:
				fired = verdict == "allow"
			case sigDeny:
				fired = verdict == "deny"
			case sigActionRE:
				fired = hasVerdict && action != "" && r.pattern.MatchString(action)
			case sigAnomalous:
				fired = ev.AnomalyVerdict() == "anomalous"
			case sigMFAGated:
				fired = ev.MFAGated()
			}
			if fired {
				catSet[r.category] = true
				for _, c := range r.controls {
					tagSet[c] = true
				}
			}
		}
		if len(tagSet) == 0 {
			continue
		}
		for tag := range tagSet {
			controlCount[tag]++
		}
		overlay = append(overlay, OverlayEntry{
			Action:         action,
			Verdict:        verdict,
			Protocol:       crossbouncer.ProtocolFor(ev.Bouncer()),
			Resources:      ev.Resources(),
			ComplianceTags: sortedSet(tagSet),
			Categories:     sortedSet(catSet),
		})
	}

	coverage := buildCoverage(controlCount, frameworkFilter)

	var partialReasons []string
	if analyzed == 0 {
		partialReasons = append(partialReasons, "no_events_observed: the audit log returned zero events for this session+window")
	}
	for _, note := range notes {
		if note != "" {
			partialReasons = append(partialReasons, "bouncer_gaps: one or more bouncers were unreachable or errored")
			break
		}
	}
	var noteList []string
	for _, b := range sortedKeys(notes) {
		if notes[b] != "" {
			noteList = append(noteList, b+": "+notes[b])
		}
	}

	return Result{
		SessionID:       sessionID,
		EventsAnalyzed:  analyzed,
		FrameworkFilter: frameworkFilter,
		Overlay:         overlay,
		Coverage:        coverage,
		IsPartial:       len(partialReasons) > 0,
		PartialReasons:  partialReasons,
		Disclaimer:      Disclaimer,
		Notes:           noteList,
	}
}

func buildCoverage(controlCount map[string]int, frameworkFilter string) []FrameworkCoverage {
	var out []FrameworkCoverage
	for _, fw := range Frameworks {
		if frameworkFilter != "" && fw.ID != frameworkFilter {
			continue
		}
		var touched []ControlTouched
		var notTouched []ControlNotTouched
		inCatalog := 0
		for _, tag := range sortedCatalogTags(fw.ID) {
			inCatalog++
			c := catalog[tag]
			if n := controlCount[tag]; n > 0 {
				touched = append(touched, ControlTouched{Control: tag, Title: c.title, Framework: fw.ID, EventCount: n})
			} else {
				notTouched = append(notTouched, ControlNotTouched{Control: tag, Title: c.title})
			}
		}
		out = append(out, FrameworkCoverage{
			Framework:            fw.ID,
			Name:                 fw.Name,
			Version:              fw.Version,
			ControlsTouched:      touched,
			ControlsTouchedCount: len(touched),
			ControlsInCatalog:    inCatalog,
			ControlsNotTouched:   notTouched,
			PartialCoverageNote: "only " + fw.Name + " controls exercised by observed audit activity are mapped; " +
				"controls outside the observable audit surface are out of scope for this overlay",
		})
	}
	return out
}

func sortedCatalogTags(framework string) []string {
	var tags []string
	for tag, c := range catalog {
		if c.framework == framework {
			tags = append(tags, tag)
		}
	}
	sort.Strings(tags)
	return tags
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsValidFramework reports whether id is a known framework filter value.
func IsValidFramework(id string) bool {
	for _, fw := range Frameworks {
		if fw.ID == id {
			return true
		}
	}
	return false
}
