// Package injectionscan — indirect-prompt-injection response-body scanner
// (iam-jit task #730 / BUILD-9).
//
// Wired into gbounce's MITM response path; only runs when MITM mode is
// active AND the profile's `injection_scan_response_bodies.enabled` is
// true. Default OFF — per [[mitm-beta-pii-pci-concern]] MITM is BETA and
// per [[ibounce-honest-positioning]] we never auto-enable detection that
// has any false-positive surface.
//
// Rule set is kept in lock-step with the Python implementation at
// iam-roles/src/iam_jit/injection_scanner/rules.py. A CI diff test is
// filed as follow-up; for v1.0 the two implementations are synced
// manually + audited line-for-line on review.
//
// The package is a PURE-FUNCTION library: ScanResponseBody is the only
// entry point + has no side effects (no network, no file IO, no
// goroutines). Callers wire the verdict into their audit + response-
// mutation paths.
package injectionscan

import (
	"regexp"
	"strings"
)

// Action is the response-handling decision after the scanner runs.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionStrip Action = "strip"
	ActionDeny  Action = "deny"
)

// Severity classifies an individual rule match.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
)

// Layer records WHICH detection tier matched.
type Layer string

const (
	LayerCurated   Layer = "curated"
	LayerHeuristic Layer = "heuristic"
)

// Rule is one named regex + provenance.
type Rule struct {
	Name     string
	Pattern  *regexp.Regexp
	Severity Severity
	Source   string // "iam-jit" | "owasp-llm01" | "owasp-agentic-01" | "indirect-pi-research"
	Note     string
}

// Indicator is one rule-match recorded in the verdict.
type Indicator struct {
	Rule     string   `json:"rule"`
	Snippet  string   `json:"snippet"`
	Layer    Layer    `json:"layer"`
	Severity Severity `json:"severity"`
	Source   string   `json:"source"`
}

// ScanResult is the verdict from ScanResponseBody.
type ScanResult struct {
	Detected                  bool        `json:"detected"`
	Indicators                []Indicator `json:"indicators"`
	Confidence                float64     `json:"confidence"`
	SuggestedAction           Action      `json:"suggested_action"`
	LowConfidenceExplanation  string      `json:"low_confidence_explanation,omitempty"`
	BodyTruncated             bool        `json:"body_truncated"`
	SkippedReason             string      `json:"skipped_reason,omitempty"`
}

// Config mirrors the Python ProfileConfig dataclass field-for-field so
// operators don't need a translation table.
type Config struct {
	Enabled               bool
	Action                Action
	AllowlistPatterns     []string
	MaxBodyBytes          int
	MinConfidenceForDeny  float64
}

// DefaultConfig returns the SAFE-OFF default. Matches Python defaults.
func DefaultConfig() Config {
	return Config{
		Enabled:              false,
		Action:               ActionWarn,
		AllowlistPatterns:    nil,
		MaxBodyBytes:         64 * 1024,
		MinConfidenceForDeny: 0.7,
	}
}

// --------------------------------------------------------------------
// Curated rules — HIGH severity. Names + sources MUST stay in lock-step
// with iam-roles/src/iam_jit/injection_scanner/rules.py HIGH_SIGNAL_RULES.
// --------------------------------------------------------------------

var highSignalRules = []Rule{
	{
		Name: "html-comment-instruction-override",
		Pattern: regexp.MustCompile(
			`(?is)<!--\s*[^>]*?\b(ignore|disregard|forget|override|bypass)\b` +
				`[^>]*?\b(previous|prior|all|your)\b[^>]*?-->`,
		),
		Severity: SeverityHigh,
		Source:   "indirect-pi-research",
		Note:     "HTML comment containing instruction-override phrase",
	},
	{
		Name: "markdown-comment-instruction-override",
		Pattern: regexp.MustCompile(
			`(?im)^\s*\[//\]:\s*#\s*\([^)]*?\b(ignore|disregard|override|bypass)\b`,
		),
		Severity: SeverityHigh,
		Source:   "indirect-pi-research",
		Note:     "Markdown invisible comment containing instruction-override",
	},
	{
		Name: "hidden-element-instruction",
		Pattern: regexp.MustCompile(
			`(?is)style\s*=\s*["'][^"']*?` +
				`(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)` +
				`[^"']*?["'][^>]*>` +
				`[^<]*?\b(ignore|disregard|override|system|assistant|tool_use)\b`,
		),
		Severity: SeverityHigh,
		Source:   "indirect-pi-research",
		Note:     "CSS-hidden element with instruction or role keyword",
	},
	{
		Name: "tool-result-envelope-forgery",
		Pattern: regexp.MustCompile(
			`(?im)^\s*<\s*(tool_result|tool_response|observation|function_result)\b`,
		),
		Severity: SeverityHigh,
		Source:   "owasp-agentic-01",
		Note:     "Forged tool-result envelope at start of line",
	},
	{
		Name: "role-confusion-headerlike",
		Pattern: regexp.MustCompile(
			`(?m)^\s*(SYSTEM|ASSISTANT|DEVELOPER|TOOL)\s*[:>]\s*\S`,
		),
		Severity: SeverityHigh,
		Source:   "owasp-llm01",
		Note:     "Uppercase role marker at start of line",
	},
	{
		Name: "json-system-prompt-smuggle",
		Pattern: regexp.MustCompile(
			`(?is)[\{\[,]\s*"(system|system_prompt|instructions|developer)"\s*:\s*"`,
		),
		Severity: SeverityHigh,
		Source:   "owasp-agentic-01",
		Note:     "JSON key 'system' / 'system_prompt' / 'instructions'",
	},
	{
		Name: "exfil-imperative",
		Pattern: regexp.MustCompile(
			`(?i)\b(send|post|upload|fetch|forward|leak|exfiltrate|transmit)\b\W+` +
				`(\w+\W+){0,8}?` +
				`\b(api[\s\-_]?key|secret|token|credential|password|` +
				`private[\s\-_]?key|\.ssh|/etc/passwd|/etc/shadow|` +
				`environment[\s\-_]?variable|env[\s\-_]?var)s?\b`,
		),
		Severity: SeverityHigh,
		Source:   "owasp-agentic-01",
		Note:     "Imperative + sensitive-resource keyword",
	},
	{
		Name: "new-instruction-replacement",
		Pattern: regexp.MustCompile(
			`(?i)(your\s+new\s+(instruction|directive|task|rule|role)s?|` +
				`from\s+now\s+on\s+you\s+(will|must|should)|` +
				`new\s+system\s+prompt)\b`,
		),
		Severity: SeverityHigh,
		Source:   "owasp-llm01",
		Note:     "Explicit instruction-replacement phrasing",
	},
	{
		Name: "canonical-injection-phrase",
		Pattern: regexp.MustCompile(
			`(?i)\bignore\s+(all\s+)?(previous|prior|the\s+above|your)\s+` +
				`(instructions|prompts|rules|directives|guidelines)\b`,
		),
		Severity: SeverityHigh,
		Source:   "owasp-llm01",
		Note:     "Canonical prompt-injection opener phrase",
	},
}

// --------------------------------------------------------------------
// Curated rules — MEDIUM severity.
// --------------------------------------------------------------------

var mediumSignalRules = []Rule{
	{
		Name:     "delimiter-smuggle",
		Pattern:  regexp.MustCompile(`<\|im_(start|end)\|>|<\|system\|>|<\|user\|>|<\|assistant\|>`),
		Severity: SeverityMedium,
		Source:   "owasp-llm01",
		Note:     "ChatML-style role delimiter",
	},
	{
		Name:     "end-of-prompt-marker",
		Pattern:  regexp.MustCompile(`(?i)---\s*end\s+of\s+(prompt|instructions|system)\s*---`),
		Severity: SeverityMedium,
		Source:   "owasp-llm01",
		Note:     "`---END OF PROMPT---`-style marker",
	},
	{
		Name: "instruction-shape-imperative",
		Pattern: regexp.MustCompile(
			`(?im)^\s*(you\s+must|you\s+should|you\s+will|` +
				`do\s+not\s+(tell|reveal|disclose|mention))\b`,
		),
		Severity: SeverityMedium,
		Source:   "indirect-pi-research",
		Note:     "Imperative addressed to 'you' (the LLM)",
	},
	{
		Name:     "zero-width-cluster",
		Pattern:  regexp.MustCompile(`[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}]{4,}`),
		Severity: SeverityMedium,
		Source:   "indirect-pi-research",
		Note:     "Zero-width character run",
	},
}

// --------------------------------------------------------------------
// Heuristic rules — structural.
// --------------------------------------------------------------------

var heuristicRules = []Rule{
	{
		Name:     "obfuscation-base64-blob",
		Pattern:  regexp.MustCompile(`[A-Za-z0-9+/]{80,}={0,2}`),
		Severity: SeverityMedium,
		Source:   "iam-jit",
		Note:     "Long base64 blob in response body",
	},
}

// --------------------------------------------------------------------
// Scanner core
// --------------------------------------------------------------------

// ScanResponseBody runs the rule set against `body` + returns a verdict.
// `contentType` may be empty; if it's image/* / audio/* / video/* /
// font/* the scan is skipped + the SkippedReason is set.
func ScanResponseBody(body []byte, contentType string, cfg Config) ScanResult {
	if len(body) == 0 {
		return ScanResult{Detected: false, SuggestedAction: ActionAllow}
	}

	if contentType != "" {
		ct := strings.ToLower(strings.TrimSpace(strings.SplitN(contentType, ";", 2)[0]))
		if strings.HasPrefix(ct, "image/") ||
			strings.HasPrefix(ct, "audio/") ||
			strings.HasPrefix(ct, "video/") ||
			strings.HasPrefix(ct, "font/") {
			return ScanResult{
				Detected:        false,
				SuggestedAction: ActionAllow,
				SkippedReason:   "binary-content-type:" + ct,
			}
		}
	}

	text := string(body)
	if len(strings.TrimSpace(text)) < 4 {
		return ScanResult{Detected: false, SuggestedAction: ActionAllow}
	}

	// Allowlist check before any scanning.
	for _, raw := range cfg.AllowlistPatterns {
		if raw == "" {
			continue
		}
		pat, err := regexp.Compile(raw)
		if err != nil {
			// Malformed allowlist regex — skip (operator misconfig is
			// logged at config-load time, not here).
			continue
		}
		if pat.FindStringIndex(text) != nil {
			reason := "allowlist:" + raw
			if len(reason) > 80 {
				reason = reason[:80]
			}
			return ScanResult{
				Detected:        false,
				SuggestedAction: ActionAllow,
				SkippedReason:   reason,
			}
		}
	}

	// Truncate (ReDoS guard).
	max := cfg.MaxBodyBytes
	if max <= 0 {
		max = 64 * 1024
	}
	truncated := false
	if len(text) > max {
		text = text[:max]
		truncated = true
	}

	indicators := scanWithRules(text, highSignalRules, LayerCurated)
	indicators = append(indicators, scanWithRules(text, mediumSignalRules, LayerCurated)...)
	indicators = append(indicators, scanWithRules(text, heuristicRules, LayerHeuristic)...)

	if len(indicators) == 0 {
		return ScanResult{
			Detected:        false,
			SuggestedAction: ActionAllow,
			BodyTruncated:   truncated,
		}
	}

	// Dedupe by rule name.
	seen := make(map[string]bool, len(indicators))
	unique := make([]Indicator, 0, len(indicators))
	for _, ind := range indicators {
		if seen[ind.Rule] {
			continue
		}
		seen[ind.Rule] = true
		unique = append(unique, ind)
	}

	highCount := 0
	mediumCount := 0
	for _, ind := range unique {
		switch ind.Severity {
		case SeverityHigh:
			highCount++
		case SeverityMedium:
			mediumCount++
		}
	}

	confidence, suggested := computeConfidence(highCount, mediumCount)

	var explanation string
	if confidence < 0.5 {
		names := make([]string, 0, len(unique))
		for _, ind := range unique {
			names = append(names, ind.Rule)
		}
		explanation = "matched " + itoa(len(unique)) + " medium-signal rule(s) only: " + strings.Join(names, ", ")
	}

	return ScanResult{
		Detected:                 true,
		Indicators:               unique,
		Confidence:               confidence,
		SuggestedAction:          suggested,
		LowConfidenceExplanation: explanation,
		BodyTruncated:            truncated,
	}
}

func scanWithRules(text string, rules []Rule, layer Layer) []Indicator {
	out := make([]Indicator, 0, len(rules))
	for _, rule := range rules {
		loc := rule.Pattern.FindStringIndex(text)
		if loc == nil {
			continue
		}
		snippet := text[loc[0]:loc[1]]
		if len(snippet) > 80 {
			snippet = snippet[:80]
		}
		out = append(out, Indicator{
			Rule:     rule.Name,
			Snippet:  snippet,
			Layer:    layer,
			Severity: rule.Severity,
			Source:   rule.Source,
		})
	}
	return out
}

// computeConfidence mirrors the Python _compute_confidence weighting.
// Per [[scorer-is-ground-truth]] this MUST NOT be tuned post-hoc to
// make individual demos pass.
func computeConfidence(highCount, mediumCount int) (float64, Action) {
	switch {
	case highCount >= 2:
		return 0.95, ActionDeny
	case highCount == 1 && mediumCount >= 1:
		return 0.85, ActionWarn
	case highCount == 1:
		return 0.8, ActionWarn
	case mediumCount >= 2:
		return 0.55, ActionWarn
	case mediumCount == 1:
		return 0.35, ActionAllow
	default:
		return 0.0, ActionAllow
	}
}

// DecideAction reconciles the scanner verdict with operator config.
// Mirrors Python decide_action exactly:
//   - undetected → always allow
//   - deny + confidence < min_floor → downgrade to warn
//   - strip + no high-severity indicators → downgrade to warn
//   - otherwise: operator's action wins
func DecideAction(result ScanResult, cfg Config) Action {
	if !result.Detected {
		return ActionAllow
	}
	switch cfg.Action {
	case ActionDeny:
		if result.Confidence < cfg.MinConfidenceForDeny {
			return ActionWarn
		}
		return ActionDeny
	case ActionStrip:
		hasHigh := false
		for _, ind := range result.Indicators {
			if ind.Severity == SeverityHigh {
				hasHigh = true
				break
			}
		}
		if !hasHigh {
			return ActionWarn
		}
		return ActionStrip
	case ActionAllow:
		return ActionAllow
	default:
		return ActionWarn
	}
}

// ApplyStrip replaces lines containing indicator snippets with a
// redaction marker. Preserves the original line endings (CRLF/LF/CR).
func ApplyStrip(body []byte, result ScanResult) []byte {
	if !result.Detected || len(result.Indicators) == 0 {
		return body
	}
	text := string(body)
	var out strings.Builder
	out.Grow(len(text))

	i := 0
	for i < len(text) {
		// Find end of next line (including the line terminator).
		j := i
		for j < len(text) && text[j] != '\n' && text[j] != '\r' {
			j++
		}
		// Capture line terminator.
		termEnd := j
		if termEnd < len(text) {
			if text[termEnd] == '\r' && termEnd+1 < len(text) && text[termEnd+1] == '\n' {
				termEnd += 2
			} else {
				termEnd++
			}
		}
		line := text[i:termEnd]
		matchedRule := ""
		lineContent := text[i:j]
		for _, ind := range result.Indicators {
			if ind.Snippet != "" && strings.Contains(lineContent, ind.Snippet) {
				matchedRule = ind.Rule
				break
			}
		}
		if matchedRule != "" {
			ending := ""
			if j < termEnd {
				ending = text[j:termEnd]
			}
			out.WriteString("[iam-jit:injection-redacted: " + matchedRule + "]" + ending)
		} else {
			out.WriteString(line)
		}
		i = termEnd
	}
	return []byte(out.String())
}

// itoa — small int → string without importing strconv just for this.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	negative := false
	if n < 0 {
		negative = true
		n = -n
	}
	digits := make([]byte, 0, 10)
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
