// validator.go — Go port of iam-roles/src/iam_jit/tool_call_validator/
// validator.py. Lock-step rule + corpus semantics; any divergence is a
// bug.
//
// Per [[ibounce-honest-positioning]]:
//   - every detected indicator carries Rule + Shape + ToolName +
//     Severity + Source + Reason
//   - confidence weighting (see computeConfidence) matches Python and
//     per [[scorer-is-ground-truth]] MUST NOT be tuned post-hoc
//   - sub-0.5 confidence populates LowConfidenceExplanation
package toolcallvalidator

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Action is the request-handling decision after the validator runs.
type Action string

const (
	ActionAllow Action = "allow"
	ActionWarn  Action = "warn"
	ActionStrip Action = "strip"
	ActionDeny  Action = "deny"
)

// Severity classifies an individual indicator.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
)

// Indicator is one rule-match recorded in the verdict.
type Indicator struct {
	Rule     string   `json:"rule"`
	Shape    string   `json:"shape"`
	ToolName string   `json:"tool_name"`
	Severity Severity `json:"severity"`
	Source   string   `json:"source"`
	Reason   string   `json:"reason"`
}

// ExtractedCall is one (shape, name) tuple the validator looked at.
type ExtractedCall struct {
	Shape string `json:"shape"`
	Name  string `json:"name"`
}

// ValidationResult is the verdict from Validate.
type ValidationResult struct {
	Detected                 bool            `json:"detected"`
	Indicators               []Indicator     `json:"indicators"`
	Confidence               float64         `json:"confidence"`
	SuggestedAction          Action          `json:"suggested_action"`
	LowConfidenceExplanation string          `json:"low_confidence_explanation,omitempty"`
	BodyTruncated            bool            `json:"body_truncated"`
	SkippedReason            string          `json:"skipped_reason,omitempty"`
	ExtractedCalls           []ExtractedCall `json:"extracted_calls"`
}

// Config mirrors the Python ProfileConfig dataclass.
type Config struct {
	Enabled              bool
	Action               Action
	AllowlistPatterns    []string
	MaxBodyBytes         int
	MinConfidenceForDeny float64
	SchemaCorpus         *SchemaCorpus // optional; nil → DefaultCorpus()
}

// DefaultConfig returns the SAFE-OFF default config. Matches Python.
func DefaultConfig() Config {
	return Config{
		Enabled:              false,
		Action:               ActionWarn,
		MaxBodyBytes:         64 * 1024,
		MinConfidenceForDeny: 0.7,
	}
}

// --------------------------------------------------------------------
// Heuristic patterns — mirror iam_jit.tool_call_validator.rules.
// --------------------------------------------------------------------

var placeholderRe = regexp.MustCompile(
	`(?i)^(` +
		`your[\-_]?(api|secret|access|aws|openai|anthropic)[\-_]?(key|token|secret)?|` +
		`replace[\-_]?(me|this|with[\-_].+)|` +
		`<\s*(your|insert|fill|enter|replace|api|secret|token).+?>|` +
		`xxx+|` +
		`placeholder.*|` +
		`example[\-_](key|token|api[\-_]?key)|` +
		`sk[\-_]?xxxxxxx+|` +
		`example\.com[/\w]*|` +
		`foo|bar|baz|qux|quux|` +
		`todo|tbd|tba` +
		`)$`,
)

var nameMixRe = regexp.MustCompile(
	`^[a-z]+(_[a-z]+)+[A-Z]|` +
		`^[a-z]+[A-Z][a-z]+(_[a-zA-Z])`,
)

func isPlaceholderValue(v any) bool {
	s, ok := v.(string)
	if !ok {
		return false
	}
	if len(s) > 256 {
		return false
	}
	stripped := strings.TrimSpace(s)
	if stripped == "" {
		return false
	}
	return placeholderRe.MatchString(stripped)
}

func hasNamingStyleMix(name string) bool {
	if len(name) < 4 {
		return false
	}
	return nameMixRe.MatchString(name)
}

// --------------------------------------------------------------------
// Tool-call extraction — JSON shape -> []ExtractedCall + args map.
// --------------------------------------------------------------------

type extractedWithArgs struct {
	Shape string
	Name  string
	Args  map[string]any
}

func extractAllCalls(parsed any) []extractedWithArgs {
	out := make([]extractedWithArgs, 0, 2)
	root, ok := parsed.(map[string]any)
	if !ok {
		return out
	}
	out = append(out, extractMCPCalls(root)...)
	out = append(out, extractOpenAICalls(root)...)
	out = append(out, extractAnthropicCalls(root)...)
	return out
}

func extractMCPCalls(root map[string]any) []extractedWithArgs {
	out := []extractedWithArgs{}
	if jr, _ := root["jsonrpc"].(string); jr != "2.0" {
		return out
	}
	method, _ := root["method"].(string)
	if method == "" {
		return out
	}
	params, _ := root["params"].(map[string]any)
	if params == nil {
		params = map[string]any{}
	}
	if method == "tools/call" {
		name, _ := params["name"].(string)
		if name == "" {
			return out
		}
		args, _ := params["arguments"].(map[string]any)
		if args == nil {
			args = map[string]any{}
		}
		out = append(out, extractedWithArgs{Shape: "mcp", Name: name, Args: args})
		return out
	}
	// Direct method — treat the method itself as the tool name.
	out = append(out, extractedWithArgs{Shape: "mcp", Name: method, Args: params})
	return out
}

func extractOpenAICalls(root map[string]any) []extractedWithArgs {
	out := []extractedWithArgs{}
	if fc, ok := root["function_call"].(map[string]any); ok {
		if name, _ := fc["name"].(string); name != "" {
			out = append(out, extractedWithArgs{
				Shape: "openai", Name: name,
				Args: decodeOpenAIArgs(fc["arguments"]),
			})
		}
	}
	if tc, ok := root["tool_calls"].([]any); ok {
		for _, entry := range tc {
			out = append(out, openAIOneToolCall(entry)...)
		}
	}
	if msgs, ok := root["messages"].([]any); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			if mfc, ok := msg["function_call"].(map[string]any); ok {
				if name, _ := mfc["name"].(string); name != "" {
					out = append(out, extractedWithArgs{
						Shape: "openai", Name: name,
						Args: decodeOpenAIArgs(mfc["arguments"]),
					})
				}
			}
			if mtc, ok := msg["tool_calls"].([]any); ok {
				for _, entry := range mtc {
					out = append(out, openAIOneToolCall(entry)...)
				}
			}
		}
	}
	return out
}

func openAIOneToolCall(entry any) []extractedWithArgs {
	em, ok := entry.(map[string]any)
	if !ok {
		return nil
	}
	if fn, ok := em["function"].(map[string]any); ok {
		if name, _ := fn["name"].(string); name != "" {
			return []extractedWithArgs{{
				Shape: "openai", Name: name,
				Args: decodeOpenAIArgs(fn["arguments"]),
			}}
		}
	}
	if name, _ := em["name"].(string); name != "" {
		return []extractedWithArgs{{
			Shape: "openai", Name: name,
			Args: decodeOpenAIArgs(em["arguments"]),
		}}
	}
	return nil
}

func decodeOpenAIArgs(raw any) map[string]any {
	if m, ok := raw.(map[string]any); ok {
		return m
	}
	if s, ok := raw.(string); ok {
		if strings.TrimSpace(s) == "" {
			return map[string]any{}
		}
		var parsed any
		if err := json.Unmarshal([]byte(s), &parsed); err != nil {
			return map[string]any{}
		}
		if m, ok := parsed.(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

func extractAnthropicCalls(root map[string]any) []extractedWithArgs {
	out := []extractedWithArgs{}
	if msgs, ok := root["messages"].([]any); ok {
		for _, m := range msgs {
			msg, ok := m.(map[string]any)
			if !ok {
				continue
			}
			content, ok := msg["content"].([]any)
			if !ok {
				continue
			}
			for _, c := range content {
				block, ok := c.(map[string]any)
				if !ok {
					continue
				}
				if t, _ := block["type"].(string); t != "tool_use" {
					continue
				}
				name, _ := block["name"].(string)
				if name == "" {
					continue
				}
				input, _ := block["input"].(map[string]any)
				if input == nil {
					input = map[string]any{}
				}
				out = append(out, extractedWithArgs{
					Shape: "anthropic", Name: name, Args: input,
				})
			}
		}
	}
	if t, _ := root["type"].(string); t == "tool_use" {
		if name, _ := root["name"].(string); name != "" {
			input, _ := root["input"].(map[string]any)
			if input == nil {
				input = map[string]any{}
			}
			out = append(out, extractedWithArgs{
				Shape: "anthropic", Name: name, Args: input,
			})
		}
	}
	return out
}

// --------------------------------------------------------------------
// Validator core
// --------------------------------------------------------------------

// Validate runs the validator against `body` + returns a verdict.
func Validate(body []byte, cfg Config) ValidationResult {
	if len(body) == 0 {
		return ValidationResult{SuggestedAction: ActionAllow}
	}
	text := string(body)
	if len(strings.TrimSpace(text)) < 4 {
		return ValidationResult{SuggestedAction: ActionAllow}
	}

	// Allowlist short-circuit.
	for _, raw := range cfg.AllowlistPatterns {
		if raw == "" {
			continue
		}
		re, err := regexp.Compile(raw)
		if err != nil {
			continue
		}
		if re.FindStringIndex(text) != nil {
			snippet := raw
			if len(snippet) > 80 {
				snippet = snippet[:80]
			}
			return ValidationResult{
				SuggestedAction: ActionAllow,
				SkippedReason:   "allowlist:" + snippet,
			}
		}
	}

	max := cfg.MaxBodyBytes
	if max <= 0 {
		max = 64 * 1024
	}
	truncated := false
	if len(text) > max {
		text = text[:max]
		truncated = true
	}

	var parsed any
	if err := json.Unmarshal([]byte(text), &parsed); err != nil {
		return ValidationResult{
			SuggestedAction: ActionAllow,
			BodyTruncated:   truncated,
			SkippedReason:   "not-json",
		}
	}

	calls := extractAllCalls(parsed)
	if len(calls) == 0 {
		return ValidationResult{
			SuggestedAction: ActionAllow,
			BodyTruncated:   truncated,
			SkippedReason:   "no-tool-call-shape",
		}
	}

	corpus := cfg.SchemaCorpus
	if corpus == nil {
		c := DefaultCorpus()
		corpus = &c
	}

	indicators := []Indicator{}
	extracted := make([]ExtractedCall, 0, len(calls))

	for _, call := range calls {
		extracted = append(extracted, ExtractedCall{Shape: call.Shape, Name: call.Name})
		tool := corpus.Lookup(call.Shape, call.Name)
		if tool == nil {
			knownCount := len(corpus.NamesForShape(call.Shape))
			indicators = append(indicators, Indicator{
				Rule:     "hallucinated-tool-name",
				Shape:    call.Shape,
				ToolName: call.Name,
				Severity: SeverityHigh,
				Source:   "iam-jit",
				Reason: fmt.Sprintf(
					"tool '%s' not in known %s corpus (%d known tools)",
					call.Name, call.Shape, knownCount,
				),
			})
			if hasNamingStyleMix(call.Name) {
				indicators = append(indicators, Indicator{
					Rule:     "naming-style-mix",
					Shape:    call.Shape,
					ToolName: call.Name,
					Severity: SeverityMedium,
					Source:   "iam-jit",
					Reason: fmt.Sprintf(
						"tool name '%s' mixes snake_case + camelCase — common hallucination tell",
						call.Name,
					),
				})
			}
			indicators = append(indicators, checkPlaceholders(call.Shape, call.Name, call.Args)...)
			continue
		}

		// Required-field check.
		for _, req := range tool.Required {
			if _, ok := call.Args[req]; !ok {
				indicators = append(indicators, Indicator{
					Rule:     "missing-required-arg",
					Shape:    call.Shape,
					ToolName: call.Name,
					Severity: SeverityHigh,
					Source:   firstNonEmpty(tool.Source, "iam-jit"),
					Reason: fmt.Sprintf(
						"required field '%s' absent from '%s' arguments",
						req, call.Name,
					),
				})
			}
		}
		// Extra-field check (only when schema has at least one allowed).
		if len(tool.Required)+len(tool.Optional) > 0 {
			allowed := make(map[string]bool, len(tool.Required)+len(tool.Optional))
			for _, k := range tool.Required {
				allowed[k] = true
			}
			for _, k := range tool.Optional {
				allowed[k] = true
			}
			for k := range call.Args {
				if !allowed[k] {
					indicators = append(indicators, Indicator{
						Rule:     "unexpected-arg",
						Shape:    call.Shape,
						ToolName: call.Name,
						Severity: SeverityMedium,
						Source:   firstNonEmpty(tool.Source, "iam-jit"),
						Reason: fmt.Sprintf(
							"field '%s' is not in schema for '%s' (allowed: %s)",
							k, call.Name, joinAllowed(tool),
						),
					})
				}
			}
		}
		indicators = append(indicators, checkPlaceholders(call.Shape, call.Name, call.Args)...)
	}

	if len(indicators) == 0 {
		return ValidationResult{
			SuggestedAction: ActionAllow,
			BodyTruncated:   truncated,
			ExtractedCalls:  extracted,
		}
	}

	// Dedupe by (rule, shape, tool_name).
	seen := make(map[string]bool, len(indicators))
	unique := make([]Indicator, 0, len(indicators))
	for _, ind := range indicators {
		k := ind.Rule + "|" + ind.Shape + "|" + ind.ToolName
		if seen[k] {
			continue
		}
		seen[k] = true
		unique = append(unique, ind)
	}

	highCount := 0
	medCount := 0
	for _, ind := range unique {
		if isHighSeverityRule(ind.Rule) {
			highCount++
		} else if isMediumSeverityRule(ind.Rule) {
			medCount++
		}
	}
	confidence, suggested := computeConfidence(highCount, medCount)

	var explanation string
	if confidence < 0.5 {
		names := make([]string, 0, len(unique))
		for _, ind := range unique {
			names = append(names, ind.Rule)
		}
		explanation = fmt.Sprintf(
			"matched %d medium-signal indicator(s) only: %s",
			len(unique), strings.Join(names, ", "),
		)
	}

	return ValidationResult{
		Detected:                 true,
		Indicators:               unique,
		Confidence:               confidence,
		SuggestedAction:          suggested,
		LowConfidenceExplanation: explanation,
		BodyTruncated:            truncated,
		ExtractedCalls:           extracted,
	}
}

func checkPlaceholders(shape, name string, args map[string]any) []Indicator {
	out := make([]Indicator, 0, 2)
	if args == nil {
		return out
	}
	// Sort keys for deterministic indicator order — Go map iteration
	// order is randomized, which would make tests flaky otherwise.
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := args[k]
		if isPlaceholderValue(v) {
			out = append(out, Indicator{
				Rule:     "placeholder-credential",
				Shape:    shape,
				ToolName: name,
				Severity: SeverityHigh,
				Source:   "iam-jit",
				Reason: fmt.Sprintf(
					"argument '%s' value looks like an LLM placeholder ('%s')",
					k, truncForReason(v),
				),
			})
		}
	}
	return out
}

func truncForReason(v any) string {
	s, _ := v.(string)
	if len(s) > 40 {
		return s[:40]
	}
	return s
}

func joinAllowed(t *ToolSchema) string {
	all := make([]string, 0, len(t.Required)+len(t.Optional))
	all = append(all, t.Required...)
	all = append(all, t.Optional...)
	sort.Strings(all)
	return strings.Join(all, ", ")
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func isHighSeverityRule(rule string) bool {
	switch rule {
	case "hallucinated-tool-name", "placeholder-credential", "missing-required-arg":
		return true
	}
	return false
}

func isMediumSeverityRule(rule string) bool {
	switch rule {
	case "unexpected-arg", "naming-style-mix":
		return true
	}
	return false
}

// computeConfidence mirrors the Python _compute_confidence weighting.
// Per [[scorer-is-ground-truth]] this MUST NOT be tuned post-hoc.
func computeConfidence(highCount, medCount int) (float64, Action) {
	switch {
	case highCount >= 2:
		return 0.95, ActionDeny
	case highCount == 1 && medCount >= 1:
		return 0.85, ActionWarn
	case highCount == 1:
		return 0.80, ActionWarn
	case medCount >= 2:
		return 0.55, ActionWarn
	case medCount == 1:
		return 0.35, ActionAllow
	default:
		return 0.0, ActionAllow
	}
}

// DecideAction reconciles validator verdict with operator config.
// Mirrors Python decide_action exactly.
func DecideAction(result ValidationResult, cfg Config) Action {
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
			if isHighSeverityRule(ind.Rule) {
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

// ApplyStrip replaces hallucinated tool-call entries with redaction
// markers. JSON-aware — mirrors Python apply_strip semantics.
// Returns the modified body as bytes; caller resets Content-Length.
func ApplyStrip(body []byte, result ValidationResult) []byte {
	if !result.Detected || len(result.Indicators) == 0 {
		return body
	}
	flagged := make(map[string]bool, len(result.Indicators))
	for _, ind := range result.Indicators {
		flagged[ind.Shape+"|"+ind.ToolName] = true
	}

	var parsed any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return body
	}
	cleaned := visitStrip(parsed, flagged)
	out, err := json.Marshal(cleaned)
	if err != nil {
		return body
	}
	return out
}

func marker(shape, name string) map[string]any {
	return map[string]any{
		"_iam_jit_tool_call_redacted": true,
		"shape":                       shape,
		"original_name":               name,
		"reason":                      "hallucinated-tool-call",
	}
}

func visitStrip(node any, flagged map[string]bool) any {
	switch n := node.(type) {
	case map[string]any:
		// MCP tools/call: params.name
		if jr, _ := n["jsonrpc"].(string); jr == "2.0" {
			if method, _ := n["method"].(string); method == "tools/call" {
				if params, ok := n["params"].(map[string]any); ok {
					if name, _ := params["name"].(string); name != "" {
						if flagged["mcp|"+name] {
							return marker("mcp", name)
						}
					}
				}
			} else if method != "" {
				if flagged["mcp|"+method] && method != "tools/call" {
					return marker("mcp", method)
				}
			}
		}
		// Anthropic tool_use
		if t, _ := n["type"].(string); t == "tool_use" {
			if name, _ := n["name"].(string); name != "" {
				if flagged["anthropic|"+name] {
					return marker("anthropic", name)
				}
			}
		}
		// OpenAI function-shape
		if fn, ok := n["function"].(map[string]any); ok {
			if name, _ := fn["name"].(string); name != "" {
				if flagged["openai|"+name] {
					return marker("openai", name)
				}
			}
		}
		if fc, ok := n["function_call"].(map[string]any); ok {
			if name, _ := fc["name"].(string); name != "" {
				if flagged["openai|"+name] {
					newNode := make(map[string]any, len(n))
					for k, v := range n {
						newNode[k] = v
					}
					newNode["function_call"] = marker("openai", name)
					return newNode
				}
			}
		}
		out := make(map[string]any, len(n))
		for k, v := range n {
			out[k] = visitStrip(v, flagged)
		}
		return out
	case []any:
		out := make([]any, len(n))
		for i, item := range n {
			out[i] = visitStrip(item, flagged)
		}
		return out
	}
	return node
}
