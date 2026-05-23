// denies.go — #388 / §A25 Phase 2 (gbounce). Read recent DENY
// decisions from the gbounce SQLite store + synthesise the
// suggested_allow_command per row.

package profileallow

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/trsreagan3/gbounce/internal/store"
)

type DenyRow struct {
	When                  string `json:"when"`
	Bouncer               string `json:"bouncer"`
	AgentSessionID        string `json:"agent_session_id"`
	Action                string `json:"action"`
	Resource              string `json:"resource"`
	DenyReason            string `json:"deny_reason"`
	DenySource            string `json:"deny_source"`
	RuleIDIfDynamic       string `json:"rule_id_if_dynamic,omitempty"`
	SuggestedAllowCommand string `json:"suggested_allow_command"`
}

const (
	DenySourceStaticProfile         = "static_profile"
	DenySourceDynamicDeny           = "dynamic_deny"
	DenySourceSafeDefault           = "safe_default"
	DenySourceProfileOnlyAccountIDs = "profile_only_account_ids"
	DenySourceProfileOnlyRegions    = "profile_only_regions"
	DenySourceProfileAllowBaseline  = "profile_allow_baseline"
	DenySourceTaskDeny              = "task_deny"
	DenySourceGlobalDeny            = "global_deny"
	DenySourceUnknown               = "unknown"
)

var dynamicRuleIDRe = regexp.MustCompile(`dd_[0-9A-HJKMNP-TV-Z]{26}`)

func ClassifyDenySource(reason string) (string, string) {
	if reason == "" {
		return DenySourceUnknown, ""
	}
	if m := dynamicRuleIDRe.FindString(reason); m != "" {
		return DenySourceDynamicDeny, m
	}
	r := strings.ToLower(reason)
	if strings.Contains(r, "dynamic deny") || strings.Contains(r, "dynamic-deny") {
		return DenySourceDynamicDeny, ""
	}
	if strings.Contains(r, "profile_only_account_ids") {
		return DenySourceProfileOnlyAccountIDs, ""
	}
	if strings.Contains(r, "profile_only_regions") {
		return DenySourceProfileOnlyRegions, ""
	}
	if strings.Contains(r, "'safe-default'") || strings.Contains(r, "safe-default") {
		return DenySourceSafeDefault, ""
	}
	if strings.Contains(r, "allow_baseline") {
		return DenySourceProfileAllowBaseline, ""
	}
	if strings.HasPrefix(r, "profile ") || strings.Contains(r, "profile '") {
		return DenySourceStaticProfile, ""
	}
	if strings.Contains(r, "task deny") || strings.Contains(r, "task-deny") {
		return DenySourceTaskDeny, ""
	}
	if strings.HasPrefix(r, "rule ") || strings.Contains(r, "global deny") ||
		strings.Contains(r, "deny_hosts") {
		return DenySourceGlobalDeny, ""
	}
	return DenySourceUnknown, ""
}

func SynthSuggestedAllowCommand(resource, action, denySource string) string {
	switch denySource {
	case DenySourceDynamicDeny:
		return "# this deny is from a dynamic-deny rule; lift via " +
			"`iam-jit deny remove <id>`"
	case DenySourceProfileOnlyAccountIDs, DenySourceProfileOnlyRegions:
		return "# this deny is from a profile account/region floor; edit " +
			"the profile's only_account_ids / only_regions field directly"
	}
	if resource == "" || resource == "*" || action == "" || !strings.Contains(action, ":") {
		return "# the deny lacks a specific resource/action; review the " +
			"profile manually before allowing"
	}
	return fmt.Sprintf("gbounce profile allow --target '%s' --action '%s' "+
		"--reason \"<why this is safe>\"", resource, action)
}

type RecentDeniesOptions struct {
	Store          *store.Store
	Since          time.Time
	AgentSessionID string
	Limit          int
}

func RecentDenies(opts RecentDeniesOptions) ([]DenyRow, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("gbounce: RecentDenies: Store is required")
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		limit = 1000
	}
	all, err := opts.Store.RecentDecisions(limit * 4)
	if err != nil {
		return nil, fmt.Errorf("gbounce: load recent decisions: %w", err)
	}
	out := make([]DenyRow, 0, limit)
	for _, d := range all {
		if !strings.EqualFold(d.Verdict, "DENY") {
			continue
		}
		if !opts.Since.IsZero() && d.At.Before(opts.Since) {
			continue
		}
		if opts.AgentSessionID != "" && d.AgentSessionID != opts.AgentSessionID {
			continue
		}
		action, resource := actionAndResource(d)
		source, ruleID := ClassifyDenySource("") // gbounce DecisionRow lacks deny_reason; classify minimal
		out = append(out, DenyRow{
			When:                  d.At.UTC().Format("2006-01-02T15:04:05Z"),
			Bouncer:               "gbounce",
			AgentSessionID:        d.AgentSessionID,
			Action:                action,
			Resource:              resource,
			DenyReason:            "", // gbounce store doesn't persist reason text
			DenySource:            source,
			RuleIDIfDynamic:       ruleID,
			SuggestedAllowCommand: SynthSuggestedAllowCommand(resource, action, source),
		})
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

// actionAndResource builds the cross-product (action, resource)
// pair from a gbounce DecisionRow.
//
//	action   = METHOD:/path-prefix  (e.g. GET:/v1/foo)
//	resource = hostname (with port when non-default)
func actionAndResource(d store.DecisionRow) (string, string) {
	method := d.Method
	if method == "" {
		method = "*"
	}
	path := d.Path
	if path == "" {
		path = "/"
	}
	action := fmt.Sprintf("%s:%s", method, path)
	resource := d.UpstreamHost
	if resource == "" {
		resource = "*"
	}
	if d.UpstreamPort != 0 && d.UpstreamPort != 80 && d.UpstreamPort != 443 {
		resource = fmt.Sprintf("%s:%d", resource, d.UpstreamPort)
	}
	return action, resource
}
