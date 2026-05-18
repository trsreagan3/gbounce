// admin_action.go ships the minimal admin-action OCSF event helper
// gbounce needs to emit a "config.export" / "config.import" row into
// the same JSONL audit-log channel the proxy writes decisions to.
//
// Cross-product parity per [[cross-product-agent-parity]]: kbounce +
// dbounce + ibounce already ship a much-larger admin-action surface
// (profile.install / pause.start / rule.add / preset.apply / ...).
// gbounce's current state model is genuinely smaller (no profiles /
// rules / pauses yet in G-Slice 1) so the wire-point lands here as a
// minimal mirror — same OCSF class 6003 shape, same SHA-256 before /
// after hashing, same source label. When later G-Slices add gbounce-
// specific config surfaces (G-2 profile mode; G-4 auto-recommender),
// each PR extends AdminAction with one constant + the export/import
// path gets the section.
//
// Wire shape: every admin-action event is OCSF v1.1.0 class 6003 (API
// Activity), severity Informational, status Success. The OCSF
// activity_id maps to Create (1) / Other (99) per the action kind.
// iam-jit-specific fields land under unmapped.iam_jit.config_change
// so a cross-product SIEM analyst pivots on the same key across all
// four Bounce products.
//
// Hash discipline: SHA-256 over canonical JSON serialization of the
// before / after state (same scheme kbounce uses; see kbouncer's
// admin_action.go for the rationale on JSON-of-struct vs YAML). nil
// inputs hash to ("", false) — distinct from "before-state was empty"
// (which marshals to "null" and hashes deterministically). Lets a
// tamper-detection rule downstream tell "before-state not captured"
// apart from "before-state was empty".
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"
)

// AdminAction names every recognized admin-action activity. Wire value
// lands in OCSF activity_name + unmapped.iam_jit.config_change.type so
// a SIEM analyst can pivot on either. Per [[security-team-positioning-
// safety-not-surveillance]] names are NEUTRAL ("config.import" — what
// happened; not "config.tampered" — an accusation).
type AdminAction string

const (
	// AdminActionConfigExport — `gbounce config export` succeeded.
	// Activity is Other (99) per the [[ocsf-audit-schema]] "honest
	// about uncategorized" stance — export doesn't fit CRUD.
	AdminActionConfigExport AdminAction = "config.export"

	// AdminActionConfigImport — `gbounce config import` succeeded.
	// Activity is Create (1) — the destination's effective config
	// state is brought into existence from the bundle.
	AdminActionConfigImport AdminAction = "config.import"

	// AdminActionDiagnosticsBundle — operator produced a diagnostics
	// bundle via `gbounce diagnostics bundle` (#277). The bundle is a
	// support-package ZIP with redacted config + audit-log tail +
	// /healthz snapshot; recording the action gives a security team a
	// witness for "who pulled diagnostics + when?" so the bundle's
	// later appearance in a support ticket / agent thread is
	// traceable. The bundle output path lands in EntityName. Mirrors
	// the kbounce + dbounce constant of the same name so a single
	// SIEM correlation rule keyed on activity_name="diagnostics.bundle"
	// catches the event regardless of which Bounce product fired it.
	AdminActionDiagnosticsBundle AdminAction = "diagnostics.bundle"

	// AdminActionBackupCreate — operator ran `gbounce backup` (#279).
	// Backup is read-only against the live store; recording it gives a
	// security team a "who copied state off the machine + when?"
	// witness. The on-disk path of the backup file lands in
	// EntityName. Activity is Other (99) — backup doesn't fit CRUD.
	// Cross-product parity: kbounce ships `store.backup` and dbounce
	// ships `backup.create`; gbounce mirrors the dbounce name so the
	// CLI-layer event name reads identically across both products.
	AdminActionBackupCreate AdminAction = "backup.create"

	// AdminActionBackupRestore — operator ran `gbounce restore`
	// (#279). Restore WHOLESALE-REPLACES the destination state.db
	// file; the OCSF activity_id is Update (3) because the entity's
	// state is changed (vs. Create, which would build a brand-new
	// entity). Severity is High because a restore touches every row
	// of state — a security team should review every restore.
	AdminActionBackupRestore AdminAction = "backup.restore"
)

// AdminActionActivityID maps an action to its OCSF activity_id (class
// 6003 enum). Mirrors the cross-product mapping in kbounce + dbounce
// so a SIEM dashboard keyed on activity_id reads the same way
// regardless of which Bounce product fired the event.
func AdminActionActivityID(a AdminAction) int {
	switch a {
	case AdminActionConfigImport:
		return ActivityCreate
	case AdminActionBackupRestore:
		// Restore wholesale REPLACES the destination DB. CRUD-wise
		// this is closest to Update (an existing entity's state is
		// changed) rather than Create (a brand-new one is built).
		return ActivityUpdate
	case AdminActionConfigExport,
		AdminActionDiagnosticsBundle,
		AdminActionBackupCreate:
		return ActivityOther
	default:
		return ActivityOther
	}
}

// AdminActionSeverity returns the OCSF severity_id + name for an admin
// action. Most admin actions are Informational (routine audit-trail
// rows); the few that touch the live state at scale (restore) escalate
// so a SIEM dashboard surfaces them automatically. Cross-product
// alignment per [[cross-product-agent-parity]]: kbounce's restore is
// also High; backup stays Informational.
func AdminActionSeverity(a AdminAction) (int, string) {
	switch a {
	case AdminActionBackupRestore:
		// Restore replaces the live state DB; a security team
		// should review every restore (vs. backup, which is
		// read-only + routine).
		return SeverityHigh, "High"
	default:
		return SeverityInformational, "Informational"
	}
}

// AdminActionSource names where the admin action came from. Lands in
// unmapped.iam_jit.config_change.source so an analyst can answer "did
// this config import come from the CLI or a future MCP tool call?"
type AdminActionSource string

const (
	// AdminActionSourceCLI — the change came from a `gbounce ...`
	// CLI invocation. The only source gbounce ships in G-Slice 1.
	AdminActionSourceCLI AdminActionSource = "cli"

	// AdminActionSourceMCP — reserved for a future MCP-tool-driven
	// admin path; not used in G-Slice 1.
	AdminActionSourceMCP AdminActionSource = "mcp"

	// AdminActionSourceUnknown — honest fallback when the source
	// could not be determined.
	AdminActionSourceUnknown AdminActionSource = "unknown"
)

// AdminActionInput is the minimal struct callers pass to
// MakeAdminActionEvent. All fields are optional; sensible defaults
// fill in when callers omit them.
type AdminActionInput struct {
	// Action names the activity. Required for a non-degenerate event.
	Action AdminAction

	// Actor identifies the operator who initiated the change. Lands
	// in OCSF actor.user.name. Empty → actor block omitted.
	Actor string

	// Before / After are the state values to hash. Either may be nil.
	// Canonical JSON-of-value serialization for determinism.
	Before any
	After  any

	// Source names where the action originated. Empty → CLI.
	Source AdminActionSource

	// EntityName is the human-readable identifier of the affected
	// entity (export destination path, import source path).
	EntityName string

	// EntityKind labels the kind of entity ("config" for the export /
	// import surface).
	EntityKind string

	// ExtraExt lets callers pass per-action context (counts, mode,
	// dry-run flag, ...). Lands under
	// unmapped.iam_jit.config_change.ext.
	ExtraExt map[string]any
}

// MakeAdminActionEvent builds an OCSF v1.1.0 class 6003 (API Activity)
// Event for an admin action. Same JSONL log writer that consumes
// FromRequest events consumes these — no transport-layer changes
// needed.
//
// before_hash / after_hash are populated via HashState. nil hashes to
// ("", false) so the field is omitted; a non-nil value (including an
// empty map) hashes deterministically.
func MakeAdminActionEvent(in AdminActionInput) Event {
	action := in.Action
	if action == "" {
		action = "admin_action"
	}
	activityID := AdminActionActivityID(action)
	source := in.Source
	if source == "" {
		source = AdminActionSourceCLI
	}

	cfgChange := map[string]any{
		"type":   string(action),
		"source": string(source),
	}
	if hashB, ok := HashState(in.Before); ok {
		cfgChange["before_hash"] = hashB
	}
	if hashA, ok := HashState(in.After); ok {
		cfgChange["after_hash"] = hashA
	}
	if in.EntityName != "" {
		cfgChange["entity"] = in.EntityName
	}
	if in.EntityKind != "" {
		cfgChange["entity_kind"] = in.EntityKind
	}
	if len(in.ExtraExt) > 0 {
		cfgChange["ext"] = in.ExtraExt
	}
	if in.Actor != "" {
		cfgChange["actor"] = in.Actor
	}

	ext := map[string]any{
		"admin_action":  string(action),
		"config_change": cfgChange,
	}

	severityID, severityName := AdminActionSeverity(action)

	return Event{
		Metadata: OCSFMetadata{
			Version: OCSFSchemaVersion,
			Product: OCSFProduct{
				Name:       ProductName,
				VendorName: VendorName,
				Version:    buildVersion,
			},
		},
		Time:         time.Now().UTC().UnixMilli(),
		ClassUID:     ClassUID,
		ClassName:    ClassName,
		CategoryUID:  CategoryUID,
		CategoryName: CategoryName,
		ActivityID:   activityID,
		ActivityName: string(action),
		TypeUID:      ClassUID*100 + activityID,
		TypeName:     typeNameForActivity(activityID),
		SeverityID:   severityID,
		Severity:     severityName,
		StatusID:     StatusSuccess,
		Status:       "Success",
		API: OCSFAPI{
			Operation: string(action),
			Service:   OCSFAPIService{Name: ProductName},
			Request:   OCSFAPIRequest{},
		},
		Resources: []OCSFResource{},
		Unmapped: OCSFUnmapped{
			IAMJIT: IAMJITExt{
				Mode:    "admin",
				Verdict: "ALLOW",
				Ext:     ext,
			},
		},
	}
}

// HashState returns the hex SHA-256 of a canonical JSON serialization
// of v. Returns ("", false) when v is nil so callers can distinguish
// "before-state not captured" from "before-state was the empty value".
//
// Per [[cross-product-agent-parity]] the hashing scheme is identical
// to kbounce + dbounce + ibounce so an analyst computing the same
// hash locally to verify tampering gets the same digest regardless of
// which Bounce product fired the event.
func HashState(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), true
}

// EmitAdminAction writes an admin-action event through the given
// LogWriter. nil writer → no-op (the same silent-when-unwired
// semantic the kbounce + dbounce emit helpers use).
//
// Best-effort: a full queue / write failure must not surface to the
// caller because the underlying admin action already succeeded. The
// LogWriter's drop counter + lastErr surface the failure separately.
func EmitAdminAction(ctx context.Context, lw *LogWriter, in AdminActionInput) {
	if lw == nil {
		return
	}
	ev := MakeAdminActionEvent(in)
	_ = lw.Write(ctx, ev)
}
