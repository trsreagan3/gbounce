// deny.go — `gbounce deny {add,list,remove,show}`.
//
// Dynamic deny rules across the Bounce suite: writes the shared
// ~/.iam-jit/dynamic-denies.yaml that every bouncer independently watches +
// honors, then fans out POST /admin/dynamic-denies/reload so the change takes
// effect immediately. gbounce is the suite anchor (founder decision
// 2026-06-04); the deny FILE is a shared artifact each bouncer chooses to
// honor — gbounce never pushes rules into another process's memory, preserving
// independence. Ported from iam-jit's Python `deny`.
package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/trsreagan3/gbounce/internal/dynamicdeny"
)

// crockford is the ULID alphabet (no I/L/O/U).
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// genDenyID returns a "dd_"-prefixed 26-char Crockford-base32 ULID
// (48-bit ms timestamp + 80-bit randomness), matching the iam-jit rule-id
// shape ^dd_[0-9A-HJKMNP-TV-Z]{26}$.
func genDenyID(now time.Time) (string, error) {
	var b [16]byte
	ms := uint64(now.UnixMilli())
	b[0] = byte(ms >> 40)
	b[1] = byte(ms >> 32)
	b[2] = byte(ms >> 24)
	b[3] = byte(ms >> 16)
	b[4] = byte(ms >> 8)
	b[5] = byte(ms)
	if _, err := rand.Read(b[6:]); err != nil {
		return "", err
	}
	// Encode 128 bits as 26 Crockford chars (5 bits each, MSB-first).
	var out [26]byte
	var acc uint64
	bits := 0
	idx := 0
	emit := func(v byte) { out[idx] = crockford[v&0x1f]; idx++ }
	// Process big-endian; first char encodes the top 2 bits (ULID convention).
	hi := binary.BigEndian.Uint64(b[0:8])
	lo := binary.BigEndian.Uint64(b[8:16])
	// Simplest correct approach: walk all 128 bits via a 130-bit shift.
	_ = acc
	_ = bits
	full := [2]uint64{hi, lo}
	for i := 0; i < 26; i++ {
		shift := uint(125 - i*5) // top group first; 26*5=130 ≥ 128
		var v uint64
		if shift >= 64 {
			v = full[0] >> (shift - 64)
		} else {
			v = (full[0] << (64 - shift)) | (full[1] >> shift)
		}
		emit(byte(v))
	}
	return "dd_" + string(out[:]), nil
}

// resolveTargetBouncers maps a deny target to the bouncer(s) that should honor
// it, mirroring iam-jit's resolver heuristics. Returns an error for an
// action:-prefixed target (#74 — dynamic-deny is target-scoped, not
// action-scoped) or an unclassifiable target.
func resolveTargetBouncers(target string) ([]string, error) {
	t := strings.TrimSpace(target)
	lt := strings.ToLower(t)
	switch {
	case lt == "":
		return nil, fmt.Errorf("empty target")
	case strings.HasPrefix(lt, "action:"):
		return nil, fmt.Errorf("action-level targets are not supported by dynamic-deny "+
			"(target %q); deny is target-scoped (an ARN / host / namespace / rds: resource), "+
			"not action-scoped. Use a bouncer rule for action gating.", target)
	case strings.HasPrefix(lt, "arn:aws:"), strings.HasPrefix(lt, "arn:aws-cn:"),
		strings.HasPrefix(lt, "arn:aws-us-gov:"), strings.HasPrefix(lt, "secret:"):
		return []string{"ibounce"}, nil
	case strings.HasPrefix(lt, "namespace:"), strings.HasPrefix(lt, "cluster:"):
		return []string{"kbounce"}, nil
	case strings.HasPrefix(lt, "rds:"):
		return []string{"dbounce"}, nil
	case isRDSShapedHost(lt):
		return []string{"dbounce", "gbounce"}, nil
	case strings.HasPrefix(lt, "http://"), strings.HasPrefix(lt, "https://"),
		strings.Contains(t, "."), strings.Contains(t, ":"):
		return []string{"gbounce"}, nil
	case isBareIdentifier(lt):
		return []string{"kbounce"}, nil
	}
	return nil, fmt.Errorf("could not route target %q to a bouncer "+
		"(expected an ARN, secret:, namespace:/cluster:, rds:, a hostname/URL, or a k8s namespace name)", target)
}

func isRDSShapedHost(h string) bool {
	return strings.Contains(h, ".rds.amazonaws.com") ||
		strings.Contains(h, "postgres") || strings.Contains(h, "mysql") ||
		strings.Contains(h, "-db") || strings.HasPrefix(h, "db.")
}

func isBareIdentifier(h string) bool {
	if h == "" || strings.ContainsAny(h, ".:/ ") {
		return false
	}
	for _, r := range h {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

var denyBouncerMgmtURL = map[string]string{
	"ibounce": "http://127.0.0.1:8767",
	"kbounce": "http://127.0.0.1:8766",
	"dbounce": "http://127.0.0.1:8768",
	"gbounce": "http://127.0.0.1:8769",
}

func newDenyCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "deny",
		Short: "Dynamic deny rules across the Bounce suite (shared ~/.iam-jit/dynamic-denies.yaml)",
		Long: "Write the shared dynamic-deny file that every bouncer independently\n" +
			"watches + honors, then fan out a reload. Targets are resources (ARN,\n" +
			"hostname/URL, namespace:/cluster:, rds:), NOT actions.",
	}
	cmd.AddCommand(newDenyAddCmd(), newDenyListCmd(), newDenyRemoveCmd(), newDenyShowCmd())
	return cmd
}

func defaultDenyPath() string { return dynamicdeny.ResolveDefaultPath() }

func loadDenyFile(path string) (*dynamicdeny.File, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &dynamicdeny.File{SchemaVersion: "1.0", Product: "iam-jit-dynamic-denies"}, nil
		}
		return nil, err
	}
	var f dynamicdeny.File
	if err := yaml.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("parse %q: %w", path, err)
	}
	if f.SchemaVersion == "" {
		f.SchemaVersion = "1.0"
	}
	return &f, nil
}

func writeDenyFile(path string, f *dynamicdeny.File) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	f.ExportedAt = time.Now().UTC().Format(time.RFC3339)
	out, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func newDenyAddCmd() *cobra.Command {
	var (
		targets  []string
		reason   string
		duration string
		bouncers []string
		path     string
		asJSON   bool
	)
	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a dynamic-deny rule + fan out a reload",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(targets) == 0 {
				return fmt.Errorf("gbounce: --target is required (repeatable)")
			}
			if strings.TrimSpace(reason) == "" {
				return fmt.Errorf("gbounce: --reason is required")
			}
			if !validDuration(duration) {
				return fmt.Errorf("gbounce: --duration must be 'permanent' or like 30m/3h/7d (got %q)", duration)
			}
			// Resolve applied_to (explicit --bouncer override, else per-target routing).
			appliedSet := map[string]bool{}
			if len(bouncers) > 0 {
				for _, b := range bouncers {
					appliedSet[strings.ToLower(strings.TrimSpace(b))] = true
				}
			} else {
				for _, tg := range targets {
					bs, err := resolveTargetBouncers(tg)
					if err != nil {
						return fmt.Errorf("gbounce: %w", err)
					}
					for _, b := range bs {
						appliedSet[b] = true
					}
				}
			}
			appliedTo := sortedSetKeys(appliedSet)

			now := time.Now().UTC()
			id, err := genDenyID(now)
			if err != nil {
				return err
			}
			rule := dynamicdeny.Rule{
				ID: id, Targets: targets, Reason: reason, Duration: duration,
				AddedBy: currentUser(), AddedAt: now, AppliedTo: appliedTo,
				AppliesToRecommender: true, Source: "cli",
			}
			if exp := expiryFor(duration, now); exp != nil {
				rule.ExpiresAt = exp
			}

			if path == "" {
				path = defaultDenyPath()
			}
			f, err := loadDenyFile(path)
			if err != nil {
				return fmt.Errorf("gbounce: %w", err)
			}
			f.Denies = append(f.Denies, rule)
			if err := writeDenyFile(path, f); err != nil {
				return fmt.Errorf("gbounce: write deny file: %w", err)
			}

			fanout := fanoutDenyReload(cmd.Context(), appliedTo, cmd.ErrOrStderr())

			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{
					"id": id, "targets": targets, "applied_to": appliedTo,
					"reason": reason, "duration": duration, "written_to": path,
					"expires_at": rule.ExpiresAt, "fanout": fanout,
				})
			}
			fmt.Fprintf(cmd.OutOrStdout(), "added %s — targets=%v applied_to=%v (written to %s)\n",
				id, targets, appliedTo, path)
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&targets, "target", nil, "deny target: ARN / secret: / namespace:/cluster: / rds: / hostname / URL (repeatable)")
	cmd.Flags().StringVar(&reason, "reason", "", "REQUIRED — why (surfaced in the deny response + audit)")
	cmd.Flags().StringVar(&duration, "duration", "permanent", "'permanent' or 30m/3h/7d/2w")
	cmd.Flags().StringArrayVar(&bouncers, "bouncer", nil, "override routing: apply to these bouncer(s) (ibounce/kbounce/dbounce/gbounce)")
	cmd.Flags().StringVar(&path, "path", "", "deny YAML path (default $IAM_JIT_DYNAMIC_DENIES_PATH or ~/.iam-jit/dynamic-denies.yaml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func newDenyListCmd() *cobra.Command {
	var (
		path           string
		asJSON         bool
		includeExpired bool
	)
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List dynamic-deny rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				path = defaultDenyPath()
			}
			f, err := loadDenyFile(path)
			if err != nil {
				return fmt.Errorf("gbounce: %w", err)
			}
			now := time.Now().UTC()
			var rules []dynamicdeny.Rule
			for _, r := range f.Denies {
				if !includeExpired && r.ExpiresAt != nil && r.ExpiresAt.Before(now) {
					continue
				}
				rules = append(rules, r)
			}
			if asJSON {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(rules)
			}
			if len(rules) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "no dynamic-deny rules")
				return nil
			}
			for _, r := range rules {
				exp := "permanent"
				if r.ExpiresAt != nil {
					exp = r.ExpiresAt.Format(time.RFC3339)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s  applied_to=%v  expires=%s  reason=%q\n    targets=%v\n",
					r.ID, r.AppliedTo, exp, r.Reason, r.Targets)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "deny YAML path")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	cmd.Flags().BoolVar(&includeExpired, "include-expired", false, "include rules whose expires_at is in the past")
	return cmd
}

func newDenyShowCmd() *cobra.Command {
	var (
		path   string
		asJSON bool
	)
	cmd := &cobra.Command{
		Use:   "show <id>",
		Short: "Show one dynamic-deny rule",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if path == "" {
				path = defaultDenyPath()
			}
			f, err := loadDenyFile(path)
			if err != nil {
				return fmt.Errorf("gbounce: %w", err)
			}
			for _, r := range f.Denies {
				if r.ID == args[0] {
					if asJSON {
						return json.NewEncoder(cmd.OutOrStdout()).Encode(r)
					}
					b, _ := yaml.Marshal(r)
					_, _ = cmd.OutOrStdout().Write(b)
					return nil
				}
			}
			return fmt.Errorf("gbounce: no rule with id %q", args[0])
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "deny YAML path")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}

func newDenyRemoveCmd() *cobra.Command {
	var (
		path    string
		expired bool
	)
	cmd := &cobra.Command{
		Use:   "remove <id>...",
		Short: "Remove dynamic-deny rule(s) by id (or --expired) + fan out a reload",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 && !expired {
				return fmt.Errorf("gbounce: pass rule id(s) or --expired")
			}
			if path == "" {
				path = defaultDenyPath()
			}
			f, err := loadDenyFile(path)
			if err != nil {
				return fmt.Errorf("gbounce: %w", err)
			}
			remove := map[string]bool{}
			for _, a := range args {
				remove[a] = true
			}
			now := time.Now().UTC()
			affected := map[string]bool{}
			var kept []dynamicdeny.Rule
			removed := 0
			for _, r := range f.Denies {
				drop := remove[r.ID] || (expired && r.ExpiresAt != nil && r.ExpiresAt.Before(now))
				if drop {
					removed++
					for _, b := range r.AppliedTo {
						affected[b] = true
					}
					continue
				}
				kept = append(kept, r)
			}
			f.Denies = kept
			if err := writeDenyFile(path, f); err != nil {
				return fmt.Errorf("gbounce: write deny file: %w", err)
			}
			fanoutDenyReload(cmd.Context(), sortedSetKeys(affected), cmd.ErrOrStderr())
			fmt.Fprintf(cmd.OutOrStdout(), "removed %d rule(s) (written to %s)\n", removed, path)
			return nil
		},
	}
	cmd.Flags().StringVar(&path, "path", "", "deny YAML path")
	cmd.Flags().BoolVar(&expired, "expired", false, "remove all rules whose expires_at is in the past")
	return cmd
}

// fanoutDenyReload POSTs /admin/dynamic-denies/reload to each affected bouncer.
// Best-effort: unreachable bouncers are warned on stderr, never fatal — the
// file write already happened + each bouncer's watcher will pick it up.
func fanoutDenyReload(ctx context.Context, bouncers []string, stderr interface{ Write([]byte) (int, error) }) []map[string]any {
	var results []map[string]any
	client := &http.Client{Timeout: 5 * time.Second}
	for _, b := range bouncers {
		url := denyBouncerMgmtURL[b]
		if url == "" {
			continue
		}
		res := map[string]any{"bouncer": b, "url": url + "/admin/dynamic-denies/reload"}
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url+"/admin/dynamic-denies/reload", bytes.NewReader([]byte("{}")))
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			res["reloaded"] = false
			res["error"] = condenseErr(err)
			fmt.Fprintf(stderr, "gbounce: %s reload failed (file written; watcher will pick it up): %v\n", b, err)
		} else {
			res["reloaded"] = resp.StatusCode == http.StatusOK
			res["status_code"] = resp.StatusCode
			resp.Body.Close()
		}
		results = append(results, res)
	}
	return results
}

// helpers ------------------------------------------------------------------

func validDuration(d string) bool {
	if d == "permanent" {
		return true
	}
	if len(d) < 2 {
		return false
	}
	unit := d[len(d)-1]
	if unit != 's' && unit != 'm' && unit != 'h' && unit != 'd' && unit != 'w' {
		return false
	}
	for _, r := range d[:len(d)-1] {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func expiryFor(d string, now time.Time) *time.Time {
	if d == "permanent" || !validDuration(d) {
		return nil
	}
	n := 0
	fmt.Sscanf(d[:len(d)-1], "%d", &n)
	var exp time.Time
	switch d[len(d)-1] {
	case 's':
		exp = now.Add(time.Duration(n) * time.Second)
	case 'm':
		exp = now.Add(time.Duration(n) * time.Minute)
	case 'h':
		exp = now.Add(time.Duration(n) * time.Hour)
	case 'd':
		exp = now.AddDate(0, 0, n)
	case 'w':
		exp = now.AddDate(0, 0, 7*n)
	}
	return &exp
}

func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return u
	}
	if u := os.Getenv("USERNAME"); u != "" {
		return u
	}
	return "gbounce-cli"
}

func sortedSetKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func condenseErr(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 100 {
		s = s[:97] + "..."
	}
	return s
}
