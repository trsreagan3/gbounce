// Package profile — install.go
//
// `gbounce profile install` support. Mirrors dbounce / kbouncer
// install shape 1:1 with two gbounce-specific deviations:
//
//   - The on-disk Profile struct holds deny_hosts + deny_rules (no
//     SQL semantics; no K8s verbs).
//   - The per-bouncer slot in a generator bundle is `gbounce.yaml`.
//
// Per §A27 (#352). Pre-fix gbounce had no install path at all —
// generator-emitted profiles needed manual translation into the
// existing `--profile-rules-file` JSON shape.
//
// Read-only invariant:
//
//   - A profile whose Source field is non-empty and not "local" is
//     refused by UpsertProfile.
//   - `profile install` itself bypasses that check via the package-
//     private writeInstalledProfiles helper.
//   - The Source field is always FORCED to the fetch source on
//     install, regardless of what the upstream YAML claims.
//
// Security:
//
//   - HTTPS preferred. http:// is accepted with a stderr WARN at the
//     CLI layer (loopback gets a silent pass) for local-dev parity
//     with the audit-export HTTP surface. Mirrors §A26 across
//     dbounce + kbouncer.
//   - Optional --sha256 pin.
//   - All-or-nothing parse: any failed validation aborts the install.

package profile

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// InstallExitOK is returned on success.
	InstallExitOK = 0
	// InstallExitPayload is returned for payload / server problems
	// (fetch failed, YAML didn't parse, validation failed).
	InstallExitPayload = 1
	// InstallExitOperator is returned for operator-fixable problems
	// (unknown URL scheme, sha256 mismatch, conflict without --force).
	InstallExitOperator = 2
)

// InstallError carries a structured exit code plus a human-readable
// message so the CLI can map both onto stderr / os.Exit without
// re-parsing the message text.
type InstallError struct {
	ExitCode   int
	Message    string
	Underlying error
}

func (e *InstallError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

func (e *InstallError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Underlying
}

func installErr(code int, msg string) *InstallError {
	return &InstallError{ExitCode: code, Message: msg}
}

func installErrWrap(code int, msg string, cause error) *InstallError {
	return &InstallError{ExitCode: code, Message: msg, Underlying: cause}
}

// InstallOptions tunes a single `profile install` invocation.
type InstallOptions struct {
	From           string
	ExpectedSHA256 string
	Force          bool
	Timeout        time.Duration
	HTTPClient     *http.Client
	ProfilesPath   string
}

// InstallResult summarizes a successful install.
type InstallResult struct {
	SourceURL      string
	ProfilesPath   string
	InstalledNames []string
	SHA256         string
	SHA256Verified bool
}

// maxProfilePayload caps `profile install` response bodies. 1 MiB is
// much larger than any legitimate profile YAML but small enough that
// an attacker can't exhaust memory in a single fetch.
const maxProfilePayload = int64(1 << 20)

// Install fetches the source, validates the payload, and writes the
// profiles to disk. The From field accepts:
//
//   - https://...                       (preferred)
//   - http://...                         (accepted; CLI prints WARN
//     for non-loopback hosts per §A26 local-dev parity)
//   - file:///abs/path/...               (single YAML file OR a
//     generator-emitted bundle directory)
//   - bare local path: ./relative or /absolute
//
// When From is a directory the install looks for `gbounce.yaml`
// first (the per-bouncer slot in the generator's bundle layout); it
// falls back to `index.yaml` + the bouncer entry naming gbounce.
func Install(ctx context.Context, opts InstallOptions) (*InstallResult, error) {
	payload, canonical, fetchErr := fetchInstallPayload(ctx, opts)
	if fetchErr != nil {
		return nil, fetchErr
	}
	if canonical != "" {
		opts.From = canonical
	}
	return InstallFromBytes(payload, opts)
}

// fetchInstallPayload resolves opts.From to the (bytes, canonical-
// source-string) pair. Canonical-source is what gets written into
// each installed profile's Source field; for local files this is the
// absolute resolved path so SIEM viewers + the UpsertProfile read-
// only check both see a stable non-"local" string.
func fetchInstallPayload(ctx context.Context, opts InstallOptions) ([]byte, string, error) {
	if opts.From == "" {
		return nil, "", installErr(InstallExitOperator,
			"refusing to fetch: --from URL_OR_PATH is required")
	}
	parsed, perr := url.Parse(opts.From)
	if perr != nil {
		return nil, "", installErrWrap(InstallExitOperator,
			fmt.Sprintf("refusing to fetch from %q: not a valid URL: %v",
				opts.From, perr), perr)
	}
	scheme := strings.ToLower(parsed.Scheme)

	switch scheme {
	case "https", "http":
		timeout := opts.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client := opts.HTTPClient
		if client == nil {
			client = &http.Client{Timeout: timeout}
		}
		fetchCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, opts.From, nil)
		if err != nil {
			return nil, "", installErrWrap(InstallExitPayload,
				fmt.Sprintf("build fetch request: %v", err), err)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, "", installErrWrap(InstallExitPayload,
				fmt.Sprintf("fetch failed: %v", err), err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, "", installErr(InstallExitPayload,
				fmt.Sprintf("fetch failed: HTTP %d", resp.StatusCode))
		}
		limited := io.LimitReader(resp.Body, maxProfilePayload+1)
		payload, err := io.ReadAll(limited)
		if err != nil {
			return nil, "", installErrWrap(InstallExitPayload,
				fmt.Sprintf("fetch failed: read body: %v", err), err)
		}
		if int64(len(payload)) > maxProfilePayload {
			return nil, "", installErr(InstallExitPayload,
				fmt.Sprintf("fetch failed: payload exceeds maximum size of %d bytes",
					maxProfilePayload))
		}
		return payload, opts.From, nil

	case "file":
		return readLocalInstallSource(filepath.Clean(parsed.Path), opts.From)
	case "":
		return readLocalInstallSource(filepath.Clean(opts.From), opts.From)
	default:
		return nil, "", installErr(InstallExitOperator,
			fmt.Sprintf("refusing to fetch from %q: scheme %q is not supported. "+
				"Use one of https://, http://, file://, or a local path.",
				opts.From, parsed.Scheme))
	}
}

// readLocalInstallSource resolves a local file or directory to a
// payload + canonical source string. Directories are treated as
// generator-emitted bundles: gbounce.yaml is preferred; index.yaml +
// the gbounce entry is the fallback.
func readLocalInstallSource(path, original string) ([]byte, string, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", installErr(InstallExitOperator,
				fmt.Sprintf("refusing to fetch from %q: path does not exist "+
					"(resolved to %q).", original, path))
		}
		return nil, "", installErrWrap(InstallExitPayload,
			fmt.Sprintf("stat %q: %v", path, err), err)
	}
	if info.IsDir() {
		candidate := filepath.Join(path, "gbounce.yaml")
		if st, serr := os.Stat(candidate); serr == nil && !st.IsDir() {
			body, rerr := os.ReadFile(candidate)
			if rerr != nil {
				return nil, "", installErrWrap(InstallExitPayload,
					fmt.Sprintf("read %q: %v", candidate, rerr), rerr)
			}
			abs, _ := filepath.Abs(candidate)
			return body, abs, nil
		}
		idx := filepath.Join(path, "index.yaml")
		if st, serr := os.Stat(idx); serr == nil && !st.IsDir() {
			idxBody, rerr := os.ReadFile(idx)
			if rerr != nil {
				return nil, "", installErrWrap(InstallExitPayload,
					fmt.Sprintf("read %q: %v", idx, rerr), rerr)
			}
			var idxDoc struct {
				Profiles []struct {
					File    string `yaml:"file"`
					Bouncer string `yaml:"bouncer"`
				} `yaml:"profiles"`
			}
			if yerr := yaml.Unmarshal(idxBody, &idxDoc); yerr != nil {
				return nil, "", installErrWrap(InstallExitPayload,
					fmt.Sprintf("%q is not valid YAML: %v", idx, yerr), yerr)
			}
			for _, entry := range idxDoc.Profiles {
				if entry.Bouncer == "gbounce" && entry.File != "" {
					target := filepath.Join(path, entry.File)
					body, rerr := os.ReadFile(target)
					if rerr != nil {
						return nil, "", installErrWrap(InstallExitPayload,
							fmt.Sprintf("read %q: %v", target, rerr), rerr)
					}
					abs, _ := filepath.Abs(target)
					return body, abs, nil
				}
			}
		}
		return nil, "", installErr(InstallExitOperator,
			fmt.Sprintf("refusing to fetch from %q: directory contains "+
				"neither `gbounce.yaml` nor a usable `index.yaml` with a "+
				"gbounce entry.", original))
	}

	body, rerr := os.ReadFile(path)
	if rerr != nil {
		return nil, "", installErrWrap(InstallExitPayload,
			fmt.Sprintf("read %q: %v", path, rerr), rerr)
	}
	abs, _ := filepath.Abs(path)
	return body, abs, nil
}

// InstallFromBytes is the half of Install that operates on already-
// fetched bytes. Exported so tests + future programmatic callers
// (e.g. an MCP tool) can install without going through the fetch
// path.
func InstallFromBytes(payload []byte, opts InstallOptions) (*InstallResult, error) {
	if opts.From == "" {
		return nil, installErr(InstallExitOperator,
			"refusing to install: opts.From is required (source string)")
	}

	sum := sha256.Sum256(payload)
	actualHex := hex.EncodeToString(sum[:])
	verified := false
	if opts.ExpectedSHA256 != "" {
		want := normalizeSHA256(opts.ExpectedSHA256)
		if want != actualHex {
			return nil, installErr(InstallExitOperator,
				fmt.Sprintf("sha256 mismatch:\n  expected: %s\n  actual:   %s\nrefusing to install.",
					want, actualHex))
		}
		verified = true
	}

	var raw map[string]any
	if err := yaml.Unmarshal(payload, &raw); err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("payload is not valid YAML: %v", err), err)
	}
	profilesMap, perr := normalizeInstallDocument(raw, opts.From)
	if perr != nil {
		return nil, perr
	}
	if len(profilesMap) == 0 {
		return nil, installErr(InstallExitPayload,
			"payload must contain a non-empty `profiles` object (or be a "+
				"generator-emitted single-profile file with `profile_name:` "+
				"+ `bouncer:` at the top level)")
	}

	parsed, names, err := parseInstallPayload(profilesMap, opts.From)
	if err != nil {
		return nil, err
	}

	resolvedPath := opts.ProfilesPath
	if resolvedPath == "" {
		rp, perr := DefaultProfilesPath()
		if perr != nil {
			return nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("resolve profiles path: %v", perr), perr)
		}
		resolvedPath = rp
	}
	existing, eerr := readProfilesFile(resolvedPath)
	if eerr != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("read existing profiles: %v", eerr), eerr)
	}
	var conflicts []conflictRow
	for _, name := range names {
		if prior, ok := existing[name]; ok {
			conflicts = append(conflicts, conflictRow{
				Name:        name,
				PriorSource: priorSourceLabel(prior),
			})
		}
	}
	if len(conflicts) > 0 && !opts.Force {
		var b strings.Builder
		b.WriteString("the following profiles already exist; pass --force to overwrite:\n")
		for _, c := range conflicts {
			fmt.Fprintf(&b, "  %s  (current source: %s)\n", c.Name, c.PriorSource)
		}
		return nil, installErr(InstallExitOperator, strings.TrimRight(b.String(), "\n"))
	}

	if err := writeInstalledProfiles(resolvedPath, parsed); err != nil {
		return nil, installErrWrap(InstallExitPayload,
			fmt.Sprintf("write profiles: %v", err), err)
	}

	return &InstallResult{
		SourceURL:      opts.From,
		ProfilesPath:   resolvedPath,
		InstalledNames: names,
		SHA256:         actualHex,
		SHA256Verified: verified,
	}, nil
}

type conflictRow struct {
	Name        string
	PriorSource string
}

func priorSourceLabel(p *Profile) string {
	if p == nil || p.Source == "" {
		return "local"
	}
	return p.Source
}

func normalizeSHA256(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, ":", "")
	s = strings.TrimSpace(s)
	return s
}

// normalizeInstallDocument lifts a parsed install YAML into the
// `{<name>: <body>}` shape the install loop consumes. Accepts:
//
//   - `{profiles: {<name>: {...}}}` — canonical fragment.
//
//   - `{schema_version, profile_name, bouncer, denies, allows, ...}` —
//     `iam-jit profile generate-from-audit` per-bouncer file. The
//     name is derived from `profile_name:` (preferred) or a fallback
//     based on the source basename.
func normalizeInstallDocument(raw map[string]any, source string) (map[string]any, *InstallError) {
	if raw == nil {
		return nil, nil
	}
	if profilesAny, ok := raw["profiles"]; ok {
		profilesMap, ok := profilesAny.(map[string]any)
		if !ok {
			return nil, installErr(InstallExitPayload,
				"payload `profiles` field must be an object")
		}
		return profilesMap, nil
	}

	hasGenShape := false
	for _, k := range []string{"profile_name", "bouncer", "denies", "allows"} {
		if _, ok := raw[k]; ok {
			hasGenShape = true
			break
		}
	}
	if !hasGenShape {
		return nil, nil
	}

	name := ""
	if n, ok := raw["profile_name"].(string); ok {
		name = strings.TrimSpace(n)
	}
	if name == "" {
		base := source
		if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
			base = base[i+1:]
		}
		if i := strings.LastIndex(base, "."); i > 0 {
			base = base[:i]
		}
		if base == "" {
			base = "generated-profile"
		}
		name = base
	}
	body := make(map[string]any, len(raw))
	for k, v := range raw {
		body[k] = v
	}
	if _, ok := body["description"]; !ok {
		bouncerName := "gbounce"
		if bv, ok := body["bouncer"].(string); ok && bv != "" {
			bouncerName = bv
		}
		body["description"] = fmt.Sprintf(
			"Generator-emitted profile (bouncer=%s) — installed from %s.",
			bouncerName, source)
	}
	return map[string]any{name: body}, nil
}

func parseInstallPayload(profilesMap map[string]any, sourceURL string) ([]*Profile, []string, *InstallError) {
	names := make([]string, 0, len(profilesMap))
	for name := range profilesMap {
		names = append(names, name)
	}
	sortStrings(names)

	parsed := make([]*Profile, 0, len(names))
	for _, name := range names {
		bodyAny := profilesMap[name]
		body, ok := bodyAny.(map[string]any)
		if !ok {
			if bodyAny == nil {
				body = map[string]any{}
			} else {
				return nil, nil, installErr(InstallExitPayload,
					fmt.Sprintf("profile %q must be a YAML object", name))
			}
		}
		body["source"] = sourceURL

		bodyYAML, err := yaml.Marshal(body)
		if err != nil {
			return nil, nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("profile %q: re-encode for validation: %v", name, err), err)
		}
		var p Profile
		if err := yaml.Unmarshal(bodyYAML, &p); err != nil {
			return nil, nil, installErrWrap(InstallExitPayload,
				fmt.Sprintf("profile %q failed to parse: %v", name, err), err)
		}
		p.Name = name
		p.Source = sourceURL
		if verr := p.validate(); verr != nil {
			return nil, nil, installErr(InstallExitPayload,
				fmt.Sprintf("profile %q failed validation: %v", name, verr))
		}
		parsed = append(parsed, &p)
	}
	return parsed, names, nil
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func readProfilesFile(path string) (map[string]*Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]*Profile{}, nil
		}
		return nil, err
	}
	var pf profileFile
	if err := yaml.Unmarshal(raw, &pf); err != nil {
		return nil, fmt.Errorf("parse profiles yaml at %s: %w", path, err)
	}
	out := map[string]*Profile{}
	for name, p := range pf.Profiles {
		if p == nil {
			p = &Profile{}
		}
		p.Name = name
		out[name] = p
	}
	return out, nil
}

// writeInstalledProfiles persists the installed profiles to the on-
// disk profiles.yaml. Existing profiles NOT touched by this install
// are preserved verbatim. Atomicity: temp file + rename so a crash
// mid-write leaves the prior file intact.
func writeInstalledProfiles(path string, profiles []*Profile) error {
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("mkdir %q: %w", dir, err)
		}
	}

	merged := profileFile{Profiles: map[string]*Profile{}}
	if raw, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(raw, &merged); err != nil {
			return fmt.Errorf("parse existing profiles yaml: %w", err)
		}
		if merged.Profiles == nil {
			merged.Profiles = map[string]*Profile{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat existing profiles yaml: %w", err)
	}

	for _, p := range profiles {
		merged.Profiles[p.Name] = p
	}

	out, err := yaml.Marshal(&merged)
	if err != nil {
		return fmt.Errorf("encode profiles yaml: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// UpsertProfile persists a single profile to profiles.yaml — insert
// if absent, replace if present.
//
// Read-only invariant: refuses to overwrite a profile whose existing
// Source field is anything other than empty/"local". `profile install`
// itself bypasses this check via writeInstalledProfiles.
func UpsertProfile(p *Profile, path string) error {
	if p == nil || p.Name == "" {
		return errors.New("gbounce: UpsertProfile: Name is required")
	}
	resolved := path
	if resolved == "" {
		rp, err := DefaultProfilesPath()
		if err != nil {
			return fmt.Errorf("gbounce: resolve profiles path: %w", err)
		}
		resolved = rp
	}
	if dir := filepath.Dir(resolved); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("gbounce: mkdir %q: %w", dir, err)
		}
	}

	merged := profileFile{Profiles: map[string]*Profile{}}
	if raw, err := os.ReadFile(resolved); err == nil {
		if err := yaml.Unmarshal(raw, &merged); err != nil {
			return fmt.Errorf("gbounce: parse existing profiles yaml: %w", err)
		}
		if merged.Profiles == nil {
			merged.Profiles = map[string]*Profile{}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("gbounce: read profiles yaml: %w", err)
	}

	if prior, exists := merged.Profiles[p.Name]; exists && prior != nil {
		if !prior.IsLocalSource() {
			return fmt.Errorf(
				"profile %q is sourced from %q and is read-only. "+
					"Pick a different name for your local override.",
				p.Name, prior.Source)
		}
	}

	merged.Profiles[p.Name] = p
	out, err := yaml.Marshal(&merged)
	if err != nil {
		return fmt.Errorf("gbounce: encode profiles yaml: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(resolved), ".profiles-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("gbounce: create temp file: %w", err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(out); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gbounce: write temp file: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("gbounce: chmod temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("gbounce: close temp file: %w", err)
	}
	if err := os.Rename(tmpName, resolved); err != nil {
		return fmt.Errorf("gbounce: rename into place: %w", err)
	}
	return nil
}

// InsecureTLSClientForTests returns an *http.Client that skips TLS
// verification. Test-only helper exported for install_test.go so
// httptest.NewTLSServer (which presents a self-signed cert) can be
// the fetch target. Production code must NEVER pass this to Install.
func InsecureTLSClientForTests() *http.Client {
	return &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			//nolint:gosec // intentional: test fixture for httptest.NewTLSServer
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}
