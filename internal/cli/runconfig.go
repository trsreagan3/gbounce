// runconfig.go — persistent operator config for `gbounce run`.
//
// gbounce historically took every setting as a CLI flag, so an operator
// change (e.g. --ui-exclude-host) lived only in the launching process's
// argv and did NOT survive a restart / machine reboot. This module adds a
// durable config file (~/.gbounce/config.yaml by default, or $GBOUNCE_CONFIG)
// that `gbounce run` loads at startup, so settings persist.
//
// Precedence (lowest → highest): flag default  <  config file  <  env  <
// explicit flag. Implemented via the resolve* helpers + cobra's
// Flags().Changed — a value in the file is a DEFAULT that an explicitly-set
// flag overrides. The file is OPTIONAL: a missing file is a no-op (found=false,
// no error), so out-of-the-box behavior is unchanged.
//
// This complements (does not replace) `config export`/`config import`, which
// round-trip the broader JSON ConfigExport shape for backup/migration. The
// run-config file is the narrower, hand-editable YAML an operator keeps.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RunConfigFile is the YAML shape of ~/.gbounce/config.yaml. Every field is
// optional; only set fields override flag defaults. Pointers/zero-values mark
// "unset" so we never clobber a flag default with an implicit zero.
type RunConfigFile struct {
	Mode               string                  `yaml:"mode"`
	AllowConnect       *bool                   `yaml:"allow_connect"`
	AuditLogPath       string                  `yaml:"audit_log_path"`
	UIExcludeHosts     []string                `yaml:"ui_exclude_hosts"`
	DenyHosts          []string                `yaml:"deny_hosts"`
	AuditObjectStorage *RunConfigObjectStorage `yaml:"audit_object_storage"`
}

// RunConfigObjectStorage persists the #317 S3-compatible audit sink config.
type RunConfigObjectStorage struct {
	Endpoint        string `yaml:"endpoint"`
	Bucket          string `yaml:"bucket"`
	Prefix          string `yaml:"prefix"`
	Region          string `yaml:"region"`
	CredentialsFile string `yaml:"credentials_file"`
	RotationMinutes int    `yaml:"rotation_minutes"`
	MaxSizeMB       int    `yaml:"max_size_mb"`
	InstanceID      string `yaml:"instance_id"`
}

// DefaultRunConfigPath resolves the config-file path: $GBOUNCE_CONFIG wins,
// else ~/.gbounce/config.yaml. Returns "" only when HOME is unresolvable and
// no env override is set (in which case the loader simply finds nothing).
func DefaultRunConfigPath() string {
	if p := strings.TrimSpace(os.Getenv("GBOUNCE_CONFIG")); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".gbounce", "config.yaml")
}

// LoadRunConfig reads + parses the config file at path. A missing file is NOT
// an error: it returns (nil, false, nil) so startup proceeds with flag
// defaults. A present-but-malformed file IS an error (fail loud — a typo in a
// security tool's config should never be silently ignored).
func LoadRunConfig(path string) (*RunConfigFile, bool, error) {
	if strings.TrimSpace(path) == "" {
		return nil, false, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read %q: %w", path, err)
	}
	var rc RunConfigFile
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true) // reject unknown keys so typos surface loudly
	if err := dec.Decode(&rc); err != nil {
		return nil, false, fmt.Errorf("parse %q: %w", path, err)
	}
	return &rc, true, nil
}

// resolve* helpers implement the "config-file value applies only when the flag
// was not explicitly set" precedence. `changed` is cobra's Flags().Changed.

func resolveString(changed bool, fileVal, current string) string {
	if !changed && fileVal != "" {
		return fileVal
	}
	return current
}

func resolveStringSlice(changed bool, fileVal, current []string) []string {
	if !changed && len(fileVal) > 0 {
		return fileVal
	}
	return current
}

func resolveBool(changed bool, fileVal *bool, current bool) bool {
	if !changed && fileVal != nil {
		return *fileVal
	}
	return current
}

func resolveInt(changed bool, fileVal, current int) int {
	if !changed && fileVal != 0 {
		return fileVal
	}
	return current
}
