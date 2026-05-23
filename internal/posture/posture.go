// Package posture implements gbounce's per-bouncer posture surface.
//
// Shared between `gbounce posture` (CLI) + `gbounce_posture` (MCP)
// per [[cross-product-agent-parity]]. Lives in its own package so
// neither cli nor mcp pulls the other.
//
// Per [[ibounce-honest-positioning]]: the output is HONEST — if
// HTTP_PROXY points at loopback but gbounce isn't running, the
// snapshot reports MISCONFIGURED rather than silently claiming
// intercept.
//
// Per [[creates-never-mutates]]: read-only; the package never writes
// to disk, never mutates env, never starts goroutines.
package posture

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// SchemaVersion pins the JSON output shape; bump on breaking changes
// per [[config-export-wire-divergence]] (string).
const SchemaVersion = "1.0"

// Default ports gbounce listens on.
const (
	DefaultWirePort = 8080
	DefaultMgmtPort = 8769
)

// EnvProfileVar matches internal/cli's "GBOUNCE_PROFILE" string.
const EnvProfileVar = "GBOUNCE_PROFILE"

// EnvModeVar — operator can pin the mode value the posture surface
// reports.
const EnvModeVar = "GBOUNCE_MODE"

// Block matches the cross-product per-bouncer schema in
// iam-roles/src/iam_jit/posture/bouncers.py.
type Block struct {
	SchemaVersion      string `json:"schema_version"`
	Bouncer            string `json:"bouncer"`
	CapturedAt         string `json:"captured_at"`
	Running            bool   `json:"running"`
	Port               int    `json:"port"`
	MgmtPort           int    `json:"mgmt_port"`
	DefaultPort        int    `json:"default_port"`
	DefaultMgmtPort    int    `json:"default_mgmt_port"`
	Mode               string `json:"mode"`
	ActiveProfile      string `json:"active_profile"`
	EnvVarPointingHere string `json:"env_var_pointing_here,omitempty"`
	EnvVarSetElsewhere string `json:"env_var_set_elsewhere,omitempty"`
	Misconfig          string `json:"misconfig,omitempty"`
}

// Capture builds the structured snapshot. No goroutines, no
// background IO — just env reads + loopback TCP probes.
// Always safe to call.
func Capture() Block {
	wirePort := DefaultWirePort
	mgmtPort := DefaultMgmtPort
	running := loopbackPortOpen(mgmtPort, 250*time.Millisecond) ||
		loopbackPortOpen(wirePort, 250*time.Millisecond)
	block := Block{
		SchemaVersion:   SchemaVersion,
		Bouncer:         "gbounce",
		CapturedAt:      time.Now().UTC().Format(time.RFC3339),
		Running:         running,
		Port:            wirePort,
		MgmtPort:        mgmtPort,
		DefaultPort:     DefaultWirePort,
		DefaultMgmtPort: DefaultMgmtPort,
		Mode:            envOrUnknown(EnvModeVar),
		ActiveProfile:   envOrUnknown(EnvProfileVar),
	}
	// HTTP_PROXY + HTTPS_PROXY env-var detection.
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		val := strings.TrimSpace(os.Getenv(name))
		if val == "" {
			continue
		}
		port := parseLoopbackProxyPort(val)
		if port == 0 {
			block.EnvVarSetElsewhere = fmt.Sprintf("%s=%s (not loopback)", name, val)
			continue
		}
		if loopbackPortOpen(port, 250*time.Millisecond) {
			block.EnvVarPointingHere = fmt.Sprintf("%s=%s", name, val)
			block.Running = true
			block.Port = port
			break
		}
		block.Misconfig = fmt.Sprintf("%s=%s but nothing is listening on that port", name, val)
	}
	return block
}

func envOrUnknown(name string) string {
	v := strings.TrimSpace(os.Getenv(name))
	if v == "" {
		return "unknown"
	}
	return v
}

func loopbackPortOpen(port int, timeout time.Duration) bool {
	if port <= 0 || port > 65535 {
		return false
	}
	conn, err := net.DialTimeout(
		"tcp", fmt.Sprintf("127.0.0.1:%d", port), timeout,
	)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// parseLoopbackProxyPort returns the port from a proxy URL of the
// form ``http://127.0.0.1:8080`` (or similar loopback variants).
// Returns 0 if the URL isn't loopback or doesn't carry a port.
func parseLoopbackProxyPort(url string) int {
	s := url
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, "@"); i >= 0 {
		s = s[i+1:]
	}
	var host, portStr string
	if strings.HasPrefix(s, "[") {
		end := strings.Index(s, "]")
		if end < 0 {
			return 0
		}
		host = s[:end+1]
		rest := s[end+1:]
		if strings.HasPrefix(rest, ":") {
			portStr = rest[1:]
		}
	} else {
		i := strings.LastIndex(s, ":")
		if i < 0 {
			host = s
		} else {
			host = s[:i]
			portStr = s[i+1:]
		}
	}
	switch host {
	case "127.0.0.1", "localhost", "::1", "[::1]":
		// fine
	default:
		return 0
	}
	if portStr == "" {
		return 0
	}
	var port int
	if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
		return 0
	}
	if port <= 0 || port > 65535 {
		return 0
	}
	return port
}
