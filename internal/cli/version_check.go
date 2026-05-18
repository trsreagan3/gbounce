// `gbounce version-check` — opt-in informational check against the
// GitHub Releases API to tell the operator whether their installed
// binary is behind the latest tagged release.
//
// Privacy posture (load-bearing, per [[self-host-zero-billing-dependency]]
// + [[opt-in-feedback-pipeline]]):
//
//   - ONE outbound GET to
//     https://api.github.com/repos/trsreagan3/gbounce/releases/latest.
//     No body, no instance id, no machine fingerprint, no install-time
//     identifier, no telemetry of any kind.
//   - The only request header that identifies gbounce is
//     User-Agent: gbounce/<version> — required by GitHub's API to
//     avoid 403s on unauthenticated reads + intentionally identical
//     for every install at the same version.
//   - The operator can disable the check entirely with
//     GBOUNCE_NO_VERSION_CHECK=1; the env-var path NEVER performs the
//     GET so the kill-switch is verifiable by reading the code.
//   - Network failure / bad JSON / non-200 response prints the error
//     to stderr + exits 0. The command is informational, not a CI
//     gate, so an offline operator never gets a failed-command exit.
//
// Sibling: kbounce / ibounce / dbounce ship the same `version-check`
// subcommand with the same env-var-name shape + same "is up to date."
// / "OUT OF DATE." output strings. Cross-product parity per
// [[cross-product-agent-parity]].
package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const versionCheckEnvVar = "GBOUNCE_NO_VERSION_CHECK"
const versionCheckURL = "https://api.github.com/repos/trsreagan3/gbounce/releases/latest"
const versionCheckTimeout = 5 * time.Second

// versionCheckTransport is overridden in tests to a mock
// http.RoundTripper so the test suite never hits the real network.
// nil → http.DefaultTransport (production path).
var versionCheckTransport http.RoundTripper

func newVersionCheckCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version-check",
		Short: "Check GitHub Releases for a newer gbounce version (opt-in, no telemetry)",
		Long: `Compare the installed gbounce binary's version against the latest
release tagged on GitHub.

Privacy: this command sends ZERO data about your install. It performs
a single outbound GET to GitHub's public releases endpoint with a
generic ` + "`User-Agent: gbounce/<version>`" + ` header. No instance
identifier, no machine fingerprint, no telemetry of any shape.

Disable entirely: ` + "`export " + versionCheckEnvVar + "=1`" + ` (the
env-var path performs no network call at all).

Output: prints "is up to date." or "OUT OF DATE." + an upgrade hint
on stdout. Exits 0 in all success paths; network / parse failure
prints the error to stderr + still exits 0 (informational, not a CI
gate — an offline operator should not get a failed-command exit).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runVersionCheck(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	return cmd
}

func runVersionCheck(ctx context.Context, stdout, stderr io.Writer) error {
	if envDisabledVersionCheck() {
		fmt.Fprintln(stdout, "gbounce version check disabled by env ("+versionCheckEnvVar+").")
		return nil
	}

	client := &http.Client{
		Timeout:   versionCheckTimeout,
		Transport: versionCheckTransport,
	}
	reqCtx, cancel := context.WithTimeout(ctx, versionCheckTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, versionCheckURL, nil)
	if err != nil {
		fmt.Fprintf(stderr, "version check failed: %v\n", err)
		return nil
	}
	req.Header.Set("User-Agent", "gbounce/"+version)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Fprintf(stderr, "version check failed: %v\n", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(stderr, "version check failed: github returned HTTP %d\n", resp.StatusCode)
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		fmt.Fprintf(stderr, "version check failed: read body: %v\n", err)
		return nil
	}
	var payload struct {
		TagName string `json:"tag_name"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		fmt.Fprintf(stderr, "version check failed: parse response: %v\n", err)
		return nil
	}
	latest := strings.TrimPrefix(strings.TrimSpace(payload.TagName), "v")
	if latest == "" {
		fmt.Fprintln(stderr, "version check failed: empty tag_name in response")
		return nil
	}
	current := strings.TrimPrefix(strings.TrimSpace(version), "v")
	if current == "" || current == "dev" {
		fmt.Fprintf(stdout,
			"gbounce is an unstamped build (version=%q). Latest release: v%s. "+
				"Upgrade: https://github.com/trsreagan3/gbounce/releases/latest\n",
			version, latest)
		return nil
	}
	cur, curOK := parseSemver(current)
	lat, latOK := parseSemver(latest)
	if !curOK || !latOK {
		fmt.Fprintf(stderr,
			"version check failed: could not compare versions (current=%q latest=%q)\n",
			current, latest)
		return nil
	}
	if compareSemver(cur, lat) >= 0 {
		fmt.Fprintf(stdout, "gbounce v%s is up to date.\n", current)
		return nil
	}
	fmt.Fprintf(stdout,
		"gbounce v%s is OUT OF DATE. Latest: v%s. "+
			"Upgrade: https://github.com/trsreagan3/gbounce/releases/latest\n",
		current, latest)
	return nil
}

func envDisabledVersionCheck() bool {
	v := strings.TrimSpace(os.Getenv(versionCheckEnvVar))
	if v == "" {
		return false
	}
	switch strings.ToLower(v) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

func parseSemver(s string) ([3]int, bool) {
	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return [3]int{}, false
	}
	var out [3]int
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return [3]int{}, false
		}
		out[i] = n
	}
	return out, true
}

func compareSemver(a, b [3]int) int {
	for i := 0; i < 3; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}
