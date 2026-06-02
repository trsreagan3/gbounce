// Cobra `gbounce mcp ...` subcommands.
//
// #363 / §A32 — gbounce MCP surface. Mirrors dbounce/internal/cli/mcp.go
// shape: serve / install-{claude-code,cursor,codex} / show-config /
// list-tools. The internal/mcp + internal/mcpinstall packages own all
// the logic; this file is just cobra wiring.

package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/trsreagan3/gbounce/internal/mcp"
	"github.com/trsreagan3/gbounce/internal/mcpinstall"
)

// newMCPCmd implements `gbounce mcp` — a command group for the
// MCP-over-stdio server an agent (Claude Code, Cursor, Codex, Devin)
// connects to so it can introspect + scope itself via the gbounce_*
// tool family.
//
// Subcommands:
//
//	gbounce mcp serve                 — start the JSON-RPC stdio server
//	gbounce mcp install-claude-code   — wire gbounce into Claude Code / Desktop
//	gbounce mcp install-cursor        — wire gbounce into Cursor
//	gbounce mcp install-codex         — wire gbounce into Codex (manual snippet)
//	gbounce mcp install-devin         — print the Devin cloud-agent wiring recipe
//	gbounce mcp show-config           — print the canonical JSON snippet
//	gbounce mcp list-tools            — print the tool list (name + summary)
//
// Backward compatibility: `gbounce mcp` with no subcommand still
// starts the server (same as `gbounce mcp serve`), matching dbounce +
// kbouncer + ibounce shape.
func newMCPCmd() *cobra.Command {
	var (
		modeStr           string
		profileName       string
		profilesPath      string
		dynamicDeniesPath string
		actor             string
	)

	runServe := func(cmd *cobra.Command, args []string) error {
		srv := mcp.NewServer(mcp.Config{
			Mode:              modeStr,
			ActiveProfileName: profileName,
			ProfilesPath:      profilesPath,
			DynamicDeniesPath: dynamicDeniesPath,
			Actor:             actor,
		})
		fmt.Fprintf(os.Stderr,
			"gbounce mcp serving on stdio (mode=%s, profile=%s)\n",
			modeStr, profileName)
		fmt.Fprintln(os.Stderr, "Press Ctrl+D / close stdin to stop.")
		return srv.Serve(os.Stdin, os.Stdout)
	}

	addServeFlags := func(cmd *cobra.Command) {
		cmd.Flags().StringVar(&modeStr, "mode", "discovery",
			"Mode the running proxy is in (discovery | mitm). "+
				"Returned by gbounce_active_mode.")
		cmd.Flags().StringVar(&profileName, "profile", "",
			"Active environment profile name (mirror of `gbounce run --profile`). "+
				"Surfaced by gbounce_active_mode.")
		cmd.Flags().StringVar(&profilesPath, "profiles-path", "",
			"Path to profiles.yaml (default: ~/.gbounce/profiles.yaml).")
		cmd.Flags().StringVar(&dynamicDeniesPath, "dynamic-denies-path", "",
			"Path to dynamic-denies.yaml (default: ~/.iam-jit/dynamic-denies.yaml).")
		cmd.Flags().StringVar(&actor, "actor", "",
			"Actor name recorded in dynamic-deny added_by when MCP-initiated "+
				"deny_add lands (default: 'gbounce-mcp').")
	}

	parent := &cobra.Command{
		Use:   "mcp",
		Short: "MCP-over-stdio server + agent-client install helpers",
		Long: `MCP-over-stdio server + install helpers for the common agent
clients (Claude Code, Cursor, Codex).

Subcommands:

  gbounce mcp serve                 start the JSON-RPC stdio server
  gbounce mcp install-claude-code   wire gbounce into Claude Code / Desktop
  gbounce mcp install-cursor        wire gbounce into Cursor
  gbounce mcp install-codex         print Codex TOML snippet (manual install)
  gbounce mcp install-devin         print the Devin cloud-agent wiring recipe
  gbounce mcp show-config           print the canonical JSON / YAML snippet
  gbounce mcp list-tools            print the gbounce_* tool list

For backward compatibility ` + "`gbounce mcp`" + ` with no subcommand
still starts the server (same as ` + "`gbounce mcp serve`" + `).

The MCP server reads the SAME on-disk state the running proxy uses
(--profiles-path + --dynamic-denies-path). It does NOT start a proxy
listener of its own — run ` + "`gbounce run`" + ` separately for the
gating + forwarding layer.

stdin/stdout are reserved for the JSON-RPC stream; logs + banner go
to stderr so they don't poison the wire.`,
		Args: cobra.ArbitraryArgs,
		RunE: runServe,
	}
	addServeFlags(parent)

	serveCmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP-over-stdio server (canonical name)",
		Args:  cobra.NoArgs,
		RunE:  runServe,
	}
	addServeFlags(serveCmd)
	parent.AddCommand(serveCmd)

	parent.AddCommand(newMCPInstallClaudeCodeCmd())
	parent.AddCommand(newMCPInstallCursorCmd())
	parent.AddCommand(newMCPInstallCodexCmd())
	parent.AddCommand(newMCPInstallDevinCmd())
	parent.AddCommand(newMCPShowConfigCmd())
	parent.AddCommand(newMCPListToolsCmd())
	return parent
}

func newMCPInstallClaudeCodeCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-claude-code",
		Short: "Install gbounce as an MCP server in Claude Code / Claude Desktop",
		Long: `Add (or update) the ` + "`gbounce`" + ` MCP server entry in your
Claude Code / Claude Desktop MCP config file.

Default config path detection (first that exists wins; otherwise the
first candidate is used as a fresh-install target):

  macOS    ~/Library/Application Support/Claude/claude_desktop_config.json
           ~/.config/claude-code/mcp.json
           ~/.claude.json
  Linux    ~/.config/Claude/claude_desktop_config.json
           ~/.config/claude-code/mcp.json
           ~/.claude.json
  Windows  %APPDATA%/Claude/claude_desktop_config.json
           ~/.claude.json

Override with --path. The merge preserves any OTHER mcpServers
entries; the gbounce entry is REPLACED (not appended) so re-running
is idempotent.

After install, restart your MCP client so it re-reads the config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallClaudeCode(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the auto-detected config path.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing config without prompting.")
	return cmd
}

func newMCPInstallCursorCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-cursor",
		Short: "Install gbounce as an MCP server in Cursor",
		Long: `Add (or update) the ` + "`gbounce`" + ` MCP server entry in your
Cursor MCP config.

Default config path: ~/.cursor/mcp.json (global).

The merge preserves any OTHER mcpServers entries; the gbounce entry
is REPLACED (not appended) so re-running is idempotent.

After install, restart Cursor so it re-reads the config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallCursor(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the auto-detected config path (default: ~/.cursor/mcp.json).")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing config without prompting.")
	return cmd
}

func newMCPInstallCodexCmd() *cobra.Command {
	var (
		path  string
		force bool
	)
	cmd := &cobra.Command{
		Use:   "install-codex",
		Short: "Print the Codex MCP server snippet (manual install)",
		Long: `Codex stores MCP config in TOML (~/.codex/config.toml). To avoid
corrupting unrelated keys in the operator's TOML config, gbounce
refuses to edit the TOML file in place + instead prints a snippet
the operator pastes into their Codex config.

If you maintain a JSON-shaped Codex config elsewhere, pass
--path /full/path/to/file.json — gbounce installs into JSON files
the same way it does for Claude Code / Cursor.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallCodex(mcpinstall.Options{
				Path:   path,
				Force:  force,
				Out:    cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&path, "path", "",
		"Override the default Codex config path. Pass a .json path to "+
			"install into a JSON-shaped Codex MCP config; .toml paths "+
			"are not edited in place.")
	cmd.Flags().BoolVar(&force, "force", false,
		"Overwrite malformed existing JSON config without prompting.")
	return cmd
}

func newMCPInstallDevinCmd() *cobra.Command {
	var devinHost string
	cmd := &cobra.Command{
		Use:   "install-devin",
		Short: "Print the Devin cloud-agent bouncer-wiring recipe",
		Long: `Print the Devin wiring recipe. Devin is a cloud-hosted agent — it
runs in Cognition's sandboxed environment, NOT on your local machine,
so there is no local config file for gbounce to write into AND a
gbounce listener on 127.0.0.1 is not reachable from Devin's sandbox.

This command prints the two supported wiring paths instead of
silently degrading:

  PATH A  add the ` + "`gbounce mcp show-config`" + ` snippet to Devin's
          MCP settings (when Devin's MCP support is enabled).
  PATH B  run gbounce on a host Devin can reach (NOT loopback) and set
          HTTP_PROXY / HTTPS_PROXY in Devin's task environment.

Pass --devin-host HOST:PORT to bake a concrete reachable address into
the printed HTTP_PROXY / HTTPS_PROXY lines (default prints a
<gbounce-host>:8080 placeholder + a substitute note).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := mcpinstall.InstallDevin(mcpinstall.Options{
				DevinHost: devinHost,
				Out:       cmd.OutOrStdout(),
				Stderr:    cmd.ErrOrStderr(),
			})
			return err
		},
	}
	cmd.Flags().StringVar(&devinHost, "devin-host", "",
		"Reachable gbounce HOST:PORT to bake into the recipe's "+
			"HTTP_PROXY / HTTPS_PROXY lines (default: <gbounce-host>:8080 placeholder).")
	return cmd
}

func newMCPShowConfigCmd() *cobra.Command {
	var shape string
	cmd := &cobra.Command{
		Use:   "show-config",
		Short: "Print the canonical MCP server config snippet",
		Long: `Print the JSON (or YAML, with --shape yaml) snippet for any
custom MCP client. Vendor-neutral — paste into any MCP-compatible
agent's config.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return mcpinstall.ShowConfig(cmd.OutOrStdout(), mcpinstall.Shape(shape))
		},
	}
	cmd.Flags().StringVar(&shape, "shape", string(mcpinstall.ShapeJSON),
		"Output shape: json | yaml.")
	return cmd
}

func newMCPListToolsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "list-tools",
		Short: "Print the gbounce_* MCP tool list (name + 1-line summary)",
		Long: `Print the tool descriptors served by the gbounce MCP server
as a 2-column table (name + 1-line summary).

The list is the same one ` + "`tools/list`" + ` returns to an agent client,
so an operator who ran ` + "`gbounce mcp install-claude-code`" + ` can
verify their install worked without restarting their agent.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			descriptors := mcp.ToolDescriptors()
			entries := make([]mcpinstall.ToolListEntry, 0, len(descriptors))
			for _, d := range descriptors {
				name, _ := d["name"].(string)
				desc, _ := d["description"].(string)
				entries = append(entries, mcpinstall.ToolListEntry{
					Name:        name,
					Description: desc,
				})
			}
			return mcpinstall.FormatToolList(cmd.OutOrStdout(), entries)
		},
	}
	return cmd
}
