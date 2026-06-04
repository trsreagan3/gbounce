// service.go — `gbounce service {install,uninstall,status}`.
//
// Auto-start gbounce at login/boot WITHOUT sudo, so the bouncer process
// survives a restart (the companion to config persistence: ~/.gbounce/config.yaml
// makes the SETTINGS durable; this makes the PROCESS durable). User-scoped:
// macOS LaunchAgent (~/Library/LaunchAgents), Linux systemd --user — neither
// needs root, per the permission-minimal-install principle. The installed
// service just runs `gbounce run`, which auto-loads ~/.gbounce/config.yaml.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

const serviceLabel = "io.bounce.gbounce"

func newServiceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "service",
		Short: "Install/remove a no-sudo auto-start service so gbounce survives a reboot",
		Long: "Register gbounce to start at login/boot without root: a LaunchAgent on\n" +
			"macOS, a systemd --user unit on Linux. The service runs `gbounce run`,\n" +
			"which auto-loads ~/.gbounce/config.yaml — so both the process AND your\n" +
			"saved settings come back after a restart.",
	}
	cmd.AddCommand(newServiceInstallCmd(), newServiceUninstallCmd(), newServiceStatusCmd())
	return cmd
}

// servicePlan is the OS-specific file + commands for (un)install. Pure data so
// the template generation is unit-testable without touching the real system.
type servicePlan struct {
	os        string
	unitPath  string
	content   string
	loadCmd   [][]string
	unloadCmd [][]string
}

func buildServicePlan(goos, binPath, home string) (servicePlan, error) {
	switch goos {
	case "darwin":
		p := filepath.Join(home, "Library", "LaunchAgents", serviceLabel+".plist")
		content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>%s</string>
  <key>ProgramArguments</key>
  <array>
    <string>%s</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>%s/.gbounce/service.out.log</string>
  <key>StandardErrorPath</key><string>%s/.gbounce/service.err.log</string>
</dict>
</plist>
`, serviceLabel, binPath, home, home)
		return servicePlan{
			os: goos, unitPath: p, content: content,
			loadCmd:   [][]string{{"launchctl", "unload", p}, {"launchctl", "load", "-w", p}},
			unloadCmd: [][]string{{"launchctl", "unload", "-w", p}},
		}, nil
	case "linux":
		p := filepath.Join(home, ".config", "systemd", "user", "gbounce.service")
		content := fmt.Sprintf(`[Unit]
Description=gbounce — Bounce suite HTTP proxy/audit bouncer
After=network-online.target

[Service]
ExecStart=%s run
Restart=on-failure
RestartSec=3

[Install]
WantedBy=default.target
`, binPath)
		return servicePlan{
			os: goos, unitPath: p, content: content,
			loadCmd:   [][]string{{"systemctl", "--user", "daemon-reload"}, {"systemctl", "--user", "enable", "--now", "gbounce.service"}},
			unloadCmd: [][]string{{"systemctl", "--user", "disable", "--now", "gbounce.service"}},
		}, nil
	}
	return servicePlan{}, fmt.Errorf("gbounce service: unsupported OS %q (supported: darwin, linux)", goos)
}

func currentPlan() (servicePlan, error) {
	bin, err := os.Executable()
	if err != nil {
		return servicePlan{}, err
	}
	if resolved, err := filepath.EvalSymlinks(bin); err == nil {
		bin = resolved
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return servicePlan{}, err
	}
	return buildServicePlan(runtime.GOOS, bin, home)
}

func newServiceInstallCmd() *cobra.Command {
	var printOnly bool
	cmd := &cobra.Command{
		Use:   "install",
		Short: "Write + load the auto-start unit (no sudo)",
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := currentPlan()
			if err != nil {
				return err
			}
			if printOnly {
				fmt.Fprintf(cmd.OutOrStdout(), "# %s\n%s\n", plan.unitPath, plan.content)
				return nil
			}
			if err := os.MkdirAll(filepath.Dir(plan.unitPath), 0o755); err != nil {
				return err
			}
			if err := os.WriteFile(plan.unitPath, []byte(plan.content), 0o644); err != nil {
				return fmt.Errorf("gbounce service: write %s: %w", plan.unitPath, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", plan.unitPath)
			for _, c := range plan.loadCmd {
				runServiceCmd(cmd, c)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "gbounce will now start at login/boot (runs `gbounce run`, auto-loads ~/.gbounce/config.yaml).")
			return nil
		},
	}
	cmd.Flags().BoolVar(&printOnly, "print", false, "print the unit file instead of installing")
	return cmd
}

func newServiceUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall",
		Short: "Unload + remove the auto-start unit",
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := currentPlan()
			if err != nil {
				return err
			}
			for _, c := range plan.unloadCmd {
				runServiceCmd(cmd, c)
			}
			if err := os.Remove(plan.unitPath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("gbounce service: remove %s: %w", plan.unitPath, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "removed %s\n", plan.unitPath)
			return nil
		},
	}
}

func newServiceStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether the auto-start unit is installed",
		RunE: func(cmd *cobra.Command, args []string) error {
			plan, err := currentPlan()
			if err != nil {
				return err
			}
			if _, err := os.Stat(plan.unitPath); err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "installed: %s (%s)\n", plan.unitPath, plan.os)
			} else {
				fmt.Fprintf(cmd.OutOrStdout(), "not installed (would write %s). Run `gbounce service install`.\n", plan.unitPath)
			}
			return nil
		},
	}
}

// runServiceCmd runs an (un)load command best-effort, reporting on stderr.
// A missing launchctl/systemctl is a warning, not fatal — the unit file is
// already written + will take effect on next login.
func runServiceCmd(cmd *cobra.Command, argv []string) {
	if _, err := exec.LookPath(argv[0]); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "gbounce service: %q not found; unit written but not loaded (takes effect next login)\n", argv[0])
		return
	}
	c := exec.Command(argv[0], argv[1:]...)
	if out, err := c.CombinedOutput(); err != nil {
		msg := strings.TrimSpace(string(out))
		fmt.Fprintf(cmd.ErrOrStderr(), "gbounce service: `%s` warned: %v %s\n", strings.Join(argv, " "), err, msg)
	}
}
