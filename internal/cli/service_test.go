package cli

import (
	"strings"
	"testing"
)

func TestBuildServicePlan_DarwinLaunchAgent(t *testing.T) {
	p, err := buildServicePlan("darwin", "/usr/local/bin/gbounce", "/Users/x")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p.unitPath, "/Library/LaunchAgents/io.bounce.gbounce.plist") {
		t.Errorf("plist path = %s", p.unitPath)
	}
	for _, want := range []string{
		"<string>/usr/local/bin/gbounce</string>",
		"<string>run</string>",
		"<key>RunAtLoad</key><true/>",
		"<key>KeepAlive</key><true/>",
		serviceLabel,
	} {
		if !strings.Contains(p.content, want) {
			t.Errorf("plist missing %q", want)
		}
	}
	// no-sudo: load via launchctl (user domain), not sudo
	if p.loadCmd[len(p.loadCmd)-1][0] != "launchctl" {
		t.Errorf("darwin load must use launchctl; got %v", p.loadCmd)
	}
}

func TestBuildServicePlan_LinuxSystemdUser(t *testing.T) {
	p, err := buildServicePlan("linux", "/home/x/go/bin/gbounce", "/home/x")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p.unitPath, "/.config/systemd/user/gbounce.service") {
		t.Errorf("unit path = %s", p.unitPath)
	}
	if !strings.Contains(p.content, "ExecStart=/home/x/go/bin/gbounce run") {
		t.Errorf("unit missing ExecStart:\n%s", p.content)
	}
	if !strings.Contains(p.content, "Restart=on-failure") {
		t.Errorf("unit should restart on failure")
	}
	// no-sudo: systemctl --user
	joined := strings.Join(p.loadCmd[len(p.loadCmd)-1], " ")
	if !strings.Contains(joined, "systemctl --user") {
		t.Errorf("linux load must use systemctl --user; got %q", joined)
	}
}

func TestBuildServicePlan_UnsupportedOS(t *testing.T) {
	if _, err := buildServicePlan("windows", "gbounce.exe", "C:\\Users\\x"); err == nil {
		t.Error("unsupported OS must error")
	}
}
