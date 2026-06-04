package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestComplianceMapCmd_MapsSessionToControls(t *testing.T) {
	// A privilege-escalation allow + a destructive deny in one session.
	ib := fakeSessionBouncer(t,
		`{"time":1000,"api":{"operation":"iam:PutRolePolicy"},"unmapped":{"iam_jit":{"verdict":"allow","agent":{"session_id":"s7"}}}}`,
		`{"time":2000,"api":{"operation":"s3:DeleteBucket"},"unmapped":{"iam_jit":{"verdict":"deny","agent":{"session_id":"s7"}}}}`,
	)

	cmd := newComplianceMapCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{
		"--session", "s7",
		"--bouncer", "ibounce=" + ib.URL,
		"--format", "summary",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	s := out.String()
	// Least-privilege (deny) + priv-esc (PutRolePolicy) both touch NIST-AC-6.
	if !strings.Contains(s, "NIST-AC-6") {
		t.Errorf("expected NIST-AC-6 touched:\n%s", s)
	}
	// Honest disclaimer always present.
	if !strings.Contains(s, "NOT a certification") {
		t.Errorf("compliance summary must carry the honesty disclaimer:\n%s", s)
	}
	// Not partial (events present, single reachable bouncer).
	if strings.Contains(s, "no_events_observed") {
		t.Errorf("should have observed events:\n%s", s)
	}
}

func TestComplianceMapCmd_RequiresSessionAndValidFramework(t *testing.T) {
	cmd := newComplianceMapCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--format", "summary"})
	if err := cmd.Execute(); err == nil {
		t.Error("missing --session must error")
	}

	cmd2 := newComplianceMapCmd()
	cmd2.SetOut(&bytes.Buffer{})
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--session", "x", "--framework", "bogus"})
	if err := cmd2.Execute(); err == nil {
		t.Error("invalid --framework must error")
	}
}
