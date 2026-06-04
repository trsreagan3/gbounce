package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestAuditQueryCmd_SummaryAndCSVAcrossBouncers(t *testing.T) {
	ib := fakeSessionBouncer(t, `{"time":2000,"api":{"operation":"s3:Get"},"unmapped":{"iam_jit":{"verdict":"deny"}}}`)
	gb := fakeSessionBouncer(t, `{"time":1000,"dst_endpoint":{"hostname":"api.github.com"},"unmapped":{"iam_jit":{"verdict":"allow"}}}`)

	// summary
	cmd := newAuditQueryCmd()
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs([]string{
		"--bouncer", "ibounce=" + ib.URL,
		"--bouncer", "gbounce=" + gb.URL,
		"--bouncer", "dbounce=http://127.0.0.1:1",
		"--format", "summary",
	})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	s := out.String()
	if !strings.Contains(s, "2 events") {
		t.Errorf("summary should count 2 events:\n%s", s)
	}
	if !strings.Contains(s, "ibounce") || !strings.Contains(s, "gbounce") {
		t.Errorf("summary should list both bouncers:\n%s", s)
	}
	// Unreachable bouncer must surface on stderr, not stdout.
	if !strings.Contains(errb.String(), "dbounce unreachable") {
		t.Errorf("expected dbounce coverage note on stderr; got %q", errb.String())
	}
	if strings.Contains(s, "unreachable") {
		t.Errorf("coverage notes must NOT pollute stdout:\n%s", s)
	}

	// csv
	cmd2 := newAuditQueryCmd()
	var out2 bytes.Buffer
	cmd2.SetOut(&out2)
	cmd2.SetErr(&bytes.Buffer{})
	cmd2.SetArgs([]string{"--bouncer", "ibounce=" + ib.URL, "--format", "csv"})
	if err := cmd2.Execute(); err != nil {
		t.Fatalf("csv execute: %v", err)
	}
	csv := out2.String()
	if !strings.HasPrefix(csv, "time,bouncer,protocol,verdict,action,principal,resources,reason") {
		t.Errorf("csv header wrong:\n%s", csv)
	}
	if !strings.Contains(csv, "ibounce,AWS,deny,s3:Get") {
		t.Errorf("csv row wrong:\n%s", csv)
	}
}
