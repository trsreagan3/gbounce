package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// roundTripFunc lets a test inject a mock http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVersion_StampOutput(t *testing.T) {
	old := version
	defer func() { version = old }()
	version = "1.2.3"
	got := versionString()
	if !strings.HasPrefix(got, "gbounce 1.2.3 ") {
		t.Errorf("versionString = %q", got)
	}
}

func TestRootCmd_VersionFlag(t *testing.T) {
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"--version"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.HasPrefix(buf.String(), "gbounce ") {
		t.Errorf("--version output = %q", buf.String())
	}
}

func TestRootCmd_HelpDoesNotErr(t *testing.T) {
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute --help: %v", err)
	}
	if !strings.Contains(buf.String(), "forward proxy") {
		t.Errorf("help missing description: %q", buf.String())
	}
}

func TestRunCmd_RequiresUpstreamOrConnect(t *testing.T) {
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"run"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when neither --upstream nor --allow-connect is set")
	}
	if !strings.Contains(err.Error(), "--upstream") {
		t.Errorf("err = %v", err)
	}
}

func TestRunCmd_RefusesNonLoopback(t *testing.T) {
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"run", "--upstream", "http://example.com", "--host", "0.0.0.0", "--port", "0", "--mgmt-port", "0"})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when binding non-loopback without ack flag")
	}
	if !strings.Contains(err.Error(), "non-loopback") {
		t.Errorf("err = %v", err)
	}
}

func TestAuditTail_EmptyMessage(t *testing.T) {
	dir := t.TempDir()
	root := newRootCmd()
	buf := &bytes.Buffer{}
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs([]string{"audit", "tail", "--db", filepath.Join(dir, "state.db")})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(buf.String(), "(no decisions recorded yet)") {
		t.Errorf("output = %q", buf.String())
	}
}

func TestVersionCheck_DisabledByEnv(t *testing.T) {
	t.Setenv(versionCheckEnvVar, "1")
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := runVersionCheck(context.Background(), stdout, stderr); err != nil {
		t.Fatalf("runVersionCheck: %v", err)
	}
	if !strings.Contains(stdout.String(), "disabled by env") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestVersionCheck_UpToDate(t *testing.T) {
	t.Setenv(versionCheckEnvVar, "")
	oldVer := version
	defer func() { version = oldVer }()
	version = "1.0.0"

	oldT := versionCheckTransport
	defer func() { versionCheckTransport = oldT }()
	versionCheckTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body := `{"tag_name": "v1.0.0"}`
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader(body)),
			Header:     http.Header{},
		}, nil
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := runVersionCheck(context.Background(), stdout, stderr); err != nil {
		t.Fatalf("runVersionCheck: %v", err)
	}
	if !strings.Contains(stdout.String(), "is up to date") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestVersionCheck_OutOfDate(t *testing.T) {
	t.Setenv(versionCheckEnvVar, "")
	oldVer := version
	defer func() { version = oldVer }()
	version = "1.0.0"

	oldT := versionCheckTransport
	defer func() { versionCheckTransport = oldT }()
	versionCheckTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		body, _ := json.Marshal(map[string]string{"tag_name": "v2.0.0"})
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     http.Header{},
		}, nil
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := runVersionCheck(context.Background(), stdout, stderr); err != nil {
		t.Fatalf("runVersionCheck: %v", err)
	}
	if !strings.Contains(stdout.String(), "OUT OF DATE") {
		t.Errorf("stdout = %q", stdout.String())
	}
}

func TestVersionCheck_NetworkErrorExits0(t *testing.T) {
	t.Setenv(versionCheckEnvVar, "")
	oldT := versionCheckTransport
	defer func() { versionCheckTransport = oldT }()
	versionCheckTransport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		return nil, http.ErrHandlerTimeout
	})
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	if err := runVersionCheck(context.Background(), stdout, stderr); err != nil {
		t.Fatalf("runVersionCheck should return nil on network error; got %v", err)
	}
	if !strings.Contains(stderr.String(), "version check failed") {
		t.Errorf("stderr = %q", stderr.String())
	}
}

func TestParseSemver(t *testing.T) {
	cases := map[string]bool{
		"1.2.3":   true,
		"0.0.0":   true,
		"":        false,
		"1.2":     false,
		"1.2.3.4": false,
		"a.b.c":   false,
		"-1.0.0":  false,
	}
	for in, wantOK := range cases {
		_, ok := parseSemver(in)
		if ok != wantOK {
			t.Errorf("parseSemver(%q) ok=%v; want %v", in, ok, wantOK)
		}
	}
}

func TestCompareSemver(t *testing.T) {
	if compareSemver([3]int{1, 0, 0}, [3]int{1, 0, 0}) != 0 {
		t.Error("equal")
	}
	if compareSemver([3]int{1, 0, 0}, [3]int{2, 0, 0}) >= 0 {
		t.Error("1 < 2")
	}
	if compareSemver([3]int{2, 0, 0}, [3]int{1, 0, 0}) <= 0 {
		t.Error("2 > 1")
	}
}
