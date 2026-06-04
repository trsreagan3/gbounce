package cli

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

var ulidRe = regexp.MustCompile(`^dd_[0-9A-HJKMNP-TV-Z]{26}$`)

func TestGenDenyID_MatchesULIDShape(t *testing.T) {
	now := time.Date(2026, 6, 5, 1, 2, 3, 0, time.UTC)
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		id, err := genDenyID(now)
		if err != nil {
			t.Fatal(err)
		}
		if !ulidRe.MatchString(id) {
			t.Fatalf("id %q does not match dd_<26 crockford>", id)
		}
		if seen[id] {
			t.Fatalf("duplicate id %q (randomness broken)", id)
		}
		seen[id] = true
	}
}

func TestResolveTargetBouncers(t *testing.T) {
	cases := []struct {
		target string
		want   []string
		err    bool
	}{
		{"arn:aws:s3:::prod-bucket", []string{"ibounce"}, false},
		{"secret:prod/db", []string{"ibounce"}, false},
		{"namespace:kube-system", []string{"kbounce"}, false},
		{"rds:prod-pg", []string{"dbounce"}, false},
		{"https://evil.example.com", []string{"gbounce"}, false},
		{"evil.example.com", []string{"gbounce"}, false},
		{"prod-db.internal", []string{"dbounce", "gbounce"}, false}, // RDS-shaped host
		{"action:s3:DeleteObject", nil, true},                       // #74 — action target rejected
		{"???", nil, true},                                          // unroutable
	}
	for _, c := range cases {
		got, err := resolveTargetBouncers(c.target)
		if c.err {
			if err == nil {
				t.Errorf("%q: expected error", c.target)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.target, err)
			continue
		}
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%q -> %v; want %v", c.target, got, c.want)
		}
	}
}

func TestDenyAddListRemove_RoundTrip(t *testing.T) {
	path := t.TempDir() + "/dynamic-denies.yaml"

	// add (no bouncer reachable, so fan-out warns but the write succeeds)
	add := newDenyAddCmd()
	var out bytes.Buffer
	add.SetOut(&out)
	add.SetErr(&bytes.Buffer{})
	add.SetArgs([]string{"--target", "arn:aws:s3:::prod", "--reason", "incident-1", "--duration", "30m", "--path", path})
	if err := add.Execute(); err != nil {
		t.Fatalf("add: %v", err)
	}

	// Verify via loadDenyFile (reads ALL rules, like `deny list`). Note
	// gbounce's dynamicdeny.LoadFile would filter this out — it only loads
	// rules that apply to gbounce, and an ARN target routes to ibounce.
	f, err := loadDenyFile(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(f.Denies) != 1 {
		t.Fatalf("want 1 rule; got %d", len(f.Denies))
	}
	id := f.Denies[0].ID
	if !ulidRe.MatchString(id) {
		t.Errorf("bad rule id %q", id)
	}
	if strings.Join(f.Denies[0].AppliedTo, ",") != "ibounce" {
		t.Errorf("arn should route to ibounce; got %v", f.Denies[0].AppliedTo)
	}
	if f.Denies[0].ExpiresAt == nil {
		t.Errorf("30m duration should set expires_at")
	}

	// list shows it
	list := newDenyListCmd()
	var lout bytes.Buffer
	list.SetOut(&lout)
	list.SetErr(&bytes.Buffer{})
	list.SetArgs([]string{"--path", path})
	if err := list.Execute(); err != nil {
		t.Fatalf("list: %v", err)
	}
	if !strings.Contains(lout.String(), id) {
		t.Errorf("list missing rule %q:\n%s", id, lout.String())
	}

	// remove it
	rm := newDenyRemoveCmd()
	rm.SetOut(&bytes.Buffer{})
	rm.SetErr(&bytes.Buffer{})
	rm.SetArgs([]string{id, "--path", path})
	if err := rm.Execute(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	f2, _ := loadDenyFile(path)
	if len(f2.Denies) != 0 {
		t.Errorf("rule should be removed; got %d", len(f2.Denies))
	}
}

func TestDenyAdd_RejectsActionTarget(t *testing.T) {
	add := newDenyAddCmd()
	add.SetOut(&bytes.Buffer{})
	add.SetErr(&bytes.Buffer{})
	add.SetArgs([]string{"--target", "action:s3:DeleteObject", "--reason", "x", "--path", t.TempDir() + "/d.yaml"})
	if err := add.Execute(); err == nil {
		t.Fatal("action: target must be rejected (#74)")
	}
}
