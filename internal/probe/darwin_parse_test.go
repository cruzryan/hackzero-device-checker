package probe

import "testing"

// These fixtures are real output captured from macOS 26.6.2 (build 25G83), plus
// the standard "off" wording, so a future change to Apple's phrasing fails a
// test here instead of silently shipping a wrong verdict.

func ptr(s string) *string { return &s }

func wantBool(t *testing.T, got *bool, want *bool, name string) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s: got %v, want nil (unknown)", name, *got)
	case want != nil && got == nil:
		t.Errorf("%s: got nil (unknown), want %v", name, *want)
	case want != nil && got != nil && *want != *got:
		t.Errorf("%s: got %v, want %v", name, *got, *want)
	}
}

func boolp(b bool) *bool { return &b }

func TestParseAutomaticUpdates(t *testing.T) {
	cases := []struct {
		name string
		in   *string
		want *bool
	}{
		{"macos26 real on", ptr("Automatic checking for updates is turned on\n"), boolp(true)},
		{"standard off", ptr("Automatic checking for updates is turned off\n"), boolp(false)},
		{"case insensitive", ptr("AUTOMATIC CHECKING FOR UPDATES IS TURNED ON"), boolp(true)},
		{"legacy wording is unknown, not a false off", ptr("Automatic check is on"), nil},
		{"command failed", nil, nil},
		{"unrecognized", ptr("Password:\n"), nil},
	}
	for _, c := range cases {
		wantBool(t, parseAutomaticUpdates(c.in), c.want, c.name)
	}
}

func TestParseFileVault(t *testing.T) {
	cases := []struct {
		name string
		in   *string
		want *bool
	}{
		{"macos26 real on", ptr("FileVault is On.\n"), boolp(true)},
		{"off", ptr("FileVault is Off.\n"), boolp(false)},
		{"command failed", nil, nil},
		{"unrecognized", ptr("something else"), nil},
	}
	for _, c := range cases {
		wantBool(t, parseFileVault(c.in), c.want, c.name)
	}
}

func TestParseGatekeeper(t *testing.T) {
	cases := []struct {
		name string
		in   *string
		want *bool
	}{
		{"macos26 real enabled", ptr("assessments enabled\n"), boolp(true)},
		{"disabled", ptr("assessments disabled\n"), boolp(false)},
		{"command failed", nil, nil},
		{"unrecognized", ptr(""), nil},
	}
	for _, c := range cases {
		wantBool(t, parseGatekeeper(c.in), c.want, c.name)
	}
}
