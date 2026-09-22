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

func TestParseScreenLock(t *testing.T) {
	// Real macOS 26.6.2 output, including the sysadminctl timestamp/pid prefix.
	on := ptr("2026-09-21 20:50:02.423 sysadminctl[22746:23830390] screenLock delay is 5 seconds\n")
	off := ptr("2026-09-21 20:51:30.063 sysadminctl[22795:23833089] screenLock is off\n")

	enabled, secure := parseScreenLock(on)
	wantBool(t, enabled, boolp(true), "on/enabled")
	wantBool(t, secure, boolp(true), "on/secure")

	enabled, secure = parseScreenLock(off)
	wantBool(t, enabled, boolp(false), "off/enabled")
	wantBool(t, secure, boolp(false), "off/secure")

	enabled, secure = parseScreenLock(nil)
	wantBool(t, enabled, nil, "nil/enabled")
	wantBool(t, secure, nil, "nil/secure")

	enabled, secure = parseScreenLock(ptr("unexpected wording"))
	wantBool(t, enabled, nil, "unknown/enabled")
	wantBool(t, secure, nil, "unknown/secure")
}

func TestParsePmsetDisplaySleep(t *testing.T) {
	real := ptr(" Sleep On Power Button 1\n disksleep            10\n displaysleep         10\n")
	wantInt(t, parsePmsetDisplaySleep(real), intp(10), "real pmset -g")
	wantInt(t, parsePmsetDisplaySleep(ptr(" displaysleep         0\n")), intp(0), "never")
	wantInt(t, parsePmsetDisplaySleep(ptr("no match here")), nil, "missing")
	wantInt(t, parsePmsetDisplaySleep(nil), nil, "command failed")
}

func TestParseIntOutput(t *testing.T) {
	wantInt(t, parseIntOutput(ptr("3600\n")), intp(3600), "idleTime")
	wantInt(t, parseIntOutput(ptr("  42  ")), intp(42), "whitespace")
	wantInt(t, parseIntOutput(ptr("not a number")), nil, "non-integer (does not exist)")
	wantInt(t, parseIntOutput(nil), nil, "command failed")
}

func TestScreenLockMinutes(t *testing.T) {
	// Friend's Mac: display sleeps at 10 min, screensaver idle 3600s (60 min) ->
	// soonest darken is 10 min.
	wantInt(t, screenLockMinutes(intp(10), intp(3600)), intp(10), "min of both")
	wantInt(t, screenLockMinutes(nil, intp(3600)), intp(60), "idle only, rounded")
	wantInt(t, screenLockMinutes(intp(10), nil), intp(10), "display only")
	wantInt(t, screenLockMinutes(intp(0), intp(0)), intp(0), "both never -> too long")
	wantInt(t, screenLockMinutes(nil, nil), nil, "neither readable")
	wantInt(t, screenLockMinutes(intp(0), intp(90)), intp(2), "never display, 90s idle rounds up")
}

func intp(i int) *int { return &i }

func wantInt(t *testing.T, got *int, want *int, name string) {
	t.Helper()
	switch {
	case want == nil && got != nil:
		t.Errorf("%s: got %v, want nil", name, *got)
	case want != nil && got == nil:
		t.Errorf("%s: got nil, want %v", name, *want)
	case want != nil && got != nil && *want != *got:
		t.Errorf("%s: got %v, want %v", name, *got, *want)
	}
}
