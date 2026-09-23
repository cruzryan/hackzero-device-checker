package probe

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

// Fixtures below are real output captured on 2026-09-23 from a MacBook Air
// (macOS 26.5.2, build 25F84, arm64) and on 2026-09-21 from macOS 26.6.2, plus
// Apple's documented alternative wordings, so a change to Apple's phrasing
// fails a test here instead of silently shipping a wrong verdict.

func ptr(s string) *string { return &s }
func boolp(b bool) *bool   { return &b }
func intp(i int) *int      { return &i }

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

const realPmsetCustom = `Battery Power:
 Sleep On Power Button 1
 lowpowermode         0
 standby              1
 ttyskeepawake        1
 hibernatemode        3
 powernap             1
 hibernatefile        /var/vm/sleepimage
 displaysleep         2
 womp                 0
 networkoversleep     0
 sleep                1
 lessbright           1
 tcpkeepalive         1
 disksleep            10
AC Power:
 Sleep On Power Button 1
 lowpowermode         0
 standby              1
 ttyskeepawake        1
 hibernatemode        3
 powernap             1
 hibernatefile        /var/vm/sleepimage
 displaysleep         30
 womp                 1
 networkoversleep     0
 sleep                1
 tcpkeepalive         1
 disksleep            10
`

const realPmsetBatt = "Now drawing from 'AC Power'\n -InternalBattery-0 (id=23003235)\t87%; charging; 1:10 remaining present: true\n"

const realIdleUnset = "2026-09-23 12:35:20.603 defaults[69266:2988063] \nThe domain/default pair of (com.apple.screensaver, idleTime) does not exist\n"

// Real /Library/Preferences/com.apple.SoftwareUpdate.plist from the same Mac,
// in the JSON form `plutil -convert json` produces (trimmed to used keys).
const realSoftwareUpdateJSON = `{
  "AutomaticDownload": 1, "AutomaticallyInstallMacOSUpdates": 1,
  "ConfigDataInstall": 1, "CriticalUpdateInstall": 1,
  "FirstOfferDateDictionary": {
    "MSU_UPDATE_25F71_patch_26.5_minor": "2026-05-20T16:15:10Z",
    "MSU_UPDATE_25G229_patch_26.7_minor": "2026-09-15T01:36:31Z",
    "MSU_UPDATE_26A428_patch_27.0_major": "2026-09-15T01:36:31Z"
  },
  "LastSuccessfulDate": "2026-09-23T18:40:50Z",
  "RecommendedUpdates": [
    {"Display Name": "Safari", "Display Version": "27.0", "Identifier": "Safari27.0TahoeAuto", "Product Key": "047-48781"},
    {"Display Name": "macOS 27", "Display Version": 27, "Identifier": "MSU_UPDATE_26A428_patch_27.0_major", "MobileSoftwareUpdate": 1, "Product Key": "MSU_UPDATE_26A428_patch_27.0_major"},
    {"Display Name": "macOS Tahoe 26.7", "Display Version": "26.7", "Identifier": "MSU_UPDATE_25G229_patch_26.7_minor", "MobileSoftwareUpdate": 1, "Product Key": "MSU_UPDATE_25G229_patch_26.7_minor"}
  ]
}`

func TestParseFileVaultState(t *testing.T) {
	cases := []struct {
		name    string
		in      *string
		state   string
		percent *int
	}{
		{"macos26 real on", ptr("FileVault is On.\n"), posture.DiskOn, nil},
		{"off", ptr("FileVault is Off.\n"), posture.DiskOff, nil},
		{"encrypting", ptr("FileVault is On.\nEncryption in progress: Percent completed = 42\n"), posture.DiskEncrypting, intp(42)},
		{"decrypting", ptr("FileVault is On.\nDecryption in progress: Percent completed = 10\n"), posture.DiskDecrypting, intp(10)},
		{"pending restart", ptr("FileVault is Off, but will be enabled after the next restart.\n"), posture.DiskPendingRestart, nil},
		{"deferred", ptr("FileVault is Off.\nDeferred enablement appears to be active for user 'alex'.\n"), posture.DiskPendingRestart, nil},
	}
	for _, c := range cases {
		got := parseFileVaultState(c.in)
		if got == nil || got.State != c.state {
			t.Errorf("%s: got %#v", c.name, got)
			continue
		}
		wantInt(t, got.Percent, c.percent, c.name)
	}
	if parseFileVaultState(nil) != nil || parseFileVaultState(ptr("something else")) != nil {
		t.Error("unreadable FileVault must be unknown")
	}
}

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

func TestParseGatekeeper(t *testing.T) {
	wantBool(t, parseGatekeeper(ptr("assessments enabled\n")), boolp(true), "real enabled")
	wantBool(t, parseGatekeeper(ptr("assessments disabled\n")), boolp(false), "disabled")
	wantBool(t, parseGatekeeper(nil), nil, "command failed")
	wantBool(t, parseGatekeeper(ptr("")), nil, "unrecognized")
}

func TestParseSysadminctlScreenLock(t *testing.T) {
	cases := []struct {
		in       *string
		password string
		delay    *int
	}{
		{ptr("2026-09-23 12:35:20.615 sysadminctl[69267:2988066] screenLock delay is 300 seconds\n"), posture.PasswordDelay, intp(300)},
		{ptr("2026-09-23 13:23:41.638 sysadminctl[69945:3023679] screenLock delay is 28800 seconds\n"), posture.PasswordDelay, intp(28800)},
		{ptr("2026-09-21 20:50:02.423 sysadminctl[22746:23830390] screenLock delay is 5 seconds\n"), posture.PasswordDelay, intp(5)},
		{ptr("2026-09-23 13:27:31.636 sysadminctl[69987:3026189] screenLock delay is immediate\n"), posture.PasswordImmediate, intp(0)},
		{ptr("2026-09-23 13:27:16.197 sysadminctl[69968:3025938] screenLock is off\n"), posture.PasswordOff, nil},
		{ptr("unexpected wording"), posture.PasswordUnknown, nil},
		{nil, posture.PasswordUnknown, nil},
	}
	for _, c := range cases {
		password, delay := parseSysadminctlScreenLock(c.in)
		if password != c.password {
			t.Errorf("%v: password %s want %s", c.in, password, c.password)
		}
		wantInt(t, delay, c.delay, password)
	}
}

func TestParsePmsetCustom(t *testing.T) {
	profiles := parsePmsetCustom(ptr(realPmsetCustom))
	if len(profiles) != 2 || profiles[0].Power != posture.PowerBattery || profiles[1].Power != posture.PowerAC {
		t.Fatalf("profiles %#v", profiles)
	}
	wantInt(t, profiles[0].DisplayOffSeconds, intp(120), "battery")
	wantInt(t, profiles[1].DisplayOffSeconds, intp(1800), "ac")

	mini := parsePmsetCustom(ptr("AC Power:\n Sleep On Power Button 1\n displaysleep         10\n sleep                1\n"))
	if len(mini) != 1 || mini[0].Power != posture.PowerAC {
		t.Fatalf("mac mini %#v", mini)
	}
	ups := parsePmsetCustom(ptr("AC Power:\n displaysleep 10\nUPS Power:\n displaysleep 0\n"))
	if len(ups) != 2 || ups[1].Power != posture.PowerUPS {
		t.Fatalf("ups %#v", ups)
	}
	wantInt(t, ups[1].DisplayOffSeconds, intp(0), "ups never")
	missing := parsePmsetCustom(ptr("AC Power:\n sleep 1\n"))
	wantInt(t, missing[0].DisplayOffSeconds, nil, "no displaysleep line")
	if parsePmsetCustom(nil) != nil {
		t.Fatal("command failed must be nil")
	}
}

func TestParseActivePower(t *testing.T) {
	if got := parseActivePower(ptr(realPmsetBatt)); got != posture.PowerAC {
		t.Fatalf("got %q", got)
	}
	if got := parseActivePower(ptr("Now drawing from 'Battery Power'\n")); got != posture.PowerBattery {
		t.Fatalf("got %q", got)
	}
	if got := parseActivePower(nil); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestParseScreensaverIdle(t *testing.T) {
	value, known := parseScreensaverIdle(ptr(realIdleUnset))
	if value != nil || !known {
		t.Fatal("unset idleTime is known and excluded")
	}
	value, known = parseScreensaverIdle(ptr("300\n"))
	wantInt(t, value, intp(300), "300")
	value, known = parseScreensaverIdle(ptr("0\n"))
	wantInt(t, value, intp(0), "never")
	if _, known = parseScreensaverIdle(nil); known {
		t.Fatal("command failure is unknown")
	}
	if _, known = parseScreensaverIdle(ptr("garbage")); known {
		t.Fatal("garbage is unknown")
	}
}

func TestParseIntOutput(t *testing.T) {
	wantInt(t, parseIntOutput(ptr("5360\n")), intp(5360), "bundle version")
	wantInt(t, parseIntOutput(ptr("not a number")), nil, "non-integer")
	wantInt(t, parseIntOutput(nil), nil, "command failed")
}

func TestParseXProtect(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 45, 0, 0, time.UTC)
	version, age := parseXProtect(ptr("Version: 5360 Installed: 2026-09-18 21:53:58 +0000\n"), now)
	wantInt(t, version, intp(5360), "version")
	wantInt(t, age, intp(4), "age")
	version, age = parseXProtect(nil, now)
	wantInt(t, version, nil, "missing")
	wantInt(t, age, nil, "missing age")
}

func mustPlist(t *testing.T, text string) map[string]any {
	t.Helper()
	plist, err := decodePlistJSON([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return plist
}

func TestMacUpdateFacts(t *testing.T) {
	facts := macUpdateFacts(mustPlist(t, realSoftwareUpdateJSON), nil, boolp(true))
	for name, value := range map[string]*bool{"check": facts.Check, "download": facts.Download, "security": facts.SecurityResponses, "data": facts.SystemData, "os": facts.OSInstall} {
		wantBool(t, value, boolp(true), name+" (AutomaticCheckEnabled absent = default on)")
	}
	managed := map[string]any{"CriticalUpdateInstall": false, "AutomaticCheckEnabled": int64(0)}
	facts = macUpdateFacts(mustPlist(t, realSoftwareUpdateJSON), managed, nil)
	wantBool(t, facts.SecurityResponses, boolp(false), "managed wins")
	wantBool(t, facts.Check, boolp(false), "managed check")
	facts = macUpdateFacts(nil, nil, boolp(false))
	wantBool(t, facts.Check, boolp(false), "schedule only")
	wantBool(t, facts.Download, nil, "not read")
	if macUpdateFacts(nil, nil, nil) != nil {
		t.Fatal("nothing read must be nil")
	}
}

func TestMacPendingUpdatesExcludeMajorUpgrade(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 45, 0, 0, time.UTC)
	pending := macPendingUpdates(mustPlist(t, realSoftwareUpdateJSON), "26.5.2", now)
	// Safari 27.0 and macOS 26.7 count; macOS 27 is a major upgrade.
	wantInt(t, pending.Count, intp(2), "count")
	wantInt(t, pending.WaitingDays, intp(8), "offered 2026-09-15")

	noMarker := mustPlist(t, `{"RecommendedUpdates":[{"Identifier":"MSU_UPDATE_X","Display Version":"27.1","MobileSoftwareUpdate":true}]}`)
	wantInt(t, macPendingUpdates(noMarker, "26.5.2", now).Count, intp(0), "major by version")
	none := macPendingUpdates(map[string]any{}, "26.5.2", now)
	wantInt(t, none.Count, intp(0), "none")
	wantInt(t, none.WaitingDays, nil, "no wait")
}

func TestDecodePlistXMLFallback(t *testing.T) {
	xmlText := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AutomaticDownload</key><true/>
	<key>CriticalUpdateInstall</key><integer>0</integer>
	<key>LastSuccessfulDate</key><date>2026-09-23T18:40:50Z</date>
	<key>FirstOfferDateDictionary</key>
	<dict><key>MSU_UPDATE_25G229_patch_26.7_minor</key><date>2026-09-15T01:36:31Z</date></dict>
	<key>RecommendedUpdates</key>
	<array>
		<dict><key>Display Version</key><string>26.7</string><key>Identifier</key><string>MSU_UPDATE_25G229_patch_26.7_minor</string><key>MobileSoftwareUpdate</key><true/></dict>
	</array>
	<key>Blob</key><data>AAEC</data>
	<key>Ratio</key><real>1.5</real>
</dict>
</plist>`
	plist, err := decodePlistXML([]byte(xmlText))
	if err != nil {
		t.Fatal(err)
	}
	facts := macUpdateFacts(plist, nil, nil)
	wantBool(t, facts.Download, boolp(true), "xml true")
	wantBool(t, facts.SecurityResponses, boolp(false), "xml integer 0")
	pending := macPendingUpdates(plist, "26.5.2", time.Date(2026, 9, 23, 0, 0, 0, 0, time.UTC))
	wantInt(t, pending.Count, intp(1), "xml count")
	wantInt(t, pending.WaitingDays, intp(7), "xml date")
}

func TestManagedScreensaverWins(t *testing.T) {
	in := macInputs{
		ConsoleSession: true, PmsetCustom: ptr(realPmsetCustom), PmsetBatt: ptr(realPmsetBatt),
		Sysadminctl:        ptr("x sysadminctl[1:2] screenLock delay is 300 seconds\n"),
		ScreensaverIdle:    ptr(realIdleUnset),
		ManagedScreensaver: map[string]any{"idleTime": int64(600), "askForPasswordDelay": int64(0)},
	}
	facts := macScreenLock(in)
	wantInt(t, facts.ScreensaverSeconds, intp(600), "managed idle")
	if facts.Password != posture.PasswordImmediate {
		t.Fatalf("managed delay: %s", facts.Password)
	}
	in.ManagedScreensaver = map[string]any{"askForPassword": false}
	if macScreenLock(in).Password != posture.PasswordOff {
		t.Fatal("managed askForPassword=0 must be off")
	}
}

func TestConsoleSession(t *testing.T) {
	if !consoleSession(501, 501) || consoleSession(0, 0) || consoleSession(501, 502) {
		t.Fatal("console session guard")
	}
}

// End to end on the real captures: the MacBook Air on 2026-09-23 with battery
// display-off 2 min, AC 30 min, password after 300 s.
func TestMacObservationRealCapture(t *testing.T) {
	now := time.Date(2026, 9, 23, 18, 45, 26, 0, time.UTC)
	in := macInputs{
		ProductVersion:  ptr("26.5.2\n"),
		FileVault:       ptr("FileVault is On.\n"),
		ConsoleSession:  true,
		PmsetCustom:     ptr(realPmsetCustom),
		PmsetBatt:       ptr(realPmsetBatt),
		Sysadminctl:     ptr("2026-09-23 12:44:57.912 sysadminctl[69493:2996173] screenLock delay is 300 seconds\n"),
		ScreensaverIdle: ptr(realIdleUnset),
		SoftwareUpdate:  mustPlist(t, realSoftwareUpdateJSON),
		Schedule:        ptr("Automatic checking for updates is turned on\n"),
		Spctl:           ptr("assessments enabled\n"),
		XProtect:        ptr("Version: 5360 Installed: 2026-09-18 21:53:58 +0000\n"),
	}
	report := posture.Evaluate(macObservation(in, now), "darwin", "", "dev", now)
	data, _ := json.Marshal(report)
	want := `{"schema_version":1,"collected_at":"2026-09-23T18:45:26Z","platform":"darwin","os_version":"26.5.2","checker_version":"dev",` +
		`"disk_encryption":{"status":"pass","detail":{"state":"on"}},` +
		`"screen_lock":{"status":"fail","code":"screen_lock_timeout_too_long","detail":{"limit_minutes":15,"password":"delay","password_delay_seconds":300,"active_power":"ac","profiles":[{"power":"battery","display_off_minutes":2,"lock_minutes":7,"ok":true},{"power":"ac","display_off_minutes":30,"lock_minutes":35,"ok":false}]}},` +
		`"automatic_updates":{"status":"pass","detail":{"check":true,"download":true,"security_responses":true,"system_data":true,"os_install":true}},` +
		`"pending_maintenance":{"status":"needs_attention","code":"updates_pending","detail":{"count":2,"waiting_days":8}},` +
		`"endpoint_protection":{"status":"pass","detail":{"gatekeeper":true,"system_data_updates":true,"definitions_version":5360,"definitions_age_days":4}}}`
	if string(data) != want {
		t.Fatalf("\n got %s\nwant %s", data, want)
	}

	// Outside the console session the screen lock is unknown, not guessed.
	in.ConsoleSession = false
	if s := posture.Evaluate(macObservation(in, now), "darwin", "", "dev", now).ScreenLock; s.Status != posture.Unknown || s.Detail != nil {
		t.Fatalf("no console user: %#v", s)
	}
}
