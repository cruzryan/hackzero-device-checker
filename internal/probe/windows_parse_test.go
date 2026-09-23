package probe

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

const powercfgVideoIdle = `Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)
  GUID Alias: SCHEME_BALANCED
  Subgroup GUID: 7516b95f-f776-4464-8c53-06167f40cc99  (Display)
    GUID Alias: SUB_VIDEO
    Power Setting GUID: 3c0bc021-c8a8-4e07-a973-6b14cbcb2b7e  (Turn off display after)
      GUID Alias: VIDEOIDLE
      Minimum Possible Setting: 0x00000000
      Maximum Possible Setting: 0xffffffff
      Possible Settings increment: 0x00000001
      Possible Settings units: Seconds
    Current AC Power Setting Index: 0x00000258
    Current DC Power Setting Index: 0x0000012c
`

const powercfgConsoleLock = `Power Scheme GUID: 381b4222-f694-41f0-9685-ff5bb260df2e  (Balanced)
  GUID Alias: SCHEME_BALANCED
  Subgroup GUID: fea3413e-7e05-4911-9a71-700331f1c294  (Settings belonging to no subgroup)
    GUID Alias: SUB_NONE
    Power Setting GUID: 0e796bdb-100d-47d6-a2d5-f7d2daa51f51  (Require a password on wakeup)
      GUID Alias: CONSOLELOCK
      Possible Setting Index: 000
      Possible Setting Friendly Name: No
      Possible Setting Index: 001
      Possible Setting Friendly Name: Yes
    Current AC Power Setting Index: 0x00000001
    Current DC Power Setting Index: 0x00000001
`

// A Spanish-localized powercfg: labels differ, the hex values do not.
const powercfgSpanish = "GUID del esquema de energía: 381b4222  (Equilibrado)\n" +
	"    Índice de configuración de corriente alterna actual: 0x00000384\n" +
	"    Índice de configuración de corriente continua actual: 0x00000000\n"

func windowsJSON(t *testing.T, overrides map[string]any) []byte {
	t.Helper()
	base := map[string]any{
		"osVersion": "10.0.26200", "currentBuild": "26200",
		"bitlocker":              map[string]any{"protectionStatus": "On", "volumeStatus": "FullyEncrypted", "encryptionPercentage": 100},
		"policyScreenSaveActive": nil, "policyScreenSaverIsSecure": nil, "policyScreenSaveTimeOut": nil, "policyScreenSaverSet": nil,
		"userScreenSaveActive": "1", "userScreenSaverIsSecure": "0", "userScreenSaveTimeOut": "900", "userScreenSaverSet": nil,
		"delayLockInterval": nil, "inactivityTimeoutSecs": nil,
		"videoIdle": powercfgVideoIdle, "consoleLock": powercfgConsoleLock, "powerLine": "Offline",
		"notificationLevel": 0, "noAutoUpdate": nil, "auOptions": nil, "pauseExpiry": nil, "wuauservStartType": "Manual",
		"defender":  map[string]any{"realtime": true, "antivirusEnabled": true, "mode": "Normal", "signatureAge": 0},
		"antivirus": []any{map[string]any{"name": "Windows Defender", "guid": defenderGUID, "state": 397568}},
	}
	for key, value := range overrides {
		base[key] = value
	}
	data, err := json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func windowsReport(t *testing.T, overrides map[string]any) posture.Report {
	t.Helper()
	raw, err := parseWindowsJSON(windowsJSON(t, overrides))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 23, 12, 0, 0, 0, time.UTC)
	return posture.Evaluate(raw.observation(now), "windows", "", "dev", now)
}

func TestProductStateBits(t *testing.T) {
	cases := []struct {
		state            int
		enabled, current bool
	}{
		{397568, true, true},  // Defender on, up to date
		{266240, true, true},  // third-party on, up to date
		{393472, false, true}, // off
		{397584, true, false}, // on, out of date
	}
	for _, c := range cases {
		if avEnabled(c.state) != c.enabled || avUpToDate(c.state) != c.current {
			t.Errorf("%d: enabled=%v current=%v", c.state, avEnabled(c.state), avUpToDate(c.state))
		}
	}
}

func TestParsePowercfgACDC(t *testing.T) {
	ac, dc := parsePowercfgACDC(ptr(powercfgVideoIdle))
	wantInt(t, ac, intp(600), "ac")
	wantInt(t, dc, intp(300), "dc")
	ac, dc = parsePowercfgACDC(ptr(powercfgSpanish))
	wantInt(t, ac, intp(900), "localized ac")
	wantInt(t, dc, intp(0), "localized dc")
	ac, _ = parsePowercfgACDC(ptr("Invalid Parameters"))
	wantInt(t, ac, nil, "error text")
	ac, _ = parsePowercfgACDC(nil)
	wantInt(t, ac, nil, "not run")
}

func TestWindowsHealthyMachine(t *testing.T) {
	r := windowsReport(t, nil)
	data, _ := json.Marshal(r)
	want := `{"schema_version":1,"collected_at":"2026-09-23T12:00:00Z","platform":"windows","os_version":"10.0.26200","checker_version":"dev",` +
		`"disk_encryption":{"status":"pass","detail":{"state":"on"}},` +
		`"screen_lock":{"status":"pass","detail":{"limit_minutes":15,"password":"immediate","password_delay_seconds":0,"active_power":"battery","profiles":[{"power":"ac","display_off_minutes":10,"lock_minutes":10,"ok":true},{"power":"battery","display_off_minutes":5,"lock_minutes":5,"ok":true}]}},` +
		`"automatic_updates":{"status":"pass","detail":{"check":true,"download":true,"paused":false,"policy_disabled":false}},` +
		`"endpoint_protection":{"status":"pass","detail":{"defender_realtime":true,"defender_mode":"normal","other_antivirus":0,"definitions_age_days":0}}}`
	if string(data) != want {
		t.Fatalf("\n got %s\nwant %s", data, want)
	}
}

func TestWindowsBitLockerStates(t *testing.T) {
	cases := []struct {
		protection, volume string
		status             posture.Status
		code               string
	}{
		{"Off", "FullyEncrypted", posture.Fail, posture.CodeDiskSuspended},
		{"Off", "FullyDecrypted", posture.Fail, posture.CodeDiskDisabled},
		{"On", "EncryptionInProgress", posture.Pass, ""},
		{"Off", "DecryptionInProgress", posture.Fail, posture.CodeDiskDecrypting},
		{"Unknown", "FullyEncrypted", posture.Unknown, posture.CodeUnavailable},
	}
	for _, c := range cases {
		s := windowsReport(t, map[string]any{"bitlocker": map[string]any{"protectionStatus": c.protection, "volumeStatus": c.volume, "encryptionPercentage": 40}}).DiskEncryption
		if s.Status != c.status || s.Code != c.code {
			t.Errorf("%s/%s: %#v", c.protection, c.volume, s)
		}
	}
	if s := windowsReport(t, map[string]any{"bitlocker": nil}).DiskEncryption; s.Status != posture.Unknown {
		t.Errorf("unreadable BitLocker must be unknown: %#v", s)
	}
}

func TestWindowsScreenLockPaths(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]any
		status    posture.Status
		code      string
	}{
		{"inactivity limit as a DWORD", map[string]any{"consoleLock": nil, "inactivityTimeoutSecs": 600}, posture.Pass, ""},
		{"policy secure screen saver overrides user", map[string]any{"consoleLock": nil, "policyScreenSaveActive": "1", "policyScreenSaverIsSecure": "1", "policyScreenSaveTimeOut": "600", "policyScreenSaverSet": true}, posture.Pass, ""},
		{"insecure user screen saver and no sign-in on wake", map[string]any{"userScreenSaverSet": true, "consoleLock": strings.ReplaceAll(powercfgConsoleLock, "0x00000001", "0x00000000")}, posture.Fail, posture.CodeScreenLockPasswordOff},
		{"display never on battery", map[string]any{"videoIdle": powercfgSpanish}, posture.Fail, posture.CodeScreenLockNever},
		{"sign-in delay pushes past the limit", map[string]any{"delayLockInterval": 360}, posture.Fail, posture.CodeScreenLockTooLong},
		{"sign-in never (DWORD 0xFFFFFFFF read as -1)", map[string]any{"delayLockInterval": -1}, posture.Fail, posture.CodeScreenLockPasswordOff},
		{"sign-in never (unsigned)", map[string]any{"delayLockInterval": 4294967295}, posture.Fail, posture.CodeScreenLockPasswordOff},
		{"hidden CONSOLELOCK read on a Modern Standby laptop, display never on AC, unreadable saver security", map[string]any{
			"videoIdle":         strings.ReplaceAll(strings.ReplaceAll(powercfgVideoIdle, "0x00000258", "0x00000000"), "0x0000012c", "0x000000b4"),
			"delayLockInterval": 900, "userScreenSaverSet": true, "userScreenSaverIsSecure": nil, "userScreenSaveTimeOut": "300",
		}, posture.Unknown, posture.CodeUnavailable},
		{"powercfg failed and nothing else", map[string]any{"videoIdle": nil}, posture.Unknown, posture.CodeUnavailable},
	}
	for _, c := range cases {
		s := windowsReport(t, c.overrides).ScreenLock
		if s.Status != c.status || s.Code != c.code {
			data, _ := json.Marshal(s)
			t.Errorf("%s: %s", c.name, data)
		}
	}
}

func TestWindowsUpdates(t *testing.T) {
	cases := []struct {
		name      string
		overrides map[string]any
		code      string
	}{
		{"default automatic", nil, ""},
		{"NoAutoUpdate policy", map[string]any{"noAutoUpdate": 1}, posture.CodeUpdatesDisabled},
		{"AUOptions notify only", map[string]any{"auOptions": 2}, posture.CodeUpdatesDisabled},
		{"AUOptions auto", map[string]any{"auOptions": 4, "notificationLevel": 1}, ""},
		{"service disabled", map[string]any{"wuauservStartType": "Disabled"}, posture.CodeUpdatesDisabled},
		{"paused into the future", map[string]any{"pauseExpiry": "2026-10-01T07:00:00Z"}, posture.CodeUpdatesPaused},
		{"pause expired", map[string]any{"pauseExpiry": "2026-09-01T07:00:00Z"}, ""},
		{"notification level disabled", map[string]any{"notificationLevel": 1}, posture.CodeUpdatesDisabled},
	}
	for _, c := range cases {
		s := windowsReport(t, c.overrides).AutomaticUpdates
		if s.Code != c.code {
			data, _ := json.Marshal(s)
			t.Errorf("%s: %s", c.name, data)
		}
	}
}

func TestWindowsEndpointProtection(t *testing.T) {
	sentinel := map[string]any{"name": "Sentinel Agent", "guid": "{1C6A3B1A-0000-0000-0000-000000000000}", "state": 266240}
	defenderPassive := map[string]any{"name": "Windows Defender", "guid": defenderGUID, "state": 393472}
	cases := []struct {
		name      string
		overrides map[string]any
		status    posture.Status
		other     int
	}{
		{"defender normal", nil, posture.Pass, 0},
		{"sentinelone with passive defender", map[string]any{
			"defender":  map[string]any{"realtime": false, "antivirusEnabled": false, "mode": "Passive Mode", "signatureAge": 30},
			"antivirus": []any{defenderPassive, sentinel},
		}, posture.Pass, 1},
		{"single product object", map[string]any{
			"defender":  map[string]any{"realtime": false, "antivirusEnabled": false, "mode": "Not running", "signatureAge": 3},
			"antivirus": sentinel,
		}, posture.Pass, 1},
		{"defender off, third party out of date", map[string]any{
			"defender":  map[string]any{"realtime": false, "antivirusEnabled": true, "mode": "Normal", "signatureAge": 1},
			"antivirus": []any{defenderPassive, map[string]any{"name": "Other AV", "guid": "{X}", "state": 397584}},
		}, posture.Fail, 0},
		{"old defender definitions still pass", map[string]any{
			"defender": map[string]any{"realtime": true, "antivirusEnabled": true, "mode": "Normal", "signatureAge": 9},
		}, posture.Pass, 0},
		{"nothing readable", map[string]any{"defender": nil, "antivirus": nil}, posture.Unknown, -1},
	}
	for _, c := range cases {
		s := windowsReport(t, c.overrides).EndpointProtection
		if s.Status != c.status || len(s.Warnings) != 0 {
			data, _ := json.Marshal(s)
			t.Errorf("%s: %s", c.name, data)
			continue
		}
		if c.other >= 0 {
			d, err := posture.DecodeDetail[posture.EndpointDetail](s.Detail)
			if err != nil || d.OtherAntivirus == nil || *d.OtherAntivirus != c.other {
				t.Errorf("%s: other antivirus %#v %v", c.name, d.OtherAntivirus, err)
			}
		}
	}
}

func TestWindowsReportIsSignatureSafe(t *testing.T) {
	// Product names and localized text in the script output never reach the
	// report: only ints, bools and fixed enum strings do.
	r := windowsReport(t, map[string]any{
		"osVersion": "10.0.26200 <script>&é",
		"antivirus": []any{map[string]any{"name": "Antivirus <Élite> & Co", "guid": "{X}", "state": 266240}},
		"defender":  map[string]any{"realtime": true, "antivirusEnabled": true, "mode": "Mode <étrange>", "signatureAge": 1},
		"videoIdle": powercfgSpanish,
	})
	data, _ := json.Marshal(r)
	for i, b := range data {
		if b >= 0x80 || b == '<' || b == '>' || b == '&' {
			t.Fatalf("unsafe byte %q at %d: %s", b, i, data)
		}
	}
}

func TestWindowsScriptIsReadOnly(t *testing.T) {
	lowered := strings.ToLower(windowsScript)
	for _, verb := range []string{"set-", "new-item", "remove-", "enable-", "disable-", "invoke-webrequest", "start-process", "/set", "/change", "/s "} {
		if strings.Contains(lowered, verb) {
			t.Errorf("script contains a mutating or network verb %q", verb)
		}
	}
}
