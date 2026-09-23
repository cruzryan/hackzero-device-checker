package posture

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

func secs(minutes int) *int { v := minutes * 60; return &v }
func ip(v int) *int         { return &v }
func bp(v bool) *bool       { return &v }

func macLock(password string, delay *int, profiles ...ProfileFacts) *ScreenLockFacts {
	return &ScreenLockFacts{Password: password, PasswordDelaySeconds: delay, ScreensaverKnown: true, ActivePower: PowerBattery, Profiles: profiles}
}

func lockDetail(t *testing.T, s Signal) ScreenLockDetail {
	t.Helper()
	d, err := DecodeDetail[ScreenLockDetail](s.Detail)
	if err != nil {
		t.Fatalf("screen lock detail: %v (%#v)", err, s)
	}
	return d
}

func evalLock(f *ScreenLockFacts) Signal {
	return Evaluate(Observation{ScreenLock: f}, "darwin", "26.5.2", "dev", time.Now()).ScreenLock
}

// The real MacBook Air from 2026-09-23: battery display-off 2 min, AC 30 min,
// password 300 s after sleep, no screen saver set.
func TestMacBatteryTwoACThirtyDelayFiveMinutesFails(t *testing.T) {
	s := evalLock(macLock(PasswordDelay, ip(300), ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(30)}))
	if s.Status != Fail || s.Code != CodeScreenLockTooLong {
		t.Fatalf("got %#v", s)
	}
	got, _ := json.Marshal(s)
	want := `{"status":"fail","code":"screen_lock_timeout_too_long","detail":{"limit_minutes":15,"password":"delay","password_delay_seconds":300,"active_power":"battery","profiles":[{"power":"battery","display_off_minutes":2,"lock_minutes":7,"ok":true},{"power":"ac","display_off_minutes":30,"lock_minutes":35,"ok":false}]}}`
	if string(got) != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestMacScreenLockRules(t *testing.T) {
	cases := []struct {
		name     string
		facts    *ScreenLockFacts
		status   Status
		code     string
		lockMins []int // per profile; -1 = absent
	}{
		{"battery 2 / ac 5 / delay 300 passes", macLock(PasswordDelay, ip(300), ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(5)}), Pass, "", []int{7, 10}},
		{"exactly 15 passes", macLock(PasswordDelay, ip(300), ProfileFacts{PowerAC, secs(10)}), Pass, "", []int{15}},
		{"16 fails", macLock(PasswordDelay, ip(300), ProfileFacts{PowerAC, secs(11)}), Fail, CodeScreenLockTooLong, []int{16}},
		{"5 s delay counts as immediate", macLock(PasswordDelay, ip(5), ProfileFacts{PowerAC, secs(15)}), Pass, "", []int{15}},
		{"6 s delay counts", macLock(PasswordDelay, ip(6), ProfileFacts{PowerAC, secs(15)}), Fail, CodeScreenLockTooLong, []int{16}},
		{"8 hour delay fails", macLock(PasswordDelay, ip(28800), ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(5)}), Fail, CodeScreenLockTooLong, []int{482, 485}},
		{"immediate passes", macLock(PasswordImmediate, ip(0), ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(10)}), Pass, "", []int{2, 10}},
		{"ac never fails as never", macLock(PasswordDelay, ip(300), ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(0)}), Fail, CodeScreenLockNever, []int{7, 0}},
		{"password off fails", macLock(PasswordOff, nil, ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(5)}), Fail, CodeScreenLockPasswordOff, []int{0, 0}},
		{"mac mini only ac", macLock(PasswordImmediate, ip(0), ProfileFacts{PowerAC, secs(10)}), Pass, "", []int{10}},
		{"ups profile counts", macLock(PasswordImmediate, ip(0), ProfileFacts{PowerAC, secs(10)}, ProfileFacts{PowerUPS, secs(20)}), Fail, CodeScreenLockTooLong, []int{10, 20}},
		{"password unknown, short display is unknown", macLock(PasswordUnknown, nil, ProfileFacts{PowerAC, secs(2)}), Unknown, CodeUnavailable, []int{-1}},
		{"password unknown, never still fails", macLock(PasswordUnknown, nil, ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(0)}), Fail, CodeScreenLockNever, []int{-1, 0}},
		{"password unknown, 30 min display is definitely too long", macLock(PasswordUnknown, nil, ProfileFacts{PowerAC, secs(30)}), Fail, CodeScreenLockTooLong, []int{-1}},
		{"unreadable display is unknown", macLock(PasswordImmediate, ip(0), ProfileFacts{PowerAC, nil}), Unknown, CodeUnavailable, []int{-1}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := evalLock(c.facts)
			if s.Status != c.status || s.Code != c.code {
				t.Fatalf("got %s/%s want %s/%s", s.Status, s.Code, c.status, c.code)
			}
			d := lockDetail(t, s)
			if len(d.Profiles) != len(c.lockMins) {
				t.Fatalf("profiles %d want %d", len(d.Profiles), len(c.lockMins))
			}
			for i, want := range c.lockMins {
				p := d.Profiles[i]
				switch {
				case want < 0 && p.LockMinutes != nil:
					t.Errorf("profile %d lock %d want absent", i, *p.LockMinutes)
				case want >= 0 && (p.LockMinutes == nil || *p.LockMinutes != want):
					t.Errorf("profile %d lock %v want %d", i, p.LockMinutes, want)
				}
				if p.OK != (want > 0 && want <= LimitMinutes) {
					t.Errorf("profile %d ok=%v", i, p.OK)
				}
			}
		})
	}
}

func TestMacScreenSaverShortensTheLock(t *testing.T) {
	f := macLock(PasswordImmediate, ip(0), ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(30)})
	f.ScreensaverSeconds = ip(300)
	s := evalLock(f)
	if s.Status != Pass {
		t.Fatalf("got %#v", s)
	}
	d := lockDetail(t, s)
	if d.ScreensaverMinutes == nil || *d.ScreensaverMinutes != 5 || *d.Profiles[1].LockMinutes != 5 {
		t.Fatalf("detail %#v", d)
	}
	// A screen saver set to never is excluded, not treated as zero minutes.
	f.ScreensaverSeconds = ip(0)
	if s := evalLock(f); s.Code != CodeScreenLockTooLong || *lockDetail(t, s).ScreensaverMinutes != 0 {
		t.Fatalf("never screen saver: %#v", s)
	}
}

func TestUnreadableScreenSaverCannotProduceAFalseFail(t *testing.T) {
	f := macLock(PasswordImmediate, ip(0), ProfileFacts{PowerAC, secs(30)})
	f.ScreensaverKnown = false
	if s := evalLock(f); s.Status != Unknown {
		t.Fatalf("got %#v", s)
	}
	// ...but a short display timer still proves the pass.
	f.Profiles = []ProfileFacts{{PowerAC, secs(3)}}
	if s := evalLock(f); s.Status != Pass {
		t.Fatalf("got %#v", s)
	}
}

func TestNoTimingReadIsUnknownWithoutDetailOrWithPassword(t *testing.T) {
	if s := evalLock(&ScreenLockFacts{Password: PasswordUnknown, ScreensaverKnown: true}); s.Status != Unknown || s.Detail != nil {
		t.Fatalf("got %#v", s)
	}
	if s := evalLock(&ScreenLockFacts{Password: PasswordOff}); s.Status != Fail || s.Code != CodeScreenLockPasswordOff {
		t.Fatalf("password off must fail even without timers: %#v", s)
	}
}

func winLock(mod func(*WindowsScreenLockFacts)) Signal {
	f := &WindowsScreenLockFacts{
		ScreensaverConfigured: bp(false),
		DisplayOffACSeconds:   ip(600), DisplayOffDCSeconds: ip(300),
		ConsoleLockAC: bp(true), ConsoleLockDC: bp(true),
		ActivePower: PowerAC,
	}
	mod(f)
	return Evaluate(Observation{WindowsScreenLock: f}, "windows", "10.0.26200", "dev", time.Now()).ScreenLock
}

func TestWindowsScreenLockRules(t *testing.T) {
	cases := []struct {
		name   string
		mod    func(*WindowsScreenLockFacts)
		status Status
		code   string
		powers []string
	}{
		{"display-off with sign-in on wake", func(*WindowsScreenLockFacts) {}, Pass, "", []string{PowerAC, PowerBattery}},
		{"delay added", func(f *WindowsScreenLockFacts) { f.DelayLockSeconds = ip(360) }, Fail, CodeScreenLockTooLong, []string{PowerAC, PowerBattery}},
		{"ac never", func(f *WindowsScreenLockFacts) { f.DisplayOffACSeconds = ip(0) }, Fail, CodeScreenLockNever, []string{PowerAC, PowerBattery}},
		{"no sign-in on wake", func(f *WindowsScreenLockFacts) { f.ConsoleLockAC, f.ConsoleLockDC = bp(false), bp(false) }, Fail, CodeScreenLockPasswordOff, []string{PowerAC, PowerBattery}},
		{"too long", func(f *WindowsScreenLockFacts) { f.DisplayOffACSeconds = ip(1800) }, Fail, CodeScreenLockTooLong, []string{PowerAC, PowerBattery}},
		{"inactivity limit wins", func(f *WindowsScreenLockFacts) {
			f.DisplayOffACSeconds = ip(0)
			f.InactivitySeconds = ip(900)
		}, Pass, "", []string{PowerAny}},
		{"secure screen saver wins", func(f *WindowsScreenLockFacts) {
			f.ConsoleLockAC, f.ConsoleLockDC = bp(false), bp(false)
			f.ScreensaverConfigured, f.ScreensaverActive, f.ScreensaverSecure, f.ScreensaverSeconds = bp(true), bp(true), bp(true), ip(600)
		}, Pass, "", []string{PowerAny}},
		{"insecure screen saver does not count", func(f *WindowsScreenLockFacts) {
			f.ConsoleLockAC, f.ConsoleLockDC = bp(false), bp(false)
			f.ScreensaverConfigured, f.ScreensaverActive, f.ScreensaverSecure, f.ScreensaverSeconds = bp(true), bp(true), bp(false), ip(600)
		}, Fail, CodeScreenLockPasswordOff, []string{PowerAC, PowerBattery}},
		{"powercfg unreadable", func(f *WindowsScreenLockFacts) { f.ConsoleLockAC = nil }, Unknown, CodeUnavailable, []string{PowerAny}},
		{"screen saver keys missing", func(f *WindowsScreenLockFacts) {
			f.DisplayOffACSeconds = ip(1800)
			f.ScreensaverConfigured, f.ScreensaverActive = bp(true), nil
		}, Unknown, CodeUnavailable, []string{PowerAC, PowerBattery}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := winLock(c.mod)
			if s.Status != c.status || s.Code != c.code {
				t.Fatalf("got %s/%s want %s/%s: %s", s.Status, s.Code, c.status, c.code, mustJSON(s))
			}
			d := lockDetail(t, s)
			if len(d.Profiles) != len(c.powers) {
				t.Fatalf("profiles %s", mustJSON(d))
			}
			for i, p := range c.powers {
				if d.Profiles[i].Power != p {
					t.Errorf("profile %d power %s want %s", i, d.Profiles[i].Power, p)
				}
			}
		})
	}
}

func TestDiskStates(t *testing.T) {
	cases := []struct {
		state  string
		status Status
		code   string
	}{
		{DiskOn, Pass, ""}, {DiskEncrypting, Pass, ""}, {DiskOff, Fail, CodeDiskDisabled},
		{DiskPendingRestart, Fail, CodeDiskDisabled}, {DiskDecrypting, Fail, CodeDiskDecrypting},
		{DiskSuspended, Fail, CodeDiskSuspended}, {"weird", Unknown, CodeUnavailable},
	}
	for _, c := range cases {
		s := Evaluate(Observation{Disk: &DiskFacts{State: c.state, Percent: ip(42)}}, "darwin", "", "", time.Now()).DiskEncryption
		if s.Status != c.status || s.Code != c.code {
			t.Errorf("%s: got %s/%s", c.state, s.Status, s.Code)
		}
	}
	s := Evaluate(Observation{Disk: &DiskFacts{State: DiskEncrypting, Percent: ip(42)}}, "darwin", "", "", time.Now()).DiskEncryption
	if mustJSON(s) != `{"status":"pass","detail":{"state":"encrypting","percent":42}}` {
		t.Fatal(mustJSON(s))
	}
	s = Evaluate(Observation{Disk: &DiskFacts{State: DiskOn, Percent: ip(100)}}, "darwin", "", "", time.Now()).DiskEncryption
	if mustJSON(s) != `{"status":"pass","detail":{"state":"on"}}` {
		t.Fatal(mustJSON(s))
	}
}

func TestMacUpdatesRequireCheckDownloadAndSecurityResponses(t *testing.T) {
	all := func() *UpdateFacts {
		return &UpdateFacts{Check: bp(true), Download: bp(true), SecurityResponses: bp(true), SystemData: bp(true), OSInstall: bp(false)}
	}
	s := Evaluate(Observation{Updates: all()}, "darwin", "", "", time.Now()).AutomaticUpdates
	if s.Status != Pass {
		t.Fatalf("os_install is not required: %s", mustJSON(s))
	}
	f := all()
	f.SecurityResponses = bp(false)
	if s := Evaluate(Observation{Updates: f}, "darwin", "", "", time.Now()).AutomaticUpdates; s.Code != CodeUpdatesDisabled {
		t.Fatal(mustJSON(s))
	}
	f = all()
	f.SystemData = bp(false)
	if s := Evaluate(Observation{Updates: f}, "darwin", "", "", time.Now()).AutomaticUpdates; s.Status != Pass {
		t.Fatalf("system data belongs to endpoint protection: %s", mustJSON(s))
	}
	if s := Evaluate(Observation{Updates: &UpdateFacts{Check: bp(true)}}, "darwin", "", "", time.Now()).AutomaticUpdates; s.Status != Unknown || mustJSON(s.Detail) != `{"check":true}` {
		t.Fatalf("partial read must be unknown: %s", mustJSON(s))
	}
	if s := Evaluate(Observation{Updates: &UpdateFacts{Check: bp(false)}}, "darwin", "", "", time.Now()).AutomaticUpdates; s.Code != CodeUpdatesDisabled {
		t.Fatalf("definite fail beats unknown: %s", mustJSON(s))
	}
}

func TestWindowsUpdates(t *testing.T) {
	base := func() *UpdateFacts {
		return &UpdateFacts{Check: bp(true), Download: bp(true), Paused: bp(false), PolicyDisabled: bp(false)}
	}
	if s := Evaluate(Observation{Updates: base()}, "windows", "", "", time.Now()).AutomaticUpdates; s.Status != Pass {
		t.Fatal(mustJSON(s))
	}
	f := base()
	f.Paused = bp(true)
	if s := Evaluate(Observation{Updates: f}, "windows", "", "", time.Now()).AutomaticUpdates; s.Code != CodeUpdatesPaused {
		t.Fatal(mustJSON(s))
	}
	f.PolicyDisabled = bp(true)
	if s := Evaluate(Observation{Updates: f}, "windows", "", "", time.Now()).AutomaticUpdates; s.Code != CodeUpdatesDisabled {
		t.Fatal(mustJSON(s))
	}
}

func TestPendingIsAWarningOnly(t *testing.T) {
	s := Evaluate(Observation{Pending: &PendingFacts{Count: ip(2), WaitingDays: ip(8)}}, "darwin", "", "", time.Now()).PendingMaintenance
	if mustJSON(s) != `{"status":"needs_attention","code":"updates_pending","detail":{"count":2,"waiting_days":8}}` {
		t.Fatal(mustJSON(s))
	}
	s = Evaluate(Observation{Pending: &PendingFacts{Count: ip(0)}}, "darwin", "", "", time.Now()).PendingMaintenance
	if mustJSON(s) != `{"status":"pass","detail":{"count":0}}` {
		t.Fatal(mustJSON(s))
	}
	if s := Evaluate(Observation{Pending: &PendingFacts{}}, "darwin", "", "", time.Now()).PendingMaintenance; s.Status != Unknown {
		t.Fatal(mustJSON(s))
	}
}

func TestMacEndpoint(t *testing.T) {
	ok := EndpointFacts{Gatekeeper: bp(true), SystemDataUpdates: bp(true), DefinitionsVersion: ip(5360), DefinitionsAgeDays: ip(4)}
	eval := func(f EndpointFacts) Signal {
		return Evaluate(Observation{Endpoint: &f}, "darwin", "", "", time.Now()).EndpointProtection
	}
	if s := eval(ok); mustJSON(s) != `{"status":"pass","detail":{"gatekeeper":true,"system_data_updates":true,"definitions_version":5360,"definitions_age_days":4}}` {
		t.Fatal(mustJSON(s))
	}
	stale := ok
	stale.DefinitionsAgeDays = ip(31)
	if s := eval(stale); s.Status != Pass || len(s.Warnings) != 1 || s.Warnings[0] != WarningDefinitionsStale {
		t.Fatalf("stale definitions warn, never fail: %s", mustJSON(s))
	}
	edge := ok
	edge.DefinitionsAgeDays = ip(30)
	if s := eval(edge); len(s.Warnings) != 0 {
		t.Fatal("30 days is not stale")
	}
	gk := ok
	gk.Gatekeeper = bp(false)
	if s := eval(gk); s.Code != CodeGatekeeperDisabled {
		t.Fatal(mustJSON(s))
	}
	data := ok
	data.SystemDataUpdates = bp(false)
	if s := eval(data); s.Code != CodeDefinitionsUpdatesOff {
		t.Fatal(mustJSON(s))
	}
	missing := ok
	missing.Gatekeeper = nil
	if s := eval(missing); s.Status != Unknown {
		t.Fatal(mustJSON(s))
	}
}

func TestWindowsEndpoint(t *testing.T) {
	eval := func(f EndpointFacts) Signal {
		return Evaluate(Observation{Endpoint: &f}, "windows", "", "", time.Now()).EndpointProtection
	}
	cases := []struct {
		name   string
		f      EndpointFacts
		status Status
		warn   bool
	}{
		{"defender normal", EndpointFacts{DefenderRealtime: bp(true), DefenderMode: DefenderNormal, OtherAntivirus: ip(0), DefinitionsAgeDays: ip(1)}, Pass, false},
		{"defender stale", EndpointFacts{DefenderRealtime: bp(true), DefenderMode: DefenderNormal, OtherAntivirus: ip(0), DefinitionsAgeDays: ip(8)}, Pass, true},
		{"sentinelone with passive defender", EndpointFacts{DefenderRealtime: bp(false), DefenderMode: DefenderPassive, OtherAntivirus: ip(1), DefinitionsAgeDays: ip(40)}, Pass, false},
		{"nothing on", EndpointFacts{DefenderRealtime: bp(false), DefenderMode: DefenderOff, OtherAntivirus: ip(0)}, Fail, false},
		{"passive and nothing else", EndpointFacts{DefenderRealtime: bp(true), DefenderMode: DefenderPassive, OtherAntivirus: ip(0)}, Fail, false},
		{"security center unreadable", EndpointFacts{DefenderRealtime: bp(false), DefenderMode: DefenderOff}, Unknown, false},
	}
	for _, c := range cases {
		s := eval(c.f)
		if s.Status != c.status || (len(s.Warnings) > 0) != c.warn {
			t.Errorf("%s: %s", c.name, mustJSON(s))
		}
	}
}

func TestLegacyReportShapeUnchanged(t *testing.T) {
	at := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	got := mustJSON(Evaluate(Observation{}, "linux", "24.04", "dev", at))
	want := `{"schema_version":1,"collected_at":"2026-09-04T12:00:00Z","platform":"linux","os_version":"24.04","checker_version":"dev","disk_encryption":{"status":"unknown","code":"signal_unavailable"},"screen_lock":{"status":"unknown","code":"signal_unavailable"},"automatic_updates":{"status":"unknown","code":"signal_unavailable"},"pending_maintenance":{"status":"unknown","code":"signal_unavailable"},"endpoint_protection":{"status":"unknown","code":"signal_unavailable"}}`
	if got != want {
		t.Fatalf("\n got %s\nwant %s", got, want)
	}
}

func TestOSVersionIsSanitized(t *testing.T) {
	r := Evaluate(Observation{OSVersion: "26.5.2 <b>é&\"x"}, "darwin", "", "v1.2.3+dirty", time.Now())
	if r.OSVersion != "26.5.2bx" || r.CheckerVersion != "v1.2.3dirty" {
		t.Fatalf("got %q %q", r.OSVersion, r.CheckerVersion)
	}
	if Evaluate(Observation{}, "darwin", "", "dev", time.Now()).OSVersion != "unknown" {
		t.Fatal("unreadable version must be the literal unknown")
	}
}

// FullReport builds a report with every detail field populated; shared by the
// signature-safety tests.
func FullReport(at time.Time) Report {
	lock := macLock(PasswordDelay, ip(300), ProfileFacts{PowerBattery, secs(2)}, ProfileFacts{PowerAC, secs(30)})
	lock.ScreensaverSeconds = ip(1200)
	return Evaluate(Observation{
		OSVersion:  "26.5.2",
		Disk:       &DiskFacts{State: DiskEncrypting, Percent: ip(42)},
		ScreenLock: lock,
		Updates:    &UpdateFacts{Check: bp(true), Download: bp(true), SecurityResponses: bp(true), SystemData: bp(true), OSInstall: bp(true), Paused: bp(false), PolicyDisabled: bp(false)},
		Pending:    &PendingFacts{Count: ip(2), WaitingDays: ip(8)},
		Endpoint:   &EndpointFacts{Gatekeeper: bp(true), SystemDataUpdates: bp(true), DefinitionsVersion: ip(5360), DefinitionsAgeDays: ip(45), DefenderRealtime: bp(true), DefenderMode: DefenderNormal, OtherAntivirus: ip(1)},
	}, "darwin", "", "0.2.0", at)
}

func TestReportIsSignatureSafeASCII(t *testing.T) {
	for _, r := range []Report{
		FullReport(time.Date(2026, 9, 23, 18, 45, 26, 597371000, time.UTC)),
		Evaluate(Observation{WindowsScreenLock: &WindowsScreenLockFacts{InactivitySeconds: ip(600), ActivePower: PowerBattery}, Endpoint: &EndpointFacts{DefenderRealtime: bp(false), DefenderMode: "EDR Block <Mode>", OtherAntivirus: ip(1)}}, "windows", "10.0.26200", "dev", time.Now()),
	} {
		data, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		for i, b := range data {
			if b >= 0x80 || b == '<' || b == '>' || b == '&' {
				t.Fatalf("unsafe byte %q at %d in %s", b, i, data)
			}
		}
		if bytes.Contains(data, []byte(`\u`)) {
			t.Fatalf("escaped characters would differ between Go and Python: %s", data)
		}
	}
}

func TestDecodedReportRemarshalsByteForByte(t *testing.T) {
	r := FullReport(time.Date(2026, 9, 23, 18, 45, 26, 597371000, time.UTC))
	first, _ := json.Marshal(r)
	var decoded Report
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatal(err)
	}
	second, _ := json.Marshal(decoded)
	if !bytes.Equal(first, second) {
		t.Fatalf("round trip changed bytes\n%s\n%s", first, second)
	}
	d, err := DecodeDetail[ScreenLockDetail](decoded.ScreenLock.Detail)
	if err != nil || d.Profiles[1].Power != PowerAC {
		t.Fatalf("decode raw detail: %v %#v", err, d)
	}
}

func mustJSON(v any) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(data)
}
