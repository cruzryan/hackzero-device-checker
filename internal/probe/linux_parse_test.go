package probe

import (
	"testing"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

func TestLinuxRootEncryption(t *testing.T) {
	if got := parseFindmntSource(ptr("/dev/mapper/luks-1234[/@]\n")); got != "/dev/mapper/luks-1234" {
		t.Fatalf("btrfs source %q", got)
	}
	if got := parseFindmntSource(ptr("rpool/ROOT/ubuntu\n")); got != "" {
		t.Fatalf("zfs source must be unknown, got %q", got)
	}
	if d := parseLsblkInverse(ptr("lvm\ncrypt\npart\ndisk\n")); d == nil || d.State != posture.DiskOn {
		t.Fatalf("luks under lvm: %#v", d)
	}
	if d := parseLsblkInverse(ptr("part\ndisk\n")); d == nil || d.State != posture.DiskOff {
		t.Fatalf("plain: %#v", d)
	}
	if parseLsblkInverse(nil) != nil || parseLsblkInverse(ptr("")) != nil {
		t.Fatal("unreadable must be unknown")
	}
}

func TestGnomeScreenLock(t *testing.T) {
	eval := func(f *posture.ScreenLockFacts) posture.Signal {
		return posture.Evaluate(posture.Observation{ScreenLock: f}, "linux", "24.04", "dev", time.Now()).ScreenLock
	}
	idle := parseGsettingsUint(ptr("uint32 300\n"))
	wantInt(t, idle, intp(300), "idle")
	lock := parseGsettingsBool(ptr("true\n"))
	delay := parseGsettingsUint(ptr("uint32 0\n"))
	if s := eval(gnomeScreenLock(idle, lock, delay)); s.Status != posture.Pass {
		t.Fatalf("5 min idle, immediate lock: %#v", s)
	}
	if s := eval(gnomeScreenLock(intp(0), lock, delay)); s.Code != posture.CodeScreenLockNever {
		t.Fatalf("idle never: %#v", s)
	}
	if s := eval(gnomeScreenLock(idle, boolp(false), delay)); s.Code != posture.CodeScreenLockPasswordOff {
		t.Fatalf("lock disabled: %#v", s)
	}
	if s := eval(gnomeScreenLock(intp(900), lock, intp(60))); s.Code != posture.CodeScreenLockTooLong {
		t.Fatalf("15 min + 1 min delay: %#v", s)
	}
	if gnomeScreenLock(nil, nil, nil) != nil {
		t.Fatal("nothing read must be nil")
	}
}

func TestParseAptPeriodic(t *testing.T) {
	on := parseAptPeriodic(ptr("APT::Periodic \"\";\nAPT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"1\";\n"))
	wantBool(t, on.Check, boolp(true), "check")
	wantBool(t, on.Download, boolp(true), "download")
	off := parseAptPeriodic(ptr("APT::Periodic::Update-Package-Lists \"1\";\nAPT::Periodic::Unattended-Upgrade \"0\";\n"))
	wantBool(t, off.Download, boolp(false), "download off")
	missing := parseAptPeriodic(ptr(""))
	wantBool(t, missing.Check, boolp(false), "apt default is off")
	if parseAptPeriodic(nil) != nil {
		t.Fatal("unreadable must be nil")
	}
}

func TestParseOSRelease(t *testing.T) {
	if got := parseOSReleaseVersion("NAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\n"); got != "24.04" {
		t.Fatalf("got %q", got)
	}
	if got := parseOSReleaseVersion("NAME=Debian\n"); got != "" {
		t.Fatalf("got %q", got)
	}
}
