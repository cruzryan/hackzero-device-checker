package posture

import (
	"testing"
	"time"
)

func TestEvaluateHealthyDevice(t *testing.T) {
	truth := true
	falsehood := false
	ten := 10
	at := time.Date(2026, 9, 4, 12, 0, 0, 0, time.FixedZone("local", -6*60*60))
	report := Evaluate(Observation{
		DiskEncryptionEnabled: &truth, ScreenLockEnabled: &truth, ScreenLockMinutes: &ten,
		AutoUpdatesEnabled: &truth, PendingUpdates: &falsehood, EndpointProtection: &truth,
	}, "windows", "11", "dev", at)
	for name, signal := range map[string]Signal{
		"encryption": report.DiskEncryption, "screen lock": report.ScreenLock,
		"updates": report.AutomaticUpdates, "maintenance": report.PendingMaintenance,
		"protection": report.EndpointProtection,
	} {
		if signal.Status != Pass {
			t.Fatalf("%s = %q, want pass", name, signal.Status)
		}
	}
	if report.CollectedAt.Location() != time.UTC {
		t.Fatal("collection time must be UTC")
	}
}

func TestPendingMaintenanceIsNotAConfigurationFailure(t *testing.T) {
	truth := true
	fifteen := 15
	report := Evaluate(Observation{DiskEncryptionEnabled: &truth, ScreenLockEnabled: &truth, ScreenLockMinutes: &fifteen, AutoUpdatesEnabled: &truth, PendingUpdates: &truth, EndpointProtection: &truth}, "macos", "15", "dev", time.Now())
	if report.AutomaticUpdates.Status != Pass {
		t.Fatal("configured automatic updates must pass")
	}
	if report.PendingMaintenance.Status != NeedsAttention {
		t.Fatal("pending work must be attention, not failure")
	}
}

func TestScreenLockOverFifteenMinutesFails(t *testing.T) {
	truth := true
	sixteen := 16
	report := Evaluate(Observation{ScreenLockEnabled: &truth, ScreenLockMinutes: &sixteen}, "linux", "24.04", "dev", time.Now())
	if report.ScreenLock.Status != Fail || report.ScreenLock.Code != "screen_lock_timeout_too_long" {
		t.Fatalf("unexpected signal: %#v", report.ScreenLock)
	}
}

func TestMissingProbeIsUnknownNotFailure(t *testing.T) {
	report := Evaluate(Observation{}, "windows", "11", "dev", time.Now())
	if report.DiskEncryption.Status != Unknown || report.EndpointProtection.Status != Unknown {
		t.Fatal("missing probes must be unknown rather than invented failures")
	}
}
