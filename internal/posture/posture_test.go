package posture

import (
	"testing"
	"time"
)

func TestEvaluateHealthyDevice(t *testing.T) {
	at := time.Date(2026, 9, 4, 12, 0, 0, 0, time.FixedZone("local", -6*60*60))
	report := Evaluate(Observation{
		DiskEncryptionEnabled: true, ScreenLockEnabled: true, ScreenLockMinutes: 10,
		AutoUpdatesEnabled: true, EndpointProtection: true,
	}, "windows", "11", "dev", at)
	for name, signal := range map[string]Signal{
		"encryption": report.DiskEncryption, "screen lock": report.ScreenLock,
		"updates": report.AutomaticUpdates, "maintenance": report.PendingMaintenance,
		"protection": report.EndpointProtection,
	} {
		if signal.Status != Pass { t.Fatalf("%s = %q, want pass", name, signal.Status) }
	}
	if report.CollectedAt.Location() != time.UTC { t.Fatal("collection time must be UTC") }
}

func TestPendingMaintenanceIsNotAConfigurationFailure(t *testing.T) {
	report := Evaluate(Observation{DiskEncryptionEnabled: true, ScreenLockEnabled: true, ScreenLockMinutes: 15, AutoUpdatesEnabled: true, PendingUpdates: true, EndpointProtection: true}, "macos", "15", "dev", time.Now())
	if report.AutomaticUpdates.Status != Pass { t.Fatal("configured automatic updates must pass") }
	if report.PendingMaintenance.Status != NeedsAttention { t.Fatal("pending work must be attention, not failure") }
}

func TestScreenLockOverFifteenMinutesFails(t *testing.T) {
	report := Evaluate(Observation{ScreenLockEnabled: true, ScreenLockMinutes: 16}, "linux", "24.04", "dev", time.Now())
	if report.ScreenLock.Status != Fail || report.ScreenLock.Code != "screen_lock_timeout_too_long" { t.Fatalf("unexpected signal: %#v", report.ScreenLock) }
}
