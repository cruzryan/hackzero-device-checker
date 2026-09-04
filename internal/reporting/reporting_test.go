package reporting

import (
	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/posture"
	"testing"
	"time"
)

func TestEnvelopeRejectsTampering(t *testing.T) {
	d, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEnvelope(d, posture.Report{SchemaVersion: 1}, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !e.Verify() {
		t.Fatal("valid envelope rejected")
	}
	e.DeviceID = "another-device"
	if e.Verify() {
		t.Fatal("tampered envelope verified")
	}
}
