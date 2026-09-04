// Package reporting defines signed, outbound-only report delivery primitives.
package reporting

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/hackzero/device-checker/internal/identity"
	"github.com/hackzero/device-checker/internal/posture"
)

// Envelope binds an exact report payload to a device key. Server receipt time,
// tenant assignment, and freshness are intentionally service-side concepts.
type Envelope struct {
	SchemaVersion int            `json:"schema_version"`
	Kind          string         `json:"kind"`
	DeviceID      string         `json:"device_id"`
	PublicKey     string         `json:"public_key"`
	CreatedAt     time.Time      `json:"created_at"`
	Report        posture.Report `json:"report"`
	Signature     string         `json:"signature"`
}

type unsignedEnvelope struct {
	SchemaVersion int            `json:"schema_version"`
	Kind          string         `json:"kind"`
	DeviceID      string         `json:"device_id"`
	PublicKey     string         `json:"public_key"`
	CreatedAt     time.Time      `json:"created_at"`
	Report        posture.Report `json:"report"`
}

// NewEnvelope serializes a stable unsigned representation before signing it.
func NewEnvelope(device identity.Device, report posture.Report, at time.Time) (Envelope, error) {
	return newEnvelope(device, "full", report, at)
}

// NewHeartbeat makes a small signed liveness signal. It carries no posture
// result, so a heartbeat can never fabricate a passed daily check.
func NewHeartbeat(device identity.Device, at time.Time) (Envelope, error) {
	return newEnvelope(device, "heartbeat", posture.Report{SchemaVersion: 1}, at)
}

func newEnvelope(device identity.Device, kind string, report posture.Report, at time.Time) (Envelope, error) {
	plain := unsignedEnvelope{1, kind, device.ID, device.PublicKey, at.UTC(), report}
	payload, err := json.Marshal(plain)
	if err != nil {
		return Envelope{}, fmt.Errorf("marshal report: %w", err)
	}
	signature, err := device.Sign(payload)
	if err != nil {
		return Envelope{}, fmt.Errorf("sign report: %w", err)
	}
	return Envelope{plain.SchemaVersion, plain.Kind, plain.DeviceID, plain.PublicKey, plain.CreatedAt, plain.Report, signature}, nil
}

// Verify checks the exact canonical payload locally. Production services must
// additionally bind the known public key and device ID to an authorized tenant.
func (e Envelope) Verify() bool {
	if e.Kind != "full" && e.Kind != "heartbeat" {
		return false
	}
	plain := unsignedEnvelope{e.SchemaVersion, e.Kind, e.DeviceID, e.PublicKey, e.CreatedAt, e.Report}
	payload, err := json.Marshal(plain)
	if err != nil {
		return false
	}
	d := identity.Device{ID: e.DeviceID, PublicKey: e.PublicKey}
	return d.Verify(payload, e.Signature)
}

// Digest returns the SHA-256 of the transmitted envelope for durable queue
// de-duplication. It is not a replacement for signature verification.
func (e Envelope) Digest() (string, error) {
	encoded, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(encoded)
	return fmt.Sprintf("%x", hash[:]), nil
}
