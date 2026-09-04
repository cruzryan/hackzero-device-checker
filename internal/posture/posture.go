// Package posture defines the small, versioned contract between OS probes and
// the reporting service. It intentionally has no facility for arbitrary host
// inspection or command execution.
package posture

import "time"

// Status is an evidence outcome. A lack of a recent report is represented by
// freshness at the service layer, never by changing a successful field to fail.
type Status string

const (
	Pass           Status = "pass"
	Fail           Status = "fail"
	NeedsAttention Status = "needs_attention"
	Unknown        Status = "unknown"
)

// Signal is one narrowly scoped, user-explainable local observation.
type Signal struct {
	Status Status `json:"status"`
	Code   string `json:"code,omitempty"`
}

// Observation is the raw probe output. It intentionally contains booleans and
// short codes only, rather than opaque command output or a host inventory.
type Observation struct {
	DiskEncryptionEnabled *bool
	ScreenLockEnabled     *bool
	ScreenLockMinutes     *int
	AutoUpdatesEnabled    *bool
	PendingUpdates        *bool
	EndpointProtection    *bool
}

// Report is the unsigned posture payload. Transport adds a signature and
// device identity outside this package.
type Report struct {
	SchemaVersion      int       `json:"schema_version"`
	CollectedAt        time.Time `json:"collected_at"`
	Platform           string    `json:"platform"`
	OSVersion          string    `json:"os_version"`
	CheckerVersion     string    `json:"checker_version"`
	DiskEncryption     Signal    `json:"disk_encryption"`
	ScreenLock         Signal    `json:"screen_lock"`
	AutomaticUpdates   Signal    `json:"automatic_updates"`
	PendingMaintenance Signal    `json:"pending_maintenance"`
	EndpointProtection Signal    `json:"endpoint_protection"`
}

// Evaluate maps known facts to transparent outcomes. A configured screen lock
// longer than 15 minutes fails the baseline; a pending normal OS update is
// explicitly not equivalent to disabled automatic updates.
func Evaluate(ob Observation, platform, osVersion, checkerVersion string, at time.Time) Report {
	return Report{
		SchemaVersion:      1,
		CollectedAt:        at.UTC(),
		Platform:           platform,
		OSVersion:          osVersion,
		CheckerVersion:     checkerVersion,
		DiskEncryption:     boolSignal(ob.DiskEncryptionEnabled, "disk_encryption_disabled"),
		ScreenLock:         screenLockSignal(ob.ScreenLockEnabled, ob.ScreenLockMinutes),
		AutomaticUpdates:   boolSignal(ob.AutoUpdatesEnabled, "automatic_updates_disabled"),
		PendingMaintenance: pendingSignal(ob.PendingUpdates),
		EndpointProtection: boolSignal(ob.EndpointProtection, "endpoint_protection_unavailable"),
	}
}

func boolSignal(ok *bool, failCode string) Signal {
	if ok == nil {
		return Signal{Status: Unknown, Code: "signal_unavailable"}
	}
	if *ok {
		return Signal{Status: Pass}
	}
	return Signal{Status: Fail, Code: failCode}
}

func screenLockSignal(enabled *bool, minutes *int) Signal {
	if enabled == nil || minutes == nil {
		return Signal{Status: Unknown, Code: "signal_unavailable"}
	}
	if !*enabled {
		return Signal{Status: Fail, Code: "screen_lock_disabled"}
	}
	if *minutes <= 0 || *minutes > 15 {
		return Signal{Status: Fail, Code: "screen_lock_timeout_too_long"}
	}
	return Signal{Status: Pass}
}

func pendingSignal(pending *bool) Signal {
	if pending == nil {
		return Signal{Status: Unknown, Code: "signal_unavailable"}
	}
	if *pending {
		return Signal{Status: NeedsAttention, Code: "updates_pending"}
	}
	return Signal{Status: Pass}
}
