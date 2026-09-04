// Package probe provides read-only, platform-native posture observations.
package probe

import "github.com/hackzero/device-checker/internal/posture"

// Collect never performs remediation, installs software, modifies policy, or
// uploads data. Platform implementations may leave a value nil where the OS
// does not offer an authoritative, readable signal.
func Collect() (posture.Observation, error) { return collect() }
