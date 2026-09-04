//go:build !windows && !darwin && !linux

package probe

import "github.com/hackzero/device-checker/internal/posture"

// Non-Windows probing is intentionally unavailable until its platform-specific
// checks are independently tested. Unknown is safer than a guessed result.
func collect() (posture.Observation, error) { return posture.Observation{}, nil }
