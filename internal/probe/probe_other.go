//go:build !windows && !darwin && !linux

package probe

import "github.com/hackzero/device-checker/internal/posture"

// Probing is intentionally unavailable on other platforms until their
// platform-specific checks are independently tested. Unknown is safer than a
// guessed result.
func collect() (posture.Observation, error) { return posture.Observation{}, nil }

func osVersion() string { return "" }
