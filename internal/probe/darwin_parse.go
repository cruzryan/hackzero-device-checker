package probe

import "strings"

// This file has no build constraint on purpose: the parsing of macOS status
// output is pure string logic, so it compiles and is unit-tested on every
// platform (including CI runners without macOS). The darwin-only file wires
// these helpers to the real commands.

// parseFileVault interprets `fdesetup status`. FileVault is the authoritative
// disk-encryption source on macOS.
func parseFileVault(output *string) *bool {
	return matchOnOff(output, "filevault is on", "filevault is off")
}

// parseAutomaticUpdates interprets `softwareupdate --schedule`. Current macOS
// prints "Automatic checking for updates is turned on" (or "...off"); the
// trailing on/off clause is the stable part to match. Older wording that this
// does not recognize returns unknown rather than a false "off" - degrading to
// unknown is safe, reporting a wrong "off" is the bug this replaces.
func parseAutomaticUpdates(output *string) *bool {
	return matchOnOff(output, "is turned on", "is turned off")
}

// parseGatekeeper interprets `spctl --status`.
func parseGatekeeper(output *string) *bool {
	return matchOnOff(output, "assessments enabled", "assessments disabled")
}

// matchOnOff returns true when the (case-insensitive) output contains onMarker,
// false when it contains offMarker, and nil (unknown) when the command did not
// run or the wording matches neither. It never guesses a result from silence,
// and never turns an unrecognized string into a passing or failing verdict.
func matchOnOff(output *string, onMarker, offMarker string) *bool {
	if output == nil {
		return nil
	}
	text := strings.ToLower(*output)
	switch {
	case strings.Contains(text, onMarker):
		value := true
		return &value
	case strings.Contains(text, offMarker):
		value := false
		return &value
	default:
		return nil
	}
}
