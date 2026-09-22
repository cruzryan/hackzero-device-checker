package probe

import (
	"regexp"
	"strconv"
	"strings"
)

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

// parseScreenLock interprets `sysadminctl -screenLock status`, which prints
// (to stderr, with a timestamp prefix) either "screenLock delay is N seconds"
// when a password is required on wake, or "screenLock is off" when it is not.
// It returns whether the lock is enabled and whether it is secure (a password
// is required); both are nil (unknown) when no GUI user is present or the
// wording is unrecognized, so we never report a false pass.
func parseScreenLock(output *string) (enabled *bool, secure *bool) {
	if output == nil {
		return nil, nil
	}
	text := strings.ToLower(*output)
	switch {
	case strings.Contains(text, "screenlock is off"):
		off := false
		return &off, &off
	case strings.Contains(text, "delay is"):
		on := true
		return &on, &on
	default:
		return nil, nil
	}
}

var displaySleepPattern = regexp.MustCompile(`(?i)displaysleep\s+(\d+)`)

// parsePmsetDisplaySleep pulls the active display-sleep timeout in minutes from
// `pmset -g`. This is when the screen goes dark and, with a password required,
// the machine locks. Returns nil when the value is not present.
func parsePmsetDisplaySleep(output *string) *int {
	if output == nil {
		return nil
	}
	match := displaySleepPattern.FindStringSubmatch(*output)
	if match == nil {
		return nil
	}
	value, err := strconv.Atoi(match[1])
	if err != nil {
		return nil
	}
	return &value
}

// parseIntOutput parses a command whose entire output is a single integer, such
// as `defaults -currentHost read com.apple.screensaver idleTime`. Returns nil
// when the command did not run or the output is not an integer.
func parseIntOutput(output *string) *int {
	if output == nil {
		return nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(*output))
	if err != nil {
		return nil
	}
	return &value
}

// screenLockMinutes computes how many minutes an unattended screen stays awake
// before it darkens (and then locks): the sooner of the display-sleep timeout
// and the screensaver idle time. A source set to 0 means "never" and is
// excluded. When both sources are readable but both are "never", it returns 0,
// which the posture layer treats as a lock timeout that is too long. When
// neither source is readable it returns nil (unknown).
func screenLockMinutes(displaySleepMinutes *int, screensaverIdleSeconds *int) *int {
	if displaySleepMinutes == nil && screensaverIdleSeconds == nil {
		return nil
	}
	var candidates []int
	if displaySleepMinutes != nil && *displaySleepMinutes > 0 {
		candidates = append(candidates, *displaySleepMinutes)
	}
	if screensaverIdleSeconds != nil && *screensaverIdleSeconds > 0 {
		// Round up so a partial minute is never reported as a shorter, safer time.
		candidates = append(candidates, (*screensaverIdleSeconds+59)/60)
	}
	if len(candidates) == 0 {
		never := 0
		return &never
	}
	soonest := candidates[0]
	for _, c := range candidates[1:] {
		if c < soonest {
			soonest = c
		}
	}
	return &soonest
}
