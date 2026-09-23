package probe

import (
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

// This file has no build constraint on purpose: the parsing of macOS status
// output is pure string logic, so it compiles and is unit-tested on every
// platform (including CI runners without macOS). The darwin-only file wires
// these helpers to the real commands. Every helper returns nil / unknown when
// its input is missing or unrecognized; none of them guesses a pass.

// macInputs is everything the macOS probe reads, as raw command output (nil =
// the command could not run) or decoded plists (nil = absent/unreadable).
type macInputs struct {
	ProductVersion *string // sw_vers -productVersion
	FileVault      *string // fdesetup status

	ConsoleSession     bool    // the collector runs as the logged-in GUI user
	PmsetCustom        *string // pmset -g custom
	PmsetBatt          *string // pmset -g batt
	Sysadminctl        *string // sysadminctl -screenLock status
	ScreensaverIdle    *string // defaults -currentHost read com.apple.screensaver idleTime (output even on exit 1)
	ManagedScreensaver map[string]any

	SoftwareUpdate        map[string]any // /Library/Preferences/com.apple.SoftwareUpdate.plist
	ManagedSoftwareUpdate map[string]any // /Library/Managed Preferences/com.apple.SoftwareUpdate.plist
	Schedule              *string        // softwareupdate --schedule

	Spctl           *string // spctl --status
	XProtect        *string // xprotect version
	XProtectVersion *string // CFBundleShortVersionString fallback
}

// macObservation assembles the posture facts from the raw macOS inputs.
func macObservation(in macInputs, now time.Time) posture.Observation {
	ob := posture.Observation{Disk: parseFileVaultState(in.FileVault)}
	if in.ProductVersion != nil {
		ob.OSVersion = posture.SanitizeToken(strings.TrimSpace(*in.ProductVersion))
	}
	if in.ConsoleSession {
		ob.ScreenLock = macScreenLock(in)
	}
	updates := macUpdateFacts(in.SoftwareUpdate, in.ManagedSoftwareUpdate, parseAutomaticUpdates(in.Schedule))
	if updates != nil {
		ob.Updates = updates
	}
	endpoint := &posture.EndpointFacts{Gatekeeper: parseGatekeeper(in.Spctl)}
	if updates != nil {
		endpoint.SystemDataUpdates = updates.SystemData
	}
	endpoint.DefinitionsVersion, endpoint.DefinitionsAgeDays = parseXProtect(in.XProtect, now)
	if endpoint.DefinitionsVersion == nil {
		endpoint.DefinitionsVersion = parseIntOutput(in.XProtectVersion)
	}
	ob.Endpoint = endpoint
	return ob
}

// parseFileVaultState interprets `fdesetup status`. FileVault is the
// authoritative disk-encryption source on macOS; diskutil's "Encrypted:" line
// says No on a FileVault Mac and is never used.
func parseFileVaultState(output *string) *posture.DiskFacts {
	if output == nil {
		return nil
	}
	text := strings.ToLower(*output)
	percent := parsePercent(text)
	switch {
	case strings.Contains(text, "decryption in progress"):
		return &posture.DiskFacts{State: posture.DiskDecrypting, Percent: percent}
	case strings.Contains(text, "encryption in progress"):
		return &posture.DiskFacts{State: posture.DiskEncrypting, Percent: percent}
	case strings.Contains(text, "will be enabled after the next restart"), strings.Contains(text, "deferred enablement appears to be active"):
		return &posture.DiskFacts{State: posture.DiskPendingRestart}
	case strings.Contains(text, "filevault is on"):
		return &posture.DiskFacts{State: posture.DiskOn}
	case strings.Contains(text, "filevault is off"):
		return &posture.DiskFacts{State: posture.DiskOff}
	default:
		return nil
	}
}

var percentPattern = regexp.MustCompile(`percent completed\s*=\s*(\d+)`)

func parsePercent(lowered string) *int {
	match := percentPattern.FindStringSubmatch(lowered)
	if match == nil {
		return nil
	}
	value, err := strconv.Atoi(match[1])
	if err != nil || value < 0 || value > 100 {
		return nil
	}
	return &value
}

// parseAutomaticUpdates interprets `softwareupdate --schedule`. Current macOS
// prints "Automatic checking for updates is turned on" (or "...off"); the
// trailing on/off clause is the stable part to match. Older wording that this
// does not recognize returns unknown rather than a false "off".
func parseAutomaticUpdates(output *string) *bool {
	return matchOnOff(output, "is turned on", "is turned off")
}

// parseGatekeeper interprets `spctl --status`.
func parseGatekeeper(output *string) *bool {
	return matchOnOff(output, "assessments enabled", "assessments disabled")
}

// matchOnOff returns true when the (case-insensitive) output contains onMarker,
// false when it contains offMarker, and nil (unknown) when the command did not
// run or the wording matches neither.
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

var screenLockDelayPattern = regexp.MustCompile(`screenlock delay is (\d+) seconds?`)

// parseSysadminctlScreenLock interprets `sysadminctl -screenLock status`, which
// prints to stderr with a timestamp prefix: "screenLock delay is 300 seconds",
// "screenLock delay is immediate", or "screenLock is off". It returns the
// password state and the delay in seconds.
func parseSysadminctlScreenLock(output *string) (string, *int) {
	if output == nil {
		return posture.PasswordUnknown, nil
	}
	text := strings.ToLower(*output)
	switch {
	case strings.Contains(text, "screenlock is off"):
		return posture.PasswordOff, nil
	case strings.Contains(text, "screenlock delay is immediate"):
		zero := 0
		return posture.PasswordImmediate, &zero
	}
	if match := screenLockDelayPattern.FindStringSubmatch(text); match != nil {
		if seconds, err := strconv.Atoi(match[1]); err == nil {
			if seconds == 0 {
				return posture.PasswordImmediate, &seconds
			}
			return posture.PasswordDelay, &seconds
		}
	}
	return posture.PasswordUnknown, nil
}

var (
	pmsetSectionPattern = regexp.MustCompile(`^(Battery|AC|UPS) Power:\s*$`)
	displaySleepPattern = regexp.MustCompile(`^displaysleep\s+(\d+)`)
)

// parsePmsetCustom reads `pmset -g custom`: one section per power source the
// machine has ("Battery Power:", "AC Power:", and possibly "UPS Power:"; a Mac
// mini has only AC), each with " displaysleep N" in minutes (0 = never).
func parsePmsetCustom(output *string) []posture.ProfileFacts {
	if output == nil {
		return nil
	}
	var profiles []posture.ProfileFacts
	current := -1
	for _, line := range strings.Split(*output, "\n") {
		trimmed := strings.TrimSpace(line)
		if match := pmsetSectionPattern.FindStringSubmatch(trimmed); match != nil {
			profiles = append(profiles, posture.ProfileFacts{Power: powerName(match[1])})
			current = len(profiles) - 1
			continue
		}
		if current < 0 {
			continue
		}
		if match := displaySleepPattern.FindStringSubmatch(trimmed); match != nil {
			if minutes, err := strconv.Atoi(match[1]); err == nil {
				seconds := minutes * 60
				profiles[current].DisplayOffSeconds = &seconds
			}
		}
	}
	return profiles
}

func powerName(source string) string {
	switch strings.ToLower(source) {
	case "battery":
		return posture.PowerBattery
	case "ac":
		return posture.PowerAC
	case "ups":
		return posture.PowerUPS
	}
	return ""
}

var drawingFromPattern = regexp.MustCompile(`Now drawing from '(Battery|AC|UPS) Power'`)

// parseActivePower reads the first line of `pmset -g batt`.
func parseActivePower(output *string) string {
	if output == nil {
		return ""
	}
	if match := drawingFromPattern.FindStringSubmatch(*output); match != nil {
		return powerName(match[1])
	}
	return ""
}

// parseScreensaverIdle reads `defaults -currentHost read com.apple.screensaver
// idleTime`. "does not exist" means the screen saver timer is not set (known,
// excluded from the lock time); an integer is seconds (0 = never); anything
// else is unreadable.
func parseScreensaverIdle(output *string) (seconds *int, known bool) {
	if output == nil {
		return nil, false
	}
	if strings.Contains(strings.ToLower(*output), "does not exist") {
		return nil, true
	}
	value := parseIntOutput(output)
	if value == nil || *value < 0 {
		return nil, false
	}
	return value, true
}

// parseIntOutput parses a command whose entire output is a single integer.
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

// macScreenLock combines the per-profile display timers, the screen saver and
// the password-on-wake setting. A configuration profile (MDM) at
// /Library/Managed Preferences wins over the user's own settings.
func macScreenLock(in macInputs) *posture.ScreenLockFacts {
	password, delay := parseSysadminctlScreenLock(in.Sysadminctl)
	saver, known := parseScreensaverIdle(in.ScreensaverIdle)
	facts := &posture.ScreenLockFacts{
		Password:             password,
		PasswordDelaySeconds: delay,
		ScreensaverSeconds:   saver,
		ScreensaverKnown:     known,
		ActivePower:          parseActivePower(in.PmsetBatt),
		Profiles:             parsePmsetCustom(in.PmsetCustom),
	}
	if managed := in.ManagedScreensaver; managed != nil {
		if idle, ok := plistInt(managed, "idleTime"); ok && idle >= 0 {
			facts.ScreensaverSeconds, facts.ScreensaverKnown = &idle, true
		}
		ask, askKnown := plistBool(managed, "askForPassword")
		managedDelay, delayKnown := plistInt(managed, "askForPasswordDelay")
		switch {
		case askKnown && !ask:
			facts.Password, facts.PasswordDelaySeconds = posture.PasswordOff, nil
		case delayKnown && managedDelay >= 0:
			facts.PasswordDelaySeconds = &managedDelay
			if managedDelay == 0 {
				facts.Password = posture.PasswordImmediate
			} else {
				facts.Password = posture.PasswordDelay
			}
		}
	}
	return facts
}

// macUpdateFacts reads the Software Update preferences. A missing key is the
// OS default, which is on. A managed (MDM) value wins over the local one.
func macUpdateFacts(local, managed map[string]any, schedule *bool) *posture.UpdateFacts {
	if local == nil && managed == nil {
		if schedule == nil {
			return nil
		}
		return &posture.UpdateFacts{Check: schedule}
	}
	read := func(key string) *bool {
		value := true
		if v, ok := plistBool(local, key); ok {
			value = v
		}
		if v, ok := plistBool(managed, key); ok {
			value = v
		}
		return &value
	}
	facts := &posture.UpdateFacts{
		Check:             read("AutomaticCheckEnabled"),
		Download:          read("AutomaticDownload"),
		SecurityResponses: read("CriticalUpdateInstall"),
		SystemData:        read("ConfigDataInstall"),
		OSInstall:         read("AutomaticallyInstallMacOSUpdates"),
	}
	if schedule != nil && !*schedule {
		off := false
		facts.Check = &off
	}
	return facts
}

var (
	xprotectVersionPattern   = regexp.MustCompile(`Version:\s*(\d+)`)
	xprotectInstalledPattern = regexp.MustCompile(`Installed:\s*(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4})`)
)

// parseXProtect reads `xprotect version`, e.g.
// "Version: 5360 Installed: 2026-09-18 21:53:58 +0000".
func parseXProtect(output *string, now time.Time) (version *int, ageDays *int) {
	if output == nil {
		return nil, nil
	}
	if match := xprotectVersionPattern.FindStringSubmatch(*output); match != nil {
		if v, err := strconv.Atoi(match[1]); err == nil {
			version = &v
		}
	}
	if match := xprotectInstalledPattern.FindStringSubmatch(*output); match != nil {
		if installed, err := time.Parse("2006-01-02 15:04:05 -0700", match[1]); err == nil {
			days := int(now.Sub(installed).Hours() / 24)
			if days < 0 {
				days = 0
			}
			ageDays = &days
		}
	}
	return version, ageDays
}

// consoleSession reports whether the collector runs as the user who owns the
// GUI console. Screen-lock settings are per user; outside the console session
// (root, or the login window) they are unknown, never guessed.
func consoleSession(consoleUID, uid uint32) bool {
	return consoleUID != 0 && consoleUID == uid
}
