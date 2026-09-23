package probe

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/hackzero/device-checker/internal/posture"
)

// Pure Linux parsing helpers, with no build constraint so they are unit-tested
// on every platform. probe_linux.go wires them to the real commands.

// parseFindmntSource cleans `findmnt -no SOURCE /`. Btrfs appends the subvolume
// in brackets ("/dev/mapper/luks-x[/@]"), which lsblk does not accept.
func parseFindmntSource(output *string) string {
	if output == nil {
		return ""
	}
	source := strings.TrimSpace(*output)
	if i := strings.Index(source, "["); i > 0 {
		source = source[:i]
	}
	if !strings.HasPrefix(source, "/dev/") {
		return ""
	}
	return source
}

// parseLsblkInverse reads `lsblk -s -n -o TYPE <root source>`, which lists the
// root device and every ancestor (for example "lvm", "crypt", "part",
// "disk"). A "crypt" ancestor means the root filesystem sits on LUKS/dm-crypt.
func parseLsblkInverse(output *string) *posture.DiskFacts {
	if output == nil {
		return nil
	}
	types := strings.Fields(*output)
	if len(types) == 0 {
		return nil
	}
	for _, kind := range types {
		if kind == "crypt" {
			return &posture.DiskFacts{State: posture.DiskOn}
		}
	}
	return &posture.DiskFacts{State: posture.DiskOff}
}

// parseGsettingsUint reads `gsettings get ... ` output such as "uint32 300".
func parseGsettingsUint(output *string) *int {
	if output == nil {
		return nil
	}
	fields := strings.Fields(*output)
	if len(fields) == 0 {
		return nil
	}
	value, err := strconv.Atoi(fields[len(fields)-1])
	if err != nil || value < 0 {
		return nil
	}
	return &value
}

// parseGsettingsBool reads "true" / "false".
func parseGsettingsBool(output *string) *bool {
	if output == nil {
		return nil
	}
	switch strings.TrimSpace(*output) {
	case "true":
		value := true
		return &value
	case "false":
		value := false
		return &value
	}
	return nil
}

// gnomeScreenLock maps GNOME's settings onto the shared screen-lock rule: the
// screen blanks after idle-delay seconds (0 = never), and when lock-enabled
// is set a password is required lock-delay seconds after that.
func gnomeScreenLock(idleDelay *int, lockEnabled *bool, lockDelay *int) *posture.ScreenLockFacts {
	if idleDelay == nil && lockEnabled == nil {
		return nil
	}
	facts := &posture.ScreenLockFacts{
		Password:         posture.PasswordUnknown,
		ScreensaverKnown: true, // GNOME has no separate screen-saver timer
		Profiles:         []posture.ProfileFacts{{Power: posture.PowerAny, DisplayOffSeconds: idleDelay}},
	}
	switch {
	case lockEnabled == nil:
	case !*lockEnabled:
		facts.Password = posture.PasswordOff
	case lockDelay != nil && *lockDelay == 0:
		facts.Password, facts.PasswordDelaySeconds = posture.PasswordImmediate, lockDelay
	case lockDelay != nil:
		facts.Password, facts.PasswordDelaySeconds = posture.PasswordDelay, lockDelay
	}
	return facts
}

var aptPeriodicPattern = regexp.MustCompile(`APT::Periodic::([A-Za-z-]+)\s+"([^"]*)"`)

// parseAptPeriodic reads `apt-config dump APT::Periodic`. A missing key is
// apt's default, which is off. "check" is Update-Package-Lists and "download"
// is Unattended-Upgrade (which downloads and installs security updates).
func parseAptPeriodic(output *string) *posture.UpdateFacts {
	if output == nil {
		return nil
	}
	values := map[string]string{}
	for _, match := range aptPeriodicPattern.FindAllStringSubmatch(*output, -1) {
		values[match[1]] = match[2]
	}
	enabled := func(key string) *bool {
		value := strings.TrimSpace(values[key])
		on := value != "" && value != "0"
		return &on
	}
	return &posture.UpdateFacts{Check: enabled("Update-Package-Lists"), Download: enabled("Unattended-Upgrade")}
}

// parseOSReleaseVersion returns VERSION_ID from /etc/os-release.
func parseOSReleaseVersion(contents string) string {
	for _, line := range strings.Split(contents, "\n") {
		if value, ok := strings.CutPrefix(strings.TrimSpace(line), "VERSION_ID="); ok {
			return posture.SanitizeToken(strings.Trim(value, `"'`))
		}
	}
	return ""
}
