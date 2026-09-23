//go:build linux

package probe

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

const commandTimeout = 20 * time.Second

// collect reads common Debian/Ubuntu evidence sources without changing them.
// Desktop lock settings are per user; they are read from GNOME only when this
// process has the user's session bus, and are unknown otherwise.
func collect() (posture.Observation, error) {
	ob := posture.Observation{
		OSVersion:          osVersion(),
		Disk:               rootEncryption(),
		Updates:            parseAptPeriodic(commandOutput("/usr/bin/apt-config", "dump", "APT::Periodic")),
		EndpointProtection: antimalwareActive(),
	}
	if hasSessionBus() {
		ob.ScreenLock = gnomeScreenLock(
			parseGsettingsUint(commandOutput("/usr/bin/gsettings", "get", "org.gnome.desktop.session", "idle-delay")),
			parseGsettingsBool(commandOutput("/usr/bin/gsettings", "get", "org.gnome.desktop.screensaver", "lock-enabled")),
			parseGsettingsUint(commandOutput("/usr/bin/gsettings", "get", "org.gnome.desktop.screensaver", "lock-delay")),
		)
	}
	return ob, nil
}

func osVersion() string {
	contents, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return ""
	}
	return parseOSReleaseVersion(string(contents))
}

// rootEncryption checks whether the root filesystem sits on a dm-crypt device.
func rootEncryption() *posture.DiskFacts {
	source := parseFindmntSource(commandOutput("/usr/bin/findmnt", "-n", "-o", "SOURCE", "/"))
	if source == "" {
		return nil
	}
	return parseLsblkInverse(commandOutput("/usr/bin/lsblk", "-s", "-n", "-o", "TYPE", source))
}

// hasSessionBus avoids gsettings' in-memory fallback, which silently prints
// schema defaults when no user session bus is reachable.
func hasSessionBus() bool {
	if os.Getenv("DBUS_SESSION_BUS_ADDRESS") != "" {
		return true
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(runtimeDir, "bus"))
	return err == nil
}

func antimalwareActive() *bool {
	output := commandOutput("/usr/bin/systemctl", "is-active", "clamav-daemon")
	if output == nil {
		return nil
	}
	value := strings.TrimSpace(*output) == "active"
	return &value
}

// commandOutput runs a read-only status command and returns its stdout, or
// nil when it could not run or failed.
func commandOutput(binary string, args ...string) *string {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	output, err := exec.CommandContext(ctx, binary, args...).Output()
	if err != nil {
		return nil
	}
	text := string(output)
	return &text
}
