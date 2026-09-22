//go:build darwin

package probe

import (
	"os"
	"os/exec"

	"github.com/hackzero/device-checker/internal/posture"
)

// xProtectBundlePaths lists the known on-disk locations of Apple's XProtect
// bundle, current layout first. macOS 10.15 (Catalina, 2019) and later moved
// the bundle onto the read-only system volume under /Library/Apple; older
// systems kept it under /System/Library. A hit at either path is authoritative;
// finding it at neither is unknown, never proof that protection is absent.
var xProtectBundlePaths = []string{
	"/Library/Apple/System/Library/CoreServices/XProtect.bundle",
	"/System/Library/CoreServices/XProtect.bundle",
}

// collect uses documented macOS command-line status interfaces. A command that
// is absent, denied, or ambiguous leaves its signal unknown; it never turns an
// inconclusive response into a passing result. Parsing lives in pure helpers
// (darwin_parse.go) so it can be unit-tested without macOS.
func collect() (posture.Observation, error) {
	fileVault := parseFileVault(commandOutput("/usr/bin/fdesetup", "status"))
	updates := parseAutomaticUpdates(commandOutput("/usr/sbin/softwareupdate", "--schedule"))
	gatekeeper := parseGatekeeper(commandOutput("/usr/sbin/spctl", "--status"))
	xProtect := anyPathExists(xProtectBundlePaths)

	var protection *bool
	if gatekeeper != nil && xProtect != nil {
		value := *gatekeeper && *xProtect
		protection = &value
	}

	return posture.Observation{
		DiskEncryptionEnabled: fileVault,
		AutoUpdatesEnabled:    updates,
		EndpointProtection:    protection,
		// macOS exposes screen-lock settings through per-user preference domains
		// that a launchd service must not read for another user, and the idle
		// timeout is not available from a system-level command, so screen lock
		// stays unknown until a signed-in user probe exists.
	}, nil
}

// commandOutput runs a read-only status command and returns its combined
// output, or nil if the command could not be executed. Combined output is used
// so a status line printed on stderr is still observed.
func commandOutput(binary string, args ...string) *string {
	output, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		return nil
	}
	text := string(output)
	return &text
}

// anyPathExists returns true at the first path that exists, and nil when none
// do. A missing path is treated as unknown, not as a negative result.
func anyPathExists(paths []string) *bool {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			value := true
			return &value
		}
	}
	return nil
}
