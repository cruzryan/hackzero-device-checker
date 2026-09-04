//go:build darwin

package probe

import (
	"os"
	"os/exec"
	"strings"

	"github.com/hackzero/device-checker/internal/posture"
)

// collect uses documented macOS command-line status interfaces. A command that
// is absent, denied, or ambiguous leaves its signal unknown; it never turns an
// inconclusive response into a passing result.
func collect() (posture.Observation, error) {
	fileVault := commandContains("/usr/bin/fdesetup", "status", "FileVault is On")
	updates := commandContains("/usr/sbin/softwareupdate", "--schedule", "Automatic check is on")
	gatekeeper := commandContains("/usr/sbin/spctl", "--status", "assessments enabled")
	xProtect := pathExists("/System/Library/CoreServices/XProtect.bundle")

	var protection *bool
	if gatekeeper != nil && xProtect != nil {
		value := *gatekeeper && *xProtect
		protection = &value
	}

	return posture.Observation{
		DiskEncryptionEnabled: fileVault,
		AutoUpdatesEnabled:    updates,
		EndpointProtection:    protection,
		// macOS exposes lock settings through user preference domains. A launchd
		// service must not read another user's preferences, so this remains
		// unknown until the signed-in user probe is available.
	}, nil
}

func commandContains(binary string, argument string, expected string) *bool {
	output, err := exec.Command(binary, argument).Output()
	if err != nil {
		return nil
	}
	value := strings.Contains(strings.ToLower(string(output)), strings.ToLower(expected))
	return &value
}

func pathExists(path string) *bool {
	_, err := os.Stat(path)
	if err != nil {
		return nil
	}
	value := true
	return &value
}
