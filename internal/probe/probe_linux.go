//go:build linux

package probe

import (
	"os"
	"os/exec"
	"strings"

	"github.com/hackzero/device-checker/internal/posture"
)

// collect reads common Debian/Ubuntu evidence sources without changing them.
// Linux desktop lock settings are per-user and desktop-specific; an unattended
// system service cannot honestly infer them, so that field remains unknown.
func collect() (posture.Observation, error) {
	return posture.Observation{
		DiskEncryptionEnabled: luksConfigured(),
		AutoUpdatesEnabled:    unattendedUpgradesEnabled(),
		EndpointProtection:    antimalwareActive(),
	}, nil
}

func luksConfigured() *bool {
	output, err := exec.Command("/usr/bin/lsblk", "--noheadings", "--output", "TYPE").Output()
	if err != nil {
		return nil
	}
	value := strings.Contains(string(output), "crypt")
	return &value
}

func unattendedUpgradesEnabled() *bool {
	contents, err := os.ReadFile("/etc/apt/apt.conf.d/20auto-upgrades")
	if err != nil {
		return nil
	}
	text := string(contents)
	updates := strings.Contains(text, "APT::Periodic::Update-Package-Lists \"1\"")
	upgrade := strings.Contains(text, "APT::Periodic::Unattended-Upgrade \"1\"")
	value := updates && upgrade
	return &value
}

func antimalwareActive() *bool {
	output, err := exec.Command("/usr/bin/systemctl", "is-active", "clamav-daemon").Output()
	if err != nil {
		return nil
	}
	value := strings.TrimSpace(string(output)) == "active"
	return &value
}
