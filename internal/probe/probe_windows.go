//go:build windows

package probe

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"

	"github.com/hackzero/device-checker/internal/posture"
)

// collect asks PowerShell for a deliberately fixed, read-only data set. There
// is no caller-controlled script interpolation. Every signal can remain unknown
// when Windows does not expose an authoritative value on the machine.
func collect() (posture.Observation, error) {
	output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", windowsScript).Output()
	if err != nil {
		return posture.Observation{}, err
	}
	var raw windowsRaw
	if err := json.Unmarshal(output, &raw); err != nil {
		return posture.Observation{}, err
	}
	return raw.observation(), nil
}

const windowsScript = `$ErrorActionPreference='SilentlyContinue'
$bitlocker=(Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus -eq 'On'
$timeout=(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut).ScreenSaveTimeOut
$screenSaver=(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive).ScreenSaveActive -eq '1'
$update=(Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU' -Name NoAutoUpdate).NoAutoUpdate -ne 1
$defender=(Get-MpComputerStatus).AntivirusEnabled
[pscustomobject]@{bitlocker=$bitlocker;screenSaver=$screenSaver;timeout=$timeout;automaticUpdates=$update;defender=$defender}|ConvertTo-Json -Compress`

type windowsRaw struct {
	BitLocker        *bool           `json:"bitlocker"`
	ScreenSaver      *bool           `json:"screenSaver"`
	Timeout          json.RawMessage `json:"timeout"`
	AutomaticUpdates *bool           `json:"automaticUpdates"`
	Defender         *bool           `json:"defender"`
}

func (r windowsRaw) observation() posture.Observation {
	return posture.Observation{
		DiskEncryptionEnabled: r.BitLocker,
		ScreenLockEnabled:     r.ScreenSaver,
		ScreenLockMinutes:     parseMinutes(r.Timeout),
		AutoUpdatesEnabled:    r.AutomaticUpdates,
		EndpointProtection:    r.Defender,
	}
}

func parseMinutes(raw json.RawMessage) *int {
	var text string
	if json.Unmarshal(raw, &text) != nil {
		return nil
	}
	seconds, err := strconv.Atoi(strings.TrimSpace(text))
	if err != nil || seconds <= 0 {
		return nil
	}
	minutes := (seconds + 59) / 60
	return &minutes
}
