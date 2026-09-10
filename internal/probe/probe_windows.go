//go:build windows

package probe

import (
	"encoding/json"
	"os/exec"
	"strconv"
	"strings"

	"github.com/hackzero/device-checker/internal/posture"
)

// Elevated is intentionally narrow: this collector only needs elevation to
// read protected Windows posture APIs. It never uses that privilege to alter
// local configuration.
func Elevated() bool {
	output, err := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)").Output()
	return err == nil && strings.EqualFold(strings.TrimSpace(string(output)), "True")
}

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
# Get-BitLockerVolume requires elevation on some Windows editions, including
# machines using the Settings "Device encryption" surface. Never turn that
# access error into an invented false value: absent evidence remains null.
$bitlocker=$null
try {
  $volume=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
  if ($null -ne $volume) { $bitlocker=($volume.ProtectionStatus -eq 'On') }
} catch {}
$timeout=(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveTimeOut).ScreenSaveTimeOut
$screenSaver=(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaveActive).ScreenSaveActive -eq '1'
$screenSecure=(Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name ScreenSaverIsSecure).ScreenSaverIsSecure -eq '1'
$update=$null
try { $settings=(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings; if ($null -ne $settings) { $update=($settings.NotificationLevel -ge 3) } } catch {}
$defender=$null
try { $state=Get-MpComputerStatus -ErrorAction Stop; $defender=($state.AntivirusEnabled -and $state.RealTimeProtectionEnabled -and $state.AMRunningMode -eq 'Normal') } catch {}
[pscustomobject]@{bitlocker=$bitlocker;screenSaver=$screenSaver;screenSecure=$screenSecure;timeout=$timeout;automaticUpdates=$update;defender=$defender}|ConvertTo-Json -Compress`

type windowsRaw struct {
	BitLocker        *bool           `json:"bitlocker"`
	ScreenSaver      *bool           `json:"screenSaver"`
	ScreenSecure     *bool           `json:"screenSecure"`
	Timeout          json.RawMessage `json:"timeout"`
	AutomaticUpdates *bool           `json:"automaticUpdates"`
	Defender         *bool           `json:"defender"`
}

func (r windowsRaw) observation() posture.Observation {
	return posture.Observation{
		DiskEncryptionEnabled: r.BitLocker,
		ScreenLockEnabled:     r.ScreenSaver,
		ScreenLockMinutes:     parseMinutes(r.Timeout),
		ScreenLockSecure:      r.ScreenSecure,
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
