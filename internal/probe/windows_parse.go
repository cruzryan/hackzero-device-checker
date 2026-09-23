package probe

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/hackzero/device-checker/internal/posture"
)

// This file has no build constraint: the Windows script is a constant and the
// mapping from its JSON to posture facts is pure Go, so both are unit-tested
// on every platform. probe_windows.go only runs the script.

// windowsScript is a deliberately fixed, read-only data set. There is no
// caller-controlled interpolation. Every value stays null when Windows does
// not expose it; the Go side turns null into unknown, never into false.
// Enum values are cast to strings so ConvertTo-Json cannot emit numbers.
const windowsScript = `$ErrorActionPreference='SilentlyContinue'
function RegValue($path,$name){ try { $item=Get-ItemProperty -Path $path -Name $name -ErrorAction Stop; return $item.$name } catch { return $null } }
function IsSet($value){ if ($null -eq $value) { return $null }; return -not [string]::IsNullOrWhiteSpace([string]$value) }
function PowerQuery($sub,$setting){ $text=(& powercfg.exe /qh SCHEME_CURRENT $sub $setting 2>$null | Out-String); if ($LASTEXITCODE -ne 0) { return $null }; return $text }
$r=[ordered]@{}
$v=[Environment]::OSVersion.Version
$r.osVersion=('{0}.{1}.{2}' -f $v.Major,$v.Minor,$v.Build)
$r.currentBuild=RegValue 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' 'CurrentBuild'
$r.bitlocker=$null
try { $vol=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop; if ($null -ne $vol) { $r.bitlocker=[ordered]@{protectionStatus=[string]$vol.ProtectionStatus;volumeStatus=[string]$vol.VolumeStatus;encryptionPercentage=[int]$vol.EncryptionPercentage} } } catch {}
$pol='HKCU:\Software\Policies\Microsoft\Windows\Control Panel\Desktop'
$usr='HKCU:\Control Panel\Desktop'
$r.policyScreenSaveActive=RegValue $pol 'ScreenSaveActive'
$r.policyScreenSaverIsSecure=RegValue $pol 'ScreenSaverIsSecure'
$r.policyScreenSaveTimeOut=RegValue $pol 'ScreenSaveTimeOut'
$r.policyScreenSaverSet=IsSet (RegValue $pol 'SCRNSAVE.EXE')
$r.userScreenSaveActive=RegValue $usr 'ScreenSaveActive'
$r.userScreenSaverIsSecure=RegValue $usr 'ScreenSaverIsSecure'
$r.userScreenSaveTimeOut=RegValue $usr 'ScreenSaveTimeOut'
$r.userScreenSaverSet=IsSet (RegValue $usr 'SCRNSAVE.EXE')
$r.delayLockInterval=RegValue $usr 'DelayLockInterval'
$r.inactivityTimeoutSecs=RegValue 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' 'InactivityTimeoutSecs'
$r.videoIdle=PowerQuery 'SUB_VIDEO' 'VIDEOIDLE'
$r.consoleLock=PowerQuery 'SUB_NONE' 'CONSOLELOCK'
$r.powerLine=$null
try { Add-Type -AssemblyName System.Windows.Forms; $r.powerLine=[string][System.Windows.Forms.SystemInformation]::PowerStatus.PowerLineStatus } catch {}
$r.notificationLevel=$null
try { $s=(New-Object -ComObject Microsoft.Update.AutoUpdate).Settings; if ($null -ne $s) { $r.notificationLevel=[int]$s.NotificationLevel } } catch {}
$au='HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
$r.noAutoUpdate=RegValue $au 'NoAutoUpdate'
$r.auOptions=RegValue $au 'AUOptions'
$r.pauseExpiry=RegValue 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' 'PauseUpdatesExpiryTime'
$r.wuauservStartType=$null
try { $svc=Get-Service -Name wuauserv -ErrorAction Stop; $r.wuauservStartType=[string]$svc.StartType } catch {}
$r.defender=$null
try { $mp=Get-MpComputerStatus -ErrorAction Stop; $r.defender=[ordered]@{realtime=[bool]$mp.RealTimeProtectionEnabled;antivirusEnabled=[bool]$mp.AntivirusEnabled;mode=[string]$mp.AMRunningMode;signatureAge=[int]$mp.AntivirusSignatureAge} } catch {}
$r.antivirus=$null
try { $r.antivirus=@(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction Stop | ForEach-Object { [ordered]@{name=[string]$_.displayName;guid=[string]$_.instanceGuid;state=[int]$_.productState} }) } catch {}
[pscustomobject]$r | ConvertTo-Json -Compress -Depth 4`

// windowsRaw is the script's JSON. Registry values arrive as numbers or
// numeric strings depending on their type, so they are decoded flexibly.
type windowsRaw struct {
	OSVersion    string   `json:"osVersion"`
	CurrentBuild flexText `json:"currentBuild"`
	BitLocker    *struct {
		ProtectionStatus     string `json:"protectionStatus"`
		VolumeStatus         string `json:"volumeStatus"`
		EncryptionPercentage *int   `json:"encryptionPercentage"`
	} `json:"bitlocker"`

	PolicyScreenSaveActive    flexText `json:"policyScreenSaveActive"`
	PolicyScreenSaverIsSecure flexText `json:"policyScreenSaverIsSecure"`
	PolicyScreenSaveTimeOut   flexText `json:"policyScreenSaveTimeOut"`
	PolicyScreenSaverSet      *bool    `json:"policyScreenSaverSet"`
	UserScreenSaveActive      flexText `json:"userScreenSaveActive"`
	UserScreenSaverIsSecure   flexText `json:"userScreenSaverIsSecure"`
	UserScreenSaveTimeOut     flexText `json:"userScreenSaveTimeOut"`
	UserScreenSaverSet        *bool    `json:"userScreenSaverSet"`
	DelayLockInterval         flexText `json:"delayLockInterval"`
	InactivityTimeoutSecs     flexText `json:"inactivityTimeoutSecs"`
	VideoIdle                 *string  `json:"videoIdle"`
	ConsoleLock               *string  `json:"consoleLock"`
	PowerLine                 *string  `json:"powerLine"`

	NotificationLevel flexText `json:"notificationLevel"`
	NoAutoUpdate      flexText `json:"noAutoUpdate"`
	AUOptions         flexText `json:"auOptions"`
	PauseExpiry       flexText `json:"pauseExpiry"`
	WuauservStartType *string  `json:"wuauservStartType"`

	Defender *struct {
		Realtime         *bool   `json:"realtime"`
		AntivirusEnabled *bool   `json:"antivirusEnabled"`
		Mode             *string `json:"mode"`
		SignatureAge     *int    `json:"signatureAge"`
	} `json:"defender"`
	Antivirus avProducts `json:"antivirus"`
}

// flexText holds a JSON string or number as text; null leaves it unset.
type flexText struct {
	Set   bool
	Value string
}

func (f *flexText) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	if text == "null" {
		*f = flexText{}
		return nil
	}
	var s string
	if json.Unmarshal(data, &s) == nil {
		*f = flexText{Set: true, Value: s}
		return nil
	}
	*f = flexText{Set: true, Value: text}
	return nil
}

func (f flexText) int() *int {
	if !f.Set {
		return nil
	}
	value, err := strconv.Atoi(strings.TrimSpace(f.Value))
	if err != nil {
		return nil
	}
	return &value
}

type avProduct struct {
	Name  string `json:"name"`
	GUID  string `json:"guid"`
	State int    `json:"state"`
}

// avProducts accepts null, one object, or an array (PowerShell collapses a
// single-element array in some versions).
type avProducts struct {
	Read  bool
	Items []avProduct
}

func (p *avProducts) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	switch {
	case text == "null":
		*p = avProducts{}
		return nil
	case strings.HasPrefix(text, "["):
		var items []avProduct
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		*p = avProducts{Read: true, Items: items}
		return nil
	default:
		var item avProduct
		if err := json.Unmarshal(data, &item); err != nil {
			return err
		}
		*p = avProducts{Read: true, Items: []avProduct{item}}
		return nil
	}
}

// defenderGUID is Microsoft Defender's fixed SecurityCenter2 instance GUID.
const defenderGUID = "{D68DDC3A-831F-4fae-9E44-DA132C1ACF46}"

// avEnabled and avUpToDate decode SecurityCenter2 productState bits.
func avEnabled(state int) bool  { return (state>>12)&0xF == 1 }
func avUpToDate(state int) bool { return (state>>4)&0xF == 0 }

func isDefender(p avProduct) bool {
	return strings.EqualFold(strings.TrimSpace(p.GUID), defenderGUID) || strings.Contains(strings.ToLower(p.Name), "defender")
}

// parseWindowsJSON decodes the script output.
func parseWindowsJSON(output []byte) (windowsRaw, error) {
	var raw windowsRaw
	err := json.Unmarshal(output, &raw)
	return raw, err
}

func (r windowsRaw) observation(now time.Time) posture.Observation {
	return posture.Observation{
		OSVersion:         r.osVersion(),
		Disk:              r.disk(),
		WindowsScreenLock: r.screenLock(),
		Updates:           r.updates(now),
		Endpoint:          r.endpoint(),
	}
}

func (r windowsRaw) osVersion() string {
	version := posture.SanitizeToken(r.OSVersion)
	if build := posture.SanitizeToken(r.CurrentBuild.Value); build != "" && strings.Count(version, ".") == 2 {
		// [Environment]::OSVersion can be capped by application manifests;
		// the registry CurrentBuild is authoritative for the build number.
		version = version[:strings.LastIndex(version, ".")+1] + build
	}
	return version
}

func (r windowsRaw) disk() *posture.DiskFacts {
	if r.BitLocker == nil {
		return nil
	}
	protection := strings.ToLower(r.BitLocker.ProtectionStatus)
	percent := r.BitLocker.EncryptionPercentage
	switch strings.ToLower(r.BitLocker.VolumeStatus) {
	case "fullyencrypted", "fullyencryptedwipeinprogress", "fullyencryptedwipeinterrupted":
		switch protection {
		case "on":
			return &posture.DiskFacts{State: posture.DiskOn}
		case "off":
			// Encrypted but the key is in the clear (suspended, or Device
			// Encryption waiting for a recovery-key backup).
			return &posture.DiskFacts{State: posture.DiskSuspended}
		}
		return nil
	case "encryptioninprogress":
		return &posture.DiskFacts{State: posture.DiskEncrypting, Percent: percent}
	case "encryptionpaused":
		return &posture.DiskFacts{State: posture.DiskSuspended, Percent: percent}
	case "decryptioninprogress", "decryptionpaused":
		return &posture.DiskFacts{State: posture.DiskDecrypting, Percent: percent}
	case "fullydecrypted":
		return &posture.DiskFacts{State: posture.DiskOff}
	}
	return nil
}

var powercfgIndexPattern = regexp.MustCompile(`0x[0-9a-fA-F]{8}`)

// parsePowercfgACDC reads `powercfg /qh SCHEME_CURRENT <sub> <setting>` (/qh
// includes settings hidden on Modern Standby laptops, such as CONSOLELOCK). Its
// labels are localized, but the current AC and DC values are always the last
// two 0x-prefixed eight-digit numbers.
func parsePowercfgACDC(output *string) (ac, dc *int) {
	if output == nil {
		return nil, nil
	}
	matches := powercfgIndexPattern.FindAllString(*output, -1)
	if len(matches) < 2 {
		return nil, nil
	}
	parse := func(hex string) *int {
		value, err := strconv.ParseInt(hex[2:], 16, 64)
		if err != nil || value < 0 || value > 1<<31 {
			return nil
		}
		v := int(value)
		return &v
	}
	return parse(matches[len(matches)-2]), parse(matches[len(matches)-1])
}

func nonZero(value *int) *bool {
	if value == nil {
		return nil
	}
	b := *value != 0
	return &b
}

// effective returns the policy value when set, else the user's.
func effective(policy, user flexText) flexText {
	if policy.Set {
		return policy
	}
	return user
}

func (r windowsRaw) screenLock() *posture.WindowsScreenLockFacts {
	facts := &posture.WindowsScreenLockFacts{
		InactivitySeconds:  r.InactivityTimeoutSecs.int(),
		ScreensaverActive:  nonZero(effective(r.PolicyScreenSaveActive, r.UserScreenSaveActive).int()),
		ScreensaverSecure:  nonZero(effective(r.PolicyScreenSaverIsSecure, r.UserScreenSaverIsSecure).int()),
		ScreensaverSeconds: effective(r.PolicyScreenSaveTimeOut, r.UserScreenSaveTimeOut).int(),
		DelayLockSeconds:   r.DelayLockInterval.int(),
	}
	// No screen-saver program in either location means no screen saver.
	configured := false
	switch {
	case r.PolicyScreenSaverSet != nil:
		configured = *r.PolicyScreenSaverSet
	case r.UserScreenSaverSet != nil:
		configured = *r.UserScreenSaverSet
	}
	facts.ScreensaverConfigured = &configured
	if facts.DelayLockSeconds == nil {
		// Absent DelayLockInterval is the Windows default: sign-in is
		// required as soon as the display turns off.
		zero := 0
		facts.DelayLockSeconds = &zero
	}
	facts.DisplayOffACSeconds, facts.DisplayOffDCSeconds = parsePowercfgACDC(r.VideoIdle)
	ac, dc := parsePowercfgACDC(r.ConsoleLock)
	facts.ConsoleLockAC, facts.ConsoleLockDC = nonZero(ac), nonZero(dc)
	if delay := *facts.DelayLockSeconds; delay < 0 || delay >= 0xFFFFFFFF {
		// 0xFFFFFFFF (read back as -1 from a DWORD) is "Never" in "If you've
		// been away, when should Windows require you to sign in again?".
		off, zero := false, 0
		facts.ConsoleLockAC, facts.ConsoleLockDC, facts.DelayLockSeconds = &off, &off, &zero
	}
	if r.PowerLine != nil {
		switch strings.ToLower(*r.PowerLine) {
		case "online":
			facts.ActivePower = posture.PowerAC
		case "offline":
			facts.ActivePower = posture.PowerBattery
		}
	}
	return facts
}

// updates maps Windows Update configuration. Windows 10/11 offers no user
// setting that turns automatic updates off: only policy (NoAutoUpdate,
// AUOptions), a disabled Windows Update service, or a pause do. With none of
// those present the OS default (automatic) applies.
func (r windowsRaw) updates(now time.Time) *posture.UpdateFacts {
	check, download := true, true
	policyDisabled := false
	if r.NoAutoUpdate.int() != nil && *r.NoAutoUpdate.int() == 1 {
		check, download, policyDisabled = false, false, true
	} else if options := r.AUOptions.int(); options != nil {
		switch *options {
		case 1:
			check, download = false, false
		case 2:
			download = false
		}
	} else if level := r.NotificationLevel.int(); level != nil {
		switch *level {
		case 1:
			check, download = false, false
		case 2:
			download = false
		}
	}
	if r.WuauservStartType != nil && strings.EqualFold(*r.WuauservStartType, "disabled") {
		check, download, policyDisabled = false, false, true
	}
	paused := false
	if r.PauseExpiry.Set {
		if expiry, err := time.Parse(time.RFC3339, strings.TrimSpace(r.PauseExpiry.Value)); err == nil {
			paused = expiry.After(now)
		}
	}
	return &posture.UpdateFacts{Check: &check, Download: &download, Paused: &paused, PolicyDisabled: &policyDisabled}
}

func defenderMode(mode string) string {
	lowered := strings.ToLower(strings.TrimSpace(mode))
	switch {
	case lowered == "normal":
		return posture.DefenderNormal
	case strings.Contains(lowered, "passive"):
		return posture.DefenderPassive
	case strings.Contains(lowered, "edr"):
		return posture.DefenderEDRBlock
	case strings.Contains(lowered, "not running"), lowered == "disabled":
		return posture.DefenderOff
	}
	return posture.DefenderUnknown
}

func (r windowsRaw) endpoint() *posture.EndpointFacts {
	facts := &posture.EndpointFacts{}
	if d := r.Defender; d != nil {
		if d.Realtime != nil && d.AntivirusEnabled != nil {
			on := *d.Realtime && *d.AntivirusEnabled
			facts.DefenderRealtime = &on
		}
		if d.Mode != nil {
			facts.DefenderMode = defenderMode(*d.Mode)
		}
		if d.SignatureAge != nil && *d.SignatureAge >= 0 {
			facts.DefinitionsAgeDays = d.SignatureAge
		}
	}
	if r.Antivirus.Read {
		count := 0
		for _, product := range r.Antivirus.Items {
			if !isDefender(product) && avEnabled(product.State) && avUpToDate(product.State) {
				count++
			}
		}
		facts.OtherAntivirus = &count
	}
	return facts
}
