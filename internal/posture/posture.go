// Package posture defines the small, versioned contract between OS probes and
// the reporting service. It intentionally has no facility for arbitrary host
// inspection or command execution.
//
// Signature safety: the service verifies the device signature over Python's
// json.dumps(..., ensure_ascii=True) of the parsed envelope, while Go signs
// json.Marshal. The two agree only when every value is an integer, a boolean,
// null, or an ASCII string without '<', '>' or '&'. Every detail value in this
// package is therefore an int, a bool, or a fixed lowercase enum string; free
// text from the operating system never enters a report, and the only
// OS-derived strings (os_version, checker_version) pass through SanitizeToken.
package posture

import (
	"encoding/json"
	"errors"
	"time"
)

// Status is an evidence outcome. A lack of a recent report is represented by
// freshness at the service layer, never by changing a successful field to fail.
type Status string

const (
	Pass           Status = "pass"
	Fail           Status = "fail"
	NeedsAttention Status = "needs_attention"
	Unknown        Status = "unknown"
)

// LimitMinutes is the HackZero screen-lock policy limit. Exactly 15 passes.
const LimitMinutes = 15

// Reason and warning codes. They are part of the wire contract.
const (
	CodeUnavailable = "signal_unavailable"

	CodeScreenLockPasswordOff = "screen_lock_password_off"
	CodeScreenLockNever       = "screen_lock_never"
	CodeScreenLockTooLong     = "screen_lock_timeout_too_long"
	// Legacy screen-lock codes, still emitted from legacy observations.
	CodeScreenLockDisabled            = "screen_lock_disabled"
	CodeScreenLockPasswordNotRequired = "screen_lock_password_not_required"

	CodeDiskDisabled   = "disk_encryption_disabled"
	CodeDiskDecrypting = "disk_encryption_decrypting"
	CodeDiskSuspended  = "disk_encryption_suspended"

	CodeUpdatesDisabled = "automatic_updates_disabled"
	CodeUpdatesPaused   = "automatic_updates_paused"
	CodeUpdatesPending  = "updates_pending"

	CodeGatekeeperDisabled      = "gatekeeper_disabled"
	CodeDefinitionsUpdatesOff   = "definitions_updates_off"
	CodeEndpointUnavailable     = "endpoint_protection_unavailable"
	WarningDefinitionsStale     = "definitions_stale"
	macDefinitionsStaleDays     = 30
	windowsDefinitionsStaleDays = 7
)

// Power profile names used in screen-lock detail.
const (
	PowerAC      = "ac"
	PowerBattery = "battery"
	PowerUPS     = "ups"
	PowerAny     = "any"
)

// Password-on-wake states used in screen-lock facts and detail.
const (
	PasswordImmediate = "immediate"
	PasswordDelay     = "delay"
	PasswordOff       = "off"
	PasswordUnknown   = "unknown"
)

// Disk encryption states.
const (
	DiskOn             = "on"
	DiskOff            = "off"
	DiskEncrypting     = "encrypting"
	DiskDecrypting     = "decrypting"
	DiskPendingRestart = "pending_restart"
	DiskSuspended      = "suspended"
)

// Windows Defender running modes.
const (
	DefenderNormal   = "normal"
	DefenderPassive  = "passive"
	DefenderEDRBlock = "edr_block"
	DefenderOff      = "off"
	DefenderUnknown  = "unknown"
)

// Detail is the per-signal raw-facts object. It is a small closed union: the
// typed structs below when a report is built, or RawDetail when a report was
// decoded from JSON (for example from the offline queue). RawDetail
// re-marshals byte for byte, so a queued report still verifies its signature.
type Detail interface{ isDetail() }

// RawDetail is a detail object decoded from JSON and kept verbatim.
type RawDetail []byte

func (RawDetail) isDetail() {}

// MarshalJSON returns the stored bytes unchanged.
func (d RawDetail) MarshalJSON() ([]byte, error) {
	if len(d) == 0 {
		return []byte("null"), nil
	}
	return []byte(d), nil
}

// DecodeDetail converts any Detail (typed or raw) into the requested struct.
func DecodeDetail[T any](d Detail) (T, error) {
	var out T
	if d == nil {
		return out, errors.New("no detail")
	}
	data, err := json.Marshal(d)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(data, &out)
	return out, err
}

// Signal is one narrowly scoped, user-explainable local observation.
type Signal struct {
	Status   Status   `json:"status"`
	Code     string   `json:"code,omitempty"`
	Detail   Detail   `json:"detail,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// UnmarshalJSON keeps the detail object verbatim so re-marshalling a decoded
// report reproduces the exact signed bytes.
func (s *Signal) UnmarshalJSON(data []byte) error {
	var raw struct {
		Status   Status          `json:"status"`
		Code     string          `json:"code"`
		Detail   json.RawMessage `json:"detail"`
		Warnings []string        `json:"warnings"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = Signal{Status: raw.Status, Code: raw.Code, Warnings: raw.Warnings}
	if len(raw.Detail) > 0 && string(raw.Detail) != "null" {
		s.Detail = RawDetail(append([]byte(nil), raw.Detail...))
	}
	return nil
}

// ScreenLockDetail explains the screen-lock verdict.
type ScreenLockDetail struct {
	LimitMinutes         int             `json:"limit_minutes"`
	Password             string          `json:"password"`
	PasswordDelaySeconds *int            `json:"password_delay_seconds,omitempty"`
	ScreensaverMinutes   *int            `json:"screensaver_minutes,omitempty"`
	ActivePower          string          `json:"active_power"`
	Profiles             []ProfileDetail `json:"profiles"`
}

func (*ScreenLockDetail) isDetail() {}

// ProfileDetail is one power profile's time until a password is required.
type ProfileDetail struct {
	Power             string `json:"power"`
	DisplayOffMinutes *int   `json:"display_off_minutes,omitempty"`
	LockMinutes       *int   `json:"lock_minutes,omitempty"`
	OK                bool   `json:"ok"`
}

// DiskDetail explains the disk-encryption verdict.
type DiskDetail struct {
	State   string `json:"state"`
	Percent *int   `json:"percent,omitempty"`
}

func (*DiskDetail) isDetail() {}

// UpdatesDetail explains the automatic-updates verdict. Keys are present only
// when they were read.
type UpdatesDetail struct {
	Check             *bool `json:"check,omitempty"`
	Download          *bool `json:"download,omitempty"`
	SecurityResponses *bool `json:"security_responses,omitempty"`
	SystemData        *bool `json:"system_data,omitempty"`
	OSInstall         *bool `json:"os_install,omitempty"`
	Paused            *bool `json:"paused,omitempty"`
	PolicyDisabled    *bool `json:"policy_disabled,omitempty"`
}

func (*UpdatesDetail) isDetail() {}

// PendingDetail describes waiting minor/security updates.
type PendingDetail struct {
	Count       int  `json:"count"`
	WaitingDays *int `json:"waiting_days,omitempty"`
}

func (*PendingDetail) isDetail() {}

// EndpointDetail explains the endpoint-protection verdict. macOS fills the
// Gatekeeper/XProtect fields, Windows the Defender/SecurityCenter fields.
type EndpointDetail struct {
	Gatekeeper         *bool  `json:"gatekeeper,omitempty"`
	SystemDataUpdates  *bool  `json:"system_data_updates,omitempty"`
	DefinitionsVersion *int   `json:"definitions_version,omitempty"`
	DefenderRealtime   *bool  `json:"defender_realtime,omitempty"`
	DefenderMode       string `json:"defender_mode,omitempty"`
	OtherAntivirus     *int   `json:"other_antivirus,omitempty"`
	DefinitionsAgeDays *int   `json:"definitions_age_days,omitempty"`
}

func (*EndpointDetail) isDetail() {}

// ProfileFacts is one power profile as read from the OS. DisplayOffSeconds nil
// means the display timer was not readable; 0 means never.
type ProfileFacts struct {
	Power             string
	DisplayOffSeconds *int
}

// ScreenLockFacts are macOS/Linux screen-lock facts. The time until a password
// is required on a profile is the sooner of display-off and screen saver
// (whichever is set and non-zero) plus the password delay.
type ScreenLockFacts struct {
	// Password is one of the Password* constants.
	Password             string
	PasswordDelaySeconds *int
	// ScreensaverSeconds is nil when the screen saver is not set (or not
	// readable); 0 means never.
	ScreensaverSeconds *int
	// ScreensaverKnown is true when the screen saver was read or is known to
	// be unset. When false, a too-long verdict cannot be definite because a
	// screen saver might start sooner.
	ScreensaverKnown bool
	ActivePower      string
	Profiles         []ProfileFacts
}

// WindowsScreenLockFacts are the Windows lock mechanisms. Any one of them can
// satisfy the limit: the machine inactivity limit, a secure screen saver, or
// display-off with "require sign-in on wake" on every power profile.
type WindowsScreenLockFacts struct {
	// InactivitySeconds is the machine inactivity limit; nil or 0 = not set.
	InactivitySeconds *int
	// ScreensaverConfigured is false when no screen saver program is set
	// (definitively none), nil when unreadable.
	ScreensaverConfigured *bool
	ScreensaverActive     *bool
	ScreensaverSecure     *bool
	ScreensaverSeconds    *int
	DisplayOffACSeconds   *int
	DisplayOffDCSeconds   *int
	ConsoleLockAC         *bool
	ConsoleLockDC         *bool
	DelayLockSeconds      *int
	ActivePower           string
}

// DiskFacts is the disk-encryption state read from the OS.
type DiskFacts struct {
	State   string
	Percent *int
}

// UpdateFacts are automatic-update settings. Nil means not read.
type UpdateFacts struct {
	Check             *bool
	Download          *bool
	SecurityResponses *bool
	SystemData        *bool
	OSInstall         *bool
	Paused            *bool
	PolicyDisabled    *bool
}

// PendingFacts counts minor/security updates waiting to install, excluding
// major OS upgrades. Count nil means unknown.
type PendingFacts struct {
	Count       *int
	WaitingDays *int
}

// EndpointFacts are malware-protection facts.
type EndpointFacts struct {
	Gatekeeper         *bool
	SystemDataUpdates  *bool
	DefinitionsVersion *int
	DefinitionsAgeDays *int
	DefenderRealtime   *bool
	DefenderMode       string
	OtherAntivirus     *int
}

// Observation is the raw probe output. It carries booleans, integers and
// fixed enum strings only, never opaque command output or a host inventory.
// The legacy boolean fields are honored when the richer facts are absent.
type Observation struct {
	DiskEncryptionEnabled *bool
	ScreenLockEnabled     *bool
	ScreenLockMinutes     *int
	ScreenLockSecure      *bool
	AutoUpdatesEnabled    *bool
	PendingUpdates        *bool
	EndpointProtection    *bool

	OSVersion         string
	Disk              *DiskFacts
	ScreenLock        *ScreenLockFacts
	WindowsScreenLock *WindowsScreenLockFacts
	Updates           *UpdateFacts
	Pending           *PendingFacts
	Endpoint          *EndpointFacts
}

// Report is the unsigned posture payload. Transport adds a signature and
// device identity outside this package.
type Report struct {
	SchemaVersion      int       `json:"schema_version"`
	CollectedAt        time.Time `json:"collected_at"`
	Platform           string    `json:"platform"`
	OSVersion          string    `json:"os_version"`
	CheckerVersion     string    `json:"checker_version"`
	DiskEncryption     Signal    `json:"disk_encryption"`
	ScreenLock         Signal    `json:"screen_lock"`
	AutomaticUpdates   Signal    `json:"automatic_updates"`
	PendingMaintenance Signal    `json:"pending_maintenance"`
	EndpointProtection Signal    `json:"endpoint_protection"`
}

// SanitizeToken keeps only [A-Za-z0-9._-] from an OS-provided string and caps
// its length, so it can never break the signature contract.
func SanitizeToken(value string) string {
	out := make([]byte, 0, len(value))
	for i := 0; i < len(value) && len(out) < 64; i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' {
			out = append(out, c)
		}
	}
	return string(out)
}

// Evaluate maps known facts to transparent outcomes. A definite failure beats
// an unknown; a pending update is a warning, never a configuration failure.
func Evaluate(ob Observation, platform, osVersion, checkerVersion string, at time.Time) Report {
	if osVersion == "" {
		osVersion = ob.OSVersion
	}
	osVersion = SanitizeToken(osVersion)
	if osVersion == "" {
		osVersion = "unknown"
	}
	return Report{
		SchemaVersion:      1,
		CollectedAt:        at.UTC(),
		Platform:           SanitizeToken(platform),
		OSVersion:          osVersion,
		CheckerVersion:     SanitizeToken(checkerVersion),
		DiskEncryption:     diskSignal(ob),
		ScreenLock:         screenLockSignal(ob),
		AutomaticUpdates:   updatesSignal(ob, platform),
		PendingMaintenance: pendingSignal(ob),
		EndpointProtection: endpointSignal(ob, platform),
	}
}

func unknown() Signal { return Signal{Status: Unknown, Code: CodeUnavailable} }

func boolSignal(ok *bool, failCode string) Signal {
	if ok == nil {
		return unknown()
	}
	if *ok {
		return Signal{Status: Pass}
	}
	return Signal{Status: Fail, Code: failCode}
}

func diskSignal(ob Observation) Signal {
	if ob.Disk == nil {
		return boolSignal(ob.DiskEncryptionEnabled, CodeDiskDisabled)
	}
	detail := &DiskDetail{State: ob.Disk.State}
	if ob.Disk.State == DiskEncrypting || ob.Disk.State == DiskDecrypting {
		detail.Percent = ob.Disk.Percent
	}
	switch ob.Disk.State {
	case DiskOn, DiskEncrypting:
		return Signal{Status: Pass, Detail: detail}
	case DiskOff, DiskPendingRestart:
		return Signal{Status: Fail, Code: CodeDiskDisabled, Detail: detail}
	case DiskDecrypting:
		return Signal{Status: Fail, Code: CodeDiskDecrypting, Detail: detail}
	case DiskSuspended:
		return Signal{Status: Fail, Code: CodeDiskSuspended, Detail: detail}
	default:
		return unknown()
	}
}

func screenLockSignal(ob Observation) Signal {
	switch {
	case ob.WindowsScreenLock != nil:
		return windowsScreenLock(*ob.WindowsScreenLock)
	case ob.ScreenLock != nil:
		return profileScreenLock(*ob.ScreenLock)
	default:
		return legacyScreenLock(ob.ScreenLockEnabled, ob.ScreenLockMinutes, ob.ScreenLockSecure)
	}
}

func legacyScreenLock(enabled *bool, minutes *int, secure *bool) Signal {
	if enabled == nil || minutes == nil || secure == nil {
		return unknown()
	}
	if !*enabled {
		return Signal{Status: Fail, Code: CodeScreenLockDisabled}
	}
	if *minutes <= 0 || *minutes > LimitMinutes {
		return Signal{Status: Fail, Code: CodeScreenLockTooLong}
	}
	if !*secure {
		return Signal{Status: Fail, Code: CodeScreenLockPasswordNotRequired}
	}
	return Signal{Status: Pass}
}

func intp(v int) *int { return &v }

// ceilMinutes rounds seconds up so a partial minute is never reported as a
// shorter, safer time.
func ceilMinutes(seconds int) int { return (seconds + 59) / 60 }

// effectiveDelay applies the owner rule: a delay of 5 seconds or less counts
// as immediate (macOS defaults to 5 s).
func effectiveDelay(seconds int) int {
	if seconds <= 5 {
		return 0
	}
	return seconds
}

type profileOutcome int

const (
	outcomeOK profileOutcome = iota
	outcomeTooLong
	outcomeNever
	outcomePasswordOff
	outcomeUnknown
)

// profileScreenLock implements the macOS/Linux rule for every power profile.
func profileScreenLock(f ScreenLockFacts) Signal {
	detail := &ScreenLockDetail{LimitMinutes: LimitMinutes, Password: f.Password, ActivePower: f.ActivePower, Profiles: []ProfileDetail{}}
	switch f.Password {
	case PasswordImmediate, PasswordDelay, PasswordOff, PasswordUnknown:
	default:
		detail.Password = PasswordUnknown
	}
	delay := -1
	if detail.Password == PasswordImmediate {
		delay = 0
		if f.PasswordDelaySeconds != nil {
			delay = *f.PasswordDelaySeconds
		}
	} else if detail.Password == PasswordDelay {
		if f.PasswordDelaySeconds != nil && *f.PasswordDelaySeconds >= 0 {
			delay = *f.PasswordDelaySeconds
		} else {
			detail.Password = PasswordUnknown
		}
	}
	if delay >= 0 {
		detail.PasswordDelaySeconds = intp(delay)
	}
	if f.ScreensaverSeconds != nil {
		detail.ScreensaverMinutes = intp(ceilMinutes(max(*f.ScreensaverSeconds, 0)))
	}

	profiles := f.Profiles
	if len(profiles) == 0 {
		// No power profile was readable: the screen saver alone can still
		// prove a pass (display-off could only make the lock sooner).
		profiles = []ProfileFacts{{Power: PowerAny}}
	}
	seen := map[profileOutcome]bool{}
	for _, p := range profiles {
		pd := ProfileDetail{Power: p.Power}
		if p.DisplayOffSeconds != nil {
			pd.DisplayOffMinutes = intp(ceilMinutes(max(*p.DisplayOffSeconds, 0)))
		}
		outcome, lockSeconds := evaluateProfile(p, f, detail.Password, delay)
		if lockSeconds != nil {
			if *lockSeconds == 0 {
				pd.LockMinutes = intp(0)
			} else {
				pd.LockMinutes = intp(ceilMinutes(*lockSeconds))
			}
		}
		pd.OK = outcome == outcomeOK
		seen[outcome] = true
		detail.Profiles = append(detail.Profiles, pd)
	}
	if len(f.Profiles) == 0 && f.ScreensaverSeconds == nil && detail.Password != PasswordOff {
		// Nothing about timing was read at all.
		if detail.Password == PasswordUnknown {
			return unknown()
		}
		return Signal{Status: Unknown, Code: CodeUnavailable, Detail: detail}
	}
	switch {
	case seen[outcomePasswordOff]:
		return Signal{Status: Fail, Code: CodeScreenLockPasswordOff, Detail: detail}
	case seen[outcomeNever]:
		return Signal{Status: Fail, Code: CodeScreenLockNever, Detail: detail}
	case seen[outcomeTooLong]:
		return Signal{Status: Fail, Code: CodeScreenLockTooLong, Detail: detail}
	case seen[outcomeUnknown]:
		return Signal{Status: Unknown, Code: CodeUnavailable, Detail: detail}
	default:
		return Signal{Status: Pass, Detail: detail}
	}
}

// evaluateProfile returns the profile's outcome and, when it is definite, the
// seconds until a password is required (0 = never).
func evaluateProfile(p ProfileFacts, f ScreenLockFacts, password string, delay int) (profileOutcome, *int) {
	if password == PasswordOff {
		return outcomePasswordOff, intp(0)
	}
	displayKnown := p.DisplayOffSeconds != nil
	idle := -1
	if displayKnown && *p.DisplayOffSeconds > 0 {
		idle = *p.DisplayOffSeconds
	}
	if f.ScreensaverSeconds != nil && *f.ScreensaverSeconds > 0 && (idle < 0 || *f.ScreensaverSeconds < idle) {
		idle = *f.ScreensaverSeconds
	}
	// Every timer that could shorten the idle time was read.
	complete := displayKnown && f.ScreensaverKnown
	if idle < 0 {
		if complete {
			return outcomeNever, intp(0)
		}
		return outcomeUnknown, nil
	}
	if password == PasswordUnknown || delay < 0 {
		// The idle time alone is a lower bound on the lock time.
		if complete && idle > LimitMinutes*60 {
			return outcomeTooLong, nil
		}
		return outcomeUnknown, nil
	}
	total := idle + effectiveDelay(delay)
	if total <= LimitMinutes*60 {
		return outcomeOK, intp(total)
	}
	if !complete {
		return outcomeUnknown, nil
	}
	return outcomeTooLong, intp(total)
}

// windowsScreenLock applies the Windows rule: every power profile's lock time
// is the soonest of the inactivity limit, a secure screen saver, and
// display-off plus the sign-in delay when sign-in on wake is required.
func windowsScreenLock(f WindowsScreenLockFacts) Signal {
	detail := &ScreenLockDetail{LimitMinutes: LimitMinutes, ActivePower: f.ActivePower, Profiles: []ProfileDetail{}}
	limit := LimitMinutes * 60

	// Profile-independent mechanisms. independent < 0 means none.
	independent := -1
	if f.InactivitySeconds != nil && *f.InactivitySeconds > 0 {
		independent = *f.InactivitySeconds
	}
	ssKnown := false
	if f.ScreensaverConfigured != nil && !*f.ScreensaverConfigured {
		ssKnown = true
	} else if f.ScreensaverConfigured != nil && f.ScreensaverActive != nil && (!*f.ScreensaverActive || (f.ScreensaverSecure != nil && f.ScreensaverSeconds != nil)) {
		ssKnown = true
		if *f.ScreensaverActive {
			detail.ScreensaverMinutes = intp(ceilMinutes(max(*f.ScreensaverSeconds, 0)))
			if *f.ScreensaverSecure && *f.ScreensaverSeconds > 0 {
				if independent < 0 || *f.ScreensaverSeconds < independent {
					independent = *f.ScreensaverSeconds
				}
			}
		}
	}

	delay := 0
	if f.DelayLockSeconds != nil && *f.DelayLockSeconds > 0 {
		delay = *f.DelayLockSeconds
	}
	displayKnown := f.DisplayOffACSeconds != nil && f.DisplayOffDCSeconds != nil && f.ConsoleLockAC != nil && f.ConsoleLockDC != nil
	consoleLock := displayKnown && (*f.ConsoleLockAC || *f.ConsoleLockDC)

	// The inactivity limit and a secure screen saver both require a password
	// immediately; display-off requires one after the sign-in delay.
	switch {
	case independent > 0 && independent <= limit:
		detail.Password = PasswordImmediate
		detail.PasswordDelaySeconds = intp(0)
	case consoleLock:
		if effectiveDelay(delay) == 0 {
			detail.Password = PasswordImmediate
		} else {
			detail.Password = PasswordDelay
		}
		detail.PasswordDelaySeconds = intp(delay)
	case independent > 0:
		detail.Password = PasswordImmediate
		detail.PasswordDelaySeconds = intp(0)
	case displayKnown && ssKnown:
		// No inactivity limit, no secure screen saver, no sign-in on wake.
		detail.Password = PasswordOff
	default:
		detail.Password = PasswordUnknown
	}

	if independent > 0 && independent <= limit {
		detail.Profiles = append(detail.Profiles, ProfileDetail{Power: PowerAny, LockMinutes: intp(ceilMinutes(independent)), OK: true})
		return Signal{Status: Pass, Detail: detail}
	}

	if !displayKnown {
		pd := ProfileDetail{Power: PowerAny}
		if independent > 0 {
			pd.LockMinutes = intp(ceilMinutes(independent))
		}
		detail.Profiles = append(detail.Profiles, pd)
		return Signal{Status: Unknown, Code: CodeUnavailable, Detail: detail}
	}

	anyNever, allOK := false, true
	for _, p := range []struct {
		power   string
		display int
		lock    bool
	}{
		{PowerAC, *f.DisplayOffACSeconds, *f.ConsoleLockAC},
		{PowerBattery, *f.DisplayOffDCSeconds, *f.ConsoleLockDC},
	} {
		lock := independent
		if p.lock && p.display > 0 {
			candidate := p.display + effectiveDelay(delay)
			if lock < 0 || candidate < lock {
				lock = candidate
			}
		}
		pd := ProfileDetail{Power: p.power, DisplayOffMinutes: intp(ceilMinutes(max(p.display, 0)))}
		if lock < 0 {
			pd.LockMinutes = intp(0)
			anyNever = true
		} else {
			pd.LockMinutes = intp(ceilMinutes(lock))
		}
		pd.OK = lock > 0 && lock <= limit
		allOK = allOK && pd.OK
		detail.Profiles = append(detail.Profiles, pd)
	}
	switch {
	case allOK:
		return Signal{Status: Pass, Detail: detail}
	case !ssKnown:
		// A screen saver that could not be read might still lock in time.
		return Signal{Status: Unknown, Code: CodeUnavailable, Detail: detail}
	case detail.Password == PasswordOff:
		return Signal{Status: Fail, Code: CodeScreenLockPasswordOff, Detail: detail}
	case anyNever:
		return Signal{Status: Fail, Code: CodeScreenLockNever, Detail: detail}
	default:
		return Signal{Status: Fail, Code: CodeScreenLockTooLong, Detail: detail}
	}
}

func updatesSignal(ob Observation, platform string) Signal {
	f := ob.Updates
	if f == nil {
		return boolSignal(ob.AutoUpdatesEnabled, CodeUpdatesDisabled)
	}
	detail := &UpdatesDetail{
		Check: f.Check, Download: f.Download, SecurityResponses: f.SecurityResponses,
		SystemData: f.SystemData, OSInstall: f.OSInstall, Paused: f.Paused, PolicyDisabled: f.PolicyDisabled,
	}
	required := []*bool{f.Check, f.Download}
	if platform == "darwin" {
		required = append(required, f.SecurityResponses)
	}
	missing := false
	for _, value := range required {
		if value == nil {
			missing = true
		} else if !*value {
			return Signal{Status: Fail, Code: CodeUpdatesDisabled, Detail: detail}
		}
	}
	if f.PolicyDisabled != nil && *f.PolicyDisabled {
		return Signal{Status: Fail, Code: CodeUpdatesDisabled, Detail: detail}
	}
	if f.Paused != nil && *f.Paused {
		return Signal{Status: Fail, Code: CodeUpdatesPaused, Detail: detail}
	}
	if missing || isEmptyUpdates(detail) {
		return Signal{Status: Unknown, Code: CodeUnavailable, Detail: nilIfEmpty(detail)}
	}
	return Signal{Status: Pass, Detail: detail}
}

func isEmptyUpdates(d *UpdatesDetail) bool {
	return d.Check == nil && d.Download == nil && d.SecurityResponses == nil && d.SystemData == nil && d.OSInstall == nil && d.Paused == nil && d.PolicyDisabled == nil
}

func nilIfEmpty(d *UpdatesDetail) Detail {
	if isEmptyUpdates(d) {
		return nil
	}
	return d
}

func pendingSignal(ob Observation) Signal {
	if ob.Pending == nil {
		if ob.PendingUpdates == nil {
			return unknown()
		}
		if *ob.PendingUpdates {
			return Signal{Status: NeedsAttention, Code: CodeUpdatesPending}
		}
		return Signal{Status: Pass}
	}
	if ob.Pending.Count == nil {
		return unknown()
	}
	detail := &PendingDetail{Count: *ob.Pending.Count}
	if *ob.Pending.Count > 0 {
		detail.WaitingDays = ob.Pending.WaitingDays
		return Signal{Status: NeedsAttention, Code: CodeUpdatesPending, Detail: detail}
	}
	return Signal{Status: Pass, Detail: detail}
}

func endpointSignal(ob Observation, platform string) Signal {
	f := ob.Endpoint
	if f == nil {
		return boolSignal(ob.EndpointProtection, CodeEndpointUnavailable)
	}
	if platform == "windows" {
		return windowsEndpoint(*f)
	}
	detail := &EndpointDetail{Gatekeeper: f.Gatekeeper, SystemDataUpdates: f.SystemDataUpdates, DefinitionsVersion: f.DefinitionsVersion, DefinitionsAgeDays: f.DefinitionsAgeDays}
	var warnings []string
	if f.DefinitionsAgeDays != nil && *f.DefinitionsAgeDays > macDefinitionsStaleDays {
		warnings = append(warnings, WarningDefinitionsStale)
	}
	switch {
	case f.Gatekeeper != nil && !*f.Gatekeeper:
		return Signal{Status: Fail, Code: CodeGatekeeperDisabled, Detail: detail, Warnings: warnings}
	case f.SystemDataUpdates != nil && !*f.SystemDataUpdates:
		return Signal{Status: Fail, Code: CodeDefinitionsUpdatesOff, Detail: detail, Warnings: warnings}
	case f.Gatekeeper == nil || f.SystemDataUpdates == nil:
		return Signal{Status: Unknown, Code: CodeUnavailable, Detail: detail, Warnings: warnings}
	default:
		return Signal{Status: Pass, Detail: detail, Warnings: warnings}
	}
}

func windowsEndpoint(f EndpointFacts) Signal {
	detail := &EndpointDetail{DefenderRealtime: f.DefenderRealtime, DefenderMode: f.DefenderMode, OtherAntivirus: f.OtherAntivirus, DefinitionsAgeDays: f.DefinitionsAgeDays}
	switch detail.DefenderMode {
	case DefenderNormal, DefenderPassive, DefenderEDRBlock, DefenderOff, DefenderUnknown, "":
	default:
		detail.DefenderMode = DefenderUnknown
	}
	defenderOK := f.DefenderRealtime != nil && *f.DefenderRealtime && detail.DefenderMode == DefenderNormal
	otherOK := f.OtherAntivirus != nil && *f.OtherAntivirus >= 1
	if defenderOK || otherOK {
		var warnings []string
		if defenderOK && !otherOK && f.DefinitionsAgeDays != nil && *f.DefinitionsAgeDays > windowsDefinitionsStaleDays {
			warnings = append(warnings, WarningDefinitionsStale)
		}
		return Signal{Status: Pass, Detail: detail, Warnings: warnings}
	}
	defenderKnown := f.DefenderRealtime != nil && detail.DefenderMode != "" && detail.DefenderMode != DefenderUnknown
	if defenderKnown && f.OtherAntivirus != nil {
		return Signal{Status: Fail, Code: CodeEndpointUnavailable, Detail: detail}
	}
	return Signal{Status: Unknown, Code: CodeUnavailable, Detail: detail}
}
