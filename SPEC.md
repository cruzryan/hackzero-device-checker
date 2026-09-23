# HackZero Device Checker

## Product decision

HackZero Device Checker is a small, open-source, read-only laptop security checker. It is not an MDM.

It runs in the background on a work laptop, checks a narrow set of security settings, and sends a signed result to HackZero. Its job is to create trustworthy, continuous evidence for SOC 2 without asking a person to repeatedly upload screenshots.

Supported in the first release:

- macOS
- Windows 11
- Ubuntu
- Debian

It does not change device settings, read files, take screenshots, record activity, provide a shell, wipe a device, or remotely control a computer.

## What it proves

The checker supplies evidence for these controls when it has a fresh report from every in-scope device:

| Control | What the checker proves |
| --- | --- |
| AC-11 Managed devices | Which laptop is assigned to each active person with production/customer-data access, and that it is reporting. |
| AC-12 Device hardening | Disk encryption, automatic screen lock, and automatic operating-system updates are enabled. |
| OPS-04 Endpoint malware protection | The operating system's approved malware protection is active and healthy. |

The checker does **not** satisfy AC-13 Device return and wipe. It can identify the departing person's assigned laptop, but it cannot claim that the laptop was returned, wiped, destroyed, or stripped of company data.

### Required checks

| Check | macOS | Windows 11 | Ubuntu / Debian |
| --- | --- | --- | --- |
| Disk encryption | FileVault enabled | BitLocker enabled | LUKS enabled |
| Screen lock | Automatic lock with password required on return, within the HackZero policy limit | Equivalent Windows lock/password policy | Equivalent supported desktop lock policy |
| Automatic OS updates | macOS automatic updates enabled | Windows Update automatic updates enabled | Unattended security updates enabled |
| Malware protection | Gatekeeper enabled and XProtect data updates on | Microsoft Defender real-time protection on, or another antivirus on | Supported malware-protection service active |

The default HackZero screen-lock limit is 15 minutes. A customer can only change that limit through their documented security policy; it is not a per-device toggle.

These four are the only things the checker checks and shows. It does not
report whether updates are waiting to install, and it does not warn about the
age of malware definitions: neither is an AC-12 requirement. Automatic updates
being enabled is the requirement; if they are disabled, AC-12 fails.

## Collector report v2

`schema_version` stays `1`; every v2 addition is optional, so older servers and
readers keep working. The report keeps its field order:
`schema_version, collected_at, platform, os_version, checker_version,
disk_encryption, screen_lock, automatic_updates, endpoint_protection`.
Earlier builds also sent `pending_maintenance`; it is no longer collected or
sent, and the service tolerates it being absent.

- `os_version` is the real OS version: macOS `sw_vers -productVersion`
  (`26.5.2`), Windows `Major.Minor.Build` (`10.0.26200`), Linux `VERSION_ID`
  (`24.04`). `unknown` when it cannot be read.
- `checker_version` is the release version set at build time; `dev` for local
  builds.

Each signal is:

```json
{ "status": "pass|fail|unknown",
  "code": "primary reason, omitted on pass",
  "detail": { "raw facts, omitted when nothing was read" },
  "warnings": ["warning codes, omitted when empty; never change status"] }
```

`warnings` stays in the contract for compatibility, but nothing emits it
today.

### Signature safety

The service verifies the Ed25519 signature over Python
`json.dumps(unsigned, separators=(",", ":"), ensure_ascii=True)` of the parsed
envelope; the collector signs Go `json.Marshal`. Those bytes agree only when
every value is an integer, a boolean, null, or an ASCII string without `<`,
`>` or `&`. Detail values are therefore only integers, booleans and fixed
lowercase enum strings: never floats, command output, or product names.
`os_version` and `checker_version` are reduced to `[A-Za-z0-9._-]`. A test
marshals a fully populated report and fails on any other byte, and the server
repository verifies envelopes signed by this code
(`apps/trust/tests/test_device_checker_signature_v2.py`).

### Rules and detail per signal

**Screen lock** (`screen_lock`). For every power profile the computer has, the
time until a password is required must be 15 minutes or less (exactly 15
passes). Time until password = the sooner of display-off and screen saver
(whichever is set and not "never") + the password delay. A delay of 5 seconds
or less counts as immediate (macOS defaults to 5 s). "Never" fails, and no
password on wake fails. A definite failure beats an unknown.

```json
{ "limit_minutes": 15,
  "password": "immediate|delay|off|unknown",
  "password_delay_seconds": 300,
  "screensaver_minutes": 20,
  "active_power": "ac|battery|ups|",
  "profiles": [ { "power": "battery|ac|ups|any", "display_off_minutes": 2,
                  "lock_minutes": 7, "ok": true } ] }
```

`password_delay_seconds` is present when the password is immediate or delayed;
`screensaver_minutes` only when a screen saver timer is set (0 = never);
`display_off_minutes` only when the profile has a display timer;
`lock_minutes` only when it is known (0 = never). Codes:
`screen_lock_password_off`, `screen_lock_never`,
`screen_lock_timeout_too_long`, `signal_unavailable`. Legacy codes
`screen_lock_disabled` and `screen_lock_password_not_required` remain valid.

| Platform | Sources |
| --- | --- |
| macOS | `pmset -g custom` (Battery / AC / UPS `displaysleep`; a Mac mini has only AC), `pmset -g batt` (active source), `sysadminctl -screenLock status` (password delay), `defaults -currentHost read com.apple.screensaver idleTime`, and an MDM profile in `/Library/Managed Preferences` which wins. Read only in the logged-in user's console session; otherwise unknown. |
| Windows | Any one of: machine `InactivityTimeoutSecs` (1-900 s); a secure screen saver (policy key overrides the user key) at 1-900 s; or display-off on AC and on battery (`powercfg /qh ... VIDEOIDLE`) with sign-in on wake (`CONSOLELOCK`) plus `DelayLockInterval`. `DelayLockInterval` = 0xFFFFFFFF means sign-in is never required. Profiles are `ac`/`battery` for the display path and `any` for the inactivity / screen-saver paths. A missing key is unknown, never false. |
| Linux (GNOME) | `org.gnome.desktop.session idle-delay`, `org.gnome.desktop.screensaver lock-enabled` and `lock-delay`, read only with the user's session bus. One `any` profile. |

**Disk encryption** (`disk_encryption`): `{ "state": "on|off|encrypting|decrypting|pending_restart|suspended", "percent": 42 }`
(`percent` while encrypting/decrypting). `encrypting` passes. Codes:
`disk_encryption_disabled` (off, pending_restart), `disk_encryption_decrypting`,
`disk_encryption_suspended` (Windows: encrypted with protection off, or
encryption paused). macOS reads `fdesetup status` only (diskutil's
"Encrypted:" says No on a FileVault Mac). Windows reads
`Get-BitLockerVolume`. Linux checks for a `crypt` ancestor of the root
filesystem (`findmnt`, `lsblk -s`).

**Automatic updates** (`automatic_updates`). macOS detail
`{ "check", "download", "security_responses", "system_data", "os_install" }`
from `/Library/Preferences/com.apple.SoftwareUpdate.plist` (a missing key is
the OS default, on; a managed profile wins). Required: check, download and
security responses. System data belongs to endpoint protection; installing
macOS upgrades automatically is not required. Windows detail
`{ "check", "download", "paused", "policy_disabled" }` from Windows Update
policy (`NoAutoUpdate`, `AUOptions`), the AutoUpdate COM notification level,
`PauseUpdatesExpiryTime`, and the `wuauserv` start type. Linux detail
`{ "check", "download" }` from `apt-config dump APT::Periodic`. Codes:
`automatic_updates_disabled`, `automatic_updates_paused`.

**Endpoint protection** (`endpoint_protection`). macOS detail
`{ "gatekeeper", "system_data_updates", "definitions_version", "definitions_age_days" }`
from `spctl --status`, `ConfigDataInstall`, and `xprotect version`. Passes
when Gatekeeper is on and XProtect data updates are on. Codes
`gatekeeper_disabled`, `definitions_updates_off`. Windows detail
`{ "defender_realtime", "defender_mode": "normal|passive|edr_block|off|unknown", "other_antivirus", "definitions_age_days" }`
from `Get-MpComputerStatus` and `root/SecurityCenter2 AntiVirusProduct`
(`other_antivirus` counts enabled, up-to-date products that are not
Defender). Passes when Defender real-time protection runs in normal mode or
another antivirus is healthy; code `endpoint_protection_unavailable`. Linux
keeps the ClamAV daemon check. `definitions_version` and
`definitions_age_days` are raw facts shown only in Diagnostics: they never
produce a warning or change the status.

## Collector command line

The desktop app talks to the collector only through these commands. All
print JSON on stdout.

| Command | Behavior |
| --- | --- |
| `status` | Collect and print the report. Never sent. |
| `report` | Collect, sign and send one full report; print a RunResult and save it as `last-report.json`. |
| `run [--once]` | Scheduler tick (loop without `--once`). Prints `{"full_report_due","heartbeat_due","delivery"}`; a full report it sends is saved as `last-report.json`. |
| `last` | Print `last-report.json`, or `{"available": false}`. |
| `diagnose` | `{checker_version, os_version, platform, paired, workspace_name, person_name, device_id, agent_state, queue_count, last}`. Never the private key or the identity file. |
| `pair`, `connection`, `disconnect` | Unchanged. |

RunResult (`last-report.json`, owner-only, written atomically):

```json
{ "source": "manual|background",
  "checked_at": "RFC 3339",
  "report": { "the exact signed report" },
  "delivery": "uploaded|queued|rejected|not_sent",
  "http_status": 200,
  "error": "short ASCII explanation when not uploaded",
  "server": { "status": "pass|fail", "problems": [], "warnings": [] } }
```

Delivery rules: a 2xx response is `uploaded` and the service's `device`
verdict is stored as `server`. No response, 5xx or 429 is `queued` and
retried in order. Any other 4xx is `rejected`: it is not queued and never
retried (401/404/410 mean the computer is no longer connected). When a queued
report is later delivered, `last-report.json` is updated. A corrupt queue file
is renamed `*.corrupt` and never blocks delivery. A lock file in the state
directory (`device-checker.lock`) lets only one collector run at a time; it is
stale after 2 minutes, and a second run waits up to 20 seconds, then prints
`{"error":"busy",...}` and exits 4.

## Who and what is in scope

The People roster is the source of truth. A person needs device evidence only if they are:

- active;
- a person, not a shared mailbox or bot; and
- marked as able to reach production or customer data.

Device records support multiple devices per person, reassignment history, BYOD, shared devices, lost/replaced devices, and duplicate detection.

Every device has a stable device identifier and one primary evidence source:

- HackZero Device Checker
- Kandji
- Jamf
- Intune

If two fresh sources disagree, HackZero shows a conflict and requires attention. A fresh explicit failure always wins over a passing result. The same laptop must never count twice.

## Installation and pairing

### Packages

| Platform | Package | Background service |
| --- | --- | --- |
| macOS | Signed and notarized `.pkg` | `launchd` |
| Windows 11 | Signed `.msi` | Windows Service |
| Ubuntu / Debian | Signed `.deb` | `systemd` |

The normal operating-system administrator confirmation happens once during install. The installer registers the service to start automatically at boot.

### Pairing

1. An admin or user selects **Install HackZero Device Checker** from HackZero.
2. They download the platform-appropriate package.
3. The installer starts the checker service.
4. The checker opens the default browser once.
5. The person signs into HackZero normally.
6. HackZero displays the device name and asks to pair it to the matching People record.
7. The browser automatically returns a one-time result to the checker.
8. The checker receives a narrow device credential and begins reporting.

Pairing uses OAuth authorization code flow with PKCE. The checker opens a temporary listener on `127.0.0.1` with an operating-system-assigned ephemeral port. It accepts only the expected callback/state, then closes within minutes.

There is no permanent local port, inbound internet connection, firewall exception, pasted long-lived token, or stored user-session token.

The checker generates a device-specific keypair locally. HackZero stores its public key and accepts only reports signed by that device. The private key stays in the operating system's secure credential store.

If the signed-in email has no matching People record, is out of scope, or has an ambiguous match, an admin assigns the device explicitly. HackZero never silently assigns it to the wrong person.

## Runtime and reporting

The service runs:

- immediately after installation;
- at each laptop boot;
- once every 24 hours for a full posture check;
- when a user selects **Check now**;
- when a queued result can be sent after the laptop comes back online.

It sends a lightweight heartbeat every 6 hours while the laptop is on and connected. The checker looks for a signed product update at launch and then once every 24 hours, with randomized delay and normal backoff.

Reports use outbound HTTPS only. The product does not run a web server or listen on a port after pairing.

### Status rules

| State | Meaning |
| --- | --- |
| Pass | A received report says every required setting passed. |
| Fail | A received report says at least one required setting failed. |
| Not recently checked | The device has not sent a recent full report; it may be powered off, asleep, or offline. |
| Not installed | An in-scope person has no checker-backed or valid manual device evidence. |
| Needs renewal | Manual evidence is more than 90 days old. |

Only a report with a failing field creates **Fail**. A laptop that was powered off does not fail a control. HackZero must never fabricate a daily passing result when no report was received.

Use HackZero server receipt time for evidence freshness, not the laptop's clock.

Freshness thresholds:

- fresh: full report received within 30 hours;
- needs a fresh check: more than 30 hours but fewer than 7 days;
- needs attention: 7 days or more without a full report.

Historic reports remain immutable if the checker is uninstalled. The device becomes no longer reporting; historic evidence is never deleted.

## Data collected

Each report contains only:

- device ID and serial/OS identity where available;
- device name;
- operating system and version;
- assigned HackZero person ID;
- result/reason for the four checks;
- agent version and rules version;
- device-signed report timestamp and HackZero server receipt timestamp.

The checker never collects:

- files or file names;
- screenshots or screen recordings;
- keystrokes;
- browser history;
- location;
- arbitrary process/app inventory;
- arbitrary shell output;
- remote-shell access;
- remote-control or wipe capability.

## HackZero web UI

There is no new top-level Device Checker tab.

The operational view belongs in the existing People page. Device records exist internally, but appear within each expanded person card.

Top-of-page rollup:

```text
Device security
2 of 3 people with production access have a current protected laptop.

[ View 1 person who needs action ]
```

Person card:

```text
Work device                                      Protected
Example work laptop · macOS 26
Checked 8 minutes ago

FileVault          On
Screen lock        Password required after 5 min
Mac updates        Automatic security updates on
Malware protection XProtect and Gatekeeper active

[ Check now ]  [ View device history ]
```

Control pages for AC-11, AC-12, and OPS-04 link directly to the filtered People records that need action. They recommend Device Checker only where it provides the control's actual evidence.

### System tray / menu bar

The local app has a minimal native status surface:

```text
HackZero Device Checker
Protected
Last checked: 8 minutes ago

[ Check now ]
[ Open HackZero ]
[ What we read ]
```

- Windows: system tray.
- macOS: menu bar.
- Ubuntu/Debian: tray icon where the desktop supports it; otherwise `hackzero-device status` and standard desktop notifications.

All detailed UX remains web-based in HackZero. Do not build an Electron or Tauri desktop dashboard.

## Remediation

Every actual failing report maps to a hand-reviewed, versioned operating-system-specific instruction page.

```text
docs/remediation/
  macos-26/
    filevault.md
    screen-lock.md
    automatic-updates.md
    malware-protection.md
  windows-11/
    bitlocker.md
    screen-lock.md
    windows-update.md
    defender.md
  ubuntu-debian/
    encryption.md
    screen-lock.md
    unattended-upgrades.md
    malware-protection.md
```

Each page states the supported OS version, exact UI path/commands, official vendor source, whether administrator permission is required, expected result after fixing, and last-reviewed date.

Production instructions are not generated by an LLM.

The website shows the matched instructions in plain English and lets the user select **Check again** when finished.

## Reminders

At more than 30 hours without a full report, HackZero shows **Needs a fresh check** in the People UI.

At 7 days without a full report, HackZero can email the person:

```text
Subject: Your HackZero Device Checker needs attention

We have not received a recent security check from your work device.

[ Download / reinstall HackZero Device Checker ]
[ Get help ]
```

The email includes the device name, last successful check date, platform-appropriate reinstall link, and support link. It does not characterize the person as failing.

## AC-13 departure flow

When an active person receives a departure date, HackZero creates one linked offboarding workflow:

1. HR-05 records access removal from the systems approved at onboarding.
2. AC-13 records what happened to each assigned device.

For each device, record one outcome:

- returned;
- securely wiped;
- securely destroyed; or
- personal device: company data removed.

The AC-13 record includes asset, date, method, and person who completed/recorded it. When there are no departures in the relevant period, create a dated no-departures record.

## Auditor evidence

Provide one clear export for checker-backed evidence:

- full in-scope People population;
- device assignments and reassignment history;
- stable device identifiers;
- primary evidence source;
- four results per report;
- full timestamped history;
- server receipt times;
- stale/reporting gaps;
- explicit failures and conflicts;
- checker version and rules version.

Update the SOC 2 control matrix so AC-11, AC-12, and OPS-04 explicitly accept the Device Checker's signed per-device report. Manual settings screenshots remain the fallback for companies that use neither an MDM nor Device Checker.

## Public page and open source

Public page: `https://hackzero.ai/device-checker`

The page should feel professional, vibrant, and confident while matching HackZero's visual language. It should not use a fake dashboard or product screenshot.

It includes:

- direct Mac, Windows, and Linux download buttons;
- a prominent GitHub source link;
- a concise explanation of what it checks;
- a prominent explanation of what it never accesses;
- install and uninstall instructions;
- privacy and security design;
- security-reporting link;
- release hashes, SBOM, and current first-party security-critical line count.

The GitHub repository includes a strong `README.md`, license, contribution guidance, security policy, threat model, supported-platform matrix, reproducible-build instructions, release signing information, and test coverage for every supported check.

Do not claim a code-size number until CI calculates it from the released source. Describe the product as small, focused, and auditable instead.
