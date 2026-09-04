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
| Malware protection | XProtect and Gatekeeper enabled/current | Microsoft Defender real-time protection enabled and current | Supported malware-protection service active and definitions current |

The default HackZero screen-lock limit is 15 minutes. A customer can only change that limit through their documented security policy; it is not a per-device toggle.

### Updates: two separate facts

The checker records both of these facts:

1. **Automatic updates enabled**. This is the AC-12 requirement. If disabled, AC-12 fails.
2. **Important update pending**. This is an amber maintenance action, not an AC-12 failure by itself. A laptop can have automatic updates enabled while it waits for a safe install/restart window.

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
Ryan's MacBook Pro · macOS 26
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

