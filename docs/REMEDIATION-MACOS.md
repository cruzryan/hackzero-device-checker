# macOS remediation guide

These instructions describe the expected user-facing settings. The checker does
not change them.

## Disk encryption is off

Open **System Settings → Privacy & Security → FileVault** and turn FileVault
on. Confirm that the recovery key is escrowed in the organization’s approved
recovery location before completing setup.

## Screen lock needs attention

Open **System Settings → Lock Screen**. The checker adds the display timer (or
the screen saver timer, whichever is sooner) to **Require password after
screen saver begins or display is turned off**, and the total must be 15
minutes or less on **every** power source:

- **Turn display off on battery when inactive** and **Turn display off on power
  adapter when inactive** are checked separately. A MacBook often has a short
  battery timer and a long power-adapter timer; the power-adapter one fails.
- **Never** fails.
- A password delay of 5 seconds or less counts as immediate. For example,
  display off after 10 minutes plus a 5 minute password delay is exactly 15
  minutes and passes.

A configuration profile from your organization overrides these settings; if
they are managed, ask the IT owner.

## Automatic updates are off

Open **System Settings → General → Software Update → Automatic Updates** and
turn on **Check for updates**, **Download new updates when available**, and
**Install Security Responses and system files**. Installing macOS updates
automatically is recommended but not required.

## Endpoint protection needs attention

Leave Gatekeeper enabled and keep **Install Security Responses and system
files** on: that setting is what keeps XProtect's malware definitions current.
A managed organization may additionally require its approved
endpoint-protection agent.
Do not bypass a Gatekeeper warning to fix this status.
