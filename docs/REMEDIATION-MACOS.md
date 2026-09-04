# macOS remediation guide

These instructions describe the expected user-facing settings. The checker does
not change them.

## Disk encryption is off

Open **System Settings → Privacy & Security → FileVault** and turn FileVault
on. Confirm that the recovery key is escrowed in the organization’s approved
recovery location before completing setup.

## Screen lock needs attention

Open **System Settings → Lock Screen**. Set **Require password after screen
saver begins or display is turned off** to immediately, and set the inactivity
timers to 15 minutes or less.

## Automatic updates are off

Open **System Settings → General → Software Update → Automatic Updates** and
enable automatic updates. Install any pending macOS update during an approved
maintenance window.

## Endpoint protection needs attention

Keep macOS current and leave Gatekeeper enabled. macOS includes XProtect; a
managed organization may additionally require its approved endpoint-protection
agent. Do not bypass a Gatekeeper warning to fix this status.
