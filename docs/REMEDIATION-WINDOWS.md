# Windows remediation guide

These instructions are for the person using the device. They are not applied
automatically by the checker.

## Disk encryption is off

Open **Settings → Privacy & security → Device encryption** and turn it on. On
editions that expose BitLocker instead, open **Settings → Privacy & security →
BitLocker Drive Encryption**. Keep the recovery key in the organization’s
approved recovery location before proceeding.

## Screen lock needs attention

Open **Settings → Personalization → Lock screen → Screen saver**. Enable a
screen saver, choose **On resume, display logon screen**, and set **Wait** to
15 minutes or less. If the organization manages this setting, ask the IT owner
to correct the policy rather than changing it locally.

## Automatic updates are off

Open **Settings → Windows Update**, turn on **Get the latest updates as soon as
they're available**, and install pending updates. A managed organization may
set this through policy; contact the IT owner if the setting is unavailable.

## Endpoint protection is off

Open **Windows Security → Virus & threat protection**. Confirm Microsoft
Defender Antivirus is active, or ask the IT owner to confirm the organization’s
approved endpoint-protection product is healthy. Do not disable one product to
enable another without the IT owner’s approval.
