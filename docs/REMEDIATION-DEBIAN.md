# Ubuntu and Debian remediation guide

These steps vary by desktop environment and organizational policy. They are
guidance, not actions performed by the checker.

## Disk encryption is off

Confirm the system volume is protected by LUKS. For a managed laptop, ask the
IT owner before attempting to retrofit encryption: changing disk encryption can
require a backup and rebuild plan.

## Screen lock needs attention

In the desktop environment’s **Privacy** or **Power** settings, enable
automatic screen lock and require authentication on resume. Set the idle delay
to 15 minutes or less.

## Automatic updates are off

Install and enable the distribution’s unattended-upgrades package according to
the organization’s approved maintenance policy. Verify that security updates
are enabled and that a maintenance/reboot plan exists.

## Endpoint protection needs attention

Use the organization-approved Linux endpoint-protection service and ensure its
definition/update service is running. A bare package install is not proof that
protection is active.
