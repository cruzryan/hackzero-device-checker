# Data inventory and privacy

The client reports the minimum necessary to substantiate endpoint evidence:

- generated device identifier and public key;
- operating system family and version (for example `26.5.2`);
- checker build version;
- collection time and report receipt time;
- encryption, screen-lock, auto-update, pending-maintenance, and endpoint-
  protection outcomes with short remediation codes, and the setting values
  behind each outcome (for example display-off minutes per power source, the
  password delay, update switches, pending-update counts, and whether Defender
  or another antivirus is healthy), as numbers, true/false values and fixed
  codes only. Product names and raw command output are never sent.

It does not collect personal files, browsing history, keystrokes, screenshots,
process lists, location, full hardware inventory, passwords, or authentication
cookies. The service associates a paired device with a person only after the
workspace administrator approves the pairing.

The local queue is encrypted using the operating system's credential storage
when implemented by the packaging layer; it contains only unsent signed reports
and is removed after acknowledged delivery.
