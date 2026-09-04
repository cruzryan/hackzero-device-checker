# Data inventory and privacy

The client reports the minimum necessary to substantiate endpoint evidence:

- generated device identifier and public key;
- operating system family and version;
- checker build version;
- collection time and report receipt time;
- encryption, screen-lock, auto-update, pending-maintenance, and endpoint-
  protection outcomes with short remediation codes.

It does not collect personal files, browsing history, keystrokes, screenshots,
process lists, location, full hardware inventory, passwords, or authentication
cookies. The service associates a paired device with a person only after the
workspace administrator approves the pairing.

The local queue is encrypted using the operating system's credential storage
when implemented by the packaging layer; it contains only unsent signed reports
and is removed after acknowledged delivery.
