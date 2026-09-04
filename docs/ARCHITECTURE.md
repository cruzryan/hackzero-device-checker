# Architecture

The checker has four local components:

1. **Probe** — a platform-specific, read-only implementation obtains a narrow
   set of operating-system security signals.
2. **Evaluator** — pure Go maps raw observations to `pass`, `fail`, or
   `needs_attention`. This is deterministic and independently unit tested.
3. **Identity** — first-run pairing launches the system browser using OAuth
   authorization code + PKCE. The resulting device certificate is bound to a
   locally generated key pair.
4. **Reporter** — sends a signed report over HTTPS and queues it locally when
   offline. It has no inbound listener after pairing completes.

The desktop surface is intentionally small: a Windows notification-area icon,
macOS menu-bar item, and Linux tray indicator where the desktop supports one.
The detailed device view belongs in the web product, linked from the People
screen. A command-line status view remains available on headless Linux.

Scans run after installation, after boot, daily, and when a user selects Check
now. A lightweight heartbeat is scheduled roughly every six hours. Server
receipt time drives freshness; no signal becomes a failure merely because a
device was asleep or offline.
