# Architecture

The checker is designed around four local components:

1. **Probe** — a platform-specific, read-only implementation obtains a narrow
   set of operating-system security signals.
2. **Evaluator** — pure Go maps raw observations to `pass`, `fail`, or
   `needs_attention`. This is deterministic and independently unit tested.
3. **Identity** — browser pairing uses OAuth authorization-code + PKCE. The
   resulting device credential is bound to a locally generated key pair.
4. **Reporter** — sends a signed report over HTTPS and queues it locally when
   offline. It has no inbound listener after pairing completes.

The desktop surface is intentionally small: a Windows notification-area icon,
macOS menu-bar item, and Linux tray indicator where the desktop supports one.
The detailed device view belongs in the web product, linked from the People
screen. A command-line status view remains available on headless Linux.

The current preview implements the read-only probe/evaluator plus independently
tested local key, report-envelope, PKCE, queue, and scheduling primitives. It
does not yet enable browser pairing, persistent service mode, or network
delivery. Once the reviewed service integration ships, scans run after install,
at boot, daily, and when a user selects Check now. A lightweight heartbeat runs
roughly every six hours. Server receipt time drives freshness; no signal becomes
a failure merely because a device was asleep or offline.
