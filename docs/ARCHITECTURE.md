# Architecture

The checker is designed around four local components:

1. **Probe** — a platform-specific, read-only implementation obtains a narrow
   set of operating-system security signals.
2. **Evaluator** — pure Go maps raw observations to `pass`, `fail`, or
   `needs_attention`. This is deterministic and independently unit tested.
3. **Identity** — browser pairing uses a short-lived, one-time approval
   code and a locally generated key pair. The browser session never enters the
   client.
4. **Reporter** — sends a signed report over HTTPS and queues it locally when
   offline. It has no inbound listener after pairing completes.

The desktop surface is intentionally small: a Windows notification-area icon,
macOS menu-bar item, and Linux tray indicator where the desktop supports one.
The detailed device view belongs in the web product, linked from the People
screen. A command-line status view remains available on headless Linux.

The runtime now has an explicit `device-checker run` mode. It retries verified
queued envelopes first, performs the full check at most once every 24 hours,
and sends a small signed heartbeat at most once every six hours. `report` is a
one-shot forced full check. Both report kinds are queued atomically while
offline, with bounded local storage. A heartbeat cannot replace a full posture
report. Server receipt time drives freshness; no signal becomes a failure just
because a device was asleep or offline.

The service endpoint remains intentionally narrow: pairing provides a report
URL and the runtime sends only signed report envelopes to that URL. The server
must verify the registered public key, device assignment, and authorization;
the agent does not accept remote commands.
