# Threat model

## Assets

- Accurate endpoint posture reports.
- The device signing key and pairing certificate.
- The privacy of people using the checker.

## Trust boundaries and mitigations

| Threat | Mitigation |
| --- | --- |
| Stolen web session | Pairing uses short-lived code + PKCE; no web session is stored by the client. |
| Report replay or modification | Every report carries nonce, collection time, and an Ed25519 signature verified server-side. |
| Local process impersonation | Pairing callback binds only to loopback with random state; the user verifies the organization in the browser. |
| Offline device | Queue signed reports; surface stale state separately, never invent a failure. |
| Overcollection | Fixed allowlist schema; no generic command, shell, inventory, or telemetry API. |
| Malicious update | Signed releases, checksums, SBOM, and verified update metadata. |

The checker cannot protect a compromised operating system from a privileged
local attacker. Its role is evidence collection, not endpoint enforcement.
