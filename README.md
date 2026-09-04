# HackZero Device Checker

[![CI](https://github.com/hackzero/device-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/hackzero/device-checker/actions/workflows/ci.yml)

A small, read-only endpoint evidence collector for SOC 2 controls. It checks
the security posture of a device and sends a signed report to the organization's
HackZero workspace after the device owner explicitly pairs it.

It is **not** an MDM, remote-control tool, asset tracker, keystroke logger, or
browser extension. It does not enforce settings, inspect documents, collect
installed-app inventories, or accept commands from the service.

## What it checks

| Signal | macOS | Windows 11 | Ubuntu / Debian |
| --- | --- | --- | --- |
| Disk encryption | FileVault | BitLocker | LUKS |
| Screen lock policy | idle lock | inactivity timeout | session idle timeout |
| Automatic OS updates | update configuration | Windows Update configuration | unattended upgrades |
| Endpoint protection | XProtect + Gatekeeper | Microsoft Defender | supported antimalware service |

Automatic-update configuration and a pending update are deliberately different:
disabled automatic updates is a failed configuration; an enabled device waiting
for its normal maintenance window is reported as `needs_attention`, not failed.

## Privacy and security boundaries

- Each report contains only OS/version, checker version, device public key,
  signal outcomes, and timestamps.
- The client creates a per-device key pair. It never persists a browser cookie,
  user password, API token, or OAuth refresh token.
- Pairing uses browser OAuth with authorization-code + PKCE and an ephemeral
  loopback listener bound to `127.0.0.1`.
- Reports are outbound HTTPS only. The client listens on no permanent port and
  accepts no remote commands.
- A device that is offline or powered off is **not failed**. The service treats
  freshness separately from the last reported result.

Read the full [threat model](docs/THREAT-MODEL.md), [architecture](docs/ARCHITECTURE.md),
and [data inventory](docs/PRIVACY.md) before deploying it.

## Development

```powershell
go test ./...
go vet ./...
go build ./cmd/device-checker
```

The production service endpoint is intentionally configurable. Local tests use
only synthetic probes and never inspect the host running the tests.

## Status

The repository contains the deliberately narrow collector core, report schema,
and deterministic posture evaluator. OS-native probes and signed packaging are
released only after the platform-specific verification suites pass; do not use
an unreleased build as compliance evidence.

## Contributing and reporting vulnerabilities

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please
do not disclose security issues in public issue trackers.
