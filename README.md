# HackZero Device Checker

[![CI](https://github.com/cruzryan/hackzero-device-checker/actions/workflows/ci.yml/badge.svg)](https://github.com/cruzryan/hackzero-device-checker/actions/workflows/ci.yml)

A small, read-only endpoint evidence collector for SOC 2 controls. It checks
the security posture of a device. The repository also contains tested building
blocks for per-device signatures, PKCE pairing values, scheduling, and a
bounded offline queue; the hosted pairing and reporting contract is not
published yet, so installers do not activate those building blocks.

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

## Verify a release

Every installer is built from its immutable public tag by GitHub
Actions. Before installing, verify its SHA-256 value and GitHub provenance:

```sh
gh attestation verify PATH_TO_DOWNLOADED_INSTALLER -R OWNER/REPOSITORY
```

The [verification guide](docs/VERIFY.md) explains hashes, provenance, and the
separate platform-signature check. A release is never described as signed or
notarized until that platform's genuine signing credentials are configured.

## Development

### Desktop application

`desktop/` is the cross-platform [Tauri 2](https://v2.tauri.app/) shell: a
custom HackZero window with a native tray/menu. The UI is allowed to run only
fixed local checker actions; it never turns UI text into a shell command, and
it needs no permanent loopback server.

```powershell
cd desktop
npm install
npm run dev
```

The build host needs its normal native linker. Windows requires Visual Studio
Build Tools (MSVC) or the GNU toolchain's `dlltool`; macOS and Debian/Ubuntu
packages are built on their native CI runners.

```powershell
go test ./...
go vet ./...
go build ./cmd/device-checker
```

The production service endpoint is intentionally configurable. Local tests use
only synthetic probes and never inspect the host running the tests.

## Status and packaging

The repository contains the deliberately narrow collector core, report schema,
deterministic posture evaluator, and unit-tested local security primitives.
Release CI produces an MSI for Windows,
a PKG for macOS, and a DEB for Ubuntu/Debian, with a SHA-256 manifest and a
GitHub provenance attestation for each installer. These early packages install
the command-line collector only; background service, pairing, reporting, and
the menu/tray surface are intentionally not claimed as complete. In particular,
the current preview does not pair to a workspace or upload evidence. Do not run
it as a background service until the hosted protocol and platform credential
storage implementations are released and independently reviewed.

Do not use an unreleased build as compliance evidence.

## Contributing and reporting vulnerabilities

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please
do not disclose security issues in public issue trackers.
