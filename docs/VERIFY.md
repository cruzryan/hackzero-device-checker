# Verify a release

There are two different questions to verify:

1. Was this installer built from the public source? GitHub provenance answers
   this question.
2. Was the installer published by the expected developer? The operating
   system's code-signature system answers this question.

Both should pass before a production installation.

## 1. Confirm the file hash

Download an installer and `SHA256SUMS.txt` from the same immutable GitHub
release tag.

```powershell
Get-FileHash .\HackZero-Device-Checker-windows-amd64.msi -Algorithm SHA256
```

```sh
sha256sum --check SHA256SUMS.txt
```

The displayed hash must exactly match the published value.

## 2. Confirm GitHub build provenance

Install the GitHub CLI, then run:

```sh
gh attestation verify PATH_TO_DOWNLOADED_INSTALLER \
  -R OWNER/REPOSITORY
```

Verification confirms that GitHub Actions built that exact file from this
repository's release workflow and identifies the source commit. Inspect that
commit and tag in the public repository before trusting it.

## 3. Confirm platform signing

### Windows

Production `.exe` and `.msi` releases will show a valid Authenticode signature
with the expected publisher. In PowerShell:

```powershell
Get-AuthenticodeSignature .\HackZero-Device-Checker-windows-amd64.msi | Format-List
```

The status must be `Valid`; do not install an artifact described as signed when
Windows reports an unknown, invalid, or mismatched publisher.

### macOS

Production `.pkg` releases will be Developer ID signed and notarized. Verify:

```sh
pkgutil --check-signature HackZero-Device-Checker-macos-arm64.pkg
spctl --assess --type install --verbose HackZero-Device-Checker-macos-arm64.pkg
```

The signature and Gatekeeper assessment must identify the expected publisher.

### Ubuntu and Debian

Until an APT repository is available, verify the `.deb` SHA-256 and GitHub
provenance as above. The production APT repository will use a dedicated signing
key via `signed-by=`, so APT itself rejects an altered package.

## Preview package scope

The first provenance-tested packages are intentionally marked as previews.
They contain the collector command line and do not yet install a background
service, tray/menu-bar interface, pairing flow, or reporting credential. A
preview package is not labelled signed or notarized. Those features and their
platform signing are released only once they have real implementation and
production credentials.

## Why signed installers are not byte-identical to source builds

Code signing and Apple notarization attach signature metadata after the program
payload is produced. That means the final installer need not have the exact
same bytes as a locally rebuilt unsigned payload. The release provides both
proofs: source-linked CI provenance for the installer and the OS signature for
the distributed installer.
