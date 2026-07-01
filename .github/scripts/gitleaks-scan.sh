#!/usr/bin/env bash
# Secret-scan the checkout with the license-free gitleaks OSS binary.
# gitleaks/gitleaks-action requires a paid license on org-owned repos; the binary
# does not. Pinned to a version tag and checksum-verified against that release's
# own (immutable) checksums file, so the download is not a mutable pin.
set -euo pipefail

VERSION="8.21.2"
base="https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}"
tarball="gitleaks_${VERSION}_linux_x64.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

curl -fsSL "$base/$tarball" -o "$tmp/$tarball"
curl -fsSL "$base/gitleaks_${VERSION}_checksums.txt" -o "$tmp/checksums.txt"

# Verify against the release's checksums file (grep the line for our asset, then -c).
(cd "$tmp" && grep " ${tarball}\$" checksums.txt | sha256sum -c -)

tar -xzf "$tmp/$tarball" -C "$tmp" gitleaks
chmod +x "$tmp/gitleaks"

# `dir` scans the working tree; non-zero exit on any finding fails the job.
"$tmp/gitleaks" dir --no-banner --redact .
