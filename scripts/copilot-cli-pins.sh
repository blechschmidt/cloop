#!/usr/bin/env bash
# copilot-cli-pins.sh — the Dockerfile ARG lines that pin a Copilot CLI version.
#
#   scripts/copilot-cli-pins.sh [VERSION]   (default: the newest on npm)
#
# The harness-copilot image installs the GitHub Copilot CLI from npm, and every
# tarball the install unpacks is checked against an sha512 integrity pinned in
# the Dockerfile (Task 20450): the loader @github/copilot, its native build for
# linux-x64 and linux-arm64, and the loader's one dependency, detect-libc, at
# the version the loader asks for. Moving the version means moving all of them
# together; this prints the lines to paste over the old ones, read from the npm
# registry with `npm view`.
#
# Read what it prints before pasting it: the integrities are what the registry
# serves today, and pinning them is the statement that those bytes are the CLI.
# Then rebuild the image (`docker build --target harness-copilot .`), which
# checks each tarball against its pin and runs `copilot --version`.
set -euo pipefail

command -v npm >/dev/null || { echo "copilot-cli-pins: npm is not installed" >&2; exit 1; }

version=${1:-$(npm view @github/copilot version)}
case "$version" in
	*[!0-9.]* | "") echo "copilot-cli-pins: $version is not an exact version" >&2; exit 1 ;;
esac

integrity() { npm view "$1" dist.integrity; }

# The loader's own range for detect-libc, resolved to the newest version in it
# — the one an install would pick.
range=$(npm view "@github/copilot@$version" dependencies.detect-libc)
[ -n "$range" ] || { echo "copilot-cli-pins: @github/copilot@$version names no detect-libc" >&2; exit 1; }
libc=$(npm view "detect-libc@$range" version | tail -n 1 | sed -e "s/^detect-libc@//" -e "s/ .*//" -e "s/'//g")

cat <<EOF
ARG COPILOT_CLI_VERSION=$version
ARG COPILOT_CLI_INTEGRITY=$(integrity "@github/copilot@$version")
ARG COPILOT_CLI_LINUX_X64_INTEGRITY=$(integrity "@github/copilot-linux-x64@$version")
ARG COPILOT_CLI_LINUX_ARM64_INTEGRITY=$(integrity "@github/copilot-linux-arm64@$version")
ARG COPILOT_CLI_DETECT_LIBC_VERSION=$libc
ARG COPILOT_CLI_DETECT_LIBC_INTEGRITY=$(integrity "detect-libc@$libc")
EOF
