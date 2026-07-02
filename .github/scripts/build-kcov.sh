#!/usr/bin/env bash
# Build kcov from source (pinned) and copy the resulting binary to $1.
#
# kcov is not packaged reliably across runner images and its DEBUG bash method (which
# the coverage harness depends on — see tests/_kcov.py) needs a recent build, so the
# bash-coverage workflow builds it once in the kcov-build job and hands the single
# binary to the shard/gate jobs as an artifact. Those jobs install only the runtime
# shared libs (libdw1 libcurl4 binutils) alongside it.
set -euo pipefail

KCOV_VERSION="v42"
out="${1:?usage: build-kcov.sh <output-binary-path>}"

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  cmake g++ pkg-config git \
  binutils-dev libdw-dev libcurl4-openssl-dev libssl-dev zlib1g-dev libiberty-dev

src="$(mktemp -d)"
git clone --depth 1 --branch "$KCOV_VERSION" https://github.com/SimonKagstrom/kcov "$src"
cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release
cmake --build "$src/build" --parallel "$(nproc)"

mkdir -p "$(dirname "$out")"
cp "$src/build/src/kcov" "$out"
"$out" --version
