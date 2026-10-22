#!/usr/bin/env bash
# Rebuild docs/demo.gif: build blastradius, generate an inert fake home, and
# record the tape with vhs (brew install vhs).
#
# Safety: the tape runs `blastradius scan` with HOME pointed at the throwaway
# fake profile and with --no-env, so the recorder's real credentials are never
# read. The fake home is a temp dir and is never committed; the report shows
# only SHA-256 fingerprints, never a secret.
set -euo pipefail

root="$(cd "$(dirname "$0")/../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

(cd "$root" && go build -ldflags "-X main.version=$(git describe --tags --always)" -o "$work/bin/blastradius" ./cmd/blastradius)
"$root/docs/demo/make-demo-home.sh" "$work/home" >/dev/null

cd "$root"
# HOME is the fake profile for the recorded shell; the tape's `cd ~` lands there.
PATH="$work/bin:$PATH" HOME="$work/home" vhs docs/demo/demo.tape
ls -la docs/demo.gif
