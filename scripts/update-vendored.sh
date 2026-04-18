#!/usr/bin/env bash
# Refresh the vendored copy of hackterm-core from its canonical GitHub repo.
# Run from the hack5250 repo root.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

URL=https://github.com/gglessner/hackterm-core
DEST="$ROOT/hackterm-core"

echo "==> $URL -> $DEST"
git clone --depth 1 "$URL" "$TMP/clone"
SHA="$(cd "$TMP/clone" && git rev-parse HEAD)"
find "$DEST" -mindepth 1 -maxdepth 1 ! -name UPSTREAM.txt -exec rm -rf {} +
cp -r "$TMP/clone/." "$DEST/"
rm -rf "$DEST/.git"
{
  echo "upstream: $URL"
  echo "pinned_commit: $SHA"
  date -u +"pinned_at: %Y-%m-%dT%H:%M:%SZ"
} > "$DEST/UPSTREAM.txt"

echo "done. (hackterm-core is loaded via sys.path from ./hackterm-core — no pip install needed)"
