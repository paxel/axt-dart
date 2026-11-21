#!/usr/bin/env bash
# Runs the conformance suite of the pinned AXT release against this library's adapter
# (AXT spec/conformance.md, sections 6 and 7). The archive is checked by its SHA-256 and
# its attestation before anything in it runs. Needs curl, gh (logged in, or GH_TOKEN set),
# uv, python3 >= 3.11 and dart.
set -euo pipefail

AXT_VERSION=0.1.0
AXT_SHA256=3f878496c5e762d583071724378e9b7d09b1b664073bb9f63e0df7d840cf4212
BASE=https://github.com/paxel/axt/releases/download/v$AXT_VERSION
ARCHIVE=axt-$AXT_VERSION.tar.gz
BUNDLE=axt-v$AXT_VERSION-provenance.sigstore.json

root=$(cd "$(dirname "$0")/.." && pwd)
work=${AXT_WORK:-$root/build/conformance}
rm -rf "$work"
mkdir -p "$work"
cd "$work"

curl --proto =https --proto-redir =https -fsSL -o "$ARCHIVE" "$BASE/$ARCHIVE"
curl --proto =https --proto-redir =https -fsSL -o "$BUNDLE" "$BASE/$BUNDLE"
echo "$AXT_SHA256  $ARCHIVE" | sha256sum --check --strict
# The release attests through the reusable provenance workflow of paxel/gates, so that
# workflow is the signer; the source is paxel/axt at the release tag.
gh attestation verify "$ARCHIVE" --bundle "$BUNDLE" --repo paxel/axt \
  --signer-workflow paxel/gates/.github/workflows/provenance.yml \
  --source-ref "refs/tags/v$AXT_VERSION"

mkdir suite
tar -xzf "$ARCHIVE" -C suite --strip-components=1
(cd suite && uv sync --frozen --no-dev --no-build)

dart compile exe "$root/tool/adapter.dart" -o "$work/adapter"

# The runner fails when the adapter declares no category; until the first category is
# implemented, the check of the archive and the adapter's hello are the whole job.
hello=$(echo '{"id": "hello", "op": "hello", "input": {"format": 1}}' | "$work/adapter")
if python3 -c 'import json, sys; sys.exit(0 if json.loads(sys.argv[1])["output"]["categories"] else 1)' "$hello"; then
  cd suite
  uv run --frozen --no-dev python3 conformance/run.py -- "$work/adapter"
else
  echo "The adapter implements no category yet; the suite was checked but not run: $hello"
fi
