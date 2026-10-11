#!/usr/bin/env bash
# Copyright 2026 Jerry David Chan, Konareef.ai
# SPDX-License-Identifier: Apache-2.0

# scripts/check_vectors_byte_identical.sh
#
# Asserts that the 4 P1.4 strict-DER + low-S conformance vectors and
# their manifest are byte-identical between reef-core and konareef.
# Run in CI; fail the build on drift. Drift would mean the Go and
# Elixir parsers could disagree on which signatures are canonical,
# violating the wire-format-identity property that PRD P1.4 locks in.
#
# Env:
#   REEF_CORE_ROOT  — path to a reef-core checkout (default: ~/work/reef-core)
#
# Exit codes:
#   0  — all files byte-identical
#   1  — drift detected (diff printed to stderr)
#   2  — required input missing (e.g. REEF_CORE_ROOT does not exist)
set -euo pipefail

REEF_DIR="${REEF_CORE_ROOT:-$HOME/work/reef-core}/test/support/fixtures/der_gate"
KONAREEF_DIR="$(git rev-parse --show-toplevel)/internal/identity/testdata/der_gate"

if [[ ! -d "$REEF_DIR" ]]; then
  echo "ERROR: reef-core fixture dir not found: $REEF_DIR" >&2
  echo "       set REEF_CORE_ROOT to a reef-core checkout." >&2
  exit 2
fi

if [[ ! -d "$KONAREEF_DIR" ]]; then
  echo "ERROR: konareef testdata dir not found: $KONAREEF_DIR" >&2
  exit 2
fi

vectors=(
  canonical_accept.bin
  high_s_reject.bin
  non_strict_leading_zero_reject.bin
  trailing_bytes_reject.bin
  vectors.json
)

drift=0
for f in "${vectors[@]}"; do
  if ! diff -q "$REEF_DIR/$f" "$KONAREEF_DIR/$f" >/dev/null; then
    echo "DRIFT: $f differs between reef-core and konareef" >&2
    diff "$REEF_DIR/$f" "$KONAREEF_DIR/$f" >&2 || true
    drift=1
  fi
done

if (( drift == 1 )); then
  exit 1
fi

echo "OK: all 4 vectors + manifest byte-identical"
