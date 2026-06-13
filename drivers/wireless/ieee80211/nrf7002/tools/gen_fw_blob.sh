#!/bin/sh
# Generate the nRF7002 RPU firmware C blob from a Nordic nrf70.bin.
#
# The firmware is Nordic-proprietary (LicenseRef-Nordic-5-Clause) and is not
# distributed in this repository.  Point this script at the nrf70.bin from your
# nRF Connect SDK installation, e.g.:
#
#   <ncs>/nrfxlib/nrf_wifi/bin/ncs/default/nrf70.bin
#
# Usage: tools/gen_fw_blob.sh /path/to/nrf70.bin
#
# It writes nrf70_fw_patch.inc (the C-array body) next to the driver sources;
# nrf7002_fw_blob.c (already in-tree, git-ignored) #includes it.
set -e

BIN="$1"
DIR="$(cd "$(dirname "$0")/.." && pwd)"
INC="$DIR/nrf70_fw_patch.inc"
BLOB="$DIR/nrf7002_fw_blob.c"

if [ -z "$BIN" ] || [ ! -f "$BIN" ]; then
  echo "usage: $0 /path/to/nrf70.bin" >&2
  exit 1
fi

# Emit "0xNN," bytes, 12 per line.
od -An -v -tx1 "$BIN" |
  tr -s ' ' '\n' |
  sed '/^$/d; s/^/0x/; s/$/,/' |
  paste -sd' ' - |
  fold -s -w 72 > "$INC"

# Create the blob translation unit if missing.
if [ ! -f "$BLOB" ]; then
  cat > "$BLOB" <<'EOF'
/* GENERATED — DO NOT COMMIT.  RPU firmware (LicenseRef-Nordic-5-Clause). */

const char g_nrf70_fw_patch[] =
{
#include "nrf70_fw_patch.inc"
};

const unsigned int g_nrf70_fw_patch_len = sizeof(g_nrf70_fw_patch);
EOF
fi

echo "generated $INC ($(wc -c < "$BIN") bytes) and $BLOB"
