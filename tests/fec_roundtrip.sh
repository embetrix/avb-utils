#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# Proves fec works rather than only that it linked: encode parity for a random
# image, corrupt a copy, and require the repaired result back byte-for-byte.
set -eu
fec=$1
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cd "$tmp"
dd if=/dev/urandom of=check.img bs=4096 count=64 status=none
"$fec" --encode --roots 2 check.img check.fec
cp check.img check_bad.img
dd if=/dev/zero of=check_bad.img bs=1 seek=8192 count=256 conv=notrunc status=none
"$fec" --decode check_bad.img check.fec check_fixed.img
cmp check.img check_fixed.img
echo 'fec round trip: corrupted image repaired byte-for-byte'
