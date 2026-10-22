#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# (C) Copyright 2026
# Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
"""
avb_sign.py - Append hash tree, sign and attach vbmeta.

Without --cert: single-pass signing (no PKCS#7 root hash signature).

With --cert: four-step signing workflow:
  1. First-pass avbtool add_hashtree_footer (generates random salt)
  2. Extract root hash and salt from the signed image
  3. Create a PKCS#7 signature over the root hash with openssl
  4. Re-sign with the pinned salt and roothash_sig property embedded

Usage:
    avb_sign.py --image IMAGE --key KEY [--cert CERT] [--output OUTPUT] [options]
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile


def run(cmd):
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {' '.join(str(c) for c in cmd)}", file=sys.stderr)
        if result.stderr:
            print(result.stderr.rstrip(), file=sys.stderr)
        sys.exit(1)
    return result


def find_avbtool(hint):
    candidates = [hint] if hint else []
    candidates += [
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "avb", "avbtool.py"),
        "avbtool",
    ]
    for c in candidates:
        if c and os.path.exists(c):
            return c
    result = subprocess.run(["which", "avbtool"], capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    print("Error: avbtool not found. Use --avbtool to specify its path.", file=sys.stderr)
    sys.exit(1)


def avbtool_cmd(avbtool):
    if avbtool.endswith(".py"):
        return [sys.executable, avbtool]
    return [avbtool]


def main():
    parser = argparse.ArgumentParser(
        description="Sign an image with AVB and embed a PKCS#7 root hash signature."
    )
    parser.add_argument("--image", required=True,
                        help="Input image file")
    parser.add_argument("--output", default=None,
                        help="Output signed image (default: overwrite input)")
    parser.add_argument("--key", required=True,
                        help="Signing key in PEM format")
    parser.add_argument("--cert", default=None,
                        help="X.509 certificate (PEM) for PKCS#7 roothash signature (omit to skip)")
    parser.add_argument("--partition-name", default="system",
                        help="Partition name embedded in vbmeta (default: system)")
    parser.add_argument("--algorithm", default="SHA256_RSA4096",
                        choices=[
                            "SHA256_RSA2048", "SHA256_RSA4096", "SHA256_RSA8192",
                            "SHA512_RSA2048", "SHA512_RSA4096", "SHA512_RSA8192",
                            "MLDSA65", "MLDSA87",
                        ],
                        help="AVB signing algorithm (default: SHA256_RSA4096)")
    parser.add_argument("--avbtool", default=None,
                        help="Path to avbtool or avbtool.py (auto-detected if omitted)")
    parser.add_argument("--fec-roots", type=int,
                        default=int(os.environ.get("AVB_FEC_ROOTS") or 2),
                        help="Reed-Solomon roots for dm-verity FEC, 2-24. Higher values "
                             "repair more corrupt blocks at proportionally more space "
                             "(default: 2, or $AVB_FEC_ROOTS)")
    parser.add_argument("--no-fec", action="store_true",
                        help="Write no forward error correction data. The image then "
                             "needs no fec tool to sign, and dm-verity fails a corrupt "
                             "block instead of repairing it")
    args = parser.parse_args()

    # dm-verity accepts 2..24 -- DM_VERITY_FEC_RSM minus MAX_RSN and MIN_RSN in
    # drivers/md/dm-verity-fec.h. Neither avbtool nor the fec tool range-checks
    # this, so without the guard an out-of-range value produces an image that
    # builds cleanly and fails at dmsetup on the device.
    if not args.no_fec and not 2 <= args.fec_roots <= 24:
        print(f"Error: --fec-roots must be between 2 and 24, got {args.fec_roots}",
              file=sys.stderr)
        sys.exit(1)

    # avbtool only shells out to fec when it generates FEC, so this is the
    # whole difference between the two modes at the avbtool level.
    fec_args = ["--do_not_generate_fec"] if args.no_fec else ["--fec_num_roots", str(args.fec_roots)]

    if not os.path.isfile(args.image):
        print(f"Error: image not found: {args.image}", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(args.key):
        print(f"Error: key not found: {args.key}", file=sys.stderr)
        sys.exit(1)
    if args.cert and not os.path.isfile(args.cert):
        print(f"Error: cert not found: {args.cert}", file=sys.stderr)
        sys.exit(1)

    avbtool = find_avbtool(args.avbtool)
    avb = avbtool_cmd(avbtool)

    work_image = args.output if args.output else args.image
    if args.output:
        shutil.copy2(args.image, args.output)

    print(f"Image:     {args.image}")
    if args.output:
        print(f"Output:    {args.output}")
    print(f"Key:       {args.key}")
    if args.cert:
        print(f"Cert:      {args.cert}")
    print(f"Partition: {args.partition_name}")
    print(f"Algorithm: {args.algorithm}")
    print(f"FEC:       {'none' if args.no_fec else f'{args.fec_roots} roots'}")
    print()

    # Pad image to a 4KB boundary so avbtool accepts it
    size = os.path.getsize(work_image)
    remainder = size % 4096
    if remainder:
        padding = 4096 - remainder
        with open(work_image, "ab") as f:
            f.write(b"\x00" * padding)
        print(f"Padded image by {padding} bytes to {size + padding} (4K aligned)")

    if not args.cert:
        print("[1/1] Adding hashtree footer...")
        run(avb + [
            "add_hashtree_footer",
            "--image",          work_image,
            "--partition_size", "0",
            "--partition_name", args.partition_name,
            "--algorithm",      args.algorithm,
            "--key",            args.key,
            "--hash_algorithm", "sha256",
        ] + fec_args)
    else:
        with tempfile.TemporaryDirectory() as tmpdir:
            roothash_file = os.path.join(tmpdir, "roothash.hex")
            p7s_file      = os.path.join(tmpdir, "roothash.p7s")

            # Step 1: first-pass signing with avbtool picks a random salt.
            # Step 4 erases this footer and rebuilds it, and the root digest
            # covers the image data and salt rather than the parity, so there
            # is nothing to gain from generating FEC that is about to be thrown
            # away.
            print("[1/4] Adding hashtree footer (first pass)...")
            run(avb + [
                "add_hashtree_footer",
                "--image",          work_image,
                "--partition_size", "0",
                "--partition_name", args.partition_name,
                "--algorithm",      args.algorithm,
                "--key",            args.key,
                "--hash_algorithm", "sha256",
                "--do_not_generate_fec",
            ])

            # Step 2: extract root hash and salt
            print("[2/4] Extracting root hash and salt...")
            info = run(avb + ["info_image", "--image", work_image])

            m_hash = re.search(r"Root Digest:\s*([0-9a-f]+)", info.stdout)
            m_salt = re.search(r"Salt:\s*([0-9a-f]+)", info.stdout)
            if not m_hash or not m_salt:
                print("Error: could not parse root hash or salt from avbtool info_image output:",
                      file=sys.stderr)
                print(info.stdout, file=sys.stderr)
                sys.exit(1)
            root_hash = m_hash.group(1)
            salt      = m_salt.group(1)
            print(f"  Root hash: {root_hash}")
            print(f"  Salt:      {salt}")

            # Step 3: PKCS#7 signature over root hash (hex string, no newline)
            print("[3/4] Creating PKCS#7 signature over root hash...")
            with open(roothash_file, "w") as f:
                f.write(root_hash)

            run([
                "openssl", "cms", "-sign",
                "-nocerts", "-noattr", "-binary",
                "-in",      roothash_file,
                "-inkey",   args.key,
                "-signer",  args.cert,
                "-outform", "der",
                "-out",     p7s_file,
            ])

            # Step 4: re-sign with pinned salt and roothash_sig embedded
            print("[4/4] Re-signing with pinned salt and embedded roothash_sig...")
            run(avb + ["erase_footer", "--image", work_image])
            run(avb + [
                "add_hashtree_footer",
                "--image",          work_image,
                "--partition_size", "0",
                "--partition_name", args.partition_name,
                "--algorithm",      args.algorithm,
                "--key",            args.key,
                "--hash_algorithm", "sha256",
                "--salt",           salt,
                "--prop_from_file", f"roothash_sig:{p7s_file}",
            ] + fec_args)

    print()
    print("Done.")


if __name__ == "__main__":
    main()
