# avb-utils

[![CI](https://github.com/embetrix/avb-utils/actions/workflows/ci.yml/badge.svg)](https://github.com/embetrix/avb-utils/actions/workflows/ci.yml)
[![License: GPL v2](https://img.shields.io/badge/License-GPLv2-blue.svg)](LICENSE)

A toolkit that brings [Android Verified Boot](https://android.googlesource.com/platform/external/avb/)
(AVB) to embedded Linux systems, extending the chain of trust:

* Append hash tree, sign and attach vbmeta on the host with [avb_sign.py](avb_sign.py)
* Verify on the target with [avb_verify](avb_verify.c)

It verifies AVB-signed images using `libavb`, extracts dm-verity parameters ready for use
with `dmsetup` and embeds a PKCS#7 root hash signature for kernel-level
integrity enforcement via: `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`.

It implements two layers of verification:

1. `AVB layer`  validates the vbmeta AVB raw signature (RSA/ML-DSA) and
   checks the embedded public key against a trusted reference key.
2. `Root hash layer` *(optional)* if the vbmeta image contains a
   `roothash_sig` property (a PKCS#7 signature of the root hash), loads it
   into the user session keyring so dm-verity can independently verify the
   root hash via `CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`.

## Prerequisites

- CMake >= 3.10
- GCC or Clang
- [libavb](https://android.googlesource.com/platform/external/avb/) (submodule)
- Python 3 + OpenSSL  for signing images with `avbtool` (development only)
- [`fec`](https://android.googlesource.com/platform/system/extras/+/refs/heads/main/verity/fec/)
  from AOSP `system/extras`  `avbtool` shells out to it to write the
  dm-verity forward error correction data (development only). Built here
  from the submodules under `fec/` with `-DBUILD_FEC=ON` (implied by
  `-DINSTALL_AVB_SIGN=ON`); that needs a C++20 compiler, OpenSSL and zlib
  development files. Not needed to sign with `--no-fec`.

> **Note:** `avb_verify` is lightweight: no external crypto library is required on the target and all cryptographic operations are handled by libavb's own built-in implementation. On the host side, `avb_sign.py` (via `avbtool`) handles dm-verity hash tree generation and vbmeta signing directly, so cryptsetup or any verity userspace tooling is not required.

## Build

```bash
git submodule update --init
cmake -B build
cmake --build build
```

For a host that signs images, add `-DINSTALL_AVB_SIGN=ON`: it installs
`avb_sign`, `avbtool` and the `fec` tool they need. The AOSP repositories fec
is assembled from are shallow submodules under `fec/`, so the init above
fetches only the pinned commit of each; a target-only build can skip them
with `git submodule update --init avb`.

## Signing (host)

Supported algorithms: `SHA256_RSA2048`, `SHA256_RSA4096`, `SHA256_RSA8192`,
`SHA512_RSA2048`, `SHA512_RSA4096`, `SHA512_RSA8192`, `MLDSA65`, `MLDSA87`.

### 1. Create the signing key and certificate

```bash
# Generate signing key
openssl genrsa -out key.pem 4096

# Self-signed certificate (required only when embedding a PKCS#7 roothash_sig)
openssl req -x509 -key key.pem -out sig_cert.pem -days 3650 -subj "/CN=avb-signer"
```

### 2. Append hash tree, sign and attach vbmeta

Without `--cert`, a single-pass sign is performed (no PKCS#7 root hash signature):

```bash
python3 avb_sign.py \
  --image rootfs.ext4 \
  --key key.pem \
  --partition-name rootfs \
  --algorithm SHA256_RSA4096
```

With `--cert`, the root hash is also signed with a PKCS#7 signature and embedded in vbmeta:

```bash
python3 avb_sign.py \
  --image rootfs.ext4 \
  --key key.pem \
  --cert sig_cert.pem \
  --partition-name rootfs \
  --algorithm SHA256_RSA4096
```

Use `--output` to write the signed image to a separate file and leave the input untouched:

```bash
python3 avb_sign.py \
  --image rootfs.ext4 \
  --output rootfs.ext4.avbverity \
  --key key.pem \
  --cert sig_cert.pem \
  --partition-name rootfs \
  --algorithm SHA256_RSA4096
```

### 3. Forward error correction

By default `avb_sign.py` writes a Reed-Solomon parity area after the hash tree,
and `avb_verify` emits the matching `use_fec_from_device` arguments in the
dm-verity table, so the kernel repairs a bounded number of corrupt blocks
instead of failing the read. `--fec-roots` sets the number of roots, 2 to 24
(the range dm-verity accepts); it defaults to `$AVB_FEC_ROOTS`, or 2. Each
255-byte codeword corrects up to `roots / 2` bad bytes, at a space cost of
`roots / (255 - roots)` of the covered data, so 2 roots repairs one corrupt
4 KiB block per interleave group for 0.8 %, and 24 repairs twelve for 10.4 %.

These are AOSP's defaults: `avbtool add_hashtree_footer` generates FEC unless
told `--do_not_generate_fec`, with `--fec_num_roots` defaulting to 2, and
`--no-fec` here maps onto that switch. An image signed with the defaults is
therefore laid out the same way one signed by a stock `avbtool` would be.

```bash
python3 avb_sign.py --image rootfs.ext4 --key key.pem --fec-roots 24
```

`--no-fec` writes no parity. The image then needs no `fec` tool to sign -- a
host built with `-DBUILD_FEC=OFF` can still sign -- and dm-verity fails a
corrupt block instead of repairing it. `avb_verify` reads either kind: the
`use_fec_from_device` group is only emitted for an image that carries FEC.

```bash
python3 avb_sign.py --image rootfs.ext4 --key key.pem --no-fec
```

### 4. Extract the public key for the target

`avb_verify` requires the public key in AVB's serialized format (not PEM):

```bash
python3 avb/avbtool.py extract_public_key --key key.pem --output pubkey.bin
```

Deploy `pubkey.bin` to the target (e.g. stored in the initramfs).
`sig_cert.pem` is compiled into the kernel at build time via `CONFIG_SYSTEM_TRUSTED_KEYS`.

## Verification (target)

```
avb_verify -d <device> -k <pubkey.bin> [-t] [-h]
```

| Option | Description |
|---|---|
| `-d, --device <path>` | Image file or block device (required) |
| `-k, --pubkey <path>` | AVB public key in serialized format (required) |
| `-t, --dm-table` | Print only the raw dm-verity table line |
| `-h, --help` | Show help |

### Default output

Prints a human-readable verification summary followed by the dm-verity table:

```bash
avb_verify -d /dev/mmcblk0p2 -k pubkey.bin
```

```
Footer scan: 39.261 ms
Roothash signature loaded into keyring: avb_roothash_sig.root (687 bytes)
Verification:  OK
Algorithm:     SHA256_RSA4096
Rollback:      0
Partition:     root
Hash alg:      sha256
Data blocks:   77046
Data block sz: 4096
Hash block sz: 4096
Hash offset:   315580416
FEC:           roots 2, offset 318070784, size 2514944
Root digest:   4aec6b1c1675f1a1bc2dd8394185e2fba4a230e8f754028e868b46e2f6cfc7a2
Salt:          72807c3fa652f8e7f176b22b55cf8c711e720ab067d9f26f8dc72a831e291be6
Roothash sig:  avb_roothash_sig.root

dm table:
  0 616368 verity 1 /dev/mmcblk0p2 /dev/mmcblk0p2 4096 4096 77046 77046 sha256 \
      4aec6b1c1675f1a1bc2dd8394185e2fba4a230e8f754028e868b46e2f6cfc7a2 72807c3fa652f8e7f176b22b55cf8c711e720ab067d9f26f8dc72a831e291be6 \
      10 use_fec_from_device /dev/mmcblk0p2 fec_roots 2 fec_blocks 77654 fec_start 77654 \
      root_hash_sig_key_desc avb_roothash_sig.root
```

`Roothash sig` and `root_hash_sig_key_desc` only appear when a `roothash_sig`
property is present in the vbmeta image (see [Root hash signature](#root-hash-signature)).
The `use_fec_from_device` group only appears when the hashtree descriptor
carries FEC, and the optional-argument count before it is the total of both.

### dm-table mode

With `-t`, outputs only the raw dm-verity table line for direct use with
`dmsetup`:

```bash
avb_verify -t -d /dev/mmcblk0p2 -k pubkey.bin | dmsetup create verity-system
```

### Root hash signature

Root hash signature verification is an additional protection layer on top of
the AVB vbmeta signature. A PKCS#7 signature of the root hash is embedded as a
vbmeta property and verified atomically by the kernel at dm-verity device
creation time, against the system's trusted keyring
(`CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG`), independently of the userspace
`avb_verify` step.

## Architecture

### Partition Layout

The verified partition is split into a data region and an appended AVB footer that points to the vbmeta struct and hashtree.

![Partition Layout](images/01-partition-layout.svg)

### VBMeta Structure

The vbmeta block holds the hashtree descriptor (root hash, salt, tree layout) and a property descriptor (`roothash_sig`) along with the public key and signature over the whole structure.

![VBMeta Structure](images/02-vbmeta.svg)

### Merkle Tree

Integrity is anchored by a Merkle tree built over fixed-size data blocks. Only the root hash needs to be trusted and any tampered block causes a verification failure up the tree.

![Merkle Tree](images/03-merkle-tree.svg)

### Hash Tree

The full on-disk hashtree layout: leaf hashes covering data blocks, intermediate levels and the root hash stored in the vbmeta descriptor.

![Hash Tree](images/04-hashtree.svg)

## How it works

1. `Locate the AVB footer`  checks the last 64 bytes first (standard
   location). If not found, detects the filesystem size from its superblock
   (ext4, erofs, squashfs) and scans forward in 1 MiB chunks starting
   1 MiB before the filesystem boundary. This allows images signed with
   `--partition_size 0` to work correctly when written to a larger block device.
2. `Verify vbmeta signature`  calls `avb_vbmeta_image_verify()` from libavb.
3. `Check public key`  compares the key embedded in vbmeta against the
   trusted `pubkey.bin`.
4. `Extract dm-verity parameters`  parses the hashtree descriptor and
   builds the dm-verity table string, including the `use_fec_from_device`
   arguments when the descriptor carries forward error correction data.
5. `Load root hash signature` *(if present)*  reads the `roothash_sig`
   vbmeta property, loads the PKCS#7 blob into the session keyring via
   `add_key(2)`, and appends `root_hash_sig_key_desc` to the dm-verity table.

## Required kernel configuration

```
CONFIG_BLK_DEV_DM=y
CONFIG_DM_VERITY=y
CONFIG_DM_VERITY_FEC=y
CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG=y
CONFIG_KEYS=y
CONFIG_ASYMMETRIC_KEY_TYPE=y
CONFIG_ASYMMETRIC_PUBLIC_KEY_SUBTYPE=y
CONFIG_X509_CERTIFICATE_PARSER=y
CONFIG_PKCS7_MESSAGE_PARSER=y
CONFIG_SYSTEM_TRUSTED_KEYRING=y
CONFIG_SYSTEM_TRUSTED_KEYS="/path/to/sig_cert.pem"
CONFIG_CRYPTO_RSA=y
CONFIG_CRYPTO_SHA256=y
```

### ML-DSA support (Linux 7.x+)

```
CONFIG_CRYPTO_MLDSA=y
CONFIG_PKCS7_WAIVE_AUTHATTRS_REJECTION_FOR_MLDSA=y
```

### Kernel Hardening

Add the option to your kernel cmdline to enforce root hash signature verification:

```
dm_verity.require_signatures=1
```

## Image layout

With `--partition_size 0`, `avbtool` appends metadata directly after the
filesystem data without padding to a fixed size:

```
Offset 0                      | filesystem data (ext4, squashfs, erofs, ...)
Offset <original_image_size>  | hashtree (dm-verity Merkle tree)
Offset <vbmeta_offset>        | VBMeta struct (signature + descriptors)
  ...padding to 4 KiB block...
End of last 4 KiB block − 64  | AVB footer (64 bytes)
```

When the image is written to a block device larger than the signed image,
trailing zeroes push the footer away from the device end. `avb_verify`
handles this by detecting the filesystem type from its superblock and
scanning forward from the filesystem boundary.

Footer scans cover up to 2 GiB from the filesystem hint, with a fallback
to the first 2 GiB. Images and devices larger than 4 GiB are supported.

AVB footer fields:

| Field | Size | Description |
|---|---|---|
| Magic (`AVBf`) | 4 bytes | Identifies this as an AVB footer |
| Version major/minor | 8 bytes | Footer format version |
| `original_image_size` | 8 bytes | Filesystem size before signing |
| `vbmeta_offset` | 8 bytes | Byte offset of the VBMeta struct |
| `vbmeta_size` | 8 bytes | Size of the VBMeta struct |
| Reserved | 28 bytes | Padding |


## Yocto Integration

avb-utils is available as a Yocto layer via [meta-avb](https://github.com/embetrix/meta-avb).


## Tests

```bash
ctest --test-dir build -V
```

The test suite creates temporary ext4, erofs, and squashfs images, signs them,
and exercises signature verification, key mismatch, corruption
detection, footer scanning on padded images, and root hash signature loading.

Additional tests cover sparse images with footers beyond 4 GiB and malformed
metadata. Loop-device and 32-bit tests run when available.

## License

This project is licensed under the [GNU General Public License v2.0](LICENSE).

### Third-party licenses

This project includes [libavb](https://android.googlesource.com/platform/external/avb/)
from the Android Open Source Project used as a git submodule under `avb`.

libavb is licensed under a permissive MIT-style license, the Apache License 2.0,
and the BSD 3-Clause License depending on the source file:
see the [upstream LICENSE](https://android.googlesource.com/platform/external/avb/+/refs/heads/master/LICENSE) for the full terms.

The `fec` host tool is assembled from further AOSP repositories used as git
submodules under `fec/`: `system/extras`, `system/libbase`, `system/core`,
`system/logging` and `external/squashfs-tools`, all Apache License 2.0, and
`external/fec` (Phil Karn's Reed-Solomon library), LGPL 2.1 or later. It is
not installed on a target.
