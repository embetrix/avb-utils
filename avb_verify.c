// SPDX-License-Identifier: GPL-2.0-only
/*
 * (C) Copyright 2026
 * Embetrix Embedded Systems Solutions, ayoub.zaki@embetrix.com
 *
 * avb_verify -- AVB vbmeta verifier and dm-verity table extractor
 *
 * Reads an image file or block device, locates the AVB footer (scanning
 * forward in 1 MiB chunks when it is not at the last block), verifies
 * the vbmeta signature, and checks the embedded public key against
 * a trusted reference key.
 *
 * Output modes:
 *   default        human-readable verification summary + indented dm-verity
 *                  table suitable for review
 *   -t/--dm-table  raw dm-verity table line only, suitable for piping
 *                  directly to "dmsetup create"
 *
 * Root hash signature (CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG):
 *   When the vbmeta image contains a "roothash_sig" property (a
 *   DER-encoded PKCS#7 signature over the root hash), it is loaded into
 *   the process session keyring via add_key(2) under the description
 *   "avb_roothash_sig.<partition>".  The dm-verity table is then extended
 *   with "root_hash_sig_key_desc <desc>" so the kernel can verify the
 *   root hash independently at mount time.
 *
 * Prepare the trusted public key with:
 *   avbtool extract_public_key --key key.pem --output pubkey.bin
 */

/* Required even when built outside CMake, before any system headers. */
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#elif _FILE_OFFSET_BITS != 64
#error "avb_verify requires _FILE_OFFSET_BITS=64"
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <inttypes.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <linux/keyctl.h>
#include <linux/magic.h>

#include <libavb/libavb.h>

_Static_assert(sizeof(off_t) >= 8, "64-bit file offsets required");

#define FAIL(...) \
	do { fprintf(stderr, __VA_ARGS__); ret = 1; goto out; } while (0)

/* avbtool block size — footer is aligned at the end of a 4 KiB block */
#define AVB_BLOCK_SIZE		4096

/* Scan chunk size: 1 MiB */
#define SCAN_CHUNK_SIZE		(1024 * 1024)

/*
 * Bytes searched from the filesystem hint (including 1 MiB look-behind).
 * If that misses, search the first 2 GiB, without rescanning any overlap.
 * This bounds I/O, not device size or the amount of trailing padding.
 */
#define FOOTER_SCAN_BUDGET	(2ULL * 1024 * 1024 * 1024)
/* Same vbmeta bound as libavb's slot verifier; also bounds untrusted allocation. */
#define VBMETA_MAX_SIZE		(64 * 1024)
#define PUBLIC_KEY_MAX_SIZE	(64 * 1024)

#define ROOTHASH_SIG_KEY_PREFIX	"avb_roothash_sig."
#define AVB_PART_NAME_MAX_LEN	128

/* Hashtree descriptor fields extracted from vbmeta */
typedef struct {
	bool found;
	bool invalid;
	AvbHashtreeDescriptor ht;
	const uint8_t *partition_name;
	const uint8_t *salt;
	const uint8_t *root_digest;
} HashtreeInfo;

/* Little-endian field readers (ext4/erofs superblocks are LE) */
static uint16_t read_le16(const uint8_t *p)
{
	return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
	       ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t read_le64(const uint8_t *p)
{
	return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

/* All conversions to off_t go through this checked, 64-bit path. */
static bool read_at(FILE *fp, uint64_t offset, void *buf, size_t len)
{
	if (offset > INT64_MAX) {
		errno = EOVERFLOW;
		return false;
	}
	if (fseeko(fp, (off_t)offset, SEEK_SET) != 0)
		return false;
	if (fread(buf, 1, len, fp) != len) {
		if (!ferror(fp))
			errno = EIO;
		return false;
	}
	return true;
}

static bool get_image_size(FILE *fp, uint64_t *size)
{
	struct stat st;

	if (fstat(fileno(fp), &st) != 0)
		return false;
	if (S_ISREG(st.st_mode)) {
		if (st.st_size < 0) {
			errno = EOVERFLOW;
			return false;
		}
		*size = (uint64_t)st.st_size;
	} else if (S_ISBLK(st.st_mode)) {
		if (ioctl(fileno(fp), BLKGETSIZE64, size) != 0)
			return false;
	} else {
		errno = EINVAL;
		return false;
	}
	if (*size > INT64_MAX) {
		errno = EOVERFLOW;
		return false;
	}
	return true;
}

/*
 * Unauthenticated search hints, never verification evidence. Reject impossible
 * sizes before shifting/multiplying. Unsupported formats use the prefix scan.
 */
static uint64_t detect_fs_size(const uint8_t *sb, size_t len, uint64_t image_size)
{
	uint64_t size = 0, blocks;
	uint32_t shift;

	if (len >= 2048 && read_le16(sb + 1024 + 56) == EXT4_SUPER_MAGIC) {
		shift = read_le32(sb + 1024 + 24);
		if (shift > 6) /* ext block sizes: 1 KiB through 64 KiB */
			return 0;
		blocks = read_le32(sb + 1024 + 4);
		if (read_le32(sb + 1024 + 96) & 0x80) /* INCOMPAT_64BIT */
			blocks |= (uint64_t)read_le32(sb + 1024 + 336) << 32;
		shift += 10;
		if (blocks > (UINT64_MAX >> shift))
			return 0;
		size = blocks << shift;
	} else if (len >= 1152 && read_le32(sb + 1024) == EROFS_SUPER_MAGIC_V1) {
		shift = sb[1024 + 12];
		if (shift < 9 || shift > 16)
			return 0;
		blocks = read_le32(sb + 1024 + 36);
		if (read_le32(sb + 1024 + 80) & 0x80) /* INCOMPAT_48BIT */
			blocks |= (uint64_t)read_le16(sb + 1024 + 14) << 32;
		if (blocks > (UINT64_MAX >> shift))
			return 0;
		size = blocks << shift;
	} else if (len >= 96 && read_le32(sb) == SQUASHFS_MAGIC) {
		shift = read_le16(sb + 22);
		if (read_le16(sb + 28) != 4 || read_le16(sb + 30) != 0 ||
		    shift < 12 || shift > 20 || read_le32(sb + 12) != (1U << shift))
			return 0;
		size = read_le64(sb + 40);
		if (size < 96)
			return 0;
		return size <= image_size ? size : 0;
	}
	return size >= 2048 && size <= image_size ? size : 0;
}

/* The footer itself is not signed. Bound every field before allocating/seeking. */
static bool decode_footer(const AvbFooter *raw, uint64_t offset, AvbFooter *footer)
{
	if (memcmp(raw->magic, AVB_FOOTER_MAGIC, AVB_FOOTER_MAGIC_LEN) != 0 ||
	    !avb_footer_validate_and_byteswap(raw, footer))
		return false;
	return footer->original_image_size <= footer->vbmeta_offset &&
	       footer->vbmeta_offset <= offset &&
	       footer->vbmeta_size >= sizeof(AvbVBMetaImageHeader) &&
	       footer->vbmeta_size <= VBMETA_MAX_SIZE &&
	       footer->vbmeta_size <= SIZE_MAX &&
	       footer->vbmeta_size <= offset - footer->vbmeta_offset;
}

/* Scan complete 4 KiB blocks in [start, end); end may be unaligned. */
static int scan_footer(FILE *fp, uint64_t start, uint64_t end, AvbFooter *footer)
{
	uint8_t *chunk = malloc(SCAN_CHUNK_SIZE);
	int result = 0;

	if (!chunk)
		return -1;
	end -= end % AVB_BLOCK_SIZE;
	for (uint64_t pos = start; pos < end;) {
		size_t len = end - pos > SCAN_CHUNK_SIZE ?
			SCAN_CHUNK_SIZE : (size_t)(end - pos);
		if (!read_at(fp, pos, chunk, len)) {
			result = -1;
			break;
		}
		for (size_t off = AVB_BLOCK_SIZE - AVB_FOOTER_SIZE;
		     off < len; off += AVB_BLOCK_SIZE) {
			AvbFooter raw;
			memcpy(&raw, chunk + off, sizeof(raw));
			if (decode_footer(&raw, pos + off, footer)) {
				result = 1;
				goto out;
			}
		}
		pos += len;
	}
out:
	free(chunk);
	return result;
}

static void print_hex(const uint8_t *data, size_t len)
{
	for (size_t i = 0; i < len; i++)
		printf("%02x", data[i]);
}

static uint8_t *read_file_all(const char *path, size_t *out_size)
{
	uint8_t *buf = NULL;
	FILE *fp = fopen(path, "rb");
	uint64_t len;

	if (!fp) {
		fprintf(stderr, "Error: cannot open '%s': %s\n", path, strerror(errno));
		return NULL;
	}
	if (!get_image_size(fp, &len) || len == 0 || len > PUBLIC_KEY_MAX_SIZE ||
	    len > SIZE_MAX) {
		fprintf(stderr, "Error: invalid public key file size.\n");
		goto out;
	}
	buf = malloc((size_t)len);
	if (!buf || !read_at(fp, 0, buf, (size_t)len)) {
		fprintf(stderr, "Error: could not read public key: %s\n", strerror(errno));
		free(buf);
		buf = NULL;
		goto out;
	}
	*out_size = (size_t)len;
out:
	fclose(fp);
	return buf;
}

static const char *algorithm_name(uint32_t type)
{
	switch (type) {
	case AVB_ALGORITHM_TYPE_SHA256_RSA2048: return "SHA256_RSA2048";
	case AVB_ALGORITHM_TYPE_SHA256_RSA4096: return "SHA256_RSA4096";
	case AVB_ALGORITHM_TYPE_SHA256_RSA8192: return "SHA256_RSA8192";
	case AVB_ALGORITHM_TYPE_SHA512_RSA2048: return "SHA512_RSA2048";
	case AVB_ALGORITHM_TYPE_SHA512_RSA4096: return "SHA512_RSA4096";
	case AVB_ALGORITHM_TYPE_SHA512_RSA8192: return "SHA512_RSA8192";
	case AVB_ALGORITHM_TYPE_MLDSA65:        return "MLDSA65";
	case AVB_ALGORITHM_TYPE_MLDSA87:        return "MLDSA87";
	default:                                return "NONE";
	}
}

/* Require one unambiguous hashtree descriptor and validate the full array. */
static bool find_hashtree(const AvbDescriptor *desc, void *user_data)
{
	HashtreeInfo *info = (HashtreeInfo *)user_data;
	AvbDescriptor header;
	const uint8_t *p;

	if (!avb_descriptor_validate_and_byteswap(desc, &header)) {
		info->invalid = true;
		return false;
	}
	if (header.tag != AVB_DESCRIPTOR_TAG_HASHTREE)
		return true;
	/* libavb's typed validator copies the fixed structure before checking size. */
	if (info->found || header.num_bytes_following <
	    sizeof(AvbHashtreeDescriptor) - sizeof(AvbDescriptor) ||
	    !avb_hashtree_descriptor_validate_and_byteswap(
			(const AvbHashtreeDescriptor *)desc, &info->ht)) {
		info->invalid = true;
		return false;
	}
	p = (const uint8_t *)desc + sizeof(AvbHashtreeDescriptor);
	info->partition_name = p;
	info->salt           = p + info->ht.partition_name_len;
	info->root_digest    = info->salt + info->ht.salt_len;
	info->found          = true;
	return true;
}

static bool valid_block_size(uint32_t size)
{
	return size >= 512 && size <= 65536 && (size & (size - 1)) == 0;
}

/* Validate signed values too: do not divide by zero or silently round a table. */
static bool valid_hashtree(const HashtreeInfo *info, uint64_t vbmeta_offset)
{
	const AvbHashtreeDescriptor *ht = &info->ht;
	const char *alg = (const char *)ht->hash_algorithm;

	if (!valid_block_size(ht->data_block_size) || !valid_block_size(ht->hash_block_size) ||
	    ht->dm_verity_version > 1 || ht->image_size == 0 ||
	    ht->image_size % ht->data_block_size != 0 ||
	    ht->tree_offset % ht->hash_block_size != 0 ||
	    ht->tree_size % ht->hash_block_size != 0 ||
	    ht->image_size > ht->tree_offset || ht->tree_offset > vbmeta_offset ||
	    ht->tree_size > vbmeta_offset - ht->tree_offset ||
	    ht->partition_name_len > AVB_PART_NAME_MAX_LEN ||
	    !memchr(alg, '\0', sizeof(ht->hash_algorithm)))
		return false;
	if (!((strcmp(alg, "sha1") == 0 && ht->root_digest_len == 20) ||
	      (strcmp(alg, "sha256") == 0 && ht->root_digest_len == 32) ||
	      (strcmp(alg, "blake2b-256") == 0 && ht->root_digest_len == 32) ||
	      (strcmp(alg, "sha512") == 0 && ht->root_digest_len == 64)))
		return false;
	/* Names are also used as a single token in the key description. */
	for (uint32_t i = 0; i < ht->partition_name_len; i++) {
		uint8_t c = info->partition_name[i];
		if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		      (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.'))
			return false;
	}
	return true;
}

/*
 * Load the PKCS#7 root hash signature from a vbmeta property into the
 * session keyring. Returns 1 if loaded, 0 if not present, -1 on error
 * (errno is set by the failed add_key syscall).
 */
static int load_roothash_sig(const uint8_t *vbmeta, size_t vbmeta_size,
			     const HashtreeInfo *ht, bool verbose,
			     bool no_keyring,
			     char *key_desc, size_t key_desc_size)
{
	const char *sig_data;
	size_t sig_size = 0;
	long key_id;

	sig_data = avb_property_lookup(vbmeta, vbmeta_size,
				       "roothash_sig", 0, &sig_size);
	if (!sig_data || sig_size == 0)
		return 0;

	snprintf(key_desc, key_desc_size, "%s%.*s",
		 ROOTHASH_SIG_KEY_PREFIX,
		 (int)ht->ht.partition_name_len, ht->partition_name);

	if (no_keyring)
		return 1;

	key_id = syscall(__NR_add_key, "user", key_desc,
			 sig_data, sig_size, KEY_SPEC_USER_SESSION_KEYRING);
	if (key_id < 0)
		return -1;

	if (verbose)
		fprintf(stderr,
			"Roothash signature loaded into keyring: %s (%zu bytes)\n",
			key_desc, sig_size);
	return 1;
}

static void print_verity_table(const char *prefix, const char *device_path,
				uint64_t sectors, const HashtreeInfo *ht,
				uint64_t data_blocks,
				uint64_t hash_start,
				bool has_roothash_sig,
				const char *sig_key_desc)
{
	bool has_fec = ht->ht.fec_num_roots > 0 && ht->ht.fec_size > 0;
	uint64_t fec_start = 0;
	unsigned int opt_args = 0;

	/* fec_blocks is the extent FEC covers rather than the size of the parity,
	 * and the parity begins immediately after what it covers, so the two are
	 * the same value. See avbtool.py make_verity_table(). */
	if (has_fec) {
		fec_start = ht->ht.fec_offset / ht->ht.data_block_size;
		opt_args += 8;
	}
	if (has_roothash_sig)
		opt_args += 2;

	printf("%s0 %" PRIu64 " verity %u %s %s %u %u %" PRIu64 " %" PRIu64 " %s ",
	       prefix, sectors, ht->ht.dm_verity_version,
	       device_path, device_path,
	       ht->ht.data_block_size, ht->ht.hash_block_size,
	       data_blocks, hash_start,
	       (const char *)ht->ht.hash_algorithm);
	print_hex(ht->root_digest, ht->ht.root_digest_len);
	printf(" ");
	if (ht->ht.salt_len)
		print_hex(ht->salt, ht->ht.salt_len);
	else
		printf("-");
	if (opt_args)
		printf(" %u", opt_args);
	if (has_fec)
		printf(" use_fec_from_device %s fec_roots %u fec_blocks %" PRIu64
		       " fec_start %" PRIu64,
		       device_path, ht->ht.fec_num_roots, fec_start, fec_start);
	if (has_roothash_sig)
		printf(" root_hash_sig_key_desc %s", sig_key_desc);
	printf("\n");
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s -d <device> -k <pubkey.bin> [-t] [-n] [-h]\n\n"
		"Verify AVB signature and print dm-verity parameters.\n\n"
		"Options:\n"
		"  -d, --device <path>             Image file or block device (required)\n"
		"  -k, --pubkey <path>             AVB public key file (required)\n"
		"  -t, --dm-table                  Print only the raw dm table line\n"
		"  -n, --no-keyring                Skip loading roothash_sig into the kernel\n"
		"                                  keyring\n"
		"  -h, --help                      Show this help\n\n"
		"If a 'roothash_sig' property (PKCS#7) is found in the vbmeta image,\n"
		"it is loaded into the session keyring and 'root_hash_sig_key_desc'\n"
		"is appended to the dm-verity table for kernel-level verification.\n\n"
		"Examples:\n"
		"  %s -d /dev/mmcblk0p2 -k pubkey.bin\n"
		"  %s -t -d /dev/mmcblk0p2 -k pubkey.bin | dmsetup create verity-system\n",
		prog, prog, prog);
}

int main(int argc, char *argv[])
{
	static const struct option long_opts[] = {
		{ "pubkey",        required_argument, NULL, 'k' },
		{ "device",        required_argument, NULL, 'd' },
		{ "dm-table",      no_argument,       NULL, 't' },
		{ "no-keyring",    no_argument,       NULL, 'n' },
		{ "help",          no_argument,       NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};
	bool dm_table_only = false;
	bool no_keyring = false;
	const char *device_path = NULL;
	const char *pubkey_path = NULL;
	int ret = 0;
	int opt;
	uint8_t *trusted_key = NULL;
	size_t trusted_key_size = 0;
	uint8_t *vbmeta = NULL;
	FILE *fp = NULL;
	uint64_t image_size;
	AvbFooter raw_footer, footer;
	bool footer_found = false;
	struct timespec ts_start, ts_end;
	double scan_ms;
	const uint8_t *embedded_key;
	size_t embedded_key_size;
	AvbVBMetaVerifyResult result;
	AvbVBMetaImageHeader raw_hdr, hdr;
	HashtreeInfo ht = { 0 };
	char sig_key_desc[AVB_PART_NAME_MAX_LEN + sizeof(ROOTHASH_SIG_KEY_PREFIX)];
	int sig_rc;
	bool has_roothash_sig;
	uint64_t data_blocks;
	uint64_t sectors;
	uint64_t hash_start;

	memset(sig_key_desc, 0, sizeof(sig_key_desc));

	while ((opt = getopt_long(argc, argv, "d:k:tnh", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'd': device_path = optarg;  break;
		case 'k': pubkey_path = optarg;  break;
		case 't': dm_table_only = true;  break;
		case 'n': no_keyring = true;     break;
		case 'h':
		default:
			usage(argv[0]);
			return (opt == 'h') ? 0 : 1;
		}
	}

	if (!device_path || !pubkey_path) {
		usage(argv[0]);
		return 1;
	}

	/* Load trusted public key */
	trusted_key = read_file_all(pubkey_path, &trusted_key_size);
	if (!trusted_key)
		return 1;

	/*
	 * Open image and find AVB footer.  Try the last 64 bytes first
	 * (standard location).  If not found, scan forward in 1 MiB chunks
	 * so that images created with --partition_size 0 work on larger
	 * block devices.
	 */
	fp = fopen(device_path, "rb");
	if (!fp)
		FAIL("Error: cannot open '%s': %s\n",
		     device_path, strerror(errno));

	if (!get_image_size(fp, &image_size))
		FAIL("Error: cannot determine image size: %s\n", strerror(errno));
	if (image_size < AVB_FOOTER_SIZE)
		FAIL("Error: image too small for AVB footer.\n");

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	/* The exact end is always tried, even for an unaligned container. */
	if (!read_at(fp, image_size - AVB_FOOTER_SIZE, &raw_footer, sizeof(raw_footer)))
		FAIL("Error: could not read footer: %s\n", strerror(errno));
	footer_found = decode_footer(&raw_footer, image_size - AVB_FOOTER_SIZE, &footer);

	if (!footer_found) {
		uint8_t sb[4096];
		size_t sb_len = image_size < sizeof(sb) ? (size_t)image_size : sizeof(sb);
		uint64_t scan_start = 0, scan_end, fs_size;
		int scan_result;

		if (!read_at(fp, 0, sb, sb_len))
			FAIL("Error: could not read superblock: %s\n", strerror(errno));
		fs_size = detect_fs_size(sb, sb_len, image_size);
		if (fs_size > SCAN_CHUNK_SIZE)
			scan_start = (fs_size - SCAN_CHUNK_SIZE) &
				     ~(uint64_t)(AVB_BLOCK_SIZE - 1);

		/* Subtract first: no overflow in scan_start + budget. */
		scan_end = scan_start + ((image_size - scan_start < FOOTER_SCAN_BUDGET) ?
			(image_size - scan_start) : FOOTER_SCAN_BUDGET);
		scan_result = scan_footer(fp, scan_start, scan_end, &footer);
		if (scan_result == 0 && scan_start != 0)
			scan_result = scan_footer(fp, 0,
				scan_start < FOOTER_SCAN_BUDGET ? scan_start : FOOTER_SCAN_BUDGET,
				&footer);
		if (scan_result < 0)
			FAIL("Error: footer scan read failed: %s\n", strerror(errno));
		footer_found = scan_result == 1;
	}

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	scan_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000.0 +
		  (ts_end.tv_nsec - ts_start.tv_nsec) / 1e6;
	if (!dm_table_only)
		fprintf(stderr, "Footer scan: %.3f ms\n", scan_ms);

	if (!footer_found)
		FAIL("Error: AVB footer not found (bounded scan; invalid footers ignored).\n");

	/* Read VBMeta blob */
	vbmeta = malloc((size_t)footer.vbmeta_size);
	if (!vbmeta)
		FAIL("Error: out of memory.\n");
	if (!read_at(fp, footer.vbmeta_offset, vbmeta, (size_t)footer.vbmeta_size))
		FAIL("Error: could not read VBMeta.\n");
	fclose(fp);
	fp = NULL;

	/* Verify VBMeta signature */
	result = avb_vbmeta_image_verify(vbmeta, (size_t)footer.vbmeta_size,
					 &embedded_key, &embedded_key_size);
	if (result != AVB_VBMETA_VERIFY_RESULT_OK)
		FAIL("FAILED: %s\n", avb_vbmeta_verify_result_to_string(result));

	/* Check public key */
	if (embedded_key_size != trusted_key_size ||
	    memcmp(embedded_key, trusted_key, trusted_key_size) != 0)
		FAIL("FAILED: public key mismatch.\n");

	/* Parse vbmeta header */
	memcpy(&raw_hdr, vbmeta, sizeof(raw_hdr));
	avb_vbmeta_image_header_to_host_byte_order(&raw_hdr, &hdr);

	/* Find hashtree descriptor */
	if (!avb_descriptor_foreach(vbmeta, (size_t)footer.vbmeta_size,
				    find_hashtree, &ht) || ht.invalid)
		FAIL("Error: invalid hashtree descriptors.\n");
	if (!ht.found)
		FAIL("No hashtree descriptor found.\n");
	if (!valid_hashtree(&ht, footer.vbmeta_offset))
		FAIL("Error: invalid dm-verity parameters.\n");

	sig_rc = load_roothash_sig(vbmeta, (size_t)footer.vbmeta_size,
				   &ht, !dm_table_only, no_keyring,
				   sig_key_desc, sizeof(sig_key_desc));
	if (sig_rc < 0)
		FAIL("Error: add_key to session keyring: %s\n", strerror(errno));
	has_roothash_sig = (sig_rc > 0);

	data_blocks = ht.ht.image_size / ht.ht.data_block_size;
	sectors     = ht.ht.image_size / 512;
	hash_start  = ht.ht.tree_offset / ht.ht.hash_block_size;

	if (dm_table_only) {
		print_verity_table("", device_path, sectors, &ht,
				   data_blocks, hash_start,
				   has_roothash_sig, sig_key_desc);
		goto out;
	}

	printf("Verification:  OK\n");
	printf("Algorithm:     %s\n", algorithm_name(hdr.algorithm_type));
	printf("Rollback:      %" PRIu64 "\n", hdr.rollback_index);
	printf("Partition:     %.*s\n",
	       (int)ht.ht.partition_name_len, ht.partition_name);
	printf("Hash alg:      %s\n", ht.ht.hash_algorithm);
	printf("Data blocks:   %" PRIu64 "\n", data_blocks);
	printf("Data block sz: %u\n", ht.ht.data_block_size);
	printf("Hash block sz: %u\n", ht.ht.hash_block_size);
	printf("Hash offset:   %" PRIu64 "\n", ht.ht.tree_offset);
	if (ht.ht.fec_num_roots > 0 && ht.ht.fec_size > 0)
		printf("FEC:           roots %u, offset %" PRIu64 ", size %" PRIu64 "\n",
		       ht.ht.fec_num_roots, ht.ht.fec_offset, ht.ht.fec_size);
	else
		printf("FEC:           none\n");
	printf("Root digest:   ");
	print_hex(ht.root_digest, ht.ht.root_digest_len);
	printf("\n");
	printf("Salt:          ");
	print_hex(ht.salt, ht.ht.salt_len);
	printf("\n");
	if (has_roothash_sig)
		printf("Roothash sig:  %s\n", sig_key_desc);

	printf("\ndm table:\n");
	print_verity_table("  ", device_path, sectors, &ht,
			   data_blocks, hash_start,
			   has_roothash_sig, sig_key_desc);

out:
	if (fp)
		fclose(fp);
	free(vbmeta);
	free(trusted_key);
	return ret;
}
