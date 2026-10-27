#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Sparse offset regressions. Synthetic cases sign metadata, not hole contents.
The real_large case separately hashes/signs all >4 GiB of data using avbtool.
Run against an old binary with AVB_VERIFY=/path/to/binary to reproduce failures.
"""
import errno
import functools
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'avb'))
import avbtool

GIB = 1 << 30
MIB = 1 << 20
BLOCK = 4096
BINARY = os.environ.get('AVB_VERIFY', str(ROOT / 'build/avb_verify'))
KEY = ROOT / 'avb/test/data/testkey_rsa2048.pem'
WRONG_KEY = ROOT / 'avb/test/data/testkey_rsa2048_2.pem'


def run_tool(*args):
    result = subprocess.run([sys.executable, str(ROOT / 'avb/avbtool.py'), *map(str, args)],
                            text=True, capture_output=True)
    if result.returncode:
        raise RuntimeError(result.stderr)


def superblock(kind, size):
    sb = bytearray(4096)
    if kind == 'erofs':
        struct.pack_into('<I', sb, 1024, 0xE0F5E1E2)
        sb[1036] = 12
        struct.pack_into('<I', sb, 1060, (size // BLOCK) & 0xffffffff)
        if size // BLOCK > 0xffffffff:
            struct.pack_into('<H', sb, 1038, size // BLOCK >> 32)
            struct.pack_into('<I', sb, 1104, 0x80)
    elif kind == 'ext4':
        struct.pack_into('<H', sb, 1080, 0xef53)
        struct.pack_into('<I', sb, 1048, 2)
        struct.pack_into('<I', sb, 1028, (size // BLOCK) & 0xffffffff)
        struct.pack_into('<I', sb, 1120, 0x80)
        struct.pack_into('<I', sb, 1360, size // BLOCK >> 32)
    elif kind == 'squashfs':
        struct.pack_into('<I', sb, 0, 0x73717368)
        struct.pack_into('<I', sb, 12, 131072)
        struct.pack_into('<H', sb, 22, 17)
        struct.pack_into('<HH', sb, 28, 4, 0)
        struct.pack_into('<Q', sb, 40, size)
    return sb


def descriptor(size, **changes):
    d = avbtool.AvbHashtreeDescriptor()
    d.dm_verity_version = 1
    d.image_size = size
    d.tree_offset = size
    d.tree_size = BLOCK
    d.data_block_size = d.hash_block_size = BLOCK
    d.hash_algorithm = 'sha256'
    d.partition_name = 'system'
    d.root_digest = bytes(32)
    d.salt = b'\x12\x34'
    for name, value in changes.items():
        setattr(d, name, value)
    return d


def sign(descs, algorithm='SHA256_RSA2048'):
    return avbtool.Avb()._generate_vbmeta_blob(
        algorithm_name=algorithm, key_path=str(KEY), public_key_metadata_path=None,
        descriptors=descs, chain_partitions_use_ab=[], chain_partitions_do_not_use_ab=[],
        rollback_index=(1 << 40) + 7, flags=0, rollback_index_location=0,
        props=[], props_from_file=[], kernel_cmdlines=[], setup_rootfs_from_kernel=None,
        ht_desc_to_setup=None, include_descriptors_from_image=[], signing_helper=None,
        signing_helper_with_files=None, release_string=None, append_to_release_string=None,
        required_libavb_version_minor=0)


@functools.lru_cache(maxsize=64)
def metadata(size):
    return sign([descriptor(size)])


class LargeImages(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='avb-large-')
        cls.dir = Path(cls.tmp.name)
        cls.pub = cls.dir / 'pub.bin'
        cls.wrong = cls.dir / 'wrong.bin'
        run_tool('extract_public_key', '--key', KEY, '--output', cls.pub)
        run_tool('extract_public_key', '--key', WRONG_KEY, '--output', cls.wrong)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def fixture(self, end=4*MIB, kind='erofs', container=None, sb=None, blob=None,
                fec_size=0):
        # Metadata and footer really reside at these large offsets; holes stay sparse.
        size = (end - 128*1024 - fec_size) // BLOCK * BLOCK
        self.vbmeta_offset = size + BLOCK + fec_size
        blob = metadata(size) if blob is None else blob
        footer = avbtool.AvbFooter()
        footer.original_image_size = size
        footer.vbmeta_offset = self.vbmeta_offset
        footer.vbmeta_size = len(blob)
        self.footer_offset = end - 64
        self.path = self.dir / 'image.img'
        with self.path.open('wb') as f:
            f.write(superblock(kind, size) if sb is None else sb)
            f.seek(self.vbmeta_offset)
            f.write(blob)
            f.seek(self.footer_offset)
            f.write(footer.encode())
            f.truncate(end if container is None else container)
        return size

    def verify(self, ok=True, key=None, error=None, path=None, table=True):
        args = [BINARY, '-n', '-d', str(path or self.path), '-k', str(key or self.pub)]
        if table:
            args.append('-t')
        r = subprocess.run(args, text=True, capture_output=True, timeout=90)
        self.assertEqual(r.returncode, 0 if ok else 1, r.stderr)
        if not ok:
            self.assertEqual(r.stdout, '', r.stdout)
        if error:
            self.assertIn(error, r.stderr)
        return r.stdout

    def patch(self, offset, data):
        with self.path.open('r+b') as f:
            f.seek(offset)
            f.write(data)

    def test_boundary_matrix(self):
        for kind in ('erofs', 'ext4', 'squashfs'):
            for boundary in (2*GIB, 4*GIB):
                for delta in (-BLOCK, 0, BLOCK):
                    for padded in (False, True):
                        with self.subTest(fs=kind, boundary=boundary, delta=delta, padded=padded):
                            end = boundary + delta
                            size = self.fixture(end, kind, end + 2*MIB + 123 if padded else end)
                            fields = self.verify().split()
                            self.assertEqual(int(fields[1]), size // 512)
                            self.assertEqual(int(fields[8]), size // BLOCK)
                            self.assertEqual(int(fields[9]), size // BLOCK)
                            self.assertEqual(self.footer_offset, end - 64)

    def test_reported_size(self):
        self.fixture(2223104000)
        self.verify()
        os.truncate(self.path, 4*GIB)
        self.verify()

    def test_large_container_small_footer(self):
        self.fixture(container=8*GIB, kind='unknown')
        self.assertLess(self.footer_offset, 2*GIB)
        self.verify()

    def test_footer_start_exactly_at_boundary(self):
        # Only the exact-end fast path supports a footer not ending on a 4 KiB block.
        for boundary in (2*GIB, 4*GIB):
            self.fixture(boundary + 64)
            self.assertEqual(self.footer_offset, boundary)
            self.verify()
            os.truncate(self.path, boundary + MIB)
            self.verify(False, error='footer not found')

    def test_scan_window_edge(self):
        hint = 4*GIB
        scan_end = hint - MIB + 2*GIB
        for delta in (0, BLOCK):
            with self.subTest(delta=delta):
                self.fixture(scan_end + delta, sb=superblock('erofs', hint), container=8*GIB)
                self.verify(delta == 0)

    def test_unknown_beyond_prefix_budget(self):
        self.fixture(2*GIB + BLOCK, kind='unknown', container=3*GIB)
        self.verify(False, error='footer not found')

    def test_prefix_last_block(self):
        self.fixture(2*GIB, kind='unknown', container=3*GIB)
        self.verify()

    def test_invalid_hints_and_prefix_fallback(self):
        cases = []
        for kind in ('erofs', 'ext4', 'squashfs'):
            cases += [superblock(kind, 0), superblock(kind, 8*GIB)]
        for shift in (0, 8, 17, 64, 255):
            sb = superblock('erofs', 4*MIB)
            sb[1036] = shift
            cases.append(sb)
        for shift in (7, 54, 64, 0xffffffff):
            sb = superblock('ext4', 4*MIB)
            struct.pack_into('<I', sb, 1048, shift)
            cases.append(sb)
        sb = superblock('ext4', 4*MIB)
        struct.pack_into('<I', sb, 1360, 0xffffffff)  # multiplication overflow
        cases.append(sb)
        sb = superblock('squashfs', (1 << 64)-1)
        cases.append(sb)
        sb = superblock('squashfs', 4*MIB)
        struct.pack_into('<H', sb, 22, 65535)
        cases.append(sb)
        cases.append(superblock('erofs', 16*MIB))  # plausible but wrong, within device
        for i, sb in enumerate(cases):
            with self.subTest(case=i):
                self.fixture(sb=sb, container=32*MIB)
                self.verify()

    def test_corrupt_and_missing_footer(self):
        for magic in (b'\0'*4, b'AVBx'):
            self.fixture(container=8*MIB)
            self.patch(self.footer_offset, magic)
            self.verify(False, error='footer not found')
        self.fixture(container=8*MIB)
        self.patch(self.footer_offset + 4, struct.pack('>I', 99))
        self.verify(False)

    def test_footer_ranges(self):
        for field, value in ((12, (1<<64)-1), (20, (1<<64)-1), (20, 4*MIB),
                             (28, 0), (28, 255), (28, 65537),
                             (28, (1<<32)+1344), (28, (1<<64)-1)):
            with self.subTest(field=field, value=value):
                self.fixture(container=8*MIB)
                self.patch(self.footer_offset + field, struct.pack('>Q', value))
                self.verify(False, error='footer not found')

    def test_bad_candidate_then_valid_footer(self):
        self.fixture(container=8*MIB)
        with self.path.open('rb') as f:
            f.seek(self.footer_offset)
            raw = bytearray(f.read(64))
        struct.pack_into('>Q', raw, 28, (1<<64)-1)
        self.patch(3*MIB - 64, raw)
        self.verify()

    def test_truncation(self):
        for length in (0, 32, 63):
            self.fixture()
            os.truncate(self.path, length)
            self.verify(False, error='too small')
        self.fixture()
        os.truncate(self.path, self.footer_offset + 32)
        self.verify(False)
        self.fixture()
        self.patch(self.footer_offset + 28, struct.pack('>Q', 256))
        self.verify(False, error='INVALID_VBMETA_HEADER')
        self.fixture()
        self.patch(self.vbmeta_offset + 12, struct.pack('>Q', (1<<64)-64))
        self.verify(False, error='INVALID_VBMETA_HEADER')

    def test_authentication(self):
        for padded in (False, True):
            self.fixture(4*GIB + MIB, container=5*GIB if padded else None)
            self.verify(False, key=self.wrong, error='public key mismatch')
            self.patch(self.vbmeta_offset + 288, b'\xff'*256)  # signature, not hash
            self.verify(False, error='SIGNATURE_MISMATCH')
        self.fixture(blob=sign([descriptor(4*MIB-128*1024)], 'NONE'))
        self.verify(False, error='OK_NOT_SIGNED')

    def test_signed_invalid_table_values(self):
        size = 4*MIB-128*1024
        for changes in ({'data_block_size': 0}, {'hash_block_size': 0},
                        {'data_block_size': 513}, {'hash_block_size': 3},
                        {'image_size': size+1}, {'image_size': (1<<64)-1},
                        {'tree_offset': size+1}, {'tree_size': (1<<64)-1},
                        {'tree_offset': 8*MIB}, {'dm_verity_version': 99}):
            with self.subTest(changes=changes):
                self.fixture(blob=sign([descriptor(size, **changes)]))
                self.verify(False, error='invalid dm-verity parameters')

    def test_signed_fec_table_values(self):
        # Synthetic signed layouts exercise metadata validation; fec_roundtrip
        # and avb_sign separately test real parity generation and repair.
        for roots in (2, 24):
            fec_size = 4 * roots * BLOCK
            size = 4*MIB - 128*1024 - fec_size
            fec_offset = size + BLOCK
            desc = descriptor(size, fec_num_roots=roots,
                              fec_offset=fec_offset, fec_size=fec_size)
            self.fixture(blob=sign([desc]), fec_size=fec_size)
            fields = self.verify().split()
            self.assertEqual(fields[13:], [
                '8', 'use_fec_from_device', str(self.path), 'fec_roots', str(roots),
                'fec_blocks', str(fec_offset // BLOCK),
                'fec_start', str(fec_offset // BLOCK)])

    def test_signed_invalid_fec_values(self):
        fec_size = 8 * BLOCK
        size = 4*MIB - 128*1024 - fec_size
        fec_offset = size + BLOCK
        for changes in (
                {'fec_num_roots': 0}, {'fec_num_roots': 1},
                {'fec_num_roots': 25}, {'fec_num_roots': (1 << 32)-1},
                {'fec_offset': 0}, {'fec_offset': fec_offset + 1},
                {'fec_offset': size}, {'fec_offset': fec_offset + BLOCK},
                {'fec_offset': 1 << 40}, {'fec_offset': (1 << 64)-1},
                {'fec_size': 0}, {'fec_size': fec_size - 1},
                {'fec_size': fec_size - BLOCK}, {'fec_size': fec_size + BLOCK},
                {'fec_size': (1 << 64)-BLOCK}, {'hash_block_size': BLOCK // 2},
                {'fec_num_roots': 0, 'fec_size': 0},
                {'fec_num_roots': 0, 'fec_offset': 0}):
            with self.subTest(changes=changes):
                values = dict(fec_num_roots=2, fec_offset=fec_offset, fec_size=fec_size)
                values.update(changes)
                self.fixture(blob=sign([descriptor(size, **values)]), fec_size=fec_size)
                self.verify(False, error='invalid dm-verity parameters')

    def test_short_signed_descriptor(self):
        class Short:
            def encode(self):
                return struct.pack('>QQ', 1, 0)
        self.fixture(blob=sign([Short()]))
        self.verify(False, error='invalid hashtree descriptors')

    def test_descriptor_array_and_strings(self):
        size = 4*MIB-128*1024
        self.fixture(blob=sign([descriptor(size), descriptor(size)]))
        self.verify(False, error='invalid hashtree descriptors')
        class Truncated:
            def encode(self):
                return struct.pack('>QQ', 1, 1024)
        self.fixture(blob=sign([descriptor(size), Truncated()]))
        self.verify(False, error='invalid hashtree descriptors')
        for changes in ({'hash_algorithm': 'x'*32}, {'root_digest': b''},
                        {'partition_name': 'bad name'}, {'partition_name': 'x'*129}):
            with self.subTest(changes=changes):
                self.fixture(blob=sign([descriptor(size, **changes)]))
                self.verify(False, error='invalid dm-verity parameters')

    def test_no_fallback_after_signature_failure(self):
        self.fixture(container=8*MIB)
        # Structurally valid end-footer points at corrupted metadata; a valid
        # signed copy remains at the earlier interior footer. Never accept it.
        with self.path.open('rb') as f:
            f.seek(self.footer_offset)
            footer = avbtool.AvbFooter(f.read(64))
            f.seek(footer.vbmeta_offset)
            blob = bytearray(f.read(footer.vbmeta_size))
        blob[288] ^= 1
        footer.vbmeta_offset = 6*MIB
        self.patch(6*MIB, blob)
        self.patch(8*MIB-64, footer.encode())
        self.verify(False, error='SIGNATURE_MISMATCH')

    def test_wide_table_and_rollback(self):
        # 512-byte verity blocks cross all three 32-bit counters above 2 TiB,
        # without exceeding the host filesystem's possible 16 TiB file limit.
        end = (1<<41) + 4*MIB
        size = end - 128*1024
        blob = sign([descriptor(size, data_block_size=512, hash_block_size=512,
                                tree_size=512)])
        for kind in ('ext4', 'erofs'):
            self.fixture(end, kind, end + MIB, blob=blob)
            fields = self.verify().split()
            self.assertEqual(fields[6:8], ['512', '512'])
            for index in (1, 8, 9):
                self.assertEqual(int(fields[index]), size//512)
                self.assertGreater(int(fields[index]), 0xffffffff)
            self.assertIn(str((1<<40)+7), self.verify(table=False))

    def require_sparse_file_size(self, size):
        # Probe only fixture creation. Never convert a verifier failure to a skip.
        try:
            with tempfile.TemporaryFile(dir=self.dir) as f:
                os.lseek(f.fileno(), size - 1, os.SEEK_SET)
                os.write(f.fileno(), b'\0')
                os.ftruncate(f.fileno(), size)
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.EFBIG, errno.EOVERFLOW):
                raise
            self.skipTest(f'temporary filesystem cannot create a {size}-byte sparse file: {exc}')

    def test_sparse_file_size_probe(self):
        # Reproduce CI's EINVAL and other file-size limits without requiring
        # a particular host filesystem; unrelated I/O errors must still fail.
        for operation in ('lseek', 'write', 'ftruncate'):
            for code in (errno.EINVAL, errno.EFBIG, errno.EOVERFLOW, errno.EIO):
                with self.subTest(operation=operation, errno=code):
                    with mock.patch('os.' + operation, side_effect=OSError(code, 'probe failure')):
                        expected = OSError if code == errno.EIO else unittest.SkipTest
                        with self.assertRaises(expected):
                            self.require_sparse_file_size(BLOCK)

    def test_high_filesystem_block_counts(self):
        # High ext4/EROFS count fields need >16 TiB with 4 KiB filesystem
        # blocks. Unit tests also cover these fields without large host files.
        end = (1<<44) + 4*MIB
        self.require_sparse_file_size(end + MIB)
        for kind in ('ext4', 'erofs'):
            size = self.fixture(end, kind, end + MIB)
            fields = self.verify().split()
            self.assertEqual(int(fields[1]), size//512)
            self.assertEqual(int(fields[8]), size//BLOCK)
            self.assertEqual(int(fields[9]), size//BLOCK)
            self.assertIn(str((1<<40)+7), self.verify(table=False))

    def test_empty_salt(self):
        self.fixture(blob=sign([descriptor(4*MIB-128*1024, salt=b'')]))
        self.assertEqual(self.verify().split()[-1], '-')

    def test_loop_device(self):
        if not shutil.which('losetup') or not os.access('/dev/loop-control', os.R_OK | os.W_OK):
            self.skipTest('no accessible /dev/loop-control; ioctl path covered by unit tests')
        self.fixture(4*GIB + MIB, container=6*GIB)
        result = subprocess.run(['losetup', '--find', '--show', '--read-only', str(self.path)],
                                text=True, capture_output=True)
        if result.returncode:
            self.skipTest('cannot allocate loop device: ' + result.stderr.strip())
        device = result.stdout.strip()
        try:
            self.verify(path=device)
        finally:
            subprocess.run(['losetup', '--detach', device], check=True)

    def test_invalid_key_sizes_and_input_type(self):
        key = self.dir / 'bad-key'
        for length in (0, 65537, 4*GIB+1):
            with key.open('wb') as f:
                f.truncate(length)
            self.fixture()
            self.verify(False, key=key)
        self.verify(False, path='/dev/null', error='cannot determine image size')

    @unittest.skipIf(os.environ.get('AVB_SKIP_REAL_LARGE'), 'explicitly skipped real large hash generation')
    def test_real_large(self):
        # This tree is actually generated from every data block; no fabricated root.
        if not shutil.which('mkfs.ext4'):
            self.skipTest('mkfs.ext4 required for the real >4 GiB filesystem')
        self.path = self.dir / 'system.img'
        size = 4*GIB + 8*MIB
        with self.path.open('wb') as f:
            f.truncate(size)
        subprocess.run(['mkfs.ext4', '-q', '-F', str(self.path)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        run_tool('add_hashtree_footer', '--image', self.path, '--partition_size', '0',
                 '--partition_name', 'system', '--algorithm', 'SHA256_RSA2048',
                 '--key', KEY, '--hash_algorithm', 'sha256', '--salt', '1234',
                 '--do_not_generate_fec')
        self.assertGreater(self.path.stat().st_size - 64, 4*GIB)
        with self.path.open('rb') as f:
            f.seek(-64, 2)
            footer = avbtool.AvbFooter(f.read(64))
        self.assertGreater(footer.vbmeta_offset, 4*GIB)
        print(f'\nReal ext4: data={size}, vbmeta={footer.vbmeta_offset}, '
              f'footer={self.path.stat().st_size - 64}, partition={6*GIB}', flush=True)
        self.verify()
        os.truncate(self.path, 6*GIB)
        fields = self.verify().split()
        self.assertEqual(int(fields[1]), size//512)
        # Verify the generated data/tree independently with avbtool on the compact form.
        os.truncate(self.path, footer.vbmeta_offset +
                    ((footer.vbmeta_size + BLOCK-1)//BLOCK)*BLOCK + BLOCK)
        run_tool('verify_image', '--image', self.path, '--key', KEY)
        self.path.unlink()


if __name__ == '__main__':
    unittest.main(verbosity=2)
