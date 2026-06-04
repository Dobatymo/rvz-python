from __future__ import annotations

import hashlib
import io
import struct
import unittest
import warnings
import zipfile

import zstandard as zstd

from rvz import RVZReader
from rvz.packing import decode_rvz_packing, generate_padding
from rvz.wii import (
    BLOCK_DATA_SIZE,
    BLOCK_HEADER_SIZE,
    BLOCK_TOTAL_SIZE,
    GROUP_DATA_SIZE,
    GROUP_TOTAL_SIZE,
    ZERO_IV,
    build_hash_blocks,
)


def build_minimal_rvz(compression: int = 5) -> tuple[bytes, bytes]:
    chunk_size = 0x8000
    disc_prefix = bytes((i * 3) % 256 for i in range(0x80))
    seed = bytes(range(68))
    literal = bytes((0x80 + i) % 256 for i in range(0x180))
    padding_size = chunk_size - len(literal)
    group = literal + generate_padding(seed, padding_size, len(literal))
    packed_group = struct.pack(">I", len(literal)) + literal + struct.pack(">I", 0x80000000 | padding_size) + seed

    iso = disc_prefix + group[0x80:]
    raw_entry = struct.pack(">QQII", 0x80, len(iso) - 0x80, 0, 1)

    data_offset = 1024
    stored_group = _compress_for_fixture(packed_group, compression)
    group_entry = struct.pack(
        ">III",
        data_offset // 4,
        0x80000000 | len(stored_group),
        len(packed_group),
    )

    raw_table = _compress_for_fixture(raw_entry, compression)
    group_table = _compress_for_fixture(group_entry, compression)
    raw_offset = 0x48 + 0xDC
    group_offset = raw_offset + len(raw_table)
    if group_offset + len(group_table) > data_offset:
        raise AssertionError("test RVZ fixture layout is too small")

    disc_header = bytearray(0xDC)
    struct.pack_into(">IIII", disc_header, 0, 1, compression, 1, chunk_size)
    disc_header[16 : 16 + 0x80] = disc_prefix
    struct.pack_into(">IIQ", disc_header, 144, 0, 48, raw_offset)
    disc_header[160:180] = hashlib.sha1(b"").digest()
    struct.pack_into(">IQIIQI", disc_header, 180, 1, raw_offset, len(raw_table), 1, group_offset, len(group_table))
    disc_header[212] = 0
    disc_hash = hashlib.sha1(disc_header).digest()

    file_size = data_offset + len(stored_group)
    header_without_hash = (
        b"RVZ\x01"
        + struct.pack(">III", 0x01000000, 0x00030000, len(disc_header))
        + disc_hash
        + struct.pack(">QQ", len(iso), file_size)
    )
    header = header_without_hash + hashlib.sha1(header_without_hash).digest()

    blob = bytearray()
    blob.extend(header)
    blob.extend(disc_header)
    blob.extend(raw_table)
    blob.extend(group_table)
    blob.extend(b"\0" * (data_offset - len(blob)))
    blob.extend(stored_group)
    return bytes(blob), iso


def _compress_for_fixture(data: bytes, compression: int) -> bytes:
    if compression == 1:
        segment = struct.pack(">II", 0, len(data)) + data
        return segment + hashlib.sha1(segment).digest()
    if compression == 5:
        return zstd.ZstdCompressor(level=1).compress(data)
    raise AssertionError(f"unsupported fixture compression {compression}")


def build_wii_partition_rvz(exception_digest: bytes = b"") -> tuple[bytes, bytes, bytes]:
    key = bytes(range(16))
    chunk_size = BLOCK_TOTAL_SIZE
    decrypted_sector = bytes((i * 5 + 3) % 256 for i in range(BLOCK_DATA_SIZE))
    data_blocks = [decrypted_sector] + [b"\0" * BLOCK_DATA_SIZE for _ in range(63)]
    hash_blocks = build_hash_blocks(data_blocks)
    exception_list = struct.pack(">H", 0)
    if exception_digest:
        hash_blocks[0][0:20] = exception_digest
        exception_list = struct.pack(">HH", 1, 0) + exception_digest

    encrypted_hash = _aes_cbc_decryptable_encrypt(key, ZERO_IV, bytes(hash_blocks[0]))
    encrypted_data = _aes_cbc_decryptable_encrypt(key, encrypted_hash[0x3D0:0x3E0], decrypted_sector)
    expected_sector = encrypted_hash + encrypted_data

    stored_group = zstd.ZstdCompressor(level=1).compress(exception_list + decrypted_sector)
    partition_entry = key + struct.pack(">IIII", 0, 1, 0, 1) + struct.pack(">IIII", 0, 0, 0, 0)
    group_entry = struct.pack(">III", 1024 // 4, 0x80000000 | len(stored_group), 0)
    partition_table_hash = hashlib.sha1(partition_entry).digest()
    group_table = zstd.ZstdCompressor(level=1).compress(group_entry)
    partition_offset = 0x48 + 0xDC
    group_table_offset = partition_offset + len(partition_entry)

    disc_header = bytearray(0xDC)
    disc_header[16 : 16 + 0x80] = expected_sector[:0x80]
    struct.pack_into(">IIII", disc_header, 0, 2, 5, 1, chunk_size)
    struct.pack_into(">IIQ", disc_header, 144, 1, 48, partition_offset)
    disc_header[160:180] = partition_table_hash
    struct.pack_into(">IQIIQI", disc_header, 180, 0, 0, 0, 1, group_table_offset, len(group_table))
    disc_hash = hashlib.sha1(disc_header).digest()

    file_size = 1024 + len(stored_group)
    header_without_hash = (
        b"RVZ\x01"
        + struct.pack(">III", 0x01000000, 0x00030000, len(disc_header))
        + disc_hash
        + struct.pack(">QQ", len(expected_sector), file_size)
    )
    header = header_without_hash + hashlib.sha1(header_without_hash).digest()

    blob = bytearray()
    blob.extend(header)
    blob.extend(disc_header)
    blob.extend(partition_entry)
    blob.extend(group_table)
    blob.extend(b"\0" * (1024 - len(blob)))
    blob.extend(stored_group)
    return bytes(blob), expected_sector, key


def _aes_cbc_decryptable_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Python 3.8 is no longer supported by the Python core team")
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _aes_cbc_decrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Python 3.8 is no longer supported by the Python core team")
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return decryptor.update(data) + decryptor.finalize()


class RVZPackingTests(unittest.TestCase):
    def test_generate_padding_matches_known_vector(self) -> None:
        seed = bytes(range(68))
        self.assertEqual(
            generate_padding(seed, 32).hex(),
            "1d757e0b64346456b7f95f37b14dcdec2ea34b4f13ef95cae6a79d4f23ca1813",
        )
        self.assertEqual(
            generate_padding(seed, 32, 7).hex(),
            "56b7f95f37b14dcdec2ea34b4f13ef95cae6a79d4f23ca18133834018c303b53",
        )

    def test_decode_rvz_packing_literals_and_padding(self) -> None:
        seed = bytes(range(68))
        packed = struct.pack(">I", 3) + b"abc" + struct.pack(">I", 0x80000005) + seed
        self.assertEqual(
            decode_rvz_packing(packed, 8),
            b"abc" + generate_padding(seed, 5, 3),
        )


class RVZReaderTests(unittest.TestCase):
    def test_read_hash_and_extract_from_file_object(self) -> None:
        blob, iso = build_minimal_rvz()
        with RVZReader(io.BytesIO(blob)) as reader:
            self.assertEqual(reader.iso_size, len(iso))
            self.assertEqual(reader.read(0, len(iso)), iso)
            self.assertEqual(reader.read(0x60, 0x80), iso[0x60:0xE0])
            self.assertEqual(reader.hash_iso("sha1"), hashlib.sha1(iso).hexdigest())
            output = io.BytesIO()
            reader.extract_iso(output)
            self.assertEqual(output.getvalue(), iso)

    def test_read_purge_compressed_raw_rvz(self) -> None:
        blob, iso = build_minimal_rvz(compression=1)
        with RVZReader(io.BytesIO(blob)) as reader:
            self.assertEqual(reader.read(0, len(iso)), iso)
            self.assertEqual(reader.hash_iso("sha1"), hashlib.sha1(iso).hexdigest())

    def test_read_from_zip_member_file_object(self) -> None:
        blob, iso = build_minimal_rvz()
        archive_data = io.BytesIO()
        with zipfile.ZipFile(archive_data, "w", zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("nested/game.rvz", blob)

        archive_data.seek(0)
        with zipfile.ZipFile(archive_data) as archive:
            with archive.open("nested/game.rvz") as fileobj:
                with RVZReader(fileobj) as reader:
                    self.assertEqual(reader.read(0, len(iso)), iso)

    def test_read_wii_partition_reconstructs_encrypted_sector(self) -> None:
        blob, iso, _key = build_wii_partition_rvz()
        with RVZReader(io.BytesIO(blob)) as reader:
            self.assertEqual(reader.disc_header.disc_type_name, "wii")
            self.assertEqual(reader.read(0, len(iso)), iso)

    def test_read_wii_partition_applies_hash_exceptions(self) -> None:
        replacement = b"\xa5" * 20
        blob, iso, key = build_wii_partition_rvz(replacement)
        with RVZReader(io.BytesIO(blob)) as reader:
            encrypted_sector = reader.read(0, BLOCK_TOTAL_SIZE)

        self.assertEqual(encrypted_sector, iso)
        decrypted_hash_block = _aes_cbc_decrypt(key, ZERO_IV, encrypted_sector[:BLOCK_HEADER_SIZE])
        self.assertEqual(decrypted_hash_block[:20], replacement)
        self.assertEqual(len(reader.read(0, GROUP_TOTAL_SIZE + GROUP_DATA_SIZE)), len(iso))


if __name__ == "__main__":
    unittest.main()
