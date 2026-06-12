import hashlib
import struct
from typing import Tuple

import zstandard as zstd
from rvz.packing import generate_padding


def _compress_for_fixture(data: bytes, compression: int) -> bytes:
    if compression == 1:
        segment = struct.pack(">II", 0, len(data)) + data
        return segment + hashlib.sha1(segment).digest()
    if compression == 5:
        return zstd.ZstdCompressor(level=1).compress(data)
    raise AssertionError(f"unsupported fixture compression {compression}")


def build_minimal_rvz(compression: int = 5) -> Tuple[bytes, bytes]:
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
