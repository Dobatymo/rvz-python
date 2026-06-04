"""Reader for Dolphin RVZ disc images."""

from __future__ import annotations

import bz2
import hashlib
import io
import lzma
import os
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from typing import IO, Optional, Tuple, Union

import zstandard as zstd

from .packing import decode_rvz_packing
from .wii import (
    BLOCK_DATA_SIZE as WII_BLOCK_DATA_SIZE,
)
from .wii import (
    BLOCK_HEADER_SIZE as WII_BLOCK_HEADER_SIZE,
)
from .wii import (
    BLOCK_TOTAL_SIZE as WII_BLOCK_TOTAL_SIZE,
)
from .wii import (
    GROUP_DATA_SIZE as WII_GROUP_DATA_SIZE,
)
from .wii import (
    GROUP_TOTAL_SIZE as WII_GROUP_TOTAL_SIZE,
)
from .wii import (
    HashException,
)
from .wii import (
    encrypt_group as encrypt_wii_group,
)

RVZ_MAGIC = b"RVZ\x01"
FILE_HEADER_SIZE = 0x48
DISC_HEADER_PARSE_SIZE = 0xDC
DISC_HEADER_MIN_SIZE = DISC_HEADER_PARSE_SIZE - 7
DISC_PREFIX_SIZE = 0x80

COMPRESSION_NONE = 0
COMPRESSION_PURGE = 1
COMPRESSION_BZIP2 = 2
COMPRESSION_LZMA = 3
COMPRESSION_LZMA2 = 4
COMPRESSION_ZSTD = 5

DISC_TYPES = {
    0: "unknown",
    1: "gamecube",
    2: "wii",
}

COMPRESSION_NAMES = {
    COMPRESSION_NONE: "none",
    COMPRESSION_PURGE: "purge",
    COMPRESSION_BZIP2: "bzip2",
    COMPRESSION_LZMA: "lzma",
    COMPRESSION_LZMA2: "lzma2",
    COMPRESSION_ZSTD: "zstandard",
}

Source = Union[str, bytes, os.PathLike, IO[bytes]]
GroupCache = Tuple[Tuple[int, int, int], bytes]
PartitionGroupCache = Tuple[Tuple[int, int, int, int], "_PartitionGroupData"]
EncryptedWiiGroupCache = Tuple[Tuple[int, int], bytes]


class RVZError(Exception):
    """Base class for RVZ reader errors."""


class InvalidRVZError(RVZError):
    """Raised when an RVZ file is malformed or fails integrity checks."""


class UnsupportedRVZError(RVZError):
    """Raised when the RVZ uses a feature this reader does not implement yet."""


@dataclass(frozen=True)
class FileHeader:
    version: int
    version_compatible: int
    disc_header_size: int
    disc_header_hash: bytes
    iso_file_size: int
    rvz_file_size: int


@dataclass(frozen=True)
class DiscHeader:
    disc_type: int
    compression: int
    compression_level: int
    chunk_size: int
    disc_prefix: bytes
    partition_count: int
    partition_entry_size: int
    partition_entries_offset: int
    partition_entries_hash: bytes
    raw_data_count: int
    raw_data_entries_offset: int
    raw_data_entries_size: int
    group_count: int
    group_entries_offset: int
    group_entries_size: int
    compressor_data_size: int
    compressor_data: bytes

    @property
    def disc_type_name(self) -> str:
        return DISC_TYPES.get(self.disc_type, "unknown")

    @property
    def compression_name(self) -> str:
        return COMPRESSION_NAMES.get(self.compression, "unknown")


@dataclass(frozen=True)
class PartitionDataEntry:
    first_sector: int
    sector_count: int
    group_index: int
    group_count: int

    @property
    def start(self) -> int:
        return self.first_sector * WII_BLOCK_TOTAL_SIZE

    @property
    def end(self) -> int:
        return self.start + self.sector_count * WII_BLOCK_TOTAL_SIZE


@dataclass(frozen=True)
class PartitionEntry:
    key: bytes
    data_entries: tuple[PartitionDataEntry, PartitionDataEntry]


@dataclass(frozen=True)
class RawDataEntry:
    data_offset: int
    data_size: int
    group_index: int
    group_count: int

    @property
    def end(self) -> int:
        return self.data_offset + self.data_size

    @property
    def normalized_offset(self) -> int:
        return self.data_offset - (self.data_offset % WII_BLOCK_TOTAL_SIZE)

    @property
    def normalized_size(self) -> int:
        return self.data_size + (self.data_offset - self.normalized_offset)


@dataclass(frozen=True)
class GroupEntry:
    data_offset: int
    data_size: int
    is_compressed: bool
    rvz_packed_size: int


@dataclass(frozen=True)
class _DataInterval:
    start: int
    end: int
    kind: str
    index: int
    partition_data_index: int = 0


@dataclass(frozen=True)
class _PartitionGroupData:
    data: bytes
    exception_lists: tuple[tuple[HashException, ...], ...]


class RVZReader:
    """Read an RVZ image from a path or seekable binary file object."""

    def __init__(self, source: Source) -> None:
        self._owns_file: bool = False
        self._source_name: Optional[str] = getattr(source, "name", None)
        if isinstance(source, (str, bytes, os.PathLike)):
            path = os.fspath(source)
            self._source_name = os.fsdecode(path)
            self._file: IO[bytes] = open(path, "rb")  # noqa: SIM115
            self._owns_file = True
        else:
            self._file = source

        self._ensure_seekable()
        self._file_size: Optional[int] = self._cheap_file_size()
        self._group_cache: Optional[GroupCache] = None
        self._partition_group_cache: Optional[PartitionGroupCache] = None
        self._encrypted_wii_group_cache: Optional[EncryptedWiiGroupCache] = None

        try:
            self.file_header: FileHeader = self._read_file_header()
            self.disc_header: DiscHeader = self._read_disc_header()
            self.partition_entries: list[PartitionEntry] = self._read_partition_entries()
            self.raw_data_entries: list[RawDataEntry] = self._read_raw_data_entries()
            self.group_entries: list[GroupEntry] = self._read_group_entries()
            self._intervals: list[_DataInterval] = self._build_intervals()
        except Exception:
            if self._owns_file:
                self._file.close()
            raise

    @property
    def iso_size(self) -> int:
        return self.file_header.iso_file_size

    @property
    def chunk_size(self) -> int:
        return self.disc_header.chunk_size

    @property
    def source_name(self) -> Optional[str]:
        return self._source_name

    def close(self) -> None:
        if self._owns_file and not self._file.closed:
            self._file.close()

    def __enter__(self) -> RVZReader:
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
        self.close()
        return False

    def read(self, offset: int, size: int) -> bytes:
        """Read ISO bytes at *offset* without writing an ISO to disk."""

        if offset < 0 or size < 0:
            raise ValueError("offset and size must be non-negative")
        if offset >= self.iso_size or size == 0:
            return b""
        size = min(size, self.iso_size - offset)

        output = bytearray()
        while size:
            if offset < DISC_PREFIX_SIZE:
                count = min(DISC_PREFIX_SIZE - offset, size)
                output.extend(self.disc_header.disc_prefix[offset : offset + count])
                offset += count
                size -= count
                continue

            interval = self._find_interval(offset)
            if interval is None:
                raise InvalidRVZError(f"no RVZ data entry covers ISO offset 0x{offset:x}")

            count = min(interval.end - offset, size)
            if interval.kind == "raw":
                output.extend(self._read_raw_interval(interval.index, offset, count))
            elif interval.kind == "partition":
                output.extend(
                    self._read_partition_interval(interval.index, interval.partition_data_index, offset, count)
                )
            else:  # pragma: no cover - defensive guard
                raise InvalidRVZError(f"unknown data interval kind {interval.kind!r}")

            offset += count
            size -= count

        return bytes(output)

    def iter_iso(self, block_size: Optional[int] = None) -> Iterator[bytes]:
        """Yield reconstructed ISO bytes in order."""

        if block_size is None:
            block_size = max(self.chunk_size, io.DEFAULT_BUFFER_SIZE)
        if block_size <= 0:
            raise ValueError("block_size must be positive")

        offset = 0
        while offset < self.iso_size:
            chunk = self.read(offset, min(block_size, self.iso_size - offset))
            if not chunk:
                break
            yield chunk
            offset += len(chunk)

    def hash_iso(self, algorithm: str = "sha1", block_size: Optional[int] = None) -> str:
        """Hash the reconstructed ISO byte stream."""

        digest = hashlib.new(algorithm)
        for chunk in self.iter_iso(block_size):
            digest.update(chunk)
        return digest.hexdigest()

    def extract_iso(self, destination: Source, block_size: Optional[int] = None) -> None:
        """Write the reconstructed ISO byte stream to *destination*."""

        close_output = False
        if isinstance(destination, (str, bytes, os.PathLike)):
            output = open(os.fspath(destination), "wb")  # noqa: SIM115
            close_output = True
        else:
            output = destination

        try:
            for chunk in self.iter_iso(block_size):
                output.write(chunk)
        finally:
            if close_output:
                output.close()

    def _ensure_seekable(self) -> None:
        seekable = getattr(self._file, "seekable", None)
        if callable(seekable) and not seekable():
            raise ValueError("RVZReader requires a seekable binary file object")
        for attr in ("read", "seek"):
            if not hasattr(self._file, attr):
                raise ValueError("RVZReader requires a binary file object with read() and seek()")

    def _cheap_file_size(self) -> Optional[int]:
        if self._owns_file:
            return os.fstat(self._file.fileno()).st_size

        getbuffer = getattr(self._file, "getbuffer", None)
        if callable(getbuffer):
            return len(getbuffer())

        zip_original_size = getattr(self._file, "_orig_file_size", None)
        if isinstance(zip_original_size, int):
            return zip_original_size

        fileno = getattr(self._file, "fileno", None)
        if callable(fileno):
            try:
                return os.fstat(fileno()).st_size
            except (OSError, io.UnsupportedOperation):
                return None

        return None

    def _read_exact_at(self, offset: int, size: int) -> bytes:
        self._file.seek(offset)
        data = self._file.read(size)
        if len(data) != size:
            raise InvalidRVZError(f"unexpected EOF at file offset 0x{offset:x}")
        return data

    def _read_file_header(self) -> FileHeader:
        data = self._read_exact_at(0, FILE_HEADER_SIZE)
        if data[:4] != RVZ_MAGIC:
            raise InvalidRVZError("not an RVZ file")
        if hashlib.sha1(data[:52]).digest() != data[52:72]:
            raise InvalidRVZError("RVZ file header SHA-1 does not match")

        version, version_compatible, disc_header_size = struct.unpack_from(">III", data, 4)
        disc_header_hash = data[16:36]
        iso_file_size, rvz_file_size = struct.unpack_from(">QQ", data, 36)

        if self._file_size is not None and rvz_file_size != self._file_size:
            raise InvalidRVZError(
                f"RVZ file size header says {rvz_file_size} bytes, actual file is {self._file_size} bytes"
            )

        return FileHeader(
            version=version,
            version_compatible=version_compatible,
            disc_header_size=disc_header_size,
            disc_header_hash=disc_header_hash,
            iso_file_size=iso_file_size,
            rvz_file_size=rvz_file_size,
        )

    def _read_disc_header(self) -> DiscHeader:
        size = self.file_header.disc_header_size
        if size < DISC_HEADER_MIN_SIZE:
            raise InvalidRVZError("RVZ disc header is too small")

        data = self._read_exact_at(FILE_HEADER_SIZE, size)
        if hashlib.sha1(data).digest() != self.file_header.disc_header_hash:
            raise InvalidRVZError("RVZ disc header SHA-1 does not match")

        padded = data + b"\0" * max(0, DISC_HEADER_PARSE_SIZE - len(data))
        disc_type, compression, compression_level_u32, chunk_size = struct.unpack_from(">IIII", padded, 0)
        compressor_data_size = padded[212]
        compressor_data = padded[213 : 213 + 7]

        if compressor_data_size > 7 or size < DISC_HEADER_MIN_SIZE + compressor_data_size:
            raise InvalidRVZError("invalid RVZ compressor data size")

        if compression == COMPRESSION_ZSTD:
            compression_level = struct.unpack(">i", struct.pack(">I", compression_level_u32))[0]
        else:
            compression_level = compression_level_u32

        if compression > COMPRESSION_ZSTD:
            raise UnsupportedRVZError(f"unsupported RVZ compression type {compression}")

        self._validate_chunk_size(chunk_size)

        (
            partition_count,
            partition_entry_size,
            partition_entries_offset,
        ) = struct.unpack_from(">IIQ", padded, 144)
        partition_entries_hash = padded[160:180]
        (
            raw_data_count,
            raw_data_entries_offset,
            raw_data_entries_size,
            group_count,
            group_entries_offset,
            group_entries_size,
        ) = struct.unpack_from(">IQIIQI", padded, 180)

        return DiscHeader(
            disc_type=disc_type,
            compression=compression,
            compression_level=compression_level,
            chunk_size=chunk_size,
            disc_prefix=padded[16 : 16 + DISC_PREFIX_SIZE],
            partition_count=partition_count,
            partition_entry_size=partition_entry_size,
            partition_entries_offset=partition_entries_offset,
            partition_entries_hash=partition_entries_hash,
            raw_data_count=raw_data_count,
            raw_data_entries_offset=raw_data_entries_offset,
            raw_data_entries_size=raw_data_entries_size,
            group_count=group_count,
            group_entries_offset=group_entries_offset,
            group_entries_size=group_entries_size,
            compressor_data_size=compressor_data_size,
            compressor_data=compressor_data[:compressor_data_size],
        )

    def _validate_chunk_size(self, chunk_size: int) -> None:
        if chunk_size < WII_BLOCK_TOTAL_SIZE:
            raise InvalidRVZError("RVZ chunk size must be at least 32 KiB")
        if chunk_size < WII_GROUP_TOTAL_SIZE:
            if chunk_size & (chunk_size - 1):
                raise InvalidRVZError("RVZ chunk sizes smaller than 2 MiB must be powers of two")
        elif chunk_size % WII_GROUP_TOTAL_SIZE:
            raise InvalidRVZError("RVZ chunk sizes at least 2 MiB must be multiples of 2 MiB")

    def _read_partition_entries(self) -> list[PartitionEntry]:
        header = self.disc_header
        total_size = header.partition_count * header.partition_entry_size
        if total_size == 0:
            if header.partition_entries_hash != hashlib.sha1(b"").digest():
                raise InvalidRVZError("empty partition table SHA-1 does not match")
            return []

        data = self._read_exact_at(header.partition_entries_offset, total_size)
        if hashlib.sha1(data).digest() != header.partition_entries_hash:
            raise InvalidRVZError("partition table SHA-1 does not match")

        entries: list[PartitionEntry] = []
        copy_size = min(header.partition_entry_size, 48)
        for index in range(header.partition_count):
            start = index * header.partition_entry_size
            entry_data = data[start : start + copy_size] + b"\0" * (48 - copy_size)
            key = entry_data[:16]
            first = PartitionDataEntry(*struct.unpack_from(">IIII", entry_data, 16))
            second = PartitionDataEntry(*struct.unpack_from(">IIII", entry_data, 32))
            entries.append(PartitionEntry(key=key, data_entries=(first, second)))
        return entries

    def _read_raw_data_entries(self) -> list[RawDataEntry]:
        header = self.disc_header
        expected_size = header.raw_data_count * 24
        if expected_size == 0:
            return []
        data = self._read_compressed_blob(
            header.raw_data_entries_offset,
            header.raw_data_entries_size,
            expected_size,
            header.compression,
        )
        entries: list[RawDataEntry] = []
        for offset in range(0, len(data), 24):
            entries.append(RawDataEntry(*struct.unpack_from(">QQII", data, offset)))
        return entries

    def _read_group_entries(self) -> list[GroupEntry]:
        header = self.disc_header
        expected_size = header.group_count * 12
        data = self._read_compressed_blob(
            header.group_entries_offset,
            header.group_entries_size,
            expected_size,
            header.compression,
        )
        entries: list[GroupEntry] = []
        for offset in range(0, len(data), 12):
            data_offset4, data_size, rvz_packed_size = struct.unpack_from(">III", data, offset)
            entries.append(
                GroupEntry(
                    data_offset=data_offset4 << 2,
                    data_size=data_size & 0x7FFFFFFF,
                    is_compressed=bool(data_size & 0x80000000),
                    rvz_packed_size=rvz_packed_size,
                )
            )
        return entries

    def _build_intervals(self) -> list[_DataInterval]:
        intervals: list[_DataInterval] = []
        for index, entry in enumerate(self.raw_data_entries):
            if entry.data_size:
                intervals.append(_DataInterval(entry.data_offset, entry.end, "raw", index))

        for partition_index, partition in enumerate(self.partition_entries):
            for data_index, entry in enumerate(partition.data_entries):
                if entry.sector_count:
                    intervals.append(_DataInterval(entry.start, entry.end, "partition", partition_index, data_index))

        intervals.sort(key=lambda item: item.start)
        last_end = 0
        for interval in intervals:
            if interval.start < last_end:
                raise InvalidRVZError("RVZ data entries overlap")
            last_end = interval.end

        return intervals

    def _find_interval(self, offset: int) -> Optional[_DataInterval]:
        for interval in self._intervals:
            if interval.start <= offset < interval.end:
                return interval
        return None

    def _read_raw_interval(self, raw_index: int, offset: int, size: int) -> bytes:
        raw_entry = self.raw_data_entries[raw_index]
        normalized_offset = raw_entry.normalized_offset
        normalized_size = raw_entry.normalized_size
        chunk_size = self.chunk_size
        output = bytearray()

        while size:
            relative = offset - normalized_offset
            group_in_raw = relative // chunk_size
            if group_in_raw >= raw_entry.group_count:
                raise InvalidRVZError("raw data entry references too few groups")

            group_offset = group_in_raw * chunk_size
            group_size = min(chunk_size, normalized_size - group_offset)
            offset_in_group = relative - group_offset
            count = min(group_size - offset_in_group, size)
            group_data = self._decode_group(raw_entry.group_index + group_in_raw, group_size, group_offset)
            output.extend(group_data[offset_in_group : offset_in_group + count])
            offset += count
            size -= count

        return bytes(output)

    def _read_partition_interval(
        self, partition_index: int, partition_data_index: int, offset: int, size: int
    ) -> bytes:
        partition = self.partition_entries[partition_index]
        partition_data_offset = partition.data_entries[0].first_sector * WII_BLOCK_TOTAL_SIZE
        entry = partition.data_entries[partition_data_index]

        if offset < entry.start or offset + size > entry.end:
            raise InvalidRVZError("partition read is outside the partition data entry")

        relative_offset = offset - partition_data_offset
        output = bytearray()
        while size:
            encrypted_group_offset = relative_offset - (relative_offset % WII_GROUP_TOTAL_SIZE)
            offset_in_group = relative_offset - encrypted_group_offset
            count = min(WII_GROUP_TOTAL_SIZE - offset_in_group, size)
            group = self._encrypt_partition_group(partition_index, encrypted_group_offset)

            output.extend(group[offset_in_group : offset_in_group + count])
            relative_offset += count
            size -= count

        return bytes(output)

    def _encrypt_partition_group(self, partition_index: int, encrypted_group_offset: int) -> bytes:
        cache_key = (partition_index, encrypted_group_offset)
        if self._encrypted_wii_group_cache is not None and self._encrypted_wii_group_cache[0] == cache_key:
            return self._encrypted_wii_group_cache[1]

        partition = self.partition_entries[partition_index]
        decrypted_group_offset = encrypted_group_offset // WII_GROUP_TOTAL_SIZE * WII_GROUP_DATA_SIZE
        total_decrypted_size = self._partition_total_sectors(partition) * WII_BLOCK_DATA_SIZE

        exceptions: list[HashException] = []
        if decrypted_group_offset < total_decrypted_size:
            decrypted_size = min(WII_GROUP_DATA_SIZE, total_decrypted_size - decrypted_group_offset)
            decrypted = self._read_partition_decrypted(
                partition_index, decrypted_group_offset, decrypted_size, exceptions
            )
        else:
            decrypted = b""

        decrypted += b"\0" * (WII_GROUP_DATA_SIZE - len(decrypted))
        data_blocks = [
            decrypted[offset : offset + WII_BLOCK_DATA_SIZE]
            for offset in range(0, WII_GROUP_DATA_SIZE, WII_BLOCK_DATA_SIZE)
        ]
        encrypted = encrypt_wii_group(data_blocks, partition.key, exceptions)

        self._encrypted_wii_group_cache = (cache_key, encrypted)
        return encrypted

    def _read_partition_decrypted(
        self,
        partition_index: int,
        offset: int,
        size: int,
        exceptions: Optional[list[HashException]] = None,
    ) -> bytes:
        partition = self.partition_entries[partition_index]
        partition_first_sector = partition.data_entries[0].first_sector

        output = bytearray()
        while size:
            matched = False
            for entry in partition.data_entries:
                if entry.sector_count == 0:
                    continue

                data_offset = (entry.first_sector - partition_first_sector) * WII_BLOCK_DATA_SIZE
                data_size = entry.sector_count * WII_BLOCK_DATA_SIZE
                if data_offset + data_size <= offset:
                    continue
                if offset < data_offset:
                    raise InvalidRVZError("Wii partition data entries have an unsupported gap")

                count = min(data_offset + data_size - offset, size)
                output.extend(
                    self._read_partition_decrypted_entry(entry, data_offset, data_size, offset, count, exceptions)
                )
                offset += count
                size -= count
                matched = True
                break

            if not matched:
                raise InvalidRVZError("Wii partition decrypted read is outside stored data entries")

        return bytes(output)

    def _read_partition_decrypted_entry(
        self,
        entry: PartitionDataEntry,
        data_offset: int,
        data_size: int,
        offset: int,
        size: int,
        exceptions: Optional[list[HashException]],
    ) -> bytes:
        chunk_size = self.chunk_size * WII_BLOCK_DATA_SIZE // WII_BLOCK_TOTAL_SIZE
        exception_lists = max(1, chunk_size // WII_GROUP_DATA_SIZE)
        skipped_data = data_offset % WII_BLOCK_DATA_SIZE
        normalized_offset = data_offset - skipped_data
        normalized_size = data_size + skipped_data

        output = bytearray()
        start_group_index = (offset - normalized_offset) // chunk_size
        for group_in_entry in range(start_group_index, entry.group_count):
            if size == 0:
                break

            group_offset_in_data = group_in_entry * chunk_size
            offset_in_group = offset - group_offset_in_data - normalized_offset
            group_size = min(chunk_size, normalized_size - group_offset_in_data)
            count = min(group_size - offset_in_group, size)
            total_group_index = entry.group_index + group_in_entry
            group = self._decode_partition_group(total_group_index, group_size, group_offset_in_data, exception_lists)

            if exceptions is not None:
                exception_list_index = offset_in_group // WII_GROUP_DATA_SIZE
                additional_offset = (
                    group_offset_in_data % WII_GROUP_DATA_SIZE // WII_BLOCK_DATA_SIZE * WII_BLOCK_HEADER_SIZE
                )
                for exception_offset, digest in group.exception_lists[exception_list_index]:
                    exceptions.append((exception_offset + additional_offset, digest))

            output.extend(group.data[offset_in_group : offset_in_group + count])
            offset += count
            size -= count

        if size:
            raise InvalidRVZError("Wii partition data entry references too few groups")
        return bytes(output)

    def _partition_total_sectors(self, partition: PartitionEntry) -> int:
        first, second = partition.data_entries
        if second.sector_count:
            return second.first_sector - first.first_sector + second.sector_count
        return first.sector_count

    def _decode_group(self, group_index: int, output_size: int, data_offset: int) -> bytes:
        cache_key = (group_index, output_size, data_offset)
        if self._group_cache is not None and self._group_cache[0] == cache_key:
            return self._group_cache[1]

        if group_index >= len(self.group_entries):
            raise InvalidRVZError(f"group index {group_index} is out of range")

        group = self.group_entries[group_index]
        if group.data_size == 0:
            data = b"\0" * output_size
        else:
            stored = self._read_exact_at(group.data_offset, group.data_size)
            compression = self.disc_header.compression if group.is_compressed else COMPRESSION_NONE
            unpacked_size = group.rvz_packed_size or output_size
            data = self._decompress(stored, compression, unpacked_size)
            if group.rvz_packed_size:
                data = decode_rvz_packing(data, output_size, data_offset)

        if len(data) != output_size:
            raise InvalidRVZError(f"group {group_index} decoded to {len(data)} bytes, expected {output_size}")

        self._group_cache = (cache_key, data)
        return data

    def _decode_partition_group(
        self, group_index: int, output_size: int, data_offset: int, exception_lists: int
    ) -> _PartitionGroupData:
        cache_key = (group_index, output_size, data_offset, exception_lists)
        if self._partition_group_cache is not None and self._partition_group_cache[0] == cache_key:
            return self._partition_group_cache[1]

        if group_index >= len(self.group_entries):
            raise InvalidRVZError(f"group index {group_index} is out of range")

        group = self.group_entries[group_index]
        if group.data_size == 0:
            decoded = _PartitionGroupData(
                data=b"\0" * output_size,
                exception_lists=tuple(() for _ in range(exception_lists)),
            )
        else:
            stored = self._read_exact_at(group.data_offset, group.data_size)
            compression = self.disc_header.compression if group.is_compressed else COMPRESSION_NONE
            if compression == COMPRESSION_PURGE:
                parsed_exception_lists, exceptions_size = self._parse_hash_exception_lists(
                    stored, exception_lists, align_last=True
                )
                data = self._decompress_purge(
                    stored[exceptions_size:],
                    group.rvz_packed_size or output_size,
                    hash_prefix=stored[:exceptions_size],
                )
            else:
                payload = self._decompress_unknown(stored, compression)
                parsed_exception_lists, exceptions_size = self._parse_hash_exception_lists(
                    payload, exception_lists, align_last=compression == COMPRESSION_NONE
                )
                data = payload[exceptions_size:]
            if group.rvz_packed_size:
                if len(data) != group.rvz_packed_size:
                    raise InvalidRVZError(
                        f"group {group_index} decoded to {len(data)} RVZ-packed bytes, expected {group.rvz_packed_size}"
                    )
                data = decode_rvz_packing(data, output_size, data_offset)
            elif len(data) != output_size:
                raise InvalidRVZError(f"group {group_index} decoded to {len(data)} bytes, expected {output_size}")

            decoded = _PartitionGroupData(data=data, exception_lists=parsed_exception_lists)

        self._partition_group_cache = (cache_key, decoded)
        return decoded

    def _read_compressed_blob(self, offset: int, compressed_size: int, expected_size: int, compression: int) -> bytes:
        if compressed_size == 0 and expected_size == 0:
            return b""
        data = self._read_exact_at(offset, compressed_size)
        return self._decompress(data, compression, expected_size)

    def _decompress(self, data: bytes, compression: int, expected_size: int) -> bytes:
        if compression == COMPRESSION_NONE:
            output = data
        elif compression == COMPRESSION_PURGE:
            output = self._decompress_purge(data, expected_size)
        elif compression == COMPRESSION_BZIP2:
            output = bz2.decompress(data)
        elif compression == COMPRESSION_LZMA:
            output = lzma.decompress(data, format=lzma.FORMAT_RAW, filters=[self._lzma_filter(False)])
        elif compression == COMPRESSION_LZMA2:
            output = lzma.decompress(data, format=lzma.FORMAT_RAW, filters=[self._lzma_filter(True)])
        elif compression == COMPRESSION_ZSTD:
            output = zstd.ZstdDecompressor().decompress(data, max_output_size=expected_size)
        else:
            raise UnsupportedRVZError(f"unsupported RVZ compression type {compression}")

        if len(output) != expected_size:
            raise InvalidRVZError(f"decompressed {len(output)} bytes, expected {expected_size}")
        return output

    def _decompress_unknown(self, data: bytes, compression: int) -> bytes:
        if compression == COMPRESSION_NONE:
            return data
        if compression == COMPRESSION_PURGE:
            raise UnsupportedRVZError("PURGE decompression requires a known output size")
        if compression == COMPRESSION_BZIP2:
            return bz2.decompress(data)
        if compression == COMPRESSION_LZMA:
            return lzma.decompress(data, format=lzma.FORMAT_RAW, filters=[self._lzma_filter(False)])
        if compression == COMPRESSION_LZMA2:
            return lzma.decompress(data, format=lzma.FORMAT_RAW, filters=[self._lzma_filter(True)])
        if compression == COMPRESSION_ZSTD:
            with zstd.ZstdDecompressor().stream_reader(io.BytesIO(data)) as reader:
                return reader.read()
        raise UnsupportedRVZError(f"unsupported RVZ compression type {compression}")

    def _decompress_purge(self, data: bytes, expected_size: int, hash_prefix: bytes = b"") -> bytes:
        digest_size = hashlib.sha1().digest_size
        if len(data) < digest_size:
            raise InvalidRVZError("truncated PURGE data")

        payload = data[:-digest_size]
        expected_hash = data[-digest_size:]
        if hashlib.sha1(hash_prefix + payload).digest() != expected_hash:
            raise InvalidRVZError("PURGE SHA-1 does not match")

        output = bytearray(expected_size)
        position = 0
        last_end = 0
        while position < len(payload):
            if position + 8 > len(payload):
                raise InvalidRVZError("truncated PURGE segment header")

            offset, size = struct.unpack_from(">II", payload, position)
            position += 8
            end = offset + size
            if offset < last_end or end > expected_size:
                raise InvalidRVZError("invalid PURGE segment range")
            if position + size > len(payload):
                raise InvalidRVZError("truncated PURGE segment data")

            output[offset:end] = payload[position : position + size]
            position += size
            last_end = end

        return bytes(output)

    def _parse_hash_exception_lists(
        self, data: bytes, exception_lists: int, align_last: bool
    ) -> tuple[tuple[tuple[HashException, ...], ...], int]:
        position = 0
        parsed_lists: list[tuple[HashException, ...]] = []
        for list_index in range(exception_lists):
            if position + 2 > len(data):
                raise InvalidRVZError("truncated Wii hash exception list")

            exception_count = struct.unpack_from(">H", data, position)[0]
            position += 2
            exceptions: list[HashException] = []
            for _ in range(exception_count):
                if position + 22 > len(data):
                    raise InvalidRVZError("truncated Wii hash exception entry")
                exceptions.append((struct.unpack_from(">H", data, position)[0], data[position + 2 : position + 22]))
                position += 22

            parsed_lists.append(tuple(exceptions))
            if align_last and list_index == exception_lists - 1:
                position = (position + 3) & ~3

        return tuple(parsed_lists), position

    def _lzma_filter(self, lzma2: bool) -> dict[str, int]:
        data = self.disc_header.compressor_data
        if lzma2:
            if len(data) != 1:
                raise InvalidRVZError("LZMA2 RVZ compressor data must be 1 byte")
            prop = data[0]
            if prop > 40:
                raise UnsupportedRVZError("unsupported RVZ LZMA2 dictionary property")
            dictionary_size = 0xFFFFFFFF if prop == 40 else (2 | (prop & 1)) << ((prop // 2) + 11)
            return {"id": lzma.FILTER_LZMA2, "dict_size": dictionary_size}

        if len(data) != 5:
            raise InvalidRVZError("LZMA RVZ compressor data must be 5 bytes")
        prop = data[0]
        if prop >= 9 * 5 * 5:
            raise UnsupportedRVZError("unsupported RVZ LZMA property byte")
        lc = prop % 9
        prop //= 9
        pb = prop // 5
        lp = prop % 5
        dictionary_size = struct.unpack("<I", data[1:5])[0]
        return {
            "id": lzma.FILTER_LZMA1,
            "dict_size": dictionary_size,
            "lc": lc,
            "lp": lp,
            "pb": pb,
        }


def open_rvz(source: Source) -> RVZReader:
    return RVZReader(source)
