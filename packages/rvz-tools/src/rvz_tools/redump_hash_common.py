"""Shared helpers for Redump RVZ hash batch tools."""

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
import zipfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import IO, BinaryIO, Dict, Iterable, List, Optional, Tuple, cast

from rvz.reader import RVZReader

STANDARD_HASHES = ("crc32", "sha1")
DEFAULT_SPOOL_SIZE = 1425760 * 1024  # exact size of GameCube Game Disc image
SUPPORTED_DISC_SUFFIXES = (".rvz", ".iso", ".gcm")


@dataclass(frozen=True)
class DiscInput:
    archive: Path
    member: str
    index: int
    size: int
    disc_type: str
    source: str


def elapsed_seconds(started: float) -> float:
    return round(time.monotonic() - started, 3)


def disc_type_from_name(name: str) -> Optional[str]:
    suffix = Path(name).suffix.lower()
    if suffix in SUPPORTED_DISC_SUFFIXES:
        return suffix[1:]
    return None


def iter_disc_inputs(root: Path) -> Iterable[DiscInput]:
    index = 0
    paths = [root] if root.is_file() else sorted(root.rglob("*"), key=lambda path: str(path).casefold())
    for path in paths:
        if path.is_dir():
            continue

        if path.suffix.lower() == ".zip":
            with zipfile.ZipFile(path) as zip_file:
                for info in zip_file.infolist():
                    disc_type = disc_type_from_name(info.filename)
                    if info.is_dir() or disc_type is None:
                        continue
                    index += 1
                    yield DiscInput(
                        archive=path,
                        member=info.filename,
                        index=index,
                        size=info.file_size,
                        disc_type=disc_type,
                        source="zip",
                    )
            continue

        disc_type = disc_type_from_name(path.name)
        if disc_type is not None:
            index += 1
            yield DiscInput(
                archive=path,
                member=path.name,
                index=index,
                size=path.stat().st_size,
                disc_type=disc_type,
                source="raw",
            )


def safe_name(member: DiscInput) -> str:
    stem = Path(member.member).name
    safe_stem = "".join(char if char.isalnum() or char in " ._-" else "_" for char in stem)
    return f"{member.index:03d}-{safe_stem}"


def extract_input(member: DiscInput, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("wb") as target:
        if member.source == "raw":
            with member.archive.open("rb") as source:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            return

        with zipfile.ZipFile(member.archive) as zip_file:
            with zip_file.open(member.member) as source:
                shutil.copyfileobj(source, target, length=1024 * 1024)


def parse_default_verify_output(output: str) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    for line in output.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        normalized = key.strip().lower()
        if normalized in {"crc32", "sha1"}:
            hashes[normalized] = value.strip().lower()
    return hashes


def run_dolphin_command(command: List[str], timeout: int = 3600) -> str:
    completed = subprocess.run(  # noqa: S603 - DolphinTool path and arguments are supplied by batch config.
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return completed.stdout.strip()


def dolphin_hashes(
    dolphin_tool: Path, dolphin_user: Path, rvz_path: Path, timeout: int, include_md5: bool
) -> Dict[str, str]:
    dolphin_user.mkdir(parents=True, exist_ok=True)
    base_command = [str(dolphin_tool), "verify", "-u", str(dolphin_user), "-i", str(rvz_path)]

    hashes = parse_default_verify_output(run_dolphin_command(base_command, timeout))
    if include_md5:
        hashes["md5"] = run_dolphin_command(
            base_command[:2] + ["-u", str(dolphin_user), "-a", "md5", "-i", str(rvz_path)], timeout
        )
    return hashes


def binary_hashes_from_fileobj(fileobj: IO[bytes], include_md5: bool) -> Dict[str, str]:
    crc32_value = 0
    md5 = hashlib.md5() if include_md5 else None
    sha1 = hashlib.sha1()

    while True:
        chunk = fileobj.read(1024 * 1024)
        if not chunk:
            break
        crc32_value = zlib.crc32(chunk, crc32_value)
        if md5 is not None:
            md5.update(chunk)
        sha1.update(chunk)

    hashes = {
        "crc32": f"{crc32_value & 0xFFFFFFFF:08x}",
        "sha1": sha1.hexdigest(),
    }
    if md5 is not None:
        hashes["md5"] = md5.hexdigest()
    return hashes


def rvz_hashes_from_reader(reader: RVZReader, include_md5: bool) -> Dict[str, str]:
    crc32_value = 0
    md5 = hashlib.md5() if include_md5 else None
    sha1 = hashlib.sha1()

    for chunk in reader.iter_iso():
        crc32_value = zlib.crc32(chunk, crc32_value)
        if md5 is not None:
            md5.update(chunk)
        sha1.update(chunk)

    hashes = {
        "crc32": f"{crc32_value & 0xFFFFFFFF:08x}",
        "sha1": sha1.hexdigest(),
    }
    if md5 is not None:
        hashes["md5"] = md5.hexdigest()
    return hashes


def hash_rvz_input(
    member: DiscInput, work_dir: Path, spool_zip_member: bool, spool_memory_limit: int, include_md5: bool
) -> Tuple[Dict[str, str], Dict[str, object]]:
    started = time.monotonic()
    timings: Dict[str, object] = {}

    if member.source == "raw":
        read_started = time.monotonic()
        with member.archive.open("rb") as fileobj:
            with RVZReader(fileobj, member.size) as reader:
                hashes = rvz_hashes_from_reader(reader, include_md5)
        timings["rvz_reader_seconds"] = elapsed_seconds(read_started)
        timings["rvz_total_seconds"] = elapsed_seconds(started)
        return hashes, timings

    with zipfile.ZipFile(member.archive) as zip_file:
        with zip_file.open(member.member) as source:
            if not spool_zip_member:
                read_started = time.monotonic()
                with RVZReader(source, member.size) as reader:
                    hashes = rvz_hashes_from_reader(reader, include_md5)
                timings["rvz_reader_seconds"] = elapsed_seconds(read_started)
                timings["rvz_total_seconds"] = elapsed_seconds(started)
                return hashes, timings

            work_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.SpooledTemporaryFile(
                max_size=spool_memory_limit, mode="w+b", dir=os.fspath(work_dir)
            ) as spooled:
                spooled_binary = cast(BinaryIO, spooled)
                spool_started = time.monotonic()
                shutil.copyfileobj(source, spooled_binary, length=1024 * 1024)
                timings["zip_spool_seconds"] = elapsed_seconds(spool_started)
                timings["zip_spooled_to_disk"] = getattr(spooled_binary, "_rolled", None)

                spooled_binary.seek(0)
                read_started = time.monotonic()
                with RVZReader(spooled_binary, member.size) as reader:
                    hashes = rvz_hashes_from_reader(reader, include_md5)
                timings["rvz_reader_seconds"] = elapsed_seconds(read_started)
                timings["rvz_total_seconds"] = elapsed_seconds(started)
                return hashes, timings

    raise ValueError(f"ZIP member not found: {member.member}")


def hash_plain_input(
    member: DiscInput, work_dir: Path, spool_zip_member: bool, spool_memory_limit: int, include_md5: bool
) -> Tuple[Dict[str, str], Dict[str, object]]:
    started = time.monotonic()
    timings: Dict[str, object] = {}

    if member.source == "raw":
        read_started = time.monotonic()
        with member.archive.open("rb") as fileobj:
            hashes = binary_hashes_from_fileobj(fileobj, include_md5)
        timings["rvz_reader_seconds"] = elapsed_seconds(read_started)
        timings["rvz_total_seconds"] = elapsed_seconds(started)
        return hashes, timings

    with zipfile.ZipFile(member.archive) as zip_file:
        with zip_file.open(member.member) as source:
            if not spool_zip_member:
                read_started = time.monotonic()
                hashes = binary_hashes_from_fileobj(source, include_md5)
                timings["rvz_reader_seconds"] = elapsed_seconds(read_started)
                timings["rvz_total_seconds"] = elapsed_seconds(started)
                return hashes, timings

            work_dir.mkdir(parents=True, exist_ok=True)
            with tempfile.SpooledTemporaryFile(
                max_size=spool_memory_limit, mode="w+b", dir=os.fspath(work_dir)
            ) as spooled:
                spooled_binary = cast(BinaryIO, spooled)
                spool_started = time.monotonic()
                shutil.copyfileobj(source, spooled_binary, length=1024 * 1024)
                timings["zip_spool_seconds"] = elapsed_seconds(spool_started)
                timings["zip_spooled_to_disk"] = getattr(spooled_binary, "_rolled", None)

                spooled_binary.seek(0)
                read_started = time.monotonic()
                hashes = binary_hashes_from_fileobj(spooled_binary, include_md5)
                timings["rvz_reader_seconds"] = elapsed_seconds(read_started)
                timings["rvz_total_seconds"] = elapsed_seconds(started)
                return hashes, timings

    raise ValueError(f"ZIP member not found: {member.member}")


def hash_disc_input(
    member: DiscInput, work_dir: Path, spool_zip_member: bool, spool_memory_limit: int, include_md5: bool
) -> Tuple[Dict[str, str], Dict[str, object]]:
    if member.disc_type == "rvz":
        return hash_rvz_input(member, work_dir, spool_zip_member, spool_memory_limit, include_md5)
    return hash_plain_input(member, work_dir, spool_zip_member, spool_memory_limit, include_md5)
