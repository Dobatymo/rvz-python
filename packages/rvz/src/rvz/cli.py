"""Command line interface for the RVZ reader."""

import argparse
import contextlib
import sys
import zipfile
from typing import Iterator, Optional, Sequence

from .reader import RVZReader


@contextlib.contextmanager
def open_input(spec: str, padding_implementation: int = 1) -> Iterator[RVZReader]:
    if "!" in spec:
        archive_path, member = spec.split("!", 1)
        with zipfile.ZipFile(archive_path) as archive:
            zi = archive.getinfo(member)
            with archive.open(zi, "r") as fileobj:
                with RVZReader(fileobj, zi.file_size, padding_implementation) as reader:
                    yield reader
    else:
        with RVZReader(spec, padding_implementation=padding_implementation) as reader:
            yield reader


def add_input_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "input",
        help="RVZ path, or ZIP/member syntax as archive.zip!path/in/archive.rvz",
    )


def add_padding_implementation_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--padding-implementation",
        type=int,
        choices=[1, 2, 3, 4],
        default=1,
        help="RVZ padding generator to use: 1=original, 2=NumPy, 3=NumPy plus exact tuple cache, 4=CFFI C loop",
    )


def command_info(args: argparse.Namespace) -> None:
    with open_input(args.input) as reader:
        header = reader.disc_header
        print("type: rvz")
        print(f"disc_type: {header.disc_type_name} ({header.disc_type})")
        print(f"iso_size: {reader.iso_size}")
        print(f"compression: {header.compression_name} ({header.compression})")
        print(f"compression_level: {header.compression_level}")
        print(f"chunk_size: {header.chunk_size}")
        print(f"raw_data_entries: {len(reader.raw_data_entries)}")
        print(f"partition_entries: {len(reader.partition_entries)}")
        print(f"group_entries: {len(reader.group_entries)}")


def command_hash(args: argparse.Namespace) -> None:
    with open_input(args.input, args.padding_implementation) as reader:
        for algorithm in args.algorithm:
            print(f"{algorithm}: {reader.hash_iso(algorithm, args.block_size)}")


def command_extract(args: argparse.Namespace) -> None:
    with open_input(args.input, args.padding_implementation) as reader:
        reader.extract_iso(args.output, args.block_size)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rvz")
    subparsers = parser.add_subparsers(dest="command", required=True)

    info = subparsers.add_parser("info", help="print RVZ metadata")
    add_input_argument(info)
    info.set_defaults(func=command_info)

    hash_parser = subparsers.add_parser("hash", help="hash reconstructed ISO bytes")
    add_input_argument(hash_parser)
    hash_parser.add_argument(
        "-a",
        "--algorithm",
        action="append",
        default=None,
        help="hashlib algorithm name; may be passed more than once (default: sha1)",
    )
    hash_parser.add_argument("--block-size", type=int, default=None)
    add_padding_implementation_argument(hash_parser)
    hash_parser.set_defaults(func=command_hash)

    extract = subparsers.add_parser("extract", help="write reconstructed ISO bytes")
    add_input_argument(extract)
    extract.add_argument("output", help="destination ISO path")
    extract.add_argument("--block-size", type=int, default=None)
    add_padding_implementation_argument(extract)
    extract.set_defaults(func=command_extract)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "algorithm", None) is None:
        args.algorithm = ["sha1"]
    try:
        args.func(args)
    except Exception as exc:
        print(f"rvz: error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
