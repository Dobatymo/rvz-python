"""Print duplicate disc hashes from a generated batch hashes.json file."""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, TextIO, Tuple, cast

DEFAULT_HASHES_JSON = Path("hash-compare") / "rvz-direct" / "hashes.json"
HASH_ALGORITHMS = ("sha1", "md5", "crc32")
Result = Dict[str, Any]
DuplicateGroup = Tuple[str, List[Result]]


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hashes-json", type=Path, default=DEFAULT_HASHES_JSON)
    parser.add_argument(
        "--algorithm",
        choices=HASH_ALGORITHMS,
        default="sha1",
        help="Hash used to identify duplicates (default: sha1).",
    )
    return parser.parse_args(argv)


def load_hash_results(path: Path) -> List[Result]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{os.fspath(path)} does not contain a result list")
    return [entry for entry in data if isinstance(entry, dict)]


def hash_value(result: Result, algorithm: str) -> Optional[str]:
    hashes = result.get("hashes", result.get("result_hashes", {}))
    if not isinstance(hashes, dict):
        return None
    value = cast(Dict[str, object], hashes).get(algorithm)
    if not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()


def result_label(result: Result) -> str:
    archive = str(result.get("archive", "<unknown archive>"))
    member = str(result.get("member", ""))
    if result.get("input_source") == "zip" and member:
        return f"{archive}!{member}"
    return archive


def find_duplicate_groups(results: Sequence[Result], algorithm: str) -> Tuple[List[DuplicateGroup], int]:
    by_hash: Dict[str, List[Result]] = {}
    usable_count = 0
    for result in results:
        if result.get("status") != "ok":
            continue
        value = hash_value(result, algorithm)
        if value is None:
            continue
        usable_count += 1
        by_hash.setdefault(value, []).append(result)

    groups = [(value, entries) for value, entries in by_hash.items() if len(entries) > 1]
    groups.sort(key=lambda group: group[0])
    return groups, usable_count


def print_duplicate_groups(
    groups: Sequence[DuplicateGroup],
    algorithm: str,
    result_count: int,
    usable_count: int,
    fileobj: TextIO = sys.stdout,
) -> None:
    algorithm_label = algorithm.upper()
    duplicate_result_count = sum(len(entries) for _, entries in groups)
    for index, (value, entries) in enumerate(groups):
        if index:
            print(file=fileobj)
        print(f"{algorithm_label} {value} ({len(entries)} results)", file=fileobj)
        for result in sorted(entries, key=lambda entry: result_label(entry).casefold()):
            print(f"  {result_label(result)}", file=fileobj)

    if groups:
        print(file=fileobj)
        print(
            f"Found {len(groups)} duplicate {algorithm_label} group(s) containing {duplicate_result_count} result(s).",
            file=fileobj,
        )
    else:
        print(f"No duplicate {algorithm_label} hashes found.", file=fileobj)
    print(
        f"Scanned {result_count} result(s); {usable_count} had usable {algorithm_label} hashes; "
        f"skipped {result_count - usable_count}.",
        file=fileobj,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parse_args(argv)
    try:
        results = load_hash_results(args.hashes_json)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"Failed to load {os.fspath(args.hashes_json)}: {exc}", file=sys.stderr)
        return 2

    groups, usable_count = find_duplicate_groups(results, args.algorithm)
    print_duplicate_groups(groups, args.algorithm, len(results), usable_count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
