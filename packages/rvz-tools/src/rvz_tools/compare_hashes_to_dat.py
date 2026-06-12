"""Compare one hash batch report against Logiqx DAT files."""

import argparse
import csv
import datetime as dt
import json
import sys
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, TextIO, Tuple, cast

from rich import box
from rich.console import Console
from rich.table import Table

DEFAULT_DAT_DIR = Path("datfiles")
DEFAULT_HASHES_JSON = Path("hash-compare") / "rvz-direct" / "hashes.json"
DEFAULT_ALGORITHMS = ("crc32", "sha1")
OPTIONAL_ALGORITHMS = ("md5",)
Result = Dict[str, Any]
DatNameMap = Dict[str, List["DatEntry"]]


@dataclass(frozen=True)
class DatEntry:
    dat_name: str
    dat_path: str
    game_name: str
    rom_name: str
    size: str
    hashes: Dict[str, str]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hashes-json", type=Path, default=DEFAULT_HASHES_JSON)
    parser.add_argument(
        "--dat-dir",
        type=Path,
        default=DEFAULT_DAT_DIR,
        help="Directory containing DAT files. Defaults to datfiles; all top-level *.dat files are loaded.",
    )
    parser.add_argument(
        "--dat",
        type=Path,
        action="append",
        default=None,
        help="Additional DAT file to load; may be passed more than once.",
    )
    parser.add_argument("--include-md5", action="store_true")
    parser.add_argument("--output-json", type=Path, default=None)
    parser.add_argument("--output-csv", type=Path, default=None)
    parser.add_argument("--output-text", type=Path, default=None)
    return parser.parse_args()


def print_progress(message: str, fileobj: TextIO = sys.stdout) -> None:
    print(message, flush=True, file=fileobj)


def load_hash_results(path: Path) -> List[Result]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} does not contain a result list")
    return [entry for entry in data if isinstance(entry, dict)]


def normalize_disc_name(name: str) -> str:
    path_name = name.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    return Path(path_name).stem.casefold()


def dat_hashes_from_rom(rom: ET.Element) -> Dict[str, str]:
    hashes: Dict[str, str] = {}
    crc = rom.get("crc")
    if crc:
        hashes["crc32"] = crc.lower()
    for algorithm in ("md5", "sha1"):
        value = rom.get(algorithm)
        if value:
            hashes[algorithm] = value.lower()
    return hashes


def load_dat_entries(path: Path) -> List[DatEntry]:
    root = ET.parse(path).getroot()  # noqa: S314 - The tool compares local Redump DAT files.
    header = root.find("header")
    dat_name = header.findtext("name", path.name) if header is not None else path.name
    entries: List[DatEntry] = []
    for game in list(root.findall("game")) + list(root.findall("machine")):
        game_name = game.get("name", "")
        for rom in game.findall("rom"):
            rom_name = rom.get("name", "")
            if not rom_name:
                continue
            entries.append(
                DatEntry(
                    dat_name=dat_name,
                    dat_path=str(path),
                    game_name=game_name,
                    rom_name=rom_name,
                    size=rom.get("size", ""),
                    hashes=dat_hashes_from_rom(rom),
                )
            )
    return entries


def load_all_dat_entries(paths: Iterable[Path]) -> List[DatEntry]:
    entries: List[DatEntry] = []
    for path in paths:
        entries.extend(load_dat_entries(path))
    return entries


def discover_dat_paths(dat_dir: Path, explicit_paths: Optional[Iterable[Path]] = None) -> Tuple[Path, ...]:
    paths = sorted(
        (path for path in dat_dir.glob("*.dat") if path.is_file()),
        key=lambda path: (path.name.casefold(), str(path)),
    )
    if explicit_paths is not None:
        paths.extend(explicit_paths)
    return tuple(dict.fromkeys(paths))


def add_to_map(mapping: DatNameMap, key: str, entry: DatEntry) -> None:
    mapping.setdefault(key, []).append(entry)


def build_dat_maps(entries: Iterable[DatEntry]) -> Tuple[DatNameMap, DatNameMap]:
    by_name: DatNameMap = {}
    by_sha1: DatNameMap = {}
    for entry in entries:
        add_to_map(by_name, normalize_disc_name(entry.rom_name), entry)
        sha1 = entry.hashes.get("sha1")
        if sha1:
            add_to_map(by_sha1, sha1, entry)
    return by_name, by_sha1


def hash_value(hashes: object, algorithm: str) -> Optional[str]:
    if not isinstance(hashes, dict):
        return None
    hash_map = cast(Dict[str, object], hashes)
    value = hash_map.get(algorithm)
    if not isinstance(value, str) or not value:
        return None
    return value.lower()


def result_hashes(result: Result) -> object:
    return result.get("hashes", result.get("result_hashes", {}))


def result_match_keys(result: Result) -> List[str]:
    keys: List[str] = []
    member = result.get("member")
    if isinstance(member, str) and member:
        keys.append(normalize_disc_name(member))
    archive = result.get("archive")
    if isinstance(archive, str) and archive:
        keys.append(normalize_disc_name(archive))
    return list(dict.fromkeys(keys))


def unique_entries(entries: Iterable[DatEntry]) -> List[DatEntry]:
    unique: Dict[Tuple[str, str, str], DatEntry] = {}
    for entry in entries:
        unique[(entry.dat_path, entry.game_name, entry.rom_name)] = entry
    return list(unique.values())


def find_dat_entry(
    result: Result, by_name: DatNameMap, by_sha1: DatNameMap
) -> Tuple[Optional[DatEntry], str, List[str]]:
    candidates: List[DatEntry] = []
    for key in result_match_keys(result):
        candidates.extend(by_name.get(key, []))
    candidates = unique_entries(candidates)

    result_sha1 = hash_value(result_hashes(result), "sha1")
    if len(candidates) == 1:
        return candidates[0], "name", []

    if len(candidates) > 1 and result_sha1:
        sha1_candidates = [entry for entry in candidates if entry.hashes.get("sha1") == result_sha1]
        if len(sha1_candidates) == 1:
            return sha1_candidates[0], "name+sha1", []
        return None, "", [f"ambiguous DAT name match: {len(candidates)} candidates"]

    if len(candidates) > 1:
        return None, "", [f"ambiguous DAT name match: {len(candidates)} candidates"]

    if result_sha1:
        sha1_candidates = by_sha1.get(result_sha1, [])
        if len(sha1_candidates) == 1:
            return sha1_candidates[0], "sha1", []
        if len(sha1_candidates) > 1:
            return None, "", [f"ambiguous DAT SHA1 match: {len(sha1_candidates)} candidates"]

    return None, "", ["no matching DAT entry"]


def compare_hashes(result: Result, entry: DatEntry, algorithms: Tuple[str, ...]) -> Tuple[List[str], List[str]]:
    missing: List[str] = []
    mismatched: List[str] = []
    hashes = result_hashes(result)
    for algorithm in algorithms:
        actual = hash_value(hashes, algorithm)
        expected = entry.hashes.get(algorithm)
        if actual is None:
            missing.append(f"result:{algorithm}")
        if expected is None:
            missing.append(f"dat:{algorithm}")
        if actual is not None and expected is not None and actual != expected:
            mismatched.append(algorithm)
    return missing, mismatched


def compare_one(result: Result, by_name: DatNameMap, by_sha1: DatNameMap, algorithms: Tuple[str, ...]) -> Result:
    archive = str(result.get("archive", ""))
    member = str(result.get("member", ""))
    output: Result = {
        "archive": archive,
        "member": member,
        "source_status": result.get("status", ""),
        "status": "error",
        "matched_by": "",
        "dat_name": "",
        "dat_path": "",
        "dat_game": "",
        "dat_rom": "",
        "dat_size": "",
        "missing_hashes": [],
        "mismatched_hashes": [],
        "errors": [],
        "result_hashes": result_hashes(result),
        "dat_hashes": {},
    }

    if result.get("status") != "ok":
        output["errors"] = [str(result.get("error", f"source status: {result.get('status')}"))]
        return output

    entry, matched_by, errors = find_dat_entry(result, by_name, by_sha1)
    if entry is None:
        output["status"] = "ambiguous" if any(error.startswith("ambiguous") for error in errors) else "unmatched"
        output["errors"] = errors
        return output

    output["matched_by"] = matched_by
    output["dat_name"] = entry.dat_name
    output["dat_path"] = entry.dat_path
    output["dat_game"] = entry.game_name
    output["dat_rom"] = entry.rom_name
    output["dat_size"] = entry.size
    output["dat_hashes"] = entry.hashes

    missing, mismatched = compare_hashes(result, entry, algorithms)
    output["missing_hashes"] = missing
    output["mismatched_hashes"] = mismatched
    if mismatched:
        output["status"] = "mismatch"
    elif missing:
        output["status"] = "missing"
    else:
        output["status"] = "match"
    return output


def compare_results(
    results: List[Result], by_name: DatNameMap, by_sha1: DatNameMap, algorithms: Tuple[str, ...]
) -> List[Result]:
    return [compare_one(result, by_name, by_sha1, algorithms) for result in results]


def status_counts(results: List[Result]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for result in results:
        status = str(result.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return counts


def available_hashes_match(result: Result) -> bool:
    return result["status"] in {"match", "missing"}


def display_filename(result: Result) -> str:
    member = result.get("member")
    if isinstance(member, str) and member:
        return member.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    archive = result.get("archive")
    if isinstance(archive, str) and archive:
        return archive.replace("\\", "/").rsplit("/", maxsplit=1)[-1]
    return ""


def match_mark(result: Result) -> str:
    return "✓" if result["status"] == "match" else "✗"


def can_encode(value: str, encoding: Optional[str]) -> bool:
    if encoding is None:
        return True
    try:
        value.encode(encoding)
    except UnicodeEncodeError:
        return False
    return True


def console_match_mark(result: Result, encoding: Optional[str]) -> str:
    mark = match_mark(result)
    if can_encode(mark, encoding):
        return mark
    return "OK" if result["status"] == "match" else "NO"


def status_style(status: str) -> str:
    if status == "match":
        return "green"
    if status == "missing":
        return "yellow"
    return "red"


def issue_summary(result: Result) -> str:
    status = result["status"]
    if status == "match":
        return ""
    if status == "mismatch":
        return "mismatch: " + ", ".join(str(item) for item in result.get("mismatched_hashes", []))
    if status == "missing":
        return "missing: " + ", ".join(str(item) for item in result.get("missing_hashes", []))
    errors = result.get("errors", [])
    if errors:
        return "; ".join(str(error) for error in errors)
    return status


def output_paths(args: argparse.Namespace) -> Tuple[Path, Path, Path]:
    output_base = args.hashes_json.parent / "dat-comparison"
    return (
        args.output_json or output_base.with_suffix(".json"),
        args.output_csv or output_base.with_suffix(".csv"),
        args.output_text or output_base.with_suffix(".txt"),
    )


def table(rows: List[Result]) -> str:
    if not rows:
        return ""
    headers = list(rows[0])
    widths = {header: max(len(header), *(len(str(row[header])) for row in rows)) for header in headers}
    lines = ["  ".join(header.ljust(widths[header]) for header in headers)]
    lines.append("  ".join("-" * widths[header] for header in headers))
    for row in rows:
        lines.append("  ".join(str(row[header]).ljust(widths[header]) for header in headers))
    return "\n".join(lines)


def mismatch_rows(results: List[Result]) -> List[Result]:
    rows: List[Result] = []
    for result in results:
        if result["status"] != "mismatch":
            continue
        hashes = result_hashes(result)
        dat_hashes = result.get("dat_hashes", {})
        for algorithm in result.get("mismatched_hashes", []):
            rows.append(
                {
                    "Archive": result["archive"],
                    "Member": result["member"],
                    "DAT": result["dat_name"],
                    "DATRom": result["dat_rom"],
                    "Algorithm": algorithm,
                    "Result": hash_value(hashes, str(algorithm)) or "",
                    "DATHash": hash_value(dat_hashes, str(algorithm)) or "",
                }
            )
    return rows


def missing_hash_rows(results: List[Result]) -> List[Result]:
    rows: List[Result] = []
    for result in results:
        if result["status"] != "missing":
            continue
        for missing_hash in result.get("missing_hashes", []):
            source, separator, algorithm = str(missing_hash).partition(":")
            rows.append(
                {
                    "Archive": result["archive"],
                    "Member": result["member"],
                    "DAT": result["dat_name"],
                    "DATRom": result["dat_rom"],
                    "MissingFrom": source if separator else "",
                    "Algorithm": algorithm if separator else missing_hash,
                }
            )
    return rows


def issue_rows(results: List[Result], status: str) -> List[Result]:
    rows: List[Result] = []
    for result in results:
        if result["status"] != status:
            continue
        rows.append(
            {
                "Archive": result["archive"],
                "Member": result["member"],
                "DAT": result.get("dat_name", ""),
                "DATRom": result.get("dat_rom", ""),
                "Errors": "; ".join(result.get("errors", [])),
            }
        )
    return rows


def write_text_report(
    path: Path,
    hashes_json: Path,
    dat_paths: Tuple[Path, ...],
    algorithms: Tuple[str, ...],
    dat_entry_count: int,
    results: List[Result],
) -> None:
    counts = status_counts(results)
    lines = [
        "DAT hash comparison",
        f"Hashes JSON: {hashes_json}",
        f"DAT files: {', '.join(str(path) for path in dat_paths)}",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        f"DAT entries: {dat_entry_count}",
        f"Hash algorithms: {', '.join(algorithms)}",
        "",
        "Summary:",
        f"  results: {len(results)}",
        f"  complete match: {counts.get('match', 0)}",
        f"  available hashes match: {sum(1 for result in results if available_hashes_match(result))}",
        f"  mismatch: {counts.get('mismatch', 0)}",
        f"  missing: {counts.get('missing', 0)}",
        f"  unmatched: {counts.get('unmatched', 0)}",
        f"  ambiguous: {counts.get('ambiguous', 0)}",
        f"  error: {counts.get('error', 0)}",
        "",
        "Mismatches:",
        table(mismatch_rows(results)) or "  none",
        "",
        "Missing hashes:",
        table(missing_hash_rows(results)) or "  none",
        "",
        "Unmatched entries:",
        table(issue_rows(results, "unmatched")) or "  none",
        "",
        "Ambiguous entries:",
        table(issue_rows(results, "ambiguous")) or "  none",
        "",
        "Errors:",
        table(issue_rows(results, "error")) or "  none",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_csv(path: Path, results: List[Result]) -> None:
    fieldnames = [
        "archive",
        "member",
        "status",
        "matched_by",
        "dat_name",
        "dat_path",
        "dat_game",
        "dat_rom",
        "dat_size",
        "result_crc32",
        "dat_crc32",
        "result_md5",
        "dat_md5",
        "result_sha1",
        "dat_sha1",
        "missing_hashes",
        "mismatched_hashes",
        "errors",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fileobj:
        writer = csv.DictWriter(fileobj, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            hashes = result_hashes(result)
            dat_hashes = result.get("dat_hashes", {})
            writer.writerow(
                {
                    "archive": result["archive"],
                    "member": result["member"],
                    "status": result["status"],
                    "matched_by": result["matched_by"],
                    "dat_name": result["dat_name"],
                    "dat_path": result["dat_path"],
                    "dat_game": result["dat_game"],
                    "dat_rom": result["dat_rom"],
                    "dat_size": result["dat_size"],
                    "result_crc32": hash_value(hashes, "crc32") or "",
                    "dat_crc32": hash_value(dat_hashes, "crc32") or "",
                    "result_md5": hash_value(hashes, "md5") or "",
                    "dat_md5": hash_value(dat_hashes, "md5") or "",
                    "result_sha1": hash_value(hashes, "sha1") or "",
                    "dat_sha1": hash_value(dat_hashes, "sha1") or "",
                    "missing_hashes": "; ".join(result.get("missing_hashes", [])),
                    "mismatched_hashes": "; ".join(result.get("mismatched_hashes", [])),
                    "errors": "; ".join(result.get("errors", [])),
                }
            )


def render_console_report(results: List[Result], hashes_json: Path, algorithms: Tuple[str, ...]) -> None:
    console = Console()
    encoding = getattr(console.file, "encoding", None)
    counts = status_counts(results)
    table = Table(
        title=f"DAT hash comparison: {hashes_json}",
        box=box.SIMPLE_HEAVY,
        safe_box=True,
        show_lines=False,
    )
    table.add_column("Match", justify="center", no_wrap=True)
    table.add_column("Filename", overflow="fold")
    table.add_column("Status", no_wrap=True)
    table.add_column("DAT", no_wrap=True)
    table.add_column("Issue", overflow="fold")

    for result in results:
        status = str(result["status"])
        style = status_style(status)
        table.add_row(
            console_match_mark(result, encoding),
            display_filename(result),
            status,
            str(result.get("dat_name", "")),
            issue_summary(result),
            style=style,
        )

    console.print(table)
    console.print(
        f"[bold]Results:[/bold] {len(results)}  "
        f"[green]matches:[/green] {counts.get('match', 0)}  "
        f"[yellow]missing:[/yellow] {counts.get('missing', 0)}  "
        f"[red]mismatch:[/red] {counts.get('mismatch', 0)}  "
        f"[red]unmatched:[/red] {counts.get('unmatched', 0)}  "
        f"[red]ambiguous:[/red] {counts.get('ambiguous', 0)}  "
        f"[red]errors:[/red] {counts.get('error', 0)}  "
        f"[bold]hashes:[/bold] {', '.join(algorithms)}"
    )


def main() -> int:
    args = parse_args()
    algorithms = DEFAULT_ALGORITHMS + OPTIONAL_ALGORITHMS if args.include_md5 else DEFAULT_ALGORITHMS
    try:
        dat_paths = discover_dat_paths(args.dat_dir, args.dat)
        if not dat_paths:
            raise ValueError(f"No .dat files found in {args.dat_dir}; use --dat-dir or --dat")
        hash_results = load_hash_results(args.hashes_json)
        dat_entries = load_all_dat_entries(dat_paths)
    except (OSError, ValueError, ET.ParseError) as exc:
        print_progress(f"Failed to load inputs: {exc}", fileobj=sys.stderr)
        return 2

    by_name, by_sha1 = build_dat_maps(dat_entries)
    results = compare_results(hash_results, by_name, by_sha1, algorithms)
    output_json, output_csv, output_text = output_paths(args)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(
            {
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "hashes_json": str(args.hashes_json),
                "dat_files": [str(path) for path in dat_paths],
                "dat_entry_count": len(dat_entries),
                "hash_algorithms": list(algorithms),
                "count_by_status": status_counts(results),
                "available_hash_match_count": sum(1 for result in results if available_hashes_match(result)),
                "results": results,
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    write_csv(output_csv, results)
    write_text_report(output_text, args.hashes_json, dat_paths, algorithms, len(dat_entries), results)
    render_console_report(results, args.hashes_json, algorithms)
    print_progress(f"Wrote {output_json}")
    print_progress(f"Wrote {output_csv}")
    print_progress(f"Wrote {output_text}")

    failures = [result for result in results if result["status"] != "match"]
    if failures:
        print_progress(f"{len(failures)} mismatch/missing/unmatched/ambiguous/error result(s)")
        return 1
    print_progress(f"All compared {', '.join(algorithms)} hashes match the DAT")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
