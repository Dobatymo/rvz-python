"""Run one Redump RVZ hash batch mode.

The batch file calls this script once per mode. This script does not invoke
other Python scripts; it only performs the requested mode and writes reports.
"""

import argparse
import csv
import json
import os
import time
from argparse import Namespace
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

from rich import box, get_console
from rich.table import Table

from .redump_hash_common import (
    DEFAULT_SPOOL_SIZE,
    DiscInput,
    dolphin_hashes,
    elapsed_seconds,
    extract_input,
    hash_disc_input,
    iter_disc_inputs,
    safe_name,
)

DEFAULT_OUTPUT_PATH = Path("hash-compare")
DEFAULT_DOLPHIN_TIMEOUT = 7200
DEFAULT_DOLPHIN_TOOL_PATH = Path("DolphinTool.exe")
CONSOLE = get_console()
Result = Dict[str, Any]
STYLE_ACTION = "cyan"
STYLE_SKIPPED = "yellow"
STYLE_OK = "green"
STYLE_ERROR = "red"


class Modes(str, Enum):
    DOLPHINTOOL = "dolphintool"
    RVZ = "rvz"
    RVZ_SPOOLED = "rvz-spooled"


MODE_DIRS = {
    Modes.DOLPHINTOOL: "dolphintool",
    Modes.RVZ: "rvz-direct",
    Modes.RVZ_SPOOLED: "rvz-spooled",
}


def parse_args(argv: Optional[Sequence[str]] = None) -> Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=tuple(Modes), type=Modes, required=True)
    parser.add_argument(
        "--in-paths",
        type=Path,
        nargs="+",
        required=True,
        metavar="PATH",
        help="Input file or directory to scan; pass multiple paths to scan them in one run.",
    )
    parser.add_argument(
        "--out-path",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
    )
    parser.add_argument("--dolphin-tool", type=Path, default=DEFAULT_DOLPHIN_TOOL_PATH)
    parser.add_argument("--dolphin-timeout", type=int, default=DEFAULT_DOLPHIN_TIMEOUT)
    parser.add_argument(
        "--zip-spool-memory",
        type=int,
        default=DEFAULT_SPOOL_SIZE,
    )
    parser.add_argument("--limit", type=int)
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--retry-errors",
        action="store_true",
        help="With --resume, retry prior non-ok results instead of skipping them.",
    )
    parser.add_argument(
        "--remove-missing",
        action="store_true",
        help="With --resume, remove prior output rows whose input is no longer found under --in-paths.",
    )
    parser.add_argument("--keep-extracted", action="store_true")
    parser.add_argument("--include-md5", action="store_true")
    args = parser.parse_args(argv)
    if args.retry_errors and not args.resume:
        parser.error("--retry-errors requires --resume")
    return args


def format_input_paths(in_paths: Iterable[Path]) -> str:
    return ", ".join(os.fspath(path) for path in in_paths)


def selected_members(in_paths: Sequence[Path], limit: Optional[int]) -> List[DiscInput]:
    members: List[DiscInput] = []
    for input_root in in_paths:
        for member in iter_disc_inputs(input_root):
            if limit is not None and len(members) >= limit:
                return members
            members.append(
                DiscInput(
                    archive=member.archive,
                    member=member.member,
                    index=len(members) + 1,
                    size=member.size,
                    disc_type=member.disc_type,
                    source=member.source,
                )
            )
    return members


def result_key(result: Result) -> Tuple[str, str]:
    return str(result.get("archive")), str(result.get("member"))


def member_key(member: DiscInput) -> Tuple[str, str]:
    return os.fspath(member.archive), member.member


def input_label(member: DiscInput) -> str:
    if member.source == "raw":
        return member.archive.name
    return f"{member.archive.name}!{member.member}"


def load_existing_results(path: Path) -> List[Result]:
    if not path.exists():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{os.fspath(path)} does not contain a result list")
    return [entry for entry in data if isinstance(entry, dict)]


def remove_missing_results(results: List[Result], current_keys: Iterable[Tuple[str, str]]) -> List[Result]:
    current_key_set = set(current_keys)
    return [result for result in results if result_key(result) in current_key_set]


def print_progress(message: str, style: Optional[str] = None) -> None:
    CONSOLE.print(message, style=style, markup=False, highlight=False)


def base_result(mode: Modes, member: DiscInput) -> Result:
    return {
        "archive": os.fspath(member.archive),
        "member": member.member,
        "input_source": member.source,
        "input_type": member.disc_type,
        "input_size": member.size,
        "rvz_size": member.size,
        "mode": mode.value,
        "status": "error",
    }


def process_dolphintool_member(args: Namespace, member: DiscInput, mode_dir: Path) -> Result:
    started = time.monotonic()
    extracted_path: Optional[Path] = None
    result = base_result(Modes.DOLPHINTOOL, member)
    timings: Result = {}

    try:
        if member.disc_type != "rvz":
            print_progress("  hashing plain disc bytes", style=STYLE_ACTION)
            hashes, hash_timings = hash_disc_input(
                member,
                mode_dir / "zip-spool",
                False,
                args.zip_spool_memory,
                args.include_md5,
            )
            timings.update(hash_timings)
            result["hash_source"] = "binary"
        else:
            rvz_path = member.archive
            if member.source == "zip":
                extracted_path = mode_dir / "extracted" / safe_name(member)
                print_progress("  extracting RVZ for DolphinTool", style=STYLE_ACTION)
                extract_started = time.monotonic()
                extract_input(member, extracted_path)
                timings["extract_seconds"] = elapsed_seconds(extract_started)
                rvz_path = extracted_path

            print_progress("  hashing RVZ with DolphinTool", style=STYLE_ACTION)
            dolphin_started = time.monotonic()
            hashes = dolphin_hashes(
                args.dolphin_tool,
                mode_dir / "dolphin-user",
                rvz_path,
                args.dolphin_timeout,
                args.include_md5,
            )
            timings["dolphin_seconds"] = elapsed_seconds(dolphin_started)
            result["hash_source"] = "dolphintool"
        result.update({"status": "ok", "hashes": hashes})
    except Exception as exc:  # noqa: BLE001 - report every file and continue.
        result["error"] = repr(exc)
    finally:
        result.update(timings)
        result["seconds"] = elapsed_seconds(started)
        if extracted_path is not None and not args.keep_extracted:
            extracted_path.unlink(missing_ok=True)

    return result


def process_rvz_member(args: Namespace, member: DiscInput, mode_dir: Path, spooled: bool) -> Result:
    started = time.monotonic()
    mode = Modes.RVZ_SPOOLED if spooled else Modes.RVZ
    result = base_result(mode, member)
    if member.source == "zip":
        result["zip_input_mode"] = "spooled" if spooled else "direct"
        if spooled:
            result["zip_spool_memory"] = args.zip_spool_memory

    try:
        print_progress(f"  hashing {member.disc_type.upper()} input", style=STYLE_ACTION)
        hashes, timings = hash_disc_input(
            member,
            mode_dir / "zip-spool",
            spooled,
            args.zip_spool_memory,
            args.include_md5,
        )
        result.update(timings)
        result.update({"status": "ok", "hashes": hashes})
    except Exception as exc:  # noqa: BLE001 - report every file and continue.
        result["error"] = repr(exc)
    finally:
        result["seconds"] = elapsed_seconds(started)

    return result


def calc_timing_totals(results: List[Result]) -> Dict[str, float]:
    timing_keys = (
        "seconds",
        "extract_seconds",
        "dolphin_seconds",
        "rvz_total_seconds",
        "rvz_reader_seconds",
        "zip_spool_seconds",
    )
    timing_totals: Dict[str, float] = {}
    for key in timing_keys:
        values = [result[key] for result in results if key in result]
        if values:
            timing_totals[key] = round(sum(values), 3)
    return timing_totals


def calc_timing_averages(results: List[Result], timing_totals: Dict[str, float]) -> Dict[str, float]:
    timing_averages: Dict[str, float] = {}
    for key, total in timing_totals.items():
        count = sum(1 for result in results if key in result)
        timing_averages[key] = round(total / count, 3)
    return timing_averages


def build_summary(results: List[Result], args: Namespace) -> Result:
    count_by_status: Dict[str, int] = {}
    for result in results:
        status = str(result.get("status", "unknown"))
        count_by_status[status] = count_by_status.get(status, 0) + 1

    timing_totals = calc_timing_totals(results)
    timing_averages = calc_timing_averages(results, timing_totals)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "in_paths": [os.fspath(path) for path in args.in_paths],
        "out_path": os.fspath(args.out_path),
        "mode": args.mode.value,
        "include_md5": args.include_md5,
        "result_count": len(results),
        "count_by_status": count_by_status,
        "total_input_bytes": sum(result.get("input_size", result["rvz_size"]) for result in results),
        "total_rvz_member_bytes": sum(result["rvz_size"] for result in results),
        "timing_totals": timing_totals,
        "timing_averages": timing_averages,
    }


def report_paths(mode_dir: Path) -> Tuple[Path, Path, Path]:
    return mode_dir / "hashes.json", mode_dir / "hashes.csv", mode_dir / "summary.json"


def write_reports(results: List[Result], args: Namespace, mode_dir: Path) -> None:
    output_json, output_csv, output_summary = report_paths(mode_dir)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
    output_summary.write_text(
        json.dumps(build_summary(results, args), ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    fieldnames = [
        "archive",
        "member",
        "input_source",
        "input_type",
        "input_size",
        "rvz_size",
        "mode",
        "hash_source",
        "zip_input_mode",
        "zip_spool_memory",
        "zip_spooled_to_disk",
        "status",
        "crc32",
        "md5",
        "sha1",
        "extract_seconds",
        "dolphin_seconds",
        "rvz_total_seconds",
        "rvz_reader_seconds",
        "zip_spool_seconds",
        "seconds",
        "error",
    ]
    with output_csv.open("w", newline="", encoding="utf-8") as fileobj:
        writer = csv.DictWriter(fileobj, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            hashes: Dict[str, str] = result.get("hashes", {})
            writer.writerow(
                {
                    "archive": result["archive"],
                    "member": result["member"],
                    "input_source": result.get("input_source", ""),
                    "input_type": result.get("input_type", ""),
                    "input_size": result.get("input_size", ""),
                    "rvz_size": result["rvz_size"],
                    "mode": result["mode"],
                    "hash_source": result.get("hash_source", ""),
                    "zip_input_mode": result.get("zip_input_mode", ""),
                    "zip_spool_memory": result.get("zip_spool_memory", ""),
                    "zip_spooled_to_disk": result.get("zip_spooled_to_disk", ""),
                    "status": result["status"],
                    "crc32": hashes.get("crc32", ""),
                    "md5": hashes.get("md5", ""),
                    "sha1": hashes.get("sha1", ""),
                    "extract_seconds": result.get("extract_seconds", ""),
                    "dolphin_seconds": result.get("dolphin_seconds", ""),
                    "rvz_total_seconds": result.get("rvz_total_seconds", ""),
                    "rvz_reader_seconds": result.get("rvz_reader_seconds", ""),
                    "zip_spool_seconds": result.get("zip_spool_seconds", ""),
                    "seconds": result["seconds"],
                    "error": result.get("error", ""),
                }
            )


def processor_for_mode(
    mode: Modes,
) -> Callable[[Namespace, DiscInput, Path], Result]:
    if mode == Modes.DOLPHINTOOL:
        return process_dolphintool_member
    elif mode == Modes.RVZ:
        return lambda args, member, mode_dir: process_rvz_member(args, member, mode_dir, spooled=False)
    elif mode == Modes.RVZ_SPOOLED:
        return lambda args, member, mode_dir: process_rvz_member(args, member, mode_dir, spooled=True)
    raise ValueError(f"unknown mode: {mode}")


def print_configuration(args: Namespace, in_paths: Sequence[Path], member_count: int) -> None:
    table = Table(title="Redump RVZ hash batch", box=box.SIMPLE_HEAVY, safe_box=True)
    table.add_column("Setting", no_wrap=True)
    table.add_column("Value", overflow="fold")
    table.add_row("Mode", args.mode.value)
    table.add_row("Input", format_input_paths(in_paths))
    table.add_row("Output", os.fspath(args.out_path))
    table.add_row("Inputs", str(member_count))
    if args.limit is not None:
        table.add_row("Limit", str(args.limit))

    if args.mode == Modes.DOLPHINTOOL:
        table.add_row("DolphinTool", os.fspath(args.dolphin_tool))
        table.add_row("Dolphin timeout", f"{args.dolphin_timeout}s")
    table.add_row("Include MD5", str(args.include_md5))
    if args.mode == Modes.RVZ_SPOOLED:
        table.add_row("Spool memory limit", str(args.zip_spool_memory))
    CONSOLE.print(table)


def render_summary(args: Namespace, summary: Result, output_json: Path, output_csv: Path, output_summary: Path) -> None:
    totals = summary["timing_totals"]
    counts = summary["count_by_status"]
    table = Table(title="Batch summary", box=box.SIMPLE_HEAVY, safe_box=True)
    table.add_column("Metric", no_wrap=True)
    table.add_column("Value", overflow="fold")
    table.add_row("Results", str(summary["result_count"]))
    table.add_row("OK", str(counts.get("ok", 0)))
    table.add_row("Errors", str(counts.get("error", 0)))
    if "seconds" in totals:
        table.add_row("Total seconds", str(totals["seconds"]))
    if args.mode == Modes.DOLPHINTOOL and "dolphin_seconds" in totals:
        table.add_row("DolphinTool seconds", str(totals["dolphin_seconds"]))
    if "rvz_reader_seconds" in totals:
        table.add_row("Reader/hash seconds", str(totals["rvz_reader_seconds"]))
    if args.mode == Modes.RVZ_SPOOLED and "zip_spool_seconds" in totals:
        table.add_row("ZIP spool seconds", str(totals["zip_spool_seconds"]))
    table.add_row("JSON", os.fspath(output_json))
    table.add_row("CSV", os.fspath(output_csv))
    table.add_row("Summary", os.fspath(output_summary))
    CONSOLE.print(table)


def run_mode(args: argparse.Namespace) -> int:
    mode_dir = args.out_path / MODE_DIRS[args.mode]
    output_json, output_csv, output_summary = report_paths(mode_dir)
    members = selected_members(args.in_paths, None if args.resume and args.remove_missing else args.limit)
    current_keys = [member_key(member) for member in members]
    if args.limit is not None:
        members = members[: args.limit]
    print_configuration(args, args.in_paths, len(members))

    results = load_existing_results(output_json) if args.resume else []
    if args.resume and args.remove_missing:
        original_count = len(results)
        results = remove_missing_results(results, current_keys)
        removed_count = original_count - len(results)
        if removed_count:
            print_progress(
                f"Removed {removed_count} missing existing result(s) from {output_json}",
                style=STYLE_SKIPPED,
            )
    retry_count = 0
    if args.resume and args.retry_errors:
        original_count = len(results)
        results = [result for result in results if result.get("status") == "ok"]
        retry_count = original_count - len(results)
    processed = {result_key(result): result for result in results}
    if results:
        print_progress(f"Loaded {len(results)} existing result(s) from {output_json}", style=STYLE_ACTION)
    if retry_count:
        print_progress(
            f"Retrying {retry_count} previous error result(s) from {output_json}",
            style=STYLE_SKIPPED,
        )

    processor = processor_for_mode(args.mode)
    for position, member in enumerate(members, start=1):
        key = member_key(member)
        if key in processed:
            print_progress(f"[{position}/{len(members)}] {input_label(member)}")
            existing_status = processed[key].get("status")
            if existing_status == "ok":
                print_progress("  skipping existing successful result", style=STYLE_SKIPPED)
            else:
                print_progress(f"  skipping existing {existing_status or 'unknown'} result", style=STYLE_ERROR)
            continue

        print_progress(f"[{position}/{len(members)}] {input_label(member)}")
        result = processor(args, member, mode_dir)
        results.append(result)
        processed[key] = result
        write_reports(results, args, mode_dir)
        status_style = STYLE_OK if result["status"] == "ok" else STYLE_ERROR
        print_progress(f"  {result['status']} in {result['seconds']}s", style=status_style)

    write_reports(results, args, mode_dir)
    summary = build_summary(results, args)
    render_summary(args, summary, output_json, output_csv, output_summary)

    failures = [result for result in results if result["status"] != "ok"]
    if failures:
        print_progress(f"{len(failures)} error result(s)", style=STYLE_ERROR)
        return 1
    print_progress("All hashes calculated", style=STYLE_OK)
    return 0


def main() -> int:
    args = parse_args()
    return run_mode(args)


if __name__ == "__main__":
    raise SystemExit(main())
