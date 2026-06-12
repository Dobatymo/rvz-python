"""Compare Redump RVZ hash reports from DolphinTool, direct RVZ, and spooled RVZ runs."""

import argparse
import csv
import datetime as dt
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, TextIO, Tuple, cast

from rich import box
from rich.console import Console
from rich.table import Table

STANDARD_HASHES = ("crc32", "sha1")
OPTIONAL_HASHES = ("md5",)
DEFAULT_RUN_DIR = Path("hash-compare")
MODE_DOLPHINTOOL = "dolphintool"
MODE_RVZ = "rvz"
MODE_RVZ_SPOOLED = "rvz-spooled"
MODE_DIRS = {
    MODE_DOLPHINTOOL: "dolphintool",
    MODE_RVZ: "rvz-direct",
    MODE_RVZ_SPOOLED: "rvz-spooled",
}
CONSOLE = Console()
ERROR_CONSOLE = Console(stderr=True)
Result = Dict[str, Any]
Summary = Dict[str, Any]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN_DIR)
    parser.add_argument("--output-json", type=Path, default=None)
    parser.add_argument("--output-csv", type=Path, default=None)
    parser.add_argument("--output-text", type=Path, default=None)
    return parser.parse_args()


def load_json_object(path: Path) -> Summary:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"{path} does not contain a JSON object")
    return data


def load_json_list(path: Path) -> List[Result]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"{path} does not contain a JSON list")
    return [entry for entry in data if isinstance(entry, dict)]


def report_json_path(run_dir: Path, mode: str) -> Path:
    return run_dir / MODE_DIRS[mode] / "hashes.json"


def summary_path(run_dir: Path, mode: str) -> Path:
    return run_dir / MODE_DIRS[mode] / "summary.json"


def result_key(result: Result) -> Tuple[str, str]:
    return str(result.get("archive")), str(result.get("member"))


def result_map(results: List[Result]) -> Dict[Tuple[str, str], Result]:
    return {result_key(result): result for result in results}


def result_has_hash(result: Result, algorithm: str) -> bool:
    hashes = result.get("hashes")
    return isinstance(hashes, dict) and algorithm in hashes


def hash_algorithms(reports: Dict[str, List[Result]], summaries: Dict[str, Summary]) -> Tuple[str, ...]:
    algorithms = list(STANDARD_HASHES)
    for algorithm in OPTIONAL_HASHES:
        summary_enabled = any(bool(summary.get(f"include_{algorithm}")) for summary in summaries.values())
        report_enabled = any(result_has_hash(result, algorithm) for results in reports.values() for result in results)
        if summary_enabled or report_enabled:
            algorithms.append(algorithm)
    return tuple(algorithms)


def hash_value(hashes: object, algorithm: str) -> Optional[str]:
    if not isinstance(hashes, dict):
        return None
    hash_map = cast(Dict[str, object], hashes)
    value = hash_map.get(algorithm)
    if not isinstance(value, str) or not value:
        return None
    return value


def compare_hashes(left_hashes: object, right_hashes: object, algorithms: Tuple[str, ...]) -> Dict[str, object]:
    matches: Dict[str, object] = {}
    for algorithm in algorithms:
        left_value = hash_value(left_hashes, algorithm)
        right_value = hash_value(right_hashes, algorithm)
        matches[algorithm] = left_value == right_value if left_value is not None and right_value is not None else ""
    return matches


def result_status_error(source: str, result: Optional[Result]) -> Optional[str]:
    if result is None:
        return f"missing {source} result"

    status = result.get("status")
    if status == "ok":
        return None

    error = result.get("error")
    if error:
        return f"{source} status: {status}: {error}"
    return f"{source} status: {status}"


def find_missing_hashes(
    source_results: List[Tuple[str, Optional[Result], object]], algorithms: Tuple[str, ...]
) -> List[Result]:
    missing_hashes: List[Result] = []
    for source, result, hashes in source_results:
        if result is None or result.get("status") != "ok":
            continue
        for algorithm in algorithms:
            if hash_value(hashes, algorithm) is None:
                missing_hashes.append({"source": source, "algorithm": algorithm})
    return missing_hashes


def all_hash_matches(*match_groups: Dict[str, object]) -> bool:
    return all(value is True for matches in match_groups for value in matches.values())


def has_hash_mismatch(*match_groups: Dict[str, object]) -> bool:
    return any(value is False for matches in match_groups for value in matches.values())


def available_hashes_match(result: Result) -> bool:
    if result["status"] == "error":
        return False
    return not has_hash_mismatch(
        result["rvz_matches_dolphintool"],
        result["rvz_spooled_matches_dolphintool"],
        result["rvz_spooled_matches_rvz"],
    )


def available_hash_match_count(results: List[Result]) -> int:
    return sum(1 for result in results if available_hashes_match(result))


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


def mismatched_algorithms(result: Result, algorithms: Tuple[str, ...]) -> List[str]:
    rows = mismatching_hash_rows([result], algorithms)
    return [str(row["Algorithm"]) for row in rows]


def issue_summary(result: Result, algorithms: Tuple[str, ...]) -> str:
    status = result["status"]
    if status == "match":
        return ""
    if status == "mismatch":
        return "mismatch: " + ", ".join(mismatched_algorithms(result, algorithms))
    if status == "missing":
        return "missing: " + missing_hash_summary(result)
    errors = result.get("errors", [])
    if errors:
        return "; ".join(str(error) for error in errors)
    return str(status)


def compare_one(
    key: Tuple[str, str],
    dolphintool: Optional[Result],
    rvz: Optional[Result],
    rvz_spooled: Optional[Result],
    algorithms: Tuple[str, ...],
) -> Result:
    errors: List[str] = []
    for error in (
        result_status_error("dolphintool", dolphintool),
        result_status_error("rvz", rvz),
        result_status_error("rvz-spooled", rvz_spooled),
    ):
        if error is not None:
            errors.append(error)

    dolphin_hashes = dolphintool.get("hashes", {}) if dolphintool else {}
    rvz_hashes = rvz.get("hashes", {}) if rvz else {}
    rvz_spooled_hashes = rvz_spooled.get("hashes", {}) if rvz_spooled else {}
    size_source = dolphintool or rvz or rvz_spooled
    missing_hashes = find_missing_hashes(
        [
            ("dolphintool", dolphintool, dolphin_hashes),
            ("rvz", rvz, rvz_hashes),
            ("rvz-spooled", rvz_spooled, rvz_spooled_hashes),
        ],
        algorithms,
    )
    direct_matches = compare_hashes(dolphin_hashes, rvz_hashes, algorithms)
    spooled_matches = compare_hashes(dolphin_hashes, rvz_spooled_hashes, algorithms)
    spooled_matches_direct = compare_hashes(rvz_hashes, rvz_spooled_hashes, algorithms)

    status = "error" if errors else "match"
    if not errors and has_hash_mismatch(direct_matches, spooled_matches, spooled_matches_direct):
        status = "mismatch"
    elif not errors and (
        missing_hashes or not all_hash_matches(direct_matches, spooled_matches, spooled_matches_direct)
    ):
        status = "missing"

    if size_source is None:
        raise ValueError(f"no report data for {key[0]}!{key[1]}")

    return {
        "archive": key[0],
        "member": key[1],
        "rvz_size": size_source["rvz_size"],
        "status": status,
        "errors": errors,
        "dolphintool_hashes": dolphin_hashes,
        "rvz_hashes": rvz_hashes,
        "rvz_spooled_hashes": rvz_spooled_hashes,
        "missing_hashes": missing_hashes,
        "rvz_matches_dolphintool": direct_matches,
        "rvz_spooled_matches_dolphintool": spooled_matches,
        "rvz_spooled_matches_rvz": spooled_matches_direct,
    }


def compare_results(
    dolphintool: List[Result],
    rvz: List[Result],
    rvz_spooled: List[Result],
    algorithms: Tuple[str, ...],
) -> List[Result]:
    dolphin_by_key = result_map(dolphintool)
    rvz_by_key = result_map(rvz)
    rvz_spooled_by_key = result_map(rvz_spooled)
    keys = sorted(set(dolphin_by_key) | set(rvz_by_key) | set(rvz_spooled_by_key))
    return [
        compare_one(key, dolphin_by_key.get(key), rvz_by_key.get(key), rvz_spooled_by_key.get(key), algorithms)
        for key in keys
    ]


def status_counts(results: List[Result]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for result in results:
        status = str(result.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1
    return counts


def summary_row(mode: str, summary: Summary) -> Result:
    counts = summary["count_by_status"]
    totals = summary["timing_totals"]
    return {
        "Mode": mode,
        "Results": summary["result_count"],
        "Ok": counts.get("ok", 0),
        "Errors": counts.get("error", 0),
        "TotalSeconds": totals.get("seconds", ""),
        "ExtractSeconds": totals.get("extract_seconds", ""),
        "DolphinSeconds": totals.get("dolphin_seconds", ""),
        "RvzTotalSeconds": totals.get("rvz_total_seconds", ""),
        "RvzReaderSeconds": totals.get("rvz_reader_seconds", ""),
        "ZipSpoolSeconds": totals.get("zip_spool_seconds", ""),
    }


def timing_delta(direct: Summary, spooled: Summary) -> Dict[str, float]:
    direct_totals = direct["timing_totals"]
    spooled_totals = spooled["timing_totals"]
    delta: Dict[str, float] = {}
    for key in ("seconds", "rvz_total_seconds", "rvz_reader_seconds", "zip_spool_seconds"):
        if key in direct_totals and key in spooled_totals:
            delta[key] = round(spooled_totals[key] - direct_totals[key], 3)
    return delta


def summary_input_label(summary: Summary) -> str:
    in_paths = summary.get("in_paths")
    if isinstance(in_paths, list):
        return ", ".join(str(path) for path in in_paths)
    return str(summary.get("in_path", ""))


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


def mismatching_hash_rows(results: List[Result], algorithms: Tuple[str, ...]) -> List[Result]:
    rows: List[Result] = []
    for result in results:
        if result["status"] == "error":
            continue

        dolphin_hashes = result["dolphintool_hashes"]
        rvz_hashes = result["rvz_hashes"]
        rvz_spooled_hashes = result["rvz_spooled_hashes"]
        for algorithm in algorithms:
            dolphin_hash = hash_value(dolphin_hashes, algorithm)
            rvz_hash = hash_value(rvz_hashes, algorithm)
            rvz_spooled_hash = hash_value(rvz_spooled_hashes, algorithm)
            present_hashes = [value for value in (dolphin_hash, rvz_hash, rvz_spooled_hash) if value is not None]
            if len(present_hashes) >= 2 and len(set(present_hashes)) > 1:
                rows.append(
                    {
                        "Archive": result["archive"],
                        "Member": result["member"],
                        "Algorithm": algorithm,
                        "DolphinTool": dolphin_hash or "",
                        "RVZ": rvz_hash or "",
                        "RVZSpooled": rvz_spooled_hash or "",
                    }
                )
    return rows


def missing_hash_rows(results: List[Result]) -> List[Result]:
    rows: List[Result] = []
    for result in results:
        if result["status"] != "missing":
            continue

        for missing_hash in result.get("missing_hashes", []):
            if not isinstance(missing_hash, dict):
                continue
            rows.append(
                {
                    "Archive": result["archive"],
                    "Member": result["member"],
                    "Source": missing_hash.get("source", ""),
                    "Algorithm": missing_hash.get("algorithm", ""),
                }
            )
    return rows


def missing_hash_summary(result: Result) -> str:
    entries: List[str] = []
    for missing_hash in result.get("missing_hashes", []):
        if not isinstance(missing_hash, dict):
            continue
        source = missing_hash.get("source", "")
        algorithm = missing_hash.get("algorithm", "")
        entries.append(f"{source}:{algorithm}")
    return "; ".join(entries)


def error_rows(results: List[Result]) -> List[Result]:
    rows: List[Result] = []
    for result in results:
        if result["status"] != "error":
            continue
        rows.append(
            {
                "Archive": result["archive"],
                "Member": result["member"],
                "Errors": "; ".join(result["errors"]),
            }
        )
    return rows


def output_paths(args: argparse.Namespace, run_dir: Path) -> Tuple[Path, Path, Path]:
    return (
        args.output_json or run_dir / "comparison.json",
        args.output_csv or run_dir / "comparison.csv",
        args.output_text or run_dir / "comparison.txt",
    )


def write_csv(path: Path, results: List[Result], algorithms: Tuple[str, ...]) -> None:
    fieldnames = [
        "archive",
        "member",
        "rvz_size",
        "status",
    ]
    for algorithm in algorithms:
        fieldnames.append(f"rvz_{algorithm}_match")
        fieldnames.append(f"rvz_spooled_{algorithm}_match")
        fieldnames.append(f"spooled_direct_{algorithm}_match")
    for algorithm in algorithms:
        fieldnames.append(f"dolphintool_{algorithm}")
        fieldnames.append(f"rvz_{algorithm}")
        fieldnames.append(f"rvz_spooled_{algorithm}")
    fieldnames.append("missing_hashes")
    fieldnames.append("errors")

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fileobj:
        writer = csv.DictWriter(fileobj, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            dolphin_hashes = result["dolphintool_hashes"]
            rvz_hashes = result["rvz_hashes"]
            rvz_spooled_hashes = result["rvz_spooled_hashes"]
            rvz_matches = result["rvz_matches_dolphintool"]
            rvz_spooled_matches = result["rvz_spooled_matches_dolphintool"]
            spooled_direct_matches = result["rvz_spooled_matches_rvz"]
            errors = result["errors"]
            row = {
                "archive": result["archive"],
                "member": result["member"],
                "rvz_size": result["rvz_size"],
                "status": result["status"],
                "missing_hashes": missing_hash_summary(result),
                "errors": "; ".join(errors),
            }
            for algorithm in algorithms:
                row[f"rvz_{algorithm}_match"] = rvz_matches.get(algorithm, "")
                row[f"rvz_spooled_{algorithm}_match"] = rvz_spooled_matches.get(algorithm, "")
                row[f"spooled_direct_{algorithm}_match"] = spooled_direct_matches.get(algorithm, "")
                row[f"dolphintool_{algorithm}"] = dolphin_hashes.get(algorithm, "")
                row[f"rvz_{algorithm}"] = rvz_hashes.get(algorithm, "")
                row[f"rvz_spooled_{algorithm}"] = rvz_spooled_hashes.get(algorithm, "")
            writer.writerow(row)


def write_text_report(
    path: Path,
    run_dir: Path,
    output_json: Path,
    output_csv: Path,
    summaries: Dict[str, Summary],
    results: List[Result],
    delta: Dict[str, float],
    algorithms: Tuple[str, ...],
) -> None:
    rows = [
        summary_row(MODE_DOLPHINTOOL, summaries[MODE_DOLPHINTOOL]),
        summary_row(MODE_RVZ, summaries[MODE_RVZ]),
        summary_row(MODE_RVZ_SPOOLED, summaries[MODE_RVZ_SPOOLED]),
    ]
    counts = status_counts(results)
    input_label = summary_input_label(summaries[MODE_DOLPHINTOOL])
    mismatch_rows = mismatching_hash_rows(results, algorithms)
    missing_rows = missing_hash_rows(results)
    report_error_rows = error_rows(results)
    lines = [
        "Redump RVZ hash comparison",
        f"Run: {run_dir}",
        f"Input: {input_label}",
        f"Generated: {dt.datetime.now().astimezone().isoformat()}",
        f"Hash algorithms: {', '.join(algorithms)}",
        "",
        table(rows),
        "",
        "RVZ spooled minus RVZ direct timing deltas:",
    ]
    if delta:
        for key, value in delta.items():
            lines.append(f"  {key}: {value}")
    else:
        lines.append("  unavailable")
    lines.extend(
        [
            "",
            "Hash comparison:",
            f"  results: {len(results)}",
            f"  complete match: {counts.get('match', 0)}",
            f"  available hashes match: {available_hash_match_count(results)}",
            f"  mismatch: {counts.get('mismatch', 0)}",
            f"  missing: {counts.get('missing', 0)}",
            f"  error: {counts.get('error', 0)}",
            "",
            "Mismatching hashes:",
            table(mismatch_rows) if mismatch_rows else "  none",
            "",
            "Missing hashes:",
            table(missing_rows) if missing_rows else "  none",
            "",
            "Errors:",
            table(report_error_rows) if report_error_rows else "  none",
            "",
            "Detailed outputs:",
            f"  dolphintool JSON: {report_json_path(run_dir, MODE_DOLPHINTOOL)}",
            f"  dolphintool CSV: {run_dir / MODE_DIRS[MODE_DOLPHINTOOL] / 'hashes.csv'}",
            f"  rvz JSON: {report_json_path(run_dir, MODE_RVZ)}",
            f"  rvz CSV: {run_dir / MODE_DIRS[MODE_RVZ] / 'hashes.csv'}",
            f"  rvz-spooled JSON: {report_json_path(run_dir, MODE_RVZ_SPOOLED)}",
            f"  rvz-spooled CSV: {run_dir / MODE_DIRS[MODE_RVZ_SPOOLED] / 'hashes.csv'}",
            f"  comparison JSON: {output_json}",
            f"  comparison CSV: {output_csv}",
        ]
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def render_console_report(run_dir: Path, results: List[Result], algorithms: Tuple[str, ...]) -> None:
    encoding = getattr(CONSOLE.file, "encoding", None)
    counts = status_counts(results)
    table = Table(
        title=f"RVZ hash comparison: {run_dir}",
        box=box.SIMPLE_HEAVY,
        safe_box=True,
        show_lines=False,
    )
    table.add_column("Match", justify="center", no_wrap=True)
    table.add_column("Filename", overflow="fold")
    table.add_column("Status", no_wrap=True)
    table.add_column("Issue", overflow="fold")

    for result in results:
        status = str(result["status"])
        table.add_row(
            console_match_mark(result, encoding),
            display_filename(result),
            status,
            issue_summary(result, algorithms),
            style=status_style(status),
        )

    CONSOLE.print(table)
    CONSOLE.print(
        f"[bold]Results:[/bold] {len(results)}  "
        f"[green]matches:[/green] {counts.get('match', 0)}  "
        f"[yellow]missing:[/yellow] {counts.get('missing', 0)}  "
        f"[red]mismatch:[/red] {counts.get('mismatch', 0)}  "
        f"[red]errors:[/red] {counts.get('error', 0)}  "
        f"[bold]available hashes match:[/bold] {available_hash_match_count(results)}  "
        f"[bold]hashes:[/bold] {', '.join(algorithms)}"
    )


def print_progress(message: str, fileobj: TextIO = sys.stdout, style: Optional[str] = None) -> None:
    console = ERROR_CONSOLE if fileobj is sys.stderr else CONSOLE
    console.print(message, style=style, markup=False)


def main() -> int:
    args = parse_args()
    try:
        run_dir = args.run_dir.resolve()
        reports = {
            mode: load_json_list(report_json_path(run_dir, mode))
            for mode in (MODE_DOLPHINTOOL, MODE_RVZ, MODE_RVZ_SPOOLED)
        }
        summaries = {
            mode: load_json_object(summary_path(run_dir, mode))
            for mode in (MODE_DOLPHINTOOL, MODE_RVZ, MODE_RVZ_SPOOLED)
        }
    except FileNotFoundError as exc:
        print_progress(f"Missing report: {exc}", fileobj=sys.stderr)
        return 2

    algorithms = hash_algorithms(reports, summaries)
    results = compare_results(reports[MODE_DOLPHINTOOL], reports[MODE_RVZ], reports[MODE_RVZ_SPOOLED], algorithms)
    delta = timing_delta(summaries[MODE_RVZ], summaries[MODE_RVZ_SPOOLED])
    output_json, output_csv, output_text = output_paths(args, run_dir)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(
        json.dumps(
            {
                "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                "run_dir": str(run_dir),
                "hash_algorithms": list(algorithms),
                "timing_summaries": summaries,
                "rvz_spooled_minus_rvz": delta,
                "count_by_status": status_counts(results),
                "available_hash_match_count": available_hash_match_count(results),
                "results": results,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    write_csv(output_csv, results, algorithms)
    write_text_report(output_text, run_dir, output_json, output_csv, summaries, results, delta, algorithms)
    render_console_report(run_dir, results, algorithms)
    print_progress(f"Wrote {output_json}")
    print_progress(f"Wrote {output_csv}")
    print_progress(f"Wrote {output_text}")

    failures = [result for result in results if result["status"] != "match"]
    if failures:
        print_progress(f"{len(failures)} mismatch/missing/error result(s)", style="red")
        return 1
    print_progress(f"All compared {', '.join(algorithms)} hashes match", style="green")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
