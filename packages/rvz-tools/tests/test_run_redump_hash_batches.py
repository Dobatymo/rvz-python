import csv
import hashlib
import io
import json
import os
import tempfile
import unittest
import zipfile
import zlib
from argparse import Namespace
from contextlib import redirect_stderr
from pathlib import Path
from typing import Dict, Sequence

from rich.console import Console
from rvz_tools import run_redump_hash_batches as runner


def expected_hashes(data: bytes, include_md5: bool) -> Dict[str, str]:
    hashes = {
        "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
        "sha1": hashlib.sha1(data).hexdigest(),
    }
    if include_md5:
        hashes["md5"] = hashlib.md5(data).hexdigest()
    return hashes


def args_for(mode: runner.Modes, in_paths: Sequence[Path], out_path: Path, include_md5: bool = False) -> Namespace:
    return Namespace(
        mode=mode,
        in_paths=tuple(in_paths),
        out_path=out_path,
        dolphin_tool=Path("missing-dolphintool.exe"),
        dolphin_timeout=1,
        zip_spool_memory=1,
        limit=None,
        resume=False,
        retry_errors=False,
        remove_missing=False,
        keep_extracted=False,
        include_md5=include_md5,
    )


class RunRedumpHashBatchesTests(unittest.TestCase):
    def setUp(self) -> None:
        self._old_console = runner.CONSOLE
        self.output = io.StringIO()
        runner.CONSOLE = Console(file=self.output, force_terminal=False, width=120)

    def tearDown(self) -> None:
        runner.CONSOLE = self._old_console

    def test_progress_output_does_not_apply_rich_highlighting(self) -> None:
        output = io.StringIO()
        runner.CONSOLE = Console(file=output, force_terminal=True, color_system="standard", width=120)
        message = "[2/509] skipping existing C:\\hashes\\Game (Rev 1).rvz"

        runner.print_progress(message)

        self.assertEqual(output.getvalue(), f"{message}\n")

    def test_progress_output_applies_explicit_status_colors(self) -> None:
        output = io.StringIO()
        runner.CONSOLE = Console(file=output, force_terminal=True, color_system="standard", width=120)

        runner.print_progress("  hashing input", style=runner.STYLE_ACTION)
        runner.print_progress("  skipping existing", style=runner.STYLE_SKIPPED)
        runner.print_progress("  ok in 1.0s", style=runner.STYLE_OK)
        runner.print_progress("  error in 1.0s", style=runner.STYLE_ERROR)

        rendered = output.getvalue()
        self.assertIn("\x1b[36m  hashing input\x1b[0m", rendered)
        self.assertIn("\x1b[33m  skipping existing\x1b[0m", rendered)
        self.assertIn("\x1b[32m  ok in 1.0s\x1b[0m", rendered)
        self.assertIn("\x1b[31m  error in 1.0s\x1b[0m", rendered)

    def test_retry_errors_requires_resume(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as raised:
            runner.parse_args(["--mode", "rvz", "--in-paths", "input", "--retry-errors"])

        self.assertEqual(raised.exception.code, 2)
        self.assertIn("--retry-errors requires --resume", stderr.getvalue())

    def test_dolphintool_mode_hashes_plain_inputs_without_dolphintool(self) -> None:
        raw_iso = b"raw iso bytes" * 1000
        zipped_gcm = b"zipped gcm bytes" * 1000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_path = root / "reports"
            (root / "raw.iso").write_bytes(raw_iso)
            with zipfile.ZipFile(root / "archive.zip", "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("nested/plain.gcm", zipped_gcm)

            args = args_for(runner.Modes.DOLPHINTOOL, [root], out_path, include_md5=True)
            self.assertEqual(runner.run_mode(args), 0)

            self.output.seek(0)
            self.output.truncate(0)
            args.resume = True
            self.assertEqual(runner.run_mode(args), 0)
            resume_output = self.output.getvalue()
            self.assertIn(
                "[1/2] archive.zip!nested/plain.gcm\n  skipping existing successful result\n",
                resume_output,
            )
            self.assertIn("[2/2] raw.iso\n  skipping existing successful result\n", resume_output)

            mode_dir = out_path / runner.MODE_DIRS[runner.Modes.DOLPHINTOOL]
            results = json.loads((mode_dir / "hashes.json").read_text(encoding="utf-8"))
            summary = json.loads((mode_dir / "summary.json").read_text(encoding="utf-8"))
            with (mode_dir / "hashes.csv").open(newline="", encoding="utf-8") as fileobj:
                csv_rows = list(csv.DictReader(fileobj))

        by_member = {result["member"]: result for result in results}
        self.assertEqual(set(by_member), {"raw.iso", "nested/plain.gcm"})
        self.assertEqual(summary["result_count"], 2)
        self.assertEqual(summary["count_by_status"], {"ok": 2})
        self.assertEqual(summary["in_paths"], [os.fspath(root)])
        self.assertNotIn("in_path", summary)
        self.assertEqual(len(csv_rows), 2)

        raw_result = by_member["raw.iso"]
        self.assertEqual(raw_result["input_source"], "raw")
        self.assertEqual(raw_result["input_type"], "iso")
        self.assertEqual(raw_result["hash_source"], "binary")
        self.assertEqual(raw_result["hashes"], expected_hashes(raw_iso, include_md5=True))
        self.assertNotIn("dolphin_seconds", raw_result)

        zipped_result = by_member["nested/plain.gcm"]
        self.assertEqual(zipped_result["input_source"], "zip")
        self.assertEqual(zipped_result["input_type"], "gcm")
        self.assertEqual(zipped_result["hash_source"], "binary")
        self.assertEqual(zipped_result["hashes"], expected_hashes(zipped_gcm, include_md5=True))
        self.assertNotIn("dolphin_seconds", zipped_result)

    def test_run_mode_accepts_multiple_input_paths(self) -> None:
        first_iso = b"first iso bytes" * 1000
        second_gcm = b"second gcm bytes" * 1000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first_root = root / "first"
            second_root = root / "second"
            out_path = root / "reports"
            first_root.mkdir()
            second_root.mkdir()
            (first_root / "first.iso").write_bytes(first_iso)
            (second_root / "second.gcm").write_bytes(second_gcm)

            args = args_for(runner.Modes.RVZ, [first_root, second_root], out_path)
            self.assertEqual(runner.run_mode(args), 0)

            mode_dir = out_path / runner.MODE_DIRS[runner.Modes.RVZ]
            results = json.loads((mode_dir / "hashes.json").read_text(encoding="utf-8"))
            summary = json.loads((mode_dir / "summary.json").read_text(encoding="utf-8"))

        by_member = {result["member"]: result for result in results}
        self.assertEqual(set(by_member), {"first.iso", "second.gcm"})
        self.assertEqual(by_member["first.iso"]["hashes"], expected_hashes(first_iso, include_md5=False))
        self.assertEqual(by_member["second.gcm"]["hashes"], expected_hashes(second_gcm, include_md5=False))
        self.assertEqual(summary["in_paths"], [os.fspath(first_root), os.fspath(second_root)])
        self.assertNotIn("in_path", summary)
        self.assertEqual(summary["result_count"], 2)

    def test_resume_can_remove_results_for_missing_inputs(self) -> None:
        keep_iso = b"keep iso bytes" * 1000
        stale_iso = b"stale iso bytes" * 1000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_path = root / "reports"
            keep_path = root / "keep.iso"
            stale_path = root / "stale.iso"
            keep_path.write_bytes(keep_iso)
            stale_path.write_bytes(stale_iso)

            args = args_for(runner.Modes.RVZ, [root], out_path)
            self.assertEqual(runner.run_mode(args), 0)

            stale_path.unlink()
            args.resume = True
            self.assertEqual(runner.run_mode(args), 0)

            mode_dir = out_path / runner.MODE_DIRS[runner.Modes.RVZ]
            results = json.loads((mode_dir / "hashes.json").read_text(encoding="utf-8"))
            self.assertEqual({result["member"] for result in results}, {"keep.iso", "stale.iso"})

            args.remove_missing = True
            self.assertEqual(runner.run_mode(args), 0)

            results = json.loads((mode_dir / "hashes.json").read_text(encoding="utf-8"))
            self.assertEqual({result["member"] for result in results}, {"keep.iso"})

    def test_resume_retries_error_results_only_when_requested(self) -> None:
        data = b"retry this input" * 1000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_path = root / "reports"
            (root / "game.iso").write_bytes(data)
            args = args_for(runner.Modes.RVZ, [root], out_path)
            self.assertEqual(runner.run_mode(args), 0)

            mode_dir = out_path / runner.MODE_DIRS[runner.Modes.RVZ]
            output_json = mode_dir / "hashes.json"
            results = json.loads(output_json.read_text(encoding="utf-8"))
            results[0]["status"] = "error"
            results[0]["error"] = "temporary failure"
            results[0].pop("hashes")
            output_json.write_text(json.dumps(results), encoding="utf-8")

            self.output.seek(0)
            self.output.truncate(0)
            args.resume = True
            self.assertEqual(runner.run_mode(args), 1)
            self.assertIn("  skipping existing error result\n", self.output.getvalue())

            self.output.seek(0)
            self.output.truncate(0)
            args.retry_errors = True
            self.assertEqual(runner.run_mode(args), 0)
            retry_output = self.output.getvalue()
            self.assertIn("Retrying 1 previous error result(s)", retry_output)
            self.assertNotIn("  skipping existing error result\n", retry_output)

            results = json.loads(output_json.read_text(encoding="utf-8"))

        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["status"], "ok")
        self.assertEqual(results[0]["hashes"], expected_hashes(data, include_md5=False))

    def test_spooled_mode_reports_zip_spooling_for_plain_zip_inputs_only(self) -> None:
        raw_iso = b"raw iso bytes" * 1000
        zipped_gcm = b"zipped gcm bytes" * 1000
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            out_path = root / "reports"
            (root / "raw.iso").write_bytes(raw_iso)
            with zipfile.ZipFile(root / "archive.zip", "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("nested/plain.gcm", zipped_gcm)

            args = args_for(runner.Modes.RVZ_SPOOLED, [root], out_path)
            self.assertEqual(runner.run_mode(args), 0)

            mode_dir = out_path / runner.MODE_DIRS[runner.Modes.RVZ_SPOOLED]
            results = json.loads((mode_dir / "hashes.json").read_text(encoding="utf-8"))

        by_member = {result["member"]: result for result in results}
        raw_result = by_member["raw.iso"]
        self.assertNotIn("zip_input_mode", raw_result)
        self.assertNotIn("zip_spool_memory", raw_result)
        self.assertNotIn("zip_spool_seconds", raw_result)
        self.assertEqual(raw_result["hashes"], expected_hashes(raw_iso, include_md5=False))

        zipped_result = by_member["nested/plain.gcm"]
        self.assertEqual(zipped_result["zip_input_mode"], "spooled")
        self.assertEqual(zipped_result["zip_spool_memory"], 1)
        self.assertIn("zip_spool_seconds", zipped_result)
        self.assertIn("zip_spooled_to_disk", zipped_result)
        self.assertEqual(zipped_result["hashes"], expected_hashes(zipped_gcm, include_md5=False))


if __name__ == "__main__":
    unittest.main()
