import tempfile
import unittest
from pathlib import Path
from typing import Dict

from rvz_tools.compare_reports import (
    compare_results,
    error_rows,
    hash_algorithms,
    mismatching_hash_rows,
    missing_hash_rows,
    status_counts,
    write_text_report,
)

Result = Dict[str, object]


def ok_result(member: str, hashes: Dict[str, str]) -> Result:
    return {
        "archive": "archive.zip",
        "member": member,
        "rvz_size": 123,
        "status": "ok",
        "hashes": hashes,
    }


class CompareReportsTests(unittest.TestCase):
    def test_write_text_report_creates_parent_and_uses_selected_output_paths(self) -> None:
        summary = {
            "count_by_status": {},
            "timing_totals": {},
            "result_count": 0,
            "in_paths": [],
        }
        summaries = {
            "dolphintool": summary,
            "rvz": summary,
            "rvz-spooled": summary,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            report_path = root / "reports" / "comparison.txt"
            output_json = root / "custom" / "result.json"
            output_csv = root / "custom" / "result.csv"

            write_text_report(
                report_path,
                root / "run",
                output_json,
                output_csv,
                summaries,
                [],
                {},
                ("crc32", "sha1"),
            )
            report = report_path.read_text(encoding="utf-8")

        self.assertIn(f"comparison JSON: {output_json}", report)
        self.assertIn(f"comparison CSV: {output_csv}", report)

    def test_hash_algorithms_includes_md5_when_summary_or_report_has_it(self) -> None:
        reports = {
            "dolphintool": [ok_result("a.rvz", {"crc32": "1", "sha1": "2"})],
            "rvz": [ok_result("a.rvz", {"crc32": "1", "sha1": "2", "md5": "3"})],
            "rvz-spooled": [ok_result("a.rvz", {"crc32": "1", "sha1": "2"})],
        }
        summaries = {
            "dolphintool": {"include_md5": False},
            "rvz": {"include_md5": False},
            "rvz-spooled": {"include_md5": False},
        }

        self.assertEqual(hash_algorithms(reports, summaries), ("crc32", "sha1", "md5"))

    def test_compare_results_separates_missing_mismatch_and_error(self) -> None:
        algorithms = ("crc32", "sha1", "md5")
        dolphintool = [
            ok_result("match.rvz", {"crc32": "aaaa", "sha1": "bbbb", "md5": "cccc"}),
            ok_result("missing-md5.rvz", {"crc32": "1111", "sha1": "2222"}),
            ok_result("mismatch.rvz", {"crc32": "dddd", "sha1": "eeee", "md5": "ffff"}),
            {
                "archive": "archive.zip",
                "member": "error.rvz",
                "rvz_size": 123,
                "status": "error",
                "error": "DolphinTool failed",
            },
        ]
        rvz = [
            ok_result("match.rvz", {"crc32": "aaaa", "sha1": "bbbb", "md5": "cccc"}),
            ok_result("missing-md5.rvz", {"crc32": "1111", "sha1": "2222", "md5": "3333"}),
            ok_result("mismatch.rvz", {"crc32": "dddd", "sha1": "bad", "md5": "ffff"}),
            ok_result("error.rvz", {"crc32": "9999", "sha1": "8888", "md5": "7777"}),
        ]
        rvz_spooled = [
            ok_result("match.rvz", {"crc32": "aaaa", "sha1": "bbbb", "md5": "cccc"}),
            ok_result("missing-md5.rvz", {"crc32": "1111", "sha1": "2222", "md5": "3333"}),
            ok_result("mismatch.rvz", {"crc32": "dddd", "sha1": "eeee", "md5": "ffff"}),
            ok_result("error.rvz", {"crc32": "9999", "sha1": "8888", "md5": "7777"}),
        ]

        results = compare_results(dolphintool, rvz, rvz_spooled, algorithms)
        by_member = {str(result["member"]): result for result in results}

        self.assertEqual(status_counts(results), {"error": 1, "match": 1, "mismatch": 1, "missing": 1})
        self.assertEqual(by_member["match.rvz"]["status"], "match")
        self.assertEqual(by_member["missing-md5.rvz"]["status"], "missing")
        self.assertEqual(by_member["mismatch.rvz"]["status"], "mismatch")
        self.assertEqual(by_member["error.rvz"]["status"], "error")

        self.assertEqual(
            missing_hash_rows(results),
            [
                {
                    "Archive": "archive.zip",
                    "Member": "missing-md5.rvz",
                    "Source": "dolphintool",
                    "Algorithm": "md5",
                }
            ],
        )

        self.assertEqual(
            mismatching_hash_rows(results, algorithms),
            [
                {
                    "Archive": "archive.zip",
                    "Member": "mismatch.rvz",
                    "Algorithm": "sha1",
                    "DolphinTool": "eeee",
                    "RVZ": "bad",
                    "RVZSpooled": "eeee",
                }
            ],
        )

        self.assertEqual(
            error_rows(results),
            [
                {
                    "Archive": "archive.zip",
                    "Member": "error.rvz",
                    "Errors": "dolphintool status: error: DolphinTool failed",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
