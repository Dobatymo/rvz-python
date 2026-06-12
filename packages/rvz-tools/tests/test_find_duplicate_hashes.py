import io
import json
import tempfile
import unittest
from pathlib import Path

from rvz_tools import find_duplicate_hashes as duplicates


def result(archive: str, sha1: str = "", status: str = "ok", member: str = "") -> duplicates.Result:
    return {
        "archive": archive,
        "member": member or Path(archive).name,
        "input_source": "zip" if member else "raw",
        "status": status,
        "hashes": {"sha1": sha1} if sha1 else {},
    }


class FindDuplicateHashesTests(unittest.TestCase):
    def test_load_and_group_duplicate_hashes(self) -> None:
        results = [
            result("C:/raw/first.iso", "ABC"),
            result("C:/zips/games.zip", "abc", member="nested/second.rvz"),
            result("C:/raw/unique.iso", "def"),
            result("C:/raw/error.iso", "abc", status="error"),
            result("C:/raw/missing.iso"),
        ]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "hashes.json"
            path.write_text(json.dumps(results), encoding="utf-8")

            loaded = duplicates.load_hash_results(path)
            groups, usable_count = duplicates.find_duplicate_groups(loaded, "sha1")

        self.assertEqual(usable_count, 3)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0][0], "abc")
        self.assertEqual(len(groups[0][1]), 2)

    def test_print_duplicate_groups(self) -> None:
        entries = [
            result("C:/zips/games.zip", "abc", member="second.rvz"),
            result("C:/raw/first.iso", "abc"),
        ]
        output = io.StringIO()

        duplicates.print_duplicate_groups([("abc", entries)], "sha1", 4, 2, fileobj=output)

        self.assertEqual(
            output.getvalue(),
            "SHA1 abc (2 results)\n"
            "  C:/raw/first.iso\n"
            "  C:/zips/games.zip!second.rvz\n"
            "\n"
            "Found 1 duplicate SHA1 group(s) containing 2 result(s).\n"
            "Scanned 4 result(s); 2 had usable SHA1 hashes; skipped 2.\n",
        )

    def test_print_no_duplicates(self) -> None:
        output = io.StringIO()

        duplicates.print_duplicate_groups([], "sha1", 2, 1, fileobj=output)

        self.assertEqual(
            output.getvalue(),
            "No duplicate SHA1 hashes found.\nScanned 2 result(s); 1 had usable SHA1 hashes; skipped 1.\n",
        )


if __name__ == "__main__":
    unittest.main()
