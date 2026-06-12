import tempfile
import unittest
from pathlib import Path
from typing import Dict, List

from rvz_tools.compare_hashes_to_dat import (
    DatEntry,
    build_dat_maps,
    compare_results,
    discover_dat_paths,
    load_dat_entries,
    mismatch_rows,
    missing_hash_rows,
    status_counts,
)

Result = Dict[str, object]


def ok_result(member: str, hashes: Dict[str, str]) -> Result:
    return {
        "archive": "archive.zip",
        "member": member,
        "status": "ok",
        "hashes": hashes,
    }


def dat_entry(rom_name: str, hashes: Dict[str, str]) -> DatEntry:
    return DatEntry(
        dat_name="Test DAT",
        dat_path="test.dat",
        game_name=Path(rom_name).stem,
        rom_name=rom_name,
        size="123",
        hashes=hashes,
    )


class CompareHashesToDatTests(unittest.TestCase):
    def test_discover_dat_paths_loads_directory_and_explicit_dat_files(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            dat_dir = Path(tmp) / "datfiles"
            dat_dir.mkdir()
            first = dat_dir / "a.dat"
            second = dat_dir / "B.dat"
            ignored = dat_dir / "ignored.txt"
            extra = Path(tmp) / "extra.dat"
            for path in (first, second, ignored, extra):
                path.write_text("", encoding="utf-8")

            paths = discover_dat_paths(dat_dir, (extra, first))

        self.assertEqual(paths, (first, second, extra))

    def test_load_dat_entries_reads_game_and_machine_roms(self) -> None:
        dat_xml = """<?xml version="1.0"?>
<datafile>
  <header><name>Local DAT</name></header>
  <game name="Game One">
    <rom name="Game One.iso" size="10" crc="AABBCCDD" md5="abc" sha1="def" />
  </game>
  <machine name="Game Two">
    <rom name="Game Two.iso" size="20" crc="11223344" sha1="456" />
  </machine>
</datafile>
"""
        with tempfile.TemporaryDirectory() as tmp:
            dat_path = Path(tmp) / "games.dat"
            dat_path.write_text(dat_xml, encoding="utf-8")

            entries = load_dat_entries(dat_path)

        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0].dat_name, "Local DAT")
        self.assertEqual(entries[0].game_name, "Game One")
        self.assertEqual(entries[0].rom_name, "Game One.iso")
        self.assertEqual(entries[0].size, "10")
        self.assertEqual(entries[0].hashes, {"crc32": "aabbccdd", "md5": "abc", "sha1": "def"})
        self.assertEqual(entries[1].game_name, "Game Two")
        self.assertEqual(entries[1].hashes, {"crc32": "11223344", "sha1": "456"})

    def test_compare_results_classifies_dat_matches_and_issues(self) -> None:
        entries = [
            dat_entry("Match Game.iso", {"crc32": "aaaa", "sha1": "bbbb", "md5": "cccc"}),
            dat_entry("Missing Md5.iso", {"crc32": "1111", "sha1": "2222", "md5": "3333"}),
            dat_entry("Mismatch.iso", {"crc32": "dddd", "sha1": "eeee", "md5": "ffff"}),
            dat_entry("Different Name.iso", {"crc32": "9999", "sha1": "fallback", "md5": "8888"}),
            DatEntry("Test DAT", "test.dat", "Duplicate A", "Duplicate.iso", "123", {"crc32": "1212", "sha1": "dup1"}),
            DatEntry("Test DAT", "test.dat", "Duplicate B", "Duplicate.iso", "123", {"crc32": "3434", "sha1": "dup2"}),
        ]
        by_name, by_sha1 = build_dat_maps(entries)
        results: List[Result] = [
            ok_result("Match Game.rvz", {"crc32": "aaaa", "sha1": "bbbb", "md5": "cccc"}),
            ok_result("Missing Md5.rvz", {"crc32": "1111", "sha1": "2222"}),
            ok_result("Mismatch.rvz", {"crc32": "dddd", "sha1": "bad", "md5": "ffff"}),
            ok_result("No Name Match.rvz", {"crc32": "9999", "sha1": "fallback", "md5": "8888"}),
            ok_result("Duplicate.rvz", {"crc32": "1212"}),
            ok_result("Unmatched.rvz", {"crc32": "0000", "sha1": "missing"}),
            {
                "archive": "archive.zip",
                "member": "Source Error.rvz",
                "status": "error",
                "error": "reader failed",
            },
        ]

        compared = compare_results(results, by_name, by_sha1, ("crc32", "sha1", "md5"))
        by_member = {str(result["member"]): result for result in compared}

        self.assertEqual(
            status_counts(compared),
            {
                "ambiguous": 1,
                "error": 1,
                "match": 2,
                "mismatch": 1,
                "missing": 1,
                "unmatched": 1,
            },
        )
        self.assertEqual(by_member["Match Game.rvz"]["status"], "match")
        self.assertEqual(by_member["No Name Match.rvz"]["matched_by"], "sha1")
        self.assertEqual(by_member["Missing Md5.rvz"]["status"], "missing")
        self.assertEqual(by_member["Mismatch.rvz"]["status"], "mismatch")
        self.assertEqual(by_member["Duplicate.rvz"]["status"], "ambiguous")
        self.assertEqual(by_member["Unmatched.rvz"]["status"], "unmatched")
        self.assertEqual(by_member["Source Error.rvz"]["status"], "error")

        self.assertEqual(
            missing_hash_rows(compared),
            [
                {
                    "Archive": "archive.zip",
                    "Member": "Missing Md5.rvz",
                    "DAT": "Test DAT",
                    "DATRom": "Missing Md5.iso",
                    "MissingFrom": "result",
                    "Algorithm": "md5",
                }
            ],
        )
        self.assertEqual(
            mismatch_rows(compared),
            [
                {
                    "Archive": "archive.zip",
                    "Member": "Mismatch.rvz",
                    "DAT": "Test DAT",
                    "DATRom": "Mismatch.iso",
                    "Algorithm": "sha1",
                    "Result": "bad",
                    "DATHash": "eeee",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
