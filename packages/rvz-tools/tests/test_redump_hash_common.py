import hashlib
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path
from typing import Dict

from rvz_tools.redump_hash_common import hash_disc_input, iter_disc_inputs


def expected_hashes(data: bytes) -> Dict[str, str]:
    return {
        "crc32": f"{zlib.crc32(data) & 0xFFFFFFFF:08x}",
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
    }


class RedumpHashCommonTests(unittest.TestCase):
    def test_iter_disc_inputs_finds_raw_and_zipped_disc_images(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "game.iso").write_bytes(b"iso")
            (root / "game.gcm").write_bytes(b"gcm")
            (root / "game.rvz").write_bytes(b"rvz")
            (root / "notes.txt").write_text("ignored", encoding="utf-8")
            with zipfile.ZipFile(root / "archive.zip", "w") as archive:
                archive.writestr("nested/from_zip.iso", b"zip iso")
                archive.writestr("nested/from_zip.gcm", b"zip gcm")
                archive.writestr("nested/from_zip.rvz", b"zip rvz")
                archive.writestr("nested/notes.txt", b"ignored")

            inputs = list(iter_disc_inputs(root))

        self.assertEqual(
            {(disc_input.source, disc_input.member, disc_input.disc_type, disc_input.size) for disc_input in inputs},
            {
                ("raw", "game.iso", "iso", 3),
                ("raw", "game.gcm", "gcm", 3),
                ("raw", "game.rvz", "rvz", 3),
                ("zip", "nested/from_zip.iso", "iso", 7),
                ("zip", "nested/from_zip.gcm", "gcm", 7),
                ("zip", "nested/from_zip.rvz", "rvz", 7),
            },
        )

    def test_hash_disc_input_hashes_raw_iso_and_gcm_bytes(self) -> None:
        payloads = {
            "raw.iso": b"iso bytes" * 1000,
            "raw.gcm": b"gcm bytes" * 1000,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for name, data in payloads.items():
                (root / name).write_bytes(data)

            inputs = {disc_input.member: disc_input for disc_input in iter_disc_inputs(root)}
            for name, data in payloads.items():
                hashes, timings = hash_disc_input(inputs[name], root / "spool", False, 1024, True)

                self.assertEqual(hashes, expected_hashes(data))
                self.assertIn("rvz_reader_seconds", timings)
                self.assertIn("rvz_total_seconds", timings)
                self.assertNotIn("zip_spool_seconds", timings)

    def test_hash_disc_input_hashes_zip_iso_and_gcm_decompressed_bytes(self) -> None:
        payloads = {
            "nested/plain.iso": b"zip iso bytes" * 1000,
            "nested/plain.gcm": b"zip gcm bytes" * 1000,
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with zipfile.ZipFile(root / "archive.zip", "w", zipfile.ZIP_DEFLATED) as archive:
                for name, data in payloads.items():
                    archive.writestr(name, data)

            inputs = {disc_input.member: disc_input for disc_input in iter_disc_inputs(root)}
            for spooled in (False, True):
                for name, data in payloads.items():
                    hashes, timings = hash_disc_input(inputs[name], root / "spool", spooled, 1024, True)

                    self.assertEqual(hashes, expected_hashes(data))
                    self.assertIn("rvz_reader_seconds", timings)
                    self.assertIn("rvz_total_seconds", timings)
                    if spooled:
                        self.assertIn("zip_spool_seconds", timings)
                    else:
                        self.assertNotIn("zip_spool_seconds", timings)


if __name__ == "__main__":
    unittest.main()
