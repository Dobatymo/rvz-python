import contextlib
import hashlib
import io
import tempfile
import unittest
import zipfile
import zlib
from pathlib import Path

from rvz.cli import main

from .utils import build_minimal_rvz


class RVZCliTests(unittest.TestCase):
    def test_hash_prints_reconstructed_iso_hashes(self) -> None:
        blob, iso = build_minimal_rvz()
        with tempfile.TemporaryDirectory() as tmp:
            rvz_path = Path(tmp) / "game.rvz"
            rvz_path.write_bytes(blob)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(["hash", str(rvz_path), "-a", "sha1", "-a", "crc32"])

        self.assertEqual(status, 0)
        self.assertEqual(
            stdout.getvalue().splitlines(),
            [
                f"sha1: {hashlib.sha1(iso).hexdigest()}",
                f"crc32: {zlib.crc32(iso) & 0xFFFFFFFF:08x}",
            ],
        )

    def test_hash_reads_zip_member_without_extracting_rvz(self) -> None:
        blob, iso = build_minimal_rvz()
        with tempfile.TemporaryDirectory() as tmp:
            archive_path = Path(tmp) / "archive.zip"
            with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.writestr("nested/game.rvz", blob)

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                status = main(["hash", f"{archive_path}!nested/game.rvz"])

        self.assertEqual(status, 0)
        self.assertEqual(stdout.getvalue().strip(), f"sha1: {hashlib.sha1(iso).hexdigest()}")

    def test_extract_writes_reconstructed_iso(self) -> None:
        blob, iso = build_minimal_rvz()
        with tempfile.TemporaryDirectory() as tmp:
            rvz_path = Path(tmp) / "game.rvz"
            iso_path = Path(tmp) / "game.iso"
            rvz_path.write_bytes(blob)

            status = main(["extract", str(rvz_path), str(iso_path)])

            self.assertEqual(status, 0)
            self.assertEqual(iso_path.read_bytes(), iso)


if __name__ == "__main__":
    unittest.main()
