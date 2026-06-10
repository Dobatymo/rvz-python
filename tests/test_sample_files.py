import hashlib
import os
import unittest
import zipfile
from pathlib import Path

from rvz import RVZReader

EXPECTED_ISO_SHA1 = "fa16772e967ad667ebff39fb6b035ff1f80bc8e4"
RVZ_SAMPLE = Path("Legend of Zelda, The - Collector's Edition (Europe) (En,Fr,De,Es,It).rvz")
ZIP_SAMPLE = Path("Legend of Zelda, The - Collector's Edition (Europe) (En,Fr,De,Es,It).zip")
ZIP_MEMBER = "Legend of Zelda, The - Collector's Edition (Europe) (En,Fr,De,Es,It).rvz"
ISO_SAMPLE = Path("Legend of Zelda, The - Collector's Edition (Europe) (En,Fr,De,Es,It).iso")
EXPECTED_WII_ISO_SHA1 = "af82fff2a46d7a2a1a7c759fa432b2398250a85b"
WII_RVZ_SAMPLE = Path("Super Fruit Fall (Europe).rvz")
WII_ZIP_SAMPLE = Path("Super Fruit Fall (Europe).zip")
WII_ZIP_MEMBER = "Super Fruit Fall (Europe).rvz"
WII_ISO_SAMPLE = Path("Super Fruit Fall (Europe).iso")


def file_sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as fileobj:
        for chunk in iter(lambda: fileobj.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


@unittest.skipUnless(
    os.environ.get("RVZ_RUN_SAMPLE_TESTS") == "1",
    "set RVZ_RUN_SAMPLE_TESTS=1 to run local large-file integration tests",
)
class SampleFileTests(unittest.TestCase):
    def test_sample_iso_matches_expected_hash(self) -> None:
        self.assertTrue(ISO_SAMPLE.exists(), f"{ISO_SAMPLE} is missing")
        self.assertEqual(file_sha1(ISO_SAMPLE), EXPECTED_ISO_SHA1)

    def test_sample_rvz_stream_matches_iso_hash(self) -> None:
        self.assertTrue(RVZ_SAMPLE.exists(), f"{RVZ_SAMPLE} is missing")
        with RVZReader(RVZ_SAMPLE) as reader:
            self.assertEqual(reader.hash_iso("sha1"), EXPECTED_ISO_SHA1)

    def test_sample_zip_member_stream_matches_iso_hash(self) -> None:
        self.assertTrue(ZIP_SAMPLE.exists(), f"{ZIP_SAMPLE} is missing")
        with zipfile.ZipFile(ZIP_SAMPLE) as archive:
            with archive.open(ZIP_MEMBER) as fileobj:
                with RVZReader(fileobj) as reader:
                    self.assertEqual(reader.hash_iso("sha1"), EXPECTED_ISO_SHA1)


@unittest.skipUnless(
    os.environ.get("RVZ_RUN_WII_SAMPLE_TESTS") == "1",
    "set RVZ_RUN_WII_SAMPLE_TESTS=1 to run slow local Wii integration tests",
)
class WiiSampleFileTests(unittest.TestCase):
    def test_wii_sample_iso_matches_expected_hash(self) -> None:
        self.assertTrue(WII_ISO_SAMPLE.exists(), f"{WII_ISO_SAMPLE} is missing")
        self.assertEqual(file_sha1(WII_ISO_SAMPLE), EXPECTED_WII_ISO_SHA1)

    def test_wii_sample_rvz_stream_matches_iso_hash(self) -> None:
        self.assertTrue(WII_RVZ_SAMPLE.exists(), f"{WII_RVZ_SAMPLE} is missing")
        with RVZReader(WII_RVZ_SAMPLE) as reader:
            self.assertEqual(reader.hash_iso("sha1"), EXPECTED_WII_ISO_SHA1)

    def test_wii_sample_zip_member_stream_matches_iso_hash(self) -> None:
        self.assertTrue(WII_ZIP_SAMPLE.exists(), f"{WII_ZIP_SAMPLE} is missing")
        with zipfile.ZipFile(WII_ZIP_SAMPLE) as archive:
            with archive.open(WII_ZIP_MEMBER) as fileobj:
                with RVZReader(fileobj) as reader:
                    self.assertEqual(reader.hash_iso("sha1"), EXPECTED_WII_ISO_SHA1)
