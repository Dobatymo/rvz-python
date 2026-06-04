rvz
===

Pure Python RVZ reader focused on streaming the reconstructed ISO byte stream.

The public API accepts either a path or a seekable binary file object, so RVZ
members can be read directly from `zipfile.ZipFile.open(...)` without extracting
the RVZ to disk first.

```python
from rvz import RVZReader

with RVZReader("game.rvz") as reader:
    print(reader.hash_iso("sha1"))
    reader.extract_iso("game.iso")
```

The command line interface supports the same streaming path:

```powershell
python -m rvz.cli info game.rvz
python -m rvz.cli hash game.rvz -a sha1
python -m rvz.cli extract game.rvz game.iso
python -m rvz.cli hash archive.zip!game.rvz
```

Large local sample files are ignored by git. To run the optional sample-file
integration checks for the GameCube sample:

```powershell
$env:RVZ_RUN_SAMPLE_TESTS = "1"
python -m unittest tests.test_sample_files
```

The real Wii sample reconstructs a 4.7 GB ISO stream and is much slower:

```powershell
$env:RVZ_RUN_WII_SAMPLE_TESTS = "1"
python -m unittest tests.test_sample_files.WiiSampleFileTests
```

Current reader support:

- RVZ container/header validation
- Zstandard, bzip2, LZMA/LZMA2, PURGE, and uncompressed RVZ data
- raw-data/GameCube RVZ reconstruction
- Wii partition hash block regeneration and AES-CBC encryption using `cryptography`
- RVZ hash exception lists for Wii partition reconstruction
- RVZ pseudorandom padding unpacking
- path and seekable file-object inputs
