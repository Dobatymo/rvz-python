# rvz workspace

This repository is a uv workspace containing three independently buildable
Python distributions with one shared lockfile:

- `rvz-performance` (`rvz_performance`): optional NumPy and CFFI padding accelerators.
- `rvz` (`rvz`): the RVZ reader and CLI, with a pure-Python padding implementation.
- `rvz-tools` (`rvz_tools`): Redump batch hashing and comparison commands.

The `rvz` package does not require `rvz-performance`. Install the optional
accelerators through `rvz[performance]`; padding implementation 1 remains pure
Python and is always available.

## Development

```powershell
python -m uv sync --locked --all-packages --all-extras
python -m uv run --locked mypy packages/rvz-performance
python -m uv run --locked mypy packages/rvz
python -m uv run --locked mypy packages/rvz-tools
python -m uv run --locked ruff check .
python -m uv run --locked --directory packages/rvz pytest .
python -m uv run --locked --directory packages/rvz-performance pytest .
python -m uv run --locked --directory packages/rvz-tools pytest .
python -m uv build --all-packages
```

Run mypy once per workspace member rather than as `mypy .`. Each independent
distribution has its own top-level `tests` package, so combining all members in
one mypy invocation creates duplicate module names.

Run pytest from each workspace member directory for the same reason. A single
root pytest invocation with the default import mode cannot collect the three
independent top-level `tests` packages correctly.

Run commands for a specific workspace package from the repository root with
`uv run --package PACKAGE COMMAND`.

## Core Library

```python
from rvz import RVZReader

with RVZReader("game.rvz") as reader:
    print(reader.hash_iso("sha1"))
    reader.extract_iso("game.iso")
```

```powershell
python -m uv run --locked --package rvz rvz info game.rvz
python -m uv run --locked --package rvz rvz hash archive.zip!game.rvz
python -m uv run --locked --package rvz --extra performance rvz hash game.rvz --padding-implementation 4
```

## Redump Tools

The scanner accepts raw `.rvz`, `.iso`, and `.gcm` files and ZIP members with
those suffixes. Pass one or more files or directories after `--in-paths`.

```powershell
python -m uv run --locked --package rvz-tools rvz-redump-hash --resume --mode dolphintool --in-paths PATH_TO_REDUMP [MORE_PATHS...] --out-path hash-compare
python -m uv run --locked --package rvz-tools rvz-redump-hash --resume --mode rvz --in-paths PATH_TO_REDUMP [MORE_PATHS...] --out-path hash-compare
python -m uv run --locked --package rvz-tools rvz-redump-hash --resume --mode rvz-spooled --in-paths PATH_TO_REDUMP [MORE_PATHS...] --out-path hash-compare
python -m uv run --locked --package rvz-tools rvz-compare-reports --run-dir hash-compare
python -m uv run --locked --package rvz-tools rvz-compare-dat --hashes-json hash-compare/rvz-direct/hashes.json
python -m uv run --locked --package rvz-tools rvz-find-duplicates --hashes-json hash-compare/rvz-direct/hashes.json
```

`rvz-compare-dat` loads every top-level `*.dat` file from `datfiles` by
default. Use `--dat-dir PATH` to select another directory, and `--dat PATH`
to add individual DAT files.

With `rvz-redump-hash --resume`, add `--retry-errors` to discard prior
non-`ok` rows and process those inputs again. `--retry-errors` requires
`--resume`.

Use `--include-md5` on all three batch modes when MD5 is needed. Duplicate
detection uses SHA1 by default and accepts `--algorithm md5` or
`--algorithm crc32`.

## Package Documentation

- [Core library](packages/rvz/README.md)
- [Performance package](packages/rvz-performance/README.md)
- [Tools package](packages/rvz-tools/README.md)
- [Padding benchmarks](packages/rvz-performance/PERFORMANCE.md)
