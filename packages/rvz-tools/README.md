# rvz-tools

Batch hashing, report comparison, DAT comparison, and duplicate detection tools
for the `rvz` package.

Installed commands:

- `rvz-redump-hash`
- `rvz-compare-reports`
- `rvz-compare-dat`
- `rvz-find-duplicates`

`rvz-compare-dat` loads every top-level `*.dat` file from `datfiles` by
default. Use `--dat-dir PATH` to select another directory, and `--dat PATH`
to add individual DAT files.

With `rvz-redump-hash --resume`, add `--retry-errors` to discard prior
non-`ok` rows and process those inputs again. `--retry-errors` requires
`--resume`.
