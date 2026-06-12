# rvz

Pure Python reader for Dolphin RVZ disc images.

The public API accepts paths and seekable binary file objects, including members
opened directly with `zipfile.ZipFile.open(...)`.

```python
from rvz import RVZReader

with RVZReader("game.rvz") as reader:
    print(reader.hash_iso("sha1"))
```

The default padding implementation is pure Python. Install `rvz[performance]`
to enable the optional NumPy and CFFI implementations selected with
`padding_implementation=2`, `3`, or `4`.
