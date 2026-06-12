# RVZ Padding Performance Notes

Date: 2026-06-10

## Summary

RVZ hashing is slow on Wii RVZ files because most time is spent regenerating RVZ pseudorandom padding, not reading ZIP data, zstd decompression, AES, or hashing.

The main hotspot is `packages/rvz/src/rvz/packing.py`:

- `decode_rvz_packing()` calls `generate_padding()` for each padding segment.
- `generate_padding()` currently advances the RVZ lagged Fibonacci generator word by word in Python and emits four bytes per word in Python.
- In a full `Super Fruit Fall (Europe).zip` cProfile run, `generate_padding()` dominated the runtime: about 1162 seconds cumulative inside a 1212 second profiled run.

## Super Fruit Fall Sample

File: `Super Fruit Fall (Europe).zip`

Metadata:

- RVZ member: `Super Fruit Fall (Europe).rvz`
- Disc type: Wii
- Compression: zstandard
- Chunk size: 131072
- ISO size: 4699979776
- Groups: 35859
- Partitions: 2

Measured reads:

- ZIP member read: about 0.118 seconds.
- `RVZReader` initialization from ZIP: about 0.073 seconds.
- 64 MiB raw RVZ region: about 10.5 seconds, around 6.1 MiB/s.
- 64 MiB Wii partition region: about 13.2 seconds, around 4.9 MiB/s.

Timer breakdown for 64 MiB Wii partition read:

- `_encrypt_partition_group`: about 13.1 seconds.
- `_decode_partition_group`: about 12.6 seconds.
- `decode_rvz_packing`: about 12.5 seconds.
- `encrypt_wii_group`: about 0.3 seconds.
- `aes_cbc_encrypt`: about 0.1 seconds.
- `build_hash_blocks`: about 0.1 seconds.

Packing tuple probe:

- 64 MiB read from ZIP prefix: 503 padding tuples, 10 unique exact `(seed, size, offset)` keys, 493 repeat hits.
- Raw region: exact tuple caching has strong potential.
- Wii partition region: padding keys are mostly unique, so exact tuple caching alone is not enough.

## New Super Mario Bros. Wii Sample

File: `New Super Mario Bros. Wii (Europe) (En,Fr,De,Es,It) (Rev 2).zip`

Metadata:

- RVZ member: `New Super Mario Bros. Wii (Europe) (En,Fr,De,Es,It) (Rev 2).rvz`
- RVZ member size: 443297352 bytes
- ZIP compressed member size: 440962206 bytes
- Disc type: Wii
- Compression: zstandard
- Chunk size: 131072
- ISO size: 4699979776
- Raw data entries: 5
- Partition entries: 2
- Groups: 35859

64 MiB tuple probe results:

- ISO prefix: 8 tuples, 8 unique, 0 repeat hits.
- First raw interval: 4 tuples, 4 unique, 0 repeat hits.
- Largest raw interval, 58654720 bytes: 448 tuples, 2 unique, 446 repeat hits.
- First partition, 2 MiB: 2 tuples, 2 unique, 0 repeat hits.
- Largest partition, 64 MiB: 2432 tuples, 2432 unique, 0 repeat hits.

For the largest partition sample, the common padding sizes were:

- 32768 bytes: 1536 segments
- 28672 bytes: 128 segments
- 4096 bytes: 128 segments
- 24576 bytes: 128 segments
- 8192 bytes: 128 segments
- 20480 bytes: 128 segments
- 12288 bytes: 128 segments
- 16384 bytes: 128 segments

## Implementation Benchmarks

The benchmark command hashed the full reconstructed ISO from the Mario ZIP member using 64 MiB hash blocks.

## Research Notes

Numba and Cython are the usual recommendations for Python code that is dominated by scalar loops. Numba's documentation says it is a just-in-time compiler that compiles decorated functions to machine code at call time and works well on loop-heavy numeric code. Its performance guide also says nopython mode produces faster executable code and that Numba is "perfectly happy with loops too." This matches the RVZ padding problem structurally, but Numba could not return a `bytes` object directly from a compiled byte list in a clean nopython implementation.

Cython's documentation points at typed memoryviews to avoid Python indexing and type-conversion overhead in tight loops. That is a good longer-term packaging option, but it would require a compiled extension build path.

CFFI compiled successfully in this Windows environment and keeps the optimized recurrence as a small native C loop in `rvz_performance/native.py`. It does not use NumPy and does not cache generated padding bytes.

References:

- [Numba 5 minute guide](https://numba.readthedocs.io/en/stable/user/5minguide.html)
- [Numba performance tips](https://numba.readthedocs.io/en/stable/user/performance-tips.html)
- [Cython memoryview guidance](https://cython.readthedocs.io/en/latest/src/userguide/numpy_tutorial.html#efficient-indexing-with-memoryviews)

The NumPy benchmark used NumPy 1.24.4. The CFFI benchmark used the package's
standard CFFI dependency.

Full Mario ISO hash benchmark:

| Implementation | Method | Elapsed | Throughput | SHA-1 |
| --- | --- | ---: | ---: | --- |
| 1 | Original pure Python | 764.6 s | 5.9 MiB/s | `91ff55875b0e0401e6246d5bc2a52d7a80517860` |
| 2 | `generate_padding_numpy` | 108.6 s | 41.3 MiB/s | `91ff55875b0e0401e6246d5bc2a52d7a80517860` |
| 3 | `generate_padding_cached_numpy` | 99.2 s | 45.2 MiB/s | `91ff55875b0e0401e6246d5bc2a52d7a80517860` |
| 4 | `generate_padding_cffi` | 39.7 s | 112.8 MiB/s | `91ff55875b0e0401e6246d5bc2a52d7a80517860` |

Implementation 4 was about 19.2x faster than the original full-file benchmark and about 2.5x faster than implementation 3.

Largest partition 64 MiB benchmark:

| Implementation | Elapsed | Throughput | SHA-1 |
| --- | ---: | ---: | --- |
| 1 | 8.67 s | 7.4 MiB/s | `37a836869e598dea6835de0171348cb6d8d3d38f` |
| 2 | 1.88 s | 34.1 MiB/s | `37a836869e598dea6835de0171348cb6d8d3d38f` |
| 3 | 1.53 s | 41.8 MiB/s | `37a836869e598dea6835de0171348cb6d8d3d38f` |
| 4 | 1.16 s | 55.4 MiB/s | `37a836869e598dea6835de0171348cb6d8d3d38f` |

## Implications

Exact `(seed, size, offset)` caching is useful for raw padding regions and can remove most repeated raw padding generation. It does not materially help the main Wii partition path in the tested Mario sample because exact keys were all unique across the 64 MiB largest-partition probe.

The most promising speedups are:

1. Use implementation 4 for performance-sensitive hashing or extraction when CFFI and a compiler are available.
2. Keep exact tuple caching as a layer above a faster generator for raw regions.
3. Benchmark against full Wii ZIP-member hashing, because small prefix reads can underrepresent the main partition cost.
