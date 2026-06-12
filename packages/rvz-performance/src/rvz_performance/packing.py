"""NumPy implementations of the RVZ padding generator."""

import importlib
import struct
from functools import lru_cache
from typing import Any, List

from .packing_utils import RVZPerformanceError, validate_padding_args

_MASK32 = 0xFFFFFFFF
_PRNG_WORDS = 521
_PRNG_J = 32
_PRNG_SEED_WORDS = 17
_NUMPY_MODULE: Any = None


def _numpy() -> Any:  # noqa: ANN401
    global _NUMPY_MODULE

    if _NUMPY_MODULE is None:
        try:
            _NUMPY_MODULE = importlib.import_module("numpy")
        except ImportError as exc:
            raise RVZPerformanceError("NumPy padding implementations require numpy") from exc
    return _NUMPY_MODULE


def _seed_buffer(seed: bytes) -> List[int]:
    buffer = list(struct.unpack(">17I", seed))
    for i in range(_PRNG_SEED_WORDS, _PRNG_WORDS):
        value = ((buffer[i - 17] << 23) & _MASK32) ^ (buffer[i - 16] >> 9) ^ buffer[i - 1]
        buffer.append(value & _MASK32)
    return buffer


def _advance_prng_numpy(buffer: Any, numpy: Any) -> None:  # noqa: ANN401
    buffer[:_PRNG_J] ^= buffer[_PRNG_WORDS - _PRNG_J : _PRNG_WORDS]
    rows = buffer[:512].reshape(16, 32)
    numpy.bitwise_xor.accumulate(rows, axis=0, out=rows)
    buffer[512:_PRNG_WORDS] ^= buffer[480 : 480 + (_PRNG_WORDS - 512)]


def generate_padding_numpy(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate RVZ pseudorandom padding bytes using NumPy vector operations."""

    validate_padding_args(seed, size, offset)
    numpy = _numpy()

    if size == 0:
        return b""

    buffer = numpy.array(_seed_buffer(seed), dtype=numpy.uint32)
    for _ in range(4):
        _advance_prng_numpy(buffer, numpy)

    words_to_skip, bytes_to_skip = divmod(offset, 4)
    while words_to_skip >= _PRNG_WORDS:
        _advance_prng_numpy(buffer, numpy)
        words_to_skip -= _PRNG_WORDS

    index = words_to_skip
    needed_words = (bytes_to_skip + size + 3) // 4
    words = numpy.empty(needed_words, dtype=numpy.uint32)
    written = 0
    while written < needed_words:
        if index == _PRNG_WORDS:
            _advance_prng_numpy(buffer, numpy)
            index = 0
        count = min(_PRNG_WORDS - index, needed_words - written)
        words[written : written + count] = buffer[index : index + count]
        written += count
        index += count

    output_words = numpy.empty((needed_words, 4), dtype=numpy.uint8)
    output_words[:, 0] = words >> 24
    output_words[:, 1] = words >> 18
    output_words[:, 2] = words >> 8
    output_words[:, 3] = words
    return output_words.reshape(needed_words * 4).tobytes()[bytes_to_skip : bytes_to_skip + size]


@lru_cache(maxsize=8192)
def _generate_padding_cached_numpy(seed: bytes, size: int, offset: int) -> bytes:
    return generate_padding_numpy(seed, size, offset)


def generate_padding_cached_numpy(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate RVZ padding using NumPy plus exact tuple caching."""

    validate_padding_args(seed, size, offset)
    return _generate_padding_cached_numpy(seed, size, offset)
