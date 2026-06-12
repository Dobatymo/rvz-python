"""RVZ packing decoder with an always-available pure Python implementation."""

import importlib
import struct
from functools import lru_cache
from typing import Callable, List

from .packing_utils import RVZPackingError, _validate_padding_args

_MASK32 = 0xFFFFFFFF
_PRNG_WORDS = 521
_PRNG_J = 32
_PRNG_SEED_WORDS = 17

PaddingGenerator = Callable[[bytes, int, int], bytes]


def _seed_buffer(seed: bytes) -> List[int]:
    buffer = list(struct.unpack(">17I", seed))
    for i in range(_PRNG_SEED_WORDS, _PRNG_WORDS):
        value = ((buffer[i - 17] << 23) & _MASK32) ^ (buffer[i - 16] >> 9) ^ buffer[i - 1]
        buffer.append(value & _MASK32)
    return buffer


def _advance_prng(buffer: List[int]) -> None:
    for i in range(_PRNG_J):
        buffer[i] = (buffer[i] ^ buffer[i + _PRNG_WORDS - _PRNG_J]) & _MASK32
    for i in range(_PRNG_J, _PRNG_WORDS):
        buffer[i] = (buffer[i] ^ buffer[i - _PRNG_J]) & _MASK32


def generate_padding(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate RVZ pseudorandom padding bytes in pure Python."""

    _validate_padding_args(seed, size, offset)

    buffer = _seed_buffer(seed)
    for _ in range(4):
        _advance_prng(buffer)

    index = 0
    output = bytearray()
    words_to_skip, bytes_to_skip = divmod(offset, 4)
    index += words_to_skip
    while index >= _PRNG_WORDS:
        _advance_prng(buffer)
        index -= _PRNG_WORDS

    if bytes_to_skip:
        word = buffer[index]
        word_bytes = bytes(((word >> 24) & 0xFF, (word >> 18) & 0xFF, (word >> 8) & 0xFF, word & 0xFF))
        index += 1
        if index == _PRNG_WORDS:
            _advance_prng(buffer)
            index = 0
        output.extend(word_bytes[bytes_to_skip:])

    while len(output) < size:
        word = buffer[index]
        output.extend(((word >> 24) & 0xFF, (word >> 18) & 0xFF, (word >> 8) & 0xFF, word & 0xFF))
        index += 1
        if index == _PRNG_WORDS:
            _advance_prng(buffer)
            index = 0

    return bytes(output[:size])


@lru_cache(maxsize=None)
def _performance_generator(name: str) -> PaddingGenerator:
    try:
        module = importlib.import_module("rvz_performance")
    except ImportError as exc:
        raise RVZPackingError(
            "padding implementations 2, 3, and 4 require rvz-performance; install rvz[performance]"
        ) from exc

    generator = getattr(module, name, None)
    if not callable(generator):
        raise RVZPackingError(f"rvz-performance does not provide {name}")
    return generator


def generate_padding_numpy(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate padding with the optional NumPy accelerator."""

    _validate_padding_args(seed, size, offset)
    return _performance_generator("generate_padding_numpy")(seed, size, offset)


def generate_padding_cached_numpy(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate padding with the optional cached NumPy accelerator."""

    _validate_padding_args(seed, size, offset)
    return _performance_generator("generate_padding_cached_numpy")(seed, size, offset)


def generate_padding_cffi(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate padding with the optional CFFI accelerator."""

    _validate_padding_args(seed, size, offset)
    return _performance_generator("generate_padding_cffi")(seed, size, offset)


def get_padding_generator(implementation: int) -> PaddingGenerator:
    if implementation == 1:
        return generate_padding
    if implementation == 2:
        return generate_padding_numpy
    if implementation == 3:
        return generate_padding_cached_numpy
    if implementation == 4:
        return generate_padding_cffi
    raise RVZPackingError(f"unknown padding implementation {implementation}")


def decode_rvz_packing(
    data: bytes,
    output_size: int,
    data_offset: int = 0,
    padding_implementation: int = 1,
) -> bytes:
    """Decode an RVZ packed group payload."""

    position = 0
    output = bytearray()
    padding_generator = get_padding_generator(padding_implementation)

    while position < len(data):
        if position + 4 > len(data):
            raise RVZPackingError("truncated RVZ packing segment header")

        segment_size = struct.unpack_from(">I", data, position)[0]
        position += 4
        is_padding = bool(segment_size & 0x80000000)
        segment_size &= 0x7FFFFFFF

        if is_padding:
            if position + 68 > len(data):
                raise RVZPackingError("truncated RVZ packing seed")
            seed = data[position : position + 68]
            position += 68
            padding_offset = (data_offset + len(output)) % 0x8000
            output.extend(padding_generator(seed, segment_size, padding_offset))
        else:
            end = position + segment_size
            if end > len(data):
                raise RVZPackingError("truncated RVZ packing literal segment")
            output.extend(data[position:end])
            position = end

        if len(output) > output_size:
            raise RVZPackingError("RVZ packing decoded more bytes than expected")

    if len(output) != output_size:
        raise RVZPackingError(f"RVZ packing decoded {len(output)} bytes, expected {output_size}")

    return bytes(output)
