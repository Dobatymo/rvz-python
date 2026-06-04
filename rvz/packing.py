"""RVZ packing decoder."""

from __future__ import annotations

import struct

_MASK32 = 0xFFFFFFFF
_PRNG_WORDS = 521
_PRNG_J = 32
_PRNG_SEED_WORDS = 17


class RVZPackingError(ValueError):
    """Raised when RVZ packed data is malformed."""


def _advance_prng(buffer: list[int]) -> None:
    for i in range(_PRNG_J):
        buffer[i] = (buffer[i] ^ buffer[i + _PRNG_WORDS - _PRNG_J]) & _MASK32
    for i in range(_PRNG_J, _PRNG_WORDS):
        buffer[i] = (buffer[i] ^ buffer[i - _PRNG_J]) & _MASK32


def generate_padding(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate RVZ pseudorandom padding bytes."""

    if len(seed) != 68:
        raise RVZPackingError("RVZ PRNG seed must be 68 bytes")
    if size < 0:
        raise RVZPackingError("padding size cannot be negative")

    buffer = list(struct.unpack(">17I", seed))
    for i in range(_PRNG_SEED_WORDS, _PRNG_WORDS):
        value = ((buffer[i - 17] << 23) & _MASK32) ^ (buffer[i - 16] >> 9) ^ buffer[i - 1]
        buffer.append(value & _MASK32)

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


def decode_rvz_packing(data: bytes, output_size: int, data_offset: int = 0) -> bytes:
    """Decode an RVZ packed group payload."""

    position = 0
    output = bytearray()

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
            output.extend(generate_padding(seed, segment_size, padding_offset))
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
