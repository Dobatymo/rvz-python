"""Native helpers for RVZ packing."""

import importlib
import os
import tempfile
from typing import Any

from .packing_utils import RVZPerformanceError, validate_padding_args

_CFFI_FFI: Any = None
_CFFI_LIB: Any = None
_CFFI_SOURCE = r"""
#include <stdint.h>
#include <stddef.h>

#define RVZ_WORDS 521
#define RVZ_J 32

static void rvz_advance_prng(uint32_t buffer[RVZ_WORDS])
{
    size_t i;
    for (i = 0; i < RVZ_J; ++i)
        buffer[i] ^= buffer[i + RVZ_WORDS - RVZ_J];
    for (i = RVZ_J; i < RVZ_WORDS; ++i)
        buffer[i] ^= buffer[i - RVZ_J];
}

void rvz_generate_padding(const unsigned char seed[68], size_t size, size_t offset, unsigned char *output)
{
    uint32_t buffer[RVZ_WORDS];
    size_t i;
    size_t index;
    size_t written = 0;
    size_t words_to_skip = offset / 4;
    size_t bytes_to_skip = offset % 4;

    for (i = 0; i < 17; ++i) {
        size_t position = i * 4;
        buffer[i] = ((uint32_t)seed[position] << 24)
            | ((uint32_t)seed[position + 1] << 16)
            | ((uint32_t)seed[position + 2] << 8)
            | (uint32_t)seed[position + 3];
    }
    for (i = 17; i < RVZ_WORDS; ++i)
        buffer[i] = (buffer[i - 17] << 23) ^ (buffer[i - 16] >> 9) ^ buffer[i - 1];

    for (i = 0; i < 4; ++i)
        rvz_advance_prng(buffer);

    while (words_to_skip >= RVZ_WORDS) {
        rvz_advance_prng(buffer);
        words_to_skip -= RVZ_WORDS;
    }
    index = words_to_skip;

    if (bytes_to_skip != 0 && written < size) {
        uint32_t word = buffer[index];
        unsigned char word_bytes[4];
        word_bytes[0] = (unsigned char)(word >> 24);
        word_bytes[1] = (unsigned char)(word >> 18);
        word_bytes[2] = (unsigned char)(word >> 8);
        word_bytes[3] = (unsigned char)word;
        ++index;
        if (index == RVZ_WORDS) {
            rvz_advance_prng(buffer);
            index = 0;
        }
        for (i = bytes_to_skip; i < 4 && written < size; ++i)
            output[written++] = word_bytes[i];
    }

    while (written < size) {
        uint32_t word = buffer[index];
        output[written++] = (unsigned char)(word >> 24);
        if (written < size)
            output[written++] = (unsigned char)(word >> 18);
        if (written < size)
            output[written++] = (unsigned char)(word >> 8);
        if (written < size)
            output[written++] = (unsigned char)word;

        ++index;
        if (index == RVZ_WORDS) {
            rvz_advance_prng(buffer);
            index = 0;
        }
    }
}
"""


def _cffi() -> Any:  # noqa: ANN401
    global _CFFI_FFI, _CFFI_LIB

    if _CFFI_FFI is None or _CFFI_LIB is None:
        try:
            cffi = importlib.import_module("cffi")
        except ImportError as exc:
            raise RVZPerformanceError("the CFFI padding implementation requires cffi") from exc

        ffi = cffi.FFI()
        ffi.cdef(
            "void rvz_generate_padding(const unsigned char seed[68], "
            "size_t size, size_t offset, unsigned char *output);"
        )
        tmpdir = os.path.join(tempfile.gettempdir(), "rvz-cffi")
        os.makedirs(tmpdir, exist_ok=True)
        _CFFI_LIB = ffi.verify(_CFFI_SOURCE, tmpdir=tmpdir)
        _CFFI_FFI = ffi

    return _CFFI_FFI, _CFFI_LIB


def generate_padding_cffi(seed: bytes, size: int, offset: int = 0) -> bytes:
    """Generate RVZ pseudorandom padding bytes using a native C loop via CFFI."""

    validate_padding_args(seed, size, offset)
    if size == 0:
        return b""

    ffi, lib = _cffi()
    output = bytearray(size)
    seed_buffer = ffi.new("unsigned char[]", seed)
    output_buffer = ffi.from_buffer("unsigned char[]", output)
    lib.rvz_generate_padding(seed_buffer, size, offset, output_buffer)
    return bytes(output)
