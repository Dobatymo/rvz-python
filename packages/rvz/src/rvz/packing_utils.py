"""Shared helpers for RVZ packing implementations."""


class RVZPackingError(ValueError):
    """Raised when RVZ packed data is malformed."""


def _validate_padding_args(seed: bytes, size: int, offset: int) -> None:
    if len(seed) != 68:
        raise RVZPackingError("RVZ PRNG seed must be 68 bytes")
    if size < 0:
        raise RVZPackingError("padding size cannot be negative")
    if offset < 0:
        raise RVZPackingError("padding offset cannot be negative")
