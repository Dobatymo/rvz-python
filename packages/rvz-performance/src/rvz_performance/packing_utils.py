"""Shared validation for accelerated RVZ padding implementations."""


class RVZPerformanceError(ValueError):
    """Raised when accelerated padding arguments are invalid."""


def validate_padding_args(seed: bytes, size: int, offset: int) -> None:
    if len(seed) != 68:
        raise RVZPerformanceError("RVZ PRNG seed must be 68 bytes")
    if size < 0:
        raise RVZPerformanceError("padding size cannot be negative")
    if offset < 0:
        raise RVZPerformanceError("padding offset cannot be negative")
