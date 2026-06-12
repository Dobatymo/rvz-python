"""Wii partition hashing and encryption helpers."""

import hashlib
import warnings
from typing import Any, List, Optional, Sequence, Tuple

AES_KEY_SIZE = 16
BLOCKS_PER_GROUP = 0x40
BLOCK_HEADER_SIZE = 0x0400
BLOCK_DATA_SIZE = 0x7C00
BLOCK_TOTAL_SIZE = BLOCK_HEADER_SIZE + BLOCK_DATA_SIZE
GROUP_HEADER_SIZE = BLOCK_HEADER_SIZE * BLOCKS_PER_GROUP
GROUP_DATA_SIZE = BLOCK_DATA_SIZE * BLOCKS_PER_GROUP
GROUP_TOTAL_SIZE = BLOCK_TOTAL_SIZE * BLOCKS_PER_GROUP

H0_OFFSET = 0
H0_SIZE = 31 * hashlib.sha1().digest_size
PADDING_0_OFFSET = H0_OFFSET + H0_SIZE
H1_OFFSET = PADDING_0_OFFSET + 20
H1_SIZE = 8 * hashlib.sha1().digest_size
PADDING_1_OFFSET = H1_OFFSET + H1_SIZE
H2_OFFSET = PADDING_1_OFFSET + 32
H2_SIZE = 8 * hashlib.sha1().digest_size

ZERO_IV = b"\0" * AES_KEY_SIZE
HashException = Tuple[int, bytes]
_CIPHER_TYPES: Optional[Tuple[Any, Any, Any]] = None


class WiiEncryptionError(ValueError):
    """Raised when Wii partition encryption input is malformed."""


def _get_cipher_types() -> Tuple[Any, Any, Any]:
    global _CIPHER_TYPES
    if _CIPHER_TYPES is None:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", message="Python 3.8 is no longer supported by the Python core team")
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

        _CIPHER_TYPES = (Cipher, algorithms, modes)
    return _CIPHER_TYPES


def aes_cbc_encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    if len(key) != AES_KEY_SIZE:
        raise WiiEncryptionError("Wii partition keys must be 16 bytes")
    if len(iv) != AES_KEY_SIZE:
        raise WiiEncryptionError("Wii AES IVs must be 16 bytes")
    if len(data) % AES_KEY_SIZE:
        raise WiiEncryptionError("Wii AES data must be aligned to 16 bytes")

    Cipher, algorithms, modes = _get_cipher_types()
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def build_hash_blocks(data_blocks: Sequence[bytes]) -> List[bytearray]:
    if len(data_blocks) != BLOCKS_PER_GROUP:
        raise WiiEncryptionError(f"Wii hash groups must contain {BLOCKS_PER_GROUP} data blocks")

    hash_blocks = [bytearray(BLOCK_HEADER_SIZE) for _ in range(BLOCKS_PER_GROUP)]
    for block_index, data in enumerate(data_blocks):
        if len(data) != BLOCK_DATA_SIZE:
            raise WiiEncryptionError(f"Wii data blocks must be {BLOCK_DATA_SIZE} bytes")

        h0_hashes = b"".join(
            hashlib.sha1(data[offset : offset + 0x400]).digest() for offset in range(0, BLOCK_DATA_SIZE, 0x400)
        )
        h1_base = block_index - (block_index % 8)
        h1_digest_offset = H1_OFFSET + (block_index - h1_base) * hashlib.sha1().digest_size

        hash_blocks[block_index][H0_OFFSET : H0_OFFSET + H0_SIZE] = h0_hashes
        hash_blocks[h1_base][h1_digest_offset : h1_digest_offset + hashlib.sha1().digest_size] = hashlib.sha1(
            h0_hashes
        ).digest()

    for h1_base in range(0, BLOCKS_PER_GROUP, 8):
        h1_hashes = bytes(hash_blocks[h1_base][H1_OFFSET : H1_OFFSET + H1_SIZE])
        h2_digest_offset = H2_OFFSET + (h1_base // 8) * hashlib.sha1().digest_size
        hash_blocks[0][h2_digest_offset : h2_digest_offset + hashlib.sha1().digest_size] = hashlib.sha1(
            h1_hashes
        ).digest()

        for block_index in range(h1_base + 1, h1_base + 8):
            hash_blocks[block_index][H1_OFFSET : H1_OFFSET + H1_SIZE] = h1_hashes

    h2_hashes = bytes(hash_blocks[0][H2_OFFSET : H2_OFFSET + H2_SIZE])
    for block_index in range(1, BLOCKS_PER_GROUP):
        hash_blocks[block_index][H2_OFFSET : H2_OFFSET + H2_SIZE] = h2_hashes

    return hash_blocks


def apply_hash_exceptions(hash_blocks: Sequence[bytearray], exceptions: Sequence[HashException]) -> None:
    for offset, digest in exceptions:
        if len(digest) != hashlib.sha1().digest_size:
            raise WiiEncryptionError("Wii hash exceptions must contain SHA-1 digests")

        block_index, offset_in_block = divmod(offset, BLOCK_HEADER_SIZE)
        if block_index >= BLOCKS_PER_GROUP or offset_in_block + len(digest) > BLOCK_HEADER_SIZE:
            raise WiiEncryptionError("Wii hash exception offset is out of range")

        hash_blocks[block_index][offset_in_block : offset_in_block + len(digest)] = digest


def encrypt_group(data_blocks: Sequence[bytes], key: bytes, exceptions: Sequence[HashException] = ()) -> bytes:
    hash_blocks = build_hash_blocks(data_blocks)
    apply_hash_exceptions(hash_blocks, exceptions)

    output = bytearray(GROUP_TOTAL_SIZE)
    for block_index, (hash_block, data_block) in enumerate(zip(hash_blocks, data_blocks)):
        block_offset = block_index * BLOCK_TOTAL_SIZE
        encrypted_hash_block = aes_cbc_encrypt(key, ZERO_IV, bytes(hash_block))
        encrypted_data_block = aes_cbc_encrypt(key, encrypted_hash_block[0x3D0:0x3E0], data_block)

        output[block_offset : block_offset + BLOCK_HEADER_SIZE] = encrypted_hash_block
        output[block_offset + BLOCK_HEADER_SIZE : block_offset + BLOCK_TOTAL_SIZE] = encrypted_data_block

    return bytes(output)
