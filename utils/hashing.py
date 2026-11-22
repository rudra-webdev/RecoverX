"""
Hashing and Deduplication Utilities for RecoverX
Provides streaming cryptographic hashes (SHA-256) for forensic verification.
"""
import hashlib
from pathlib import Path
from typing import Union, BinaryIO

def compute_sha256(data_or_path: Union[bytes, bytearray, str, Path]) -> str:
    """Computes SHA-256 for in-memory bytes or a file path."""
    hasher = hashlib.sha256()
    if isinstance(data_or_path, (bytes, bytearray, memoryview)):
        hasher.update(data_or_path)
        return hasher.hexdigest()

    file_path = Path(data_or_path)
    if not file_path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            hasher.update(chunk)
    return hasher.hexdigest()

def compute_sha256_stream(stream: BinaryIO, max_length: int = -1, chunk_size: int = 1024 * 1024) -> str:
    """Computes SHA-256 from an open binary stream up to max_length bytes."""
    hasher = hashlib.sha256()
    bytes_read = 0
    while True:
        if max_length >= 0:
            to_read = min(chunk_size, max_length - bytes_read)
            if to_read <= 0:
                break
        else:
            to_read = chunk_size

        chunk = stream.read(to_read)
        if not chunk:
            break
        hasher.update(chunk)
        bytes_read += len(chunk)

    return hasher.hexdigest()

