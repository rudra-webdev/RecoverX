"""
Signature-based File Carving Scanner for RecoverX
Carves files from raw disk images, dumps, or unallocated binary streams.
Supports progress callbacks for responsive GUI integration.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Callable, Union
import os

from utils.file_signatures import (
    SIGNATURE_DATABASE,
    SignatureDefinition,
    parse_riff_size,
    parse_bmp_size,
    parse_png_size,
    parse_zip_size,
    parse_7z_size,
    parse_mp4_size,
    parse_isobmff_size,
    parse_jpeg_size,
    parse_pdf_size,
    parse_gif_size,
    get_file_category
)
from engine.file_validator import FileValidator
from utils.hashing import compute_sha256
from utils.logging_config import logger
from config import CHUNK_SIZE, OVERLAP_SIZE, MAX_CARVE_FILE_SIZE

class CarvedItem:
    def __init__(
        self,
        offset: int,
        length: int,
        extension: str,
        data: bytes,
        sha256: str,
        is_valid: bool,
        confidence: float,
        details: Dict[str, Any],
        is_duplicate: bool = False,
        category: str = "Other",
        fragmented_warning: bool = False,
        original_path: Optional[str] = None
    ):
        self.offset = offset
        self.length = length
        self.extension = extension
        self.data = data
        self.sha256 = sha256
        self.is_valid = is_valid
        self.confidence = confidence
        self.details = details
        self.is_duplicate = is_duplicate
        self.category = category or get_file_category(extension)
        self.fragmented_warning = fragmented_warning
        self.original_path = original_path

    def to_dict(self) -> Dict[str, Any]:
        return {
            "offset": self.offset,
            "length": self.length,
            "extension": self.extension,
            "category": self.category,
            "sha256": self.sha256,
            "is_valid": self.is_valid,
            "confidence": self.confidence,
            "details": self.details,
            "is_duplicate": self.is_duplicate,
            "fragmented_warning": self.fragmented_warning,
            "original_path": self.original_path,
            "preview_available": self.category == "Images" and self.is_valid
        }

class SignatureScanner:
    def __init__(self, target_formats: Optional[List[str]] = None):
        self.target_formats = [f.lower() for f in target_formats] if target_formats else None
        self.signatures = self._filter_signatures()
        self.seen_hashes: Set[str] = set()

    def _filter_signatures(self) -> List[SignatureDefinition]:
        if not self.target_formats:
            return SIGNATURE_DATABASE
        return [sig for sig in SIGNATURE_DATABASE if sig.extension in self.target_formats]

    def scan_bytes(self, data: bytes, base_offset: int = 0, item_callback: Optional[Callable[[CarvedItem], None]] = None) -> List[CarvedItem]:
        """Carves supported files from an in-memory byte buffer using fast C-level pattern search."""
        carved_items: List[CarvedItem] = []
        data_len = len(data)
        if data_len == 0:
            return carved_items

        # Collect candidate signature match positions
        candidates = []
        for sig in self.signatures:
            for header in sig.headers:
                hdr_offset = sig.header_offset
                pos = 0
                while pos + len(header) <= data_len:
                    found_idx = data.find(header, pos)
                    if found_idx == -1:
                        break

                    if sig.extension in ("mp4", "mov", "m4a", "heic") and found_idx >= 4:
                        box_start = found_idx - 4
                    else:
                        box_start = max(0, found_idx - hdr_offset)

                    candidates.append((box_start, sig))
                    pos = found_idx + max(1, len(header))

        # Sort candidate positions in increasing offset order
        candidates.sort(key=lambda c: c[0])

        current_carved_end = 0
        for box_start, sig in candidates:
            if box_start < current_carved_end:
                # Skip candidate if it falls inside a previously carved valid item
                continue

            carve_res = self._carve_candidate(data, box_start, sig.extension)
            if carve_res:
                carved_bytes, estimated_len, is_frag = carve_res
                if len(carved_bytes) >= sig.min_size:
                    validation = FileValidator.validate(carved_bytes, sig.extension)
                    sha256 = compute_sha256(carved_bytes)
                    is_dup = sha256 in self.seen_hashes
                    self.seen_hashes.add(sha256)

                    detected_ext = validation.get("type", sig.extension)
                    detected_cat = validation.get("category", sig.category)

                    item = CarvedItem(
                        offset=base_offset + box_start,
                        length=len(carved_bytes),
                        extension=detected_ext,
                        data=carved_bytes,
                        sha256=sha256,
                        is_valid=validation["is_valid"],
                        confidence=validation["confidence"],
                        details=validation["details"],
                        is_duplicate=is_dup,
                        category=detected_cat,
                        fragmented_warning=is_frag
                    )
                    carved_items.append(item)
                    if item_callback:
                        item_callback(item)

                    current_carved_end = box_start + len(carved_bytes)

        return carved_items

    def _carve_candidate(self, data: bytes, offset: int, ext: str) -> Optional[tuple[bytes, int, bool]]:
        """Determines boundaries and extracts carved bytes. Returns (bytes, len, is_fragmented)."""
        sub = data[offset:]
        sub_len = len(sub)
        if sub_len == 0:
            return None

        length: Optional[int] = None
        is_fragmented = False

        if ext in ("webp", "avi", "wav"):
            length = parse_riff_size(sub, 0)
        elif ext == "bmp":
            length = parse_bmp_size(sub, 0)
        elif ext == "png":
            length = parse_png_size(sub, 0)
        elif ext == "zip":
            length = parse_zip_size(sub, 0)
        elif ext == "7z":
            length = parse_7z_size(sub, 0)
        elif ext in ("mp4", "mov", "m4a", "heic"):
            length = parse_isobmff_size(sub, 0)
        elif ext == "jpg":
            length = parse_jpeg_size(sub, 0)
        elif ext == "pdf":
            length = parse_pdf_size(sub, 0)
        elif ext == "gif":
            length = parse_gif_size(sub, 0)

        if length is not None:
            if length <= sub_len and length <= MAX_CARVE_FILE_SIZE:
                return sub[:length], length, False
            elif sub_len < length:
                # File appears truncated or fragmented
                is_fragmented = True
                return sub[:sub_len], sub_len, True

        # Fallback trailer scan
        sig_def = next((s for s in self.signatures if s.extension == ext), None)
        if sig_def and sig_def.trailers:
            for trailer in sig_def.trailers:
                t_idx = sub.find(trailer)
                if t_idx != -1:
                    t_len = t_idx + len(trailer)
                    if t_len <= MAX_CARVE_FILE_SIZE:
                        return sub[:t_len], t_len, False

        return None

    def scan_image_file(
        self,
        file_path: Union[Path, str],
        progress_callback: Optional[Callable[[int, int], None]] = None,
        item_callback: Optional[Callable[[CarvedItem], None]] = None
    ) -> List[CarvedItem]:
        """Scans a physical drive, raw volume, or disk image file in chunks with overlap."""
        from engine.win32_raw_reader import Win32RawDeviceReader

        with Win32RawDeviceReader(file_path) as reader:
            file_size = reader.get_size()
            dev_label = Path(str(file_path)).name if not str(file_path).startswith("\\\\.\\") else str(file_path)
            logger.info(f"Initiating signature carving on {dev_label} ({file_size} bytes)...")

            results: List[CarvedItem] = []
            offset = 0
            carry_over = b""

            while True:
                chunk = reader.read(CHUNK_SIZE)
                if not chunk:
                    if carry_over:
                        items = self.scan_bytes(carry_over, base_offset=offset, item_callback=item_callback)
                        results.extend(items)
                    break

                buffer = carry_over + chunk
                items = self.scan_bytes(buffer, base_offset=offset, item_callback=item_callback)
                results.extend(items)

                bytes_processed = min(offset + len(chunk), file_size) if file_size > 0 else (offset + len(chunk))
                if progress_callback and file_size > 0:
                    progress_callback(bytes_processed, file_size)

                if len(chunk) == CHUNK_SIZE:
                    carry_over = buffer[-OVERLAP_SIZE:]
                    offset += len(chunk)
                else:
                    break

        if progress_callback and file_size > 0:
            progress_callback(file_size, file_size)

        logger.info(f"Signature scan complete. Found {len(results)} carved artifacts.")
        return results
