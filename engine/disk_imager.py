"""
Forensic Disk Imager for RecoverX
================================
Creates bit-stream raw disk images (.raw / .dd / .img) with:
1. Strict read-only source access via Win32RawDeviceReader.
2. Source != Destination enforcement and path safety validation.
3. Destination free-space verification before commencing write operations.
4. Sector-aligned chunked streaming (64KB - 1MB blocks).
5. Incremental on-the-fly SHA-256 hash calculation.
6. Post-write image integrity verification.
7. Cooperative cancellation and progress callbacks.
8. Generation of forensic metadata and chain-of-custody logs.
"""

from pathlib import Path
from typing import Dict, Any, Optional, Callable, Union
import hashlib
import json
import shutil
import time
import os
import datetime

from engine.win32_raw_reader import Win32RawDeviceReader
from engine.recovery_manager import RecoveryManager
from utils.logging_config import logger

class DiskImager:
    """Manages forensic bit-stream acquisition and disk imaging."""

    DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MB sector-aligned buffer

    @classmethod
    def validate_destination_capacity(cls, required_bytes: int, dest_dir: Path) -> int:
        """
        Verifies destination storage volume has sufficient free space.
        Leaves a 100 MB safety buffer.
        """
        dest_resolved = Path(dest_dir).resolve()
        dest_resolved.mkdir(parents=True, exist_ok=True)

        try:
            usage = shutil.disk_usage(dest_resolved)
            available_bytes = usage.free
        except Exception as e:
            logger.warning(f"Could not query destination free space via shutil: {e}")
            return required_bytes

        safety_margin = 100 * 1024 * 1024  # 100 MB buffer
        if required_bytes > 0 and available_bytes < (required_bytes + safety_margin):
            req_gb = round(required_bytes / (1024**3), 2)
            avail_gb = round(available_bytes / (1024**3), 2)
            raise RuntimeError(
                f"Insufficient disk space on destination volume ({dest_resolved.drive}). "
                f"Required: {req_gb} GB, Available: {avail_gb} GB."
            )

        return available_bytes

    @classmethod
    def create_image(
        cls,
        source_path: Union[str, Path],
        output_image_path: Union[str, Path],
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        progress_callback: Optional[Callable[[int, int, float], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None
    ) -> Dict[str, Any]:
        """
        Executes bit-stream acquisition of source device/image into output_image_path.
        Computes and verifies SHA-256 on the fly.
        """
        source_str = str(source_path)
        dest_path = Path(output_image_path).resolve()
        dest_dir = dest_path.parent
        dest_dir.mkdir(parents=True, exist_ok=True)

        # 1. Validate destination safety
        if not source_str.startswith("\\\\.\\"):
            RecoveryManager.validate_destination_safety(Path(source_str), dest_dir)
        else:
            # If source is raw volume \\.\D:, ensure output is not located on D:\
            vol_letter = source_str.replace("\\\\.\\", "").rstrip(":")
            if len(vol_letter) == 1 and dest_dir.drive.upper().startswith(vol_letter.upper()):
                raise PermissionError(
                    f"Forensic Safety Violation: Output image cannot be written to the same volume ({vol_letter}:) being imaged."
                )

        # 2. Open read-only device/file
        with Win32RawDeviceReader(source_str) as reader:
            total_size = reader.get_size()

            # 3. Check destination capacity if size is known
            if total_size > 0:
                cls.validate_destination_capacity(total_size, dest_dir)

            logger.info(f"[DiskImager] Starting forensic acquisition: {source_str} -> {dest_path} ({total_size} bytes)")
            start_time = time.time()
            sha256_hasher = hashlib.sha256()

            bytes_written = 0
            with open(dest_path, "wb") as out_f:
                while True:
                    if is_cancelled and is_cancelled():
                        logger.warning("[DiskImager] Acquisition cancelled by user.")
                        out_f.flush()
                        return {
                            "status": "CANCELLED",
                            "source": source_str,
                            "output_file": str(dest_path),
                            "bytes_written": bytes_written,
                            "total_bytes": total_size,
                            "sha256": sha256_hasher.hexdigest(),
                            "verified": False,
                            "error": "Operation aborted by user"
                        }

                    chunk = reader.read(chunk_size)
                    if not chunk:
                        break

                    sha256_hasher.update(chunk)
                    out_f.write(chunk)
                    bytes_written += len(chunk)

                    if progress_callback:
                        throughput_mb = (bytes_written / (1024 * 1024)) / max(0.001, time.time() - start_time)
                        progress_callback(bytes_written, total_size, throughput_mb)

                out_f.flush()
                os.fsync(out_f.fileno())

            end_time = time.time()
            duration = max(0.001, end_time - start_time)
            avg_throughput = round((bytes_written / (1024 * 1024)) / duration, 2)
            calculated_hash = sha256_hasher.hexdigest()

            # 4. Post-write verification
            logger.info(f"[DiskImager] Acquisition finished. Verifying written image integrity...")
            verify_hasher = hashlib.sha256()
            with open(dest_path, "rb") as verify_f:
                while True:
                    b = verify_f.read(chunk_size)
                    if not b:
                        break
                    verify_hasher.update(b)
            verify_hash = verify_hasher.hexdigest()

            verified = (calculated_hash == verify_hash)
            if not verified:
                raise RuntimeError(
                    f"Forensic Integrity Failure: Source stream hash ({calculated_hash}) does not match written image hash ({verify_hash})!"
                )

            # 5. Write forensic sidecar metadata
            metadata = {
                "source": source_str,
                "output_image": str(dest_path),
                "total_bytes": bytes_written,
                "sha256": calculated_hash,
                "verified": verified,
                "started": datetime.datetime.fromtimestamp(start_time, datetime.timezone.utc).isoformat(),
                "completed": datetime.datetime.fromtimestamp(end_time, datetime.timezone.utc).isoformat(),
                "duration_seconds": round(duration, 2),
                "average_throughput_mb_s": avg_throughput,
                "status": "COMPLETED_VERIFIED"
            }

            meta_file = dest_path.with_suffix(dest_path.suffix + ".metadata.json")
            try:
                meta_file.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
            except Exception as e:
                logger.warning(f"Could not write sidecar metadata file: {e}")

            logger.info(f"[DiskImager] Forensic image created successfully. SHA-256: {calculated_hash}")
            return metadata

