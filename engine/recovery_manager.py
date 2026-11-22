"""
Recovery Manager for RecoverX
Manages extraction and restoration of discovered and carved files to a safe, isolated output directory.
Enforces strict forensic isolation: NEVER writes to source media.
Handles on-demand extraction from disk images, TSK inode extraction, format validation,
SHA-256 verification, and duplicate collision safety.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable, Union
import shutil
import os

from engine.signature_scanner import CarvedItem
from engine.file_validator import FileValidator
from engine.win32_raw_reader import Win32RawDeviceReader, is_raw_device_path, normalize_device_path
from utils.hashing import compute_sha256
from utils.logging_config import logger
from config import RECOVERED_DIR

class RecoveryManager:
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or RECOVERED_DIR).resolve()
        self.output_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def validate_destination_safety(source_path: Path, output_dir: Path) -> None:
        """
        Validates that output destination is strictly isolated from source media.
        Raises PermissionError if output overlaps with or is inside source media.
        """
        is_raw = is_raw_device_path(source_path)
        output_resolved = Path(output_dir).resolve()

        if is_raw:
            norm_dev = normalize_device_path(str(source_path)).upper()
            out_drive = output_resolved.drive.upper()
            if len(norm_dev) == 6 and norm_dev.startswith("\\\\.\\") and norm_dev[5] == ":":
                dev_letter = norm_dev[4:6]
                if out_drive == dev_letter:
                    raise PermissionError(
                        f"Forensic Safety Violation: Output directory ({output_resolved}) is located on the source drive ({dev_letter}). "
                        "To prevent overwriting deleted data, please select a different physical or logical drive."
                    )
        else:
            source_resolved = Path(source_path).resolve()
            if output_resolved == source_resolved:
                raise PermissionError(
                    f"Forensic Safety Violation: Output directory ({output_resolved}) cannot be identical to source media ({source_resolved})."
                )

            if output_resolved in source_resolved.parents:
                raise PermissionError(
                    f"Forensic Safety Violation: Output directory ({output_resolved}) contains source media ({source_resolved})."
                )

            if source_resolved in output_resolved.parents:
                raise PermissionError(
                    f"Forensic Safety Violation: Output directory ({output_resolved}) is located inside source media ({source_resolved})."
                )

    def recover_carved_items(
        self,
        carved_items: List[CarvedItem],
        source_path: Path,
        skip_duplicates: bool = True,
        only_valid: bool = False
    ) -> Dict[str, Any]:
        """
        Backward-compatible wrapper for recovering CarvedItem objects.
        """
        return self.recover_artifacts(
            artifacts=carved_items,
            source_path=source_path,
            skip_duplicates=skip_duplicates,
            only_valid=only_valid
        )

    def recover_artifacts(
        self,
        artifacts: List[Union[CarvedItem, Dict[str, Any]]],
        source_path: Path,
        skip_duplicates: bool = True,
        only_valid: bool = False,
        progress_callback: Optional[Callable[[int, int, str, Dict[str, int]], None]] = None,
        is_cancelled_callback: Optional[Callable[[], bool]] = None
    ) -> Dict[str, Any]:
        """
        Safely extracts and writes selected artifacts to the output directory.
        Performs post-extraction SHA-256 verification, structural validation,
        and safe unique naming.
        """
        self.validate_destination_safety(source_path, self.output_dir)
        source_resolved = Path(source_path).resolve()

        logger.info(f"Initiating file recovery of {len(artifacts)} items to {self.output_dir}...")

        recovered_files: List[Dict[str, Any]] = []
        counts = {
            "success": 0,
            "partial": 0,
            "failed": 0,
            "skipped": 0,
            "metadata_only": 0
        }
        written_hashes = set()
        total_items = len(artifacts)

        # Open source file in read-only mode for reading carved offsets if needed
        source_file_handle = None
        source_is_device = is_raw_device_path(source_path)
        if source_is_device or (not source_is_device and Path(source_path).is_file()):
            try:
                from engine.win32_raw_reader import Win32RawDeviceReader
                source_file_handle = Win32RawDeviceReader(source_path)
                source_file_handle.open()
            except Exception as e:
                logger.warning(f"Could not open source for streaming extraction: {e}")

        try:
            for idx, artifact in enumerate(artifacts, 1):
                if is_cancelled_callback and is_cancelled_callback():
                    logger.warning("Recovery cancelled by user. Terminating extraction cleanly.")
                    break

                # Extract metadata from CarvedItem or dict
                if isinstance(artifact, CarvedItem):
                    raw_data = artifact.data
                    offset = artifact.offset
                    length = artifact.length
                    extension = artifact.extension.lower()
                    expected_sha = artifact.sha256
                    is_valid = artifact.is_valid
                    confidence = artifact.confidence
                    fragmented = artifact.fragmented_warning
                    inode = None
                    filename_hint = f"recovered_{offset:08x}_{expected_sha[:8]}.{extension}"
                else:
                    c_obj = artifact.get("_carved_object")
                    if c_obj and isinstance(c_obj, CarvedItem):
                        raw_data = c_obj.data
                        offset = c_obj.offset
                        length = c_obj.length
                        extension = c_obj.extension.lower()
                        expected_sha = c_obj.sha256
                        is_valid = c_obj.is_valid
                        confidence = c_obj.confidence
                        fragmented = c_obj.fragmented_warning
                        inode = None
                        filename_hint = f"recovered_{offset:08x}_{expected_sha[:8]}.{extension}"
                    else:
                        raw_data = artifact.get("data")
                        offset = artifact.get("offset", 0)
                        length = artifact.get("length", artifact.get("size_bytes", 0))
                        extension = artifact.get("extension", "bin").lower()
                        expected_sha = artifact.get("sha256", "")
                        is_valid = artifact.get("is_valid", False)
                        confidence = artifact.get("confidence", 0.5)
                        fragmented = artifact.get("fragmented_warning", False)
                        inode = artifact.get("inode")
                        filename_hint = artifact.get("filename") or f"recovered_{offset:08x}.{extension}"

                current_filename = filename_hint

                is_dict = isinstance(artifact, dict)
                artifact_status = artifact.get("status") if is_dict else getattr(artifact, "status", None)

                # If item is metadata only (e.g. TSK record with no carved data and no inode extraction capability)
                if artifact_status == "METADATA_RECORD_IDENTIFIED" and not raw_data and not inode:
                    counts["metadata_only"] += 1
                    if progress_callback:
                        progress_callback(idx, total_items, current_filename, counts)
                    continue

                if only_valid and not is_valid:
                    counts["skipped"] += 1
                    if progress_callback:
                        progress_callback(idx, total_items, current_filename, counts)
                    continue

                # Check duplicate SHA-256
                if skip_duplicates and expected_sha and expected_sha in written_hashes:
                    counts["skipped"] += 1
                    if progress_callback:
                        progress_callback(idx, total_items, current_filename, counts)
                    continue

                # Obtain file data bytes
                payload_bytes = None
                if raw_data is not None and len(raw_data) > 0:
                    payload_bytes = raw_data
                elif source_file_handle and offset is not None and length > 0:
                    try:
                        source_file_handle.seek(offset)
                        payload_bytes = source_file_handle.read(length)
                    except Exception as e:
                        logger.error(f"Failed to read {length} bytes at offset 0x{offset:X}: {e}")

                # Handle TSK inode extraction if payload is empty but inode is available
                if payload_bytes is None and inode:
                    from integrations.sleuthkit.runner import TheSleuthKitIntegration
                    tsk = TheSleuthKitIntegration()
                    temp_out = self.output_dir / extension / f"temp_{idx}.{extension}"
                    temp_out.parent.mkdir(parents=True, exist_ok=True)
                    if tsk.extract_file_content(source_resolved, str(inode), temp_out):
                        payload_bytes = temp_out.read_bytes()
                        temp_out.unlink(missing_ok=True)

                if payload_bytes is None or len(payload_bytes) == 0:
                    counts["failed"] += 1
                    recovered_files.append({
                        "filename": current_filename,
                        "path": None,
                        "extension": extension,
                        "offset": offset,
                        "size_bytes": 0,
                        "sha256": None,
                        "verified": False,
                        "status": "FAILED_READ",
                        "is_valid": False
                    })
                    if progress_callback:
                        progress_callback(idx, total_items, current_filename, counts)
                    continue

                # Determine extension folder
                ext_dir = self.output_dir / (extension if extension else "unknown")
                ext_dir.mkdir(parents=True, exist_ok=True)

                # Generate unique non-colliding filename
                clean_name = current_filename.replace("/", "_").replace("\\", "_")
                base_name = Path(clean_name).stem
                ext_suffix = f".{extension}" if extension else ""
                out_file = ext_dir / f"{base_name}{ext_suffix}"

                counter = 1
                while out_file.exists():
                    existing_hash = compute_sha256(out_file)
                    actual_payload_hash = compute_sha256(payload_bytes)
                    if skip_duplicates and existing_hash == actual_payload_hash:
                        out_file = None
                        break
                    out_file = ext_dir / f"{base_name}_{counter}{ext_suffix}"
                    counter += 1

                if out_file is None:
                    # Duplicate of existing file on disk
                    counts["skipped"] += 1
                    if progress_callback:
                        progress_callback(idx, total_items, current_filename, counts)
                    continue

                # Write data safely
                try:
                    with open(out_file, "wb") as out_f:
                        out_f.write(payload_bytes)
                except Exception as e:
                    logger.error(f"Failed to write extracted file {out_file}: {e}")
                    counts["failed"] += 1
                    recovered_files.append({
                        "filename": out_file.name,
                        "path": str(out_file),
                        "extension": extension,
                        "offset": offset,
                        "size_bytes": len(payload_bytes),
                        "sha256": None,
                        "verified": False,
                        "status": "FAILED_WRITE",
                        "is_valid": False
                    })
                    if progress_callback:
                        progress_callback(idx, total_items, current_filename, counts)
                    continue

                # Post-write verification
                written_hash = compute_sha256(out_file)
                val_result = FileValidator.validate(payload_bytes, extension)
                hash_match = (written_hash == expected_sha) if expected_sha else True
                file_valid = val_result.get("is_valid", False)

                if not hash_match:
                    status = "CORRUPT_WRITE"
                    counts["failed"] += 1
                elif fragmented or (file_valid and confidence < 0.7):
                    status = "PARTIAL_SUCCESS"
                    counts["partial"] += 1
                elif file_valid:
                    status = "VERIFIED_SUCCESS"
                    counts["success"] += 1
                else:
                    status = "CARVED_UNVALIDATED"
                    counts["partial"] += 1

                written_hashes.add(written_hash)
                recovered_files.append({
                    "filename": out_file.name,
                    "path": str(out_file),
                    "extension": extension,
                    "offset": offset,
                    "size_bytes": len(payload_bytes),
                    "sha256": written_hash,
                    "verified": hash_match and file_valid,
                    "status": status,
                    "is_valid": file_valid,
                    "confidence": confidence,
                    "signature_detected": val_result.get("signature_detected", True),
                    "structure_validated": val_result.get("structure_validated", False),
                    "content_readable": val_result.get("content_readable", False),
                    "recovery_completed": True,
                    "hash_verified": hash_match,
                    "validation_details": val_result.get("details", {})
                })

                if progress_callback:
                    progress_callback(idx, total_items, out_file.name, counts)

        finally:
            if source_file_handle:
                try:
                    source_file_handle.close()
                except Exception:
                    pass

        logger.info(
            f"Recovery complete. Recovered {counts['success'] + counts['partial']} files "
            f"({counts['success']} verified, {counts['partial']} partial). "
            f"Skipped {counts['skipped']} duplicates, Failed: {counts['failed']}."
        )

        return {
            "output_directory": str(self.output_dir),
            "total_selected": total_items,
            "total_recovered": counts["success"] + counts["partial"],
            "verified_success": counts["success"],
            "partial_success": counts["partial"],
            "failed_count": counts["failed"],
            "skipped_duplicates": counts["skipped"],
            "metadata_only_count": counts["metadata_only"],
            "files": recovered_files
        }
