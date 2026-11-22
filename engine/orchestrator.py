"""
Unified Recovery Engine Orchestrator for RecoverX
Coordinates carving and discovery across:
1. RecoverX Native Signature Carver
2. PhotoRec (Optional external carver)
3. The Sleuth Kit (Optional filesystem metadata engine)
Deduplicates artifacts, preserves provenance and engine attribution,
and produces a unified result model.
"""
from pathlib import Path
from typing import List, Dict, Any, Optional, Callable
import datetime
import uuid

from engine.signature_scanner import SignatureScanner, CarvedItem
from integrations.photorec.runner import PhotoRecIntegration
from integrations.sleuthkit.runner import TheSleuthKitIntegration
from engine.file_validator import FileValidator
from utils.file_signatures import get_file_category
from utils.hashing import compute_sha256
from utils.logging_config import logger

class UnifiedArtifact:
    """Standardized representation of a recovered or discovered forensic item."""
    def __init__(
        self,
        artifact_id: str,
        filename: str,
        extension: str,
        detected_format: str,
        category: str,
        source_path: str,
        source_offset: Optional[int],
        inode_or_meta_id: Optional[str],
        original_size: int,
        extracted_size: int,
        recovery_engine: str,
        recovery_status: str,
        validation_result: Dict[str, Any],
        sha256: str,
        output_path: Optional[str] = None,
        data: Optional[bytes] = None,
        raw_obj: Optional[Any] = None
    ):
        self.artifact_id = artifact_id
        self.filename = filename
        self.extension = extension.lower()
        self.detected_format = detected_format.upper()
        self.category = category
        self.source_path = source_path
        self.source_offset = source_offset
        self.inode_or_meta_id = inode_or_meta_id
        self.original_size = original_size
        self.extracted_size = extracted_size
        self.recovery_engine = recovery_engine
        self.recovery_status = recovery_status
        self.validation_result = validation_result
        self.sha256 = sha256
        self.output_path = output_path
        self.timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        self.data = data
        self.raw_obj = raw_obj

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_id": self.artifact_id,
            "filename": self.filename,
            "extension": self.extension,
            "detected_format": self.detected_format,
            "category": self.category,
            "source_path": self.source_path,
            "offset": self.source_offset,
            "inode": self.inode_or_meta_id,
            "size_bytes": self.extracted_size,
            "length": self.extracted_size,
            "original_size": self.original_size,
            "backend": self.recovery_engine,
            "recovery_engine": self.recovery_engine,
            "status": self.recovery_status,
            "is_valid": self.validation_result.get("is_valid", False),
            "confidence": self.validation_result.get("confidence", 0.8),
            "sha256": self.sha256,
            "output_path": self.output_path,
            "timestamp": self.timestamp,
            "details": self.validation_result.get("details", {}),
            "is_duplicate": False,
            "_carved_object": self.raw_obj,
            "data": self.data
        }

class RecoveryOrchestrator:
    def __init__(
        self,
        use_native_carver: bool = True,
        use_photorec: bool = False,
        use_tsk: bool = False,
        photorec_bin: Optional[str] = None,
        tsk_bin_dir: Optional[str] = None
    ):
        self.use_native_carver = use_native_carver
        self.use_photorec = use_photorec
        self.use_tsk = use_tsk

        self.native_scanner = SignatureScanner() if use_native_carver else None
        self.photorec = PhotoRecIntegration(binary_path=photorec_bin) if use_photorec else None
        self.tsk = TheSleuthKitIntegration(bin_dir=tsk_bin_dir) if use_tsk else None

    def scan(
        self,
        source_path: Path,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        item_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
        is_cancelled: Optional[Callable[[], bool]] = None
    ) -> List[Dict[str, Any]]:
        """
        Runs configured engines against source path and merges/deduplicates artifacts.
        """
        source_resolved = Path(source_path).resolve()
        artifacts_by_key: Dict[str, UnifiedArtifact] = {}

        # 1. The Sleuth Kit (Filesystem Metadata Discovery)
        if self.use_tsk and self.tsk:
            tsk_status = self.tsk.get_status()
            if tsk_status.get("is_available") and source_resolved.is_file():
                logger.info(f"[Orchestrator] Running The Sleuth Kit on {source_resolved.name}...")
                try:
                    tsk_entries = self.tsk.find_deleted_entries(source_resolved)
                    for entry in tsk_entries:
                        if is_cancelled and is_cancelled():
                            break
                        art_id = f"tsk_{entry.get('inode', uuid.uuid4().hex[:8])}"
                        ua = UnifiedArtifact(
                            artifact_id=art_id,
                            filename=entry.get("filename", "unknown"),
                            extension=entry.get("extension", ""),
                            detected_format=entry.get("extension", "bin").upper(),
                            category=entry.get("category", "Other"),
                            source_path=str(source_resolved),
                            source_offset=None,
                            inode_or_meta_id=entry.get("inode"),
                            original_size=0,
                            extracted_size=0,
                            recovery_engine="The Sleuth Kit (TSK)",
                            recovery_status="METADATA_RECORD_IDENTIFIED",
                            validation_result={"is_valid": False, "confidence": 0.5, "details": {"note": "Metadata entry"}},
                            sha256="",
                            raw_obj=entry
                        )
                        key = f"inode:{entry.get('inode')}"
                        artifacts_by_key[key] = ua
                        if item_callback:
                            item_callback(ua.to_dict())
                except Exception as e:
                    logger.warning(f"[Orchestrator] TSK scan failed: {e}")

        # 2. RecoverX Native Signature Carver
        if self.use_native_carver and self.native_scanner and source_resolved.is_file():
            logger.info(f"[Orchestrator] Running RecoverX Carver on {source_resolved.name}...")
            try:
                def on_carve_item(item: CarvedItem):
                    if is_cancelled and is_cancelled():
                        return
                    art_id = f"rx_{item.offset:08x}_{item.sha256[:8]}"
                    ua = UnifiedArtifact(
                        artifact_id=art_id,
                        filename=f"carved_{item.offset:08x}_{item.sha256[:8]}.{item.extension}",
                        extension=item.extension,
                        detected_format=item.extension.upper(),
                        category=item.category,
                        source_path=str(source_resolved),
                        source_offset=item.offset,
                        inode_or_meta_id=None,
                        original_size=item.length,
                        extracted_size=len(item.data),
                        recovery_engine="RecoverX Carver",
                        recovery_status="Recoverable" if item.is_valid and not item.fragmented_warning else "Partially Recoverable",
                        validation_result={"is_valid": item.is_valid, "confidence": item.confidence, "details": item.details},
                        sha256=item.sha256,
                        data=item.data,
                        raw_obj=item
                    )
                    # Deduplication key by sha256 or offset
                    key = f"sha:{item.sha256}" if item.sha256 else f"off:{item.offset}"
                    if key in artifacts_by_key:
                        # If previously found via metadata only, merge with actual carved data
                        existing = artifacts_by_key[key]
                        if existing.recovery_status == "METADATA_RECORD_IDENTIFIED":
                            existing.data = item.data
                            existing.extracted_size = len(item.data)
                            existing.sha256 = item.sha256
                            existing.recovery_status = ua.recovery_status
                            existing.validation_result = ua.validation_result
                            existing.recovery_engine = f"{existing.recovery_engine} + RecoverX Carver"
                    else:
                        artifacts_by_key[key] = ua
                        if item_callback:
                            item_callback(ua.to_dict())

                self.native_scanner.scan_image_file(
                    source_resolved,
                    progress_callback=progress_callback,
                    item_callback=on_carve_item
                )
            except Exception as e:
                logger.error(f"[Orchestrator] RecoverX carving failed: {e}")

        # 3. PhotoRec Integration (if requested and available)
        if self.use_photorec and self.photorec and source_resolved.is_file():
            pr_status = self.photorec.get_status()
            if pr_status.get("is_available"):
                logger.info(f"[Orchestrator] Running PhotoRec on {source_resolved.name}...")
                try:
                    import tempfile
                    with tempfile.TemporaryDirectory(prefix="recoverx_pr_") as pr_tmp:
                        pr_res = self.photorec.run_carving(source_resolved, Path(pr_tmp))
                        for item in pr_res.get("recovered_files", []):
                            if is_cancelled and is_cancelled():
                                break
                            sha = item.get("sha256", "")
                            key = f"sha:{sha}" if sha else f"pr_{item.get('filename')}"
                            if key not in artifacts_by_key:
                                ua = UnifiedArtifact(
                                    artifact_id=f"pr_{sha[:8]}",
                                    filename=item.get("filename", "unknown"),
                                    extension=item.get("extension", ""),
                                    detected_format=item.get("extension", "").upper(),
                                    category=item.get("category", "Other"),
                                    source_path=str(source_resolved),
                                    source_offset=None,
                                    inode_or_meta_id=None,
                                    original_size=item.get("size_bytes", 0),
                                    extracted_size=item.get("size_bytes", 0),
                                    recovery_engine="PhotoRec",
                                    recovery_status="Recoverable" if item.get("is_valid") else "Carved / Unvalidated",
                                    validation_result={"is_valid": item.get("is_valid", False), "confidence": 0.8},
                                    sha256=sha,
                                    raw_obj=item
                                )
                                artifacts_by_key[key] = ua
                                if item_callback:
                                    item_callback(ua.to_dict())
                except Exception as e:
                    logger.warning(f"[Orchestrator] PhotoRec scan failed: {e}")

        return [ua.to_dict() for ua in artifacts_by_key.values()]

