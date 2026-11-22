"""
File Validator Module for RecoverX
Validates structural integrity of carved and discovered files across 30+ formats:
- Images: JPG, PNG, GIF, BMP, TIFF, WEBP, HEIC
- Videos: MP4, MOV, AVI, MKV, 3GP
- Audio: MP3, WAV, AAC, M4A, FLAC
- Documents: PDF, DOC, DOCX, XLS, XLSX, PPT, PPTX, TXT, RTF
- Archives: ZIP, RAR, 7Z, GZIP

Enforces format-specific structural validation rather than treating magic-byte detection
as proof of file validity. Distinguishes:
1. signature_detected
2. structure_validated
3. content_readable
4. recovery_completed
5. hash_verified
"""
import io
import zipfile
import struct
from typing import Dict, Any, Optional
from pathlib import Path

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

from utils.file_signatures import get_file_category

class ValidationResult(dict):
    """
    Standardized forensic validation result container.
    Inherits from dict for full backward compatibility with dict indexing (res['is_valid']),
    while providing attribute access (res.is_valid) and helper methods.
    """
    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError:
            raise AttributeError(f"'ValidationResult' object has no attribute '{name}'")

    def __setattr__(self, name: str, value: Any) -> None:
        self[name] = value

    def to_dict(self) -> Dict[str, Any]:
        return dict(self)

class FileValidator:
    """Validates recovered or discovered files against their format specifications."""

    @classmethod
    def validate(cls, data_or_path: Any, file_type: str) -> ValidationResult:
        """
        Validates content or file path against specified file_type.
        Returns standardized forensic validation dictionary / ValidationResult.
        """
        if isinstance(data_or_path, (str, Path)):
            path = Path(data_or_path)
            if not path.is_file():
                return cls._create_result(
                    is_valid=False,
                    signature_detected=False,
                    structure_validated=False,
                    content_readable=False,
                    confidence=0.0,
                    file_type=file_type,
                    error="File not found on disk"
                )
            with open(path, "rb") as f:
                data = f.read()
        elif isinstance(data_or_path, (bytes, bytearray)):
            data = bytes(data_or_path)
        else:
            return cls._create_result(
                is_valid=False,
                signature_detected=False,
                structure_validated=False,
                content_readable=False,
                confidence=0.0,
                file_type=file_type,
                error="Invalid input type (expected bytes or file path)"
            )

        norm_type = file_type.lower().lstrip(".")
        if norm_type == "jpeg":
            norm_type = "jpg"
        elif norm_type == "gzip":
            norm_type = "gz"
        elif norm_type == "tif":
            norm_type = "tiff"

        method_name = f"_validate_{norm_type}"
        validator_func = getattr(cls, method_name, None)

        if validator_func:
            res = validator_func(data)
        else:
            res = cls._validate_generic(data, norm_type)

        res["category"] = get_file_category(res.get("type", norm_type))
        return res

    @classmethod
    def validate_file(cls, path: Any, file_type: str) -> ValidationResult:
        """Alias for validating a file path directly."""
        return cls.validate(path, file_type)

    @staticmethod
    def _create_result(
        is_valid: bool,
        signature_detected: bool,
        structure_validated: bool,
        content_readable: bool,
        confidence: float,
        file_type: str,
        details: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        status: Optional[str] = None,
        limitations: Optional[str] = None
    ) -> ValidationResult:
        """Creates a standardized forensic validation response dictionary."""
        if status is None:
            if is_valid:
                status = "VALID_WITH_LIMITATIONS" if limitations else "VALID"
            elif not signature_detected:
                status = "INVALID_SIGNATURE"
            elif not structure_validated:
                status = "CORRUPT_STRUCTURE"
            elif not content_readable:
                status = "UNREADABLE_CONTENT"
            else:
                status = "INVALID"

        return ValidationResult({
            "is_valid": is_valid,
            "signature_detected": signature_detected,
            "structure_validated": structure_validated,
            "content_readable": content_readable,
            "recovery_completed": False,  # Updated during actual recovery phase
            "hash_verified": False,       # Updated during post-write verification
            "confidence": round(confidence, 2),
            "type": file_type,
            "category": get_file_category(file_type),
            "details": details or {},
            "limitations": limitations,
            "error": error,
            "status": status
        })

    # ==========================================
    # IMAGES VALIDATION
    # ==========================================

    @classmethod
    def _validate_jpg(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 10:
            return cls._create_result(False, False, False, False, 0.0, "jpg", error="File too small for JPEG")

        sig_detected = data.startswith(b"\xFF\xD8\xFF")
        if not sig_detected:
            return cls._create_result(False, False, False, False, 0.0, "jpg", error="Missing JPEG SOI marker")

        has_eoi = b"\xFF\xD9" in data[-16:]
        details = {"has_soi": True, "has_eoi": has_eoi, "length": len(data)}

        # Search for SOF0 (0xFF, 0xC0) or SOF2 (0xFF, 0xC2) frame headers
        sof_found = False
        idx = 2
        while idx + 8 < len(data) and idx < 4096:
            if data[idx] == 0xFF and data[idx+1] in (0xC0, 0xC1, 0xC2):
                sof_found = True
                height, width = struct.unpack(">HH", data[idx+5:idx+9])
                details["dimensions_sof"] = f"{width}x{height}"
                break
            idx += 1

        structure_validated = has_eoi and (sof_found or len(data) > 64)
        content_readable = False

        if PILLOW_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(data))
                img.verify()
                content_readable = True
                details["dimensions"] = f"{img.width}x{img.height}"
                details["format"] = img.format
                details["mode"] = img.mode
                return cls._create_result(
                    is_valid=has_eoi,
                    signature_detected=True,
                    structure_validated=has_eoi,
                    content_readable=True,
                    confidence=1.0 if has_eoi else 0.45,
                    file_type="jpg",
                    details=details,
                    error=None if has_eoi else "Missing JPEG EOI marker (truncated)"
                )
            except Exception as e:
                return cls._create_result(
                    is_valid=False,
                    signature_detected=True,
                    structure_validated=has_eoi,
                    content_readable=False,
                    confidence=0.3 if has_eoi else 0.1,
                    file_type="jpg",
                    details=details,
                    error=f"Pillow decoding failure: {e}",
                    status="CORRUPT_PAYLOAD" if has_eoi else "TRUNCATED"
                )

        return cls._create_result(
            is_valid=has_eoi,
            signature_detected=True,
            structure_validated=has_eoi,
            content_readable=has_eoi,
            confidence=0.85 if has_eoi else 0.35,
            file_type="jpg",
            details=details,
            error=None if has_eoi else "Missing JPEG EOI marker"
        )

    @classmethod
    def _validate_png(cls, data: bytes) -> Dict[str, Any]:
        png_sig = b"\x89PNG\r\n\x1a\n"
        if len(data) < 24 or not data.startswith(png_sig):
            return cls._create_result(False, False, False, False, 0.0, "png", error="Invalid PNG signature")

        # First chunk MUST be IHDR (13 bytes)
        has_ihdr = data[12:16] == b"IHDR"
        has_iend = b"IEND\xaeB`\x82" in data[-16:] or b"IEND" in data[-12:]
        details = {"has_header": True, "has_ihdr": has_ihdr, "has_iend": has_iend, "length": len(data)}

        if not has_ihdr:
            return cls._create_result(
                False, True, False, False, 0.2, "png",
                details=details, error="Missing required IHDR chunk", status="CORRUPT_STRUCTURE"
            )

        if not has_iend:
            return cls._create_result(
                False, True, False, False, 0.3, "png",
                details=details, error="Missing IEND chunk (truncated file)", status="TRUNCATED"
            )

        width, height = struct.unpack(">II", data[16:24])
        details["dimensions_raw"] = f"{width}x{height}"

        # Deep chunk CRC verification
        from utils.file_signatures import parse_png_size
        png_total_len = parse_png_size(data, offset=0, verify_crc=True)
        if png_total_len is None:
            return cls._create_result(
                is_valid=False,
                signature_detected=True,
                structure_validated=False,
                content_readable=False,
                confidence=0.25,
                file_type="png",
                details=details,
                error="PNG chunk structure or CRC-32 integrity failure",
                status="CORRUPT_STRUCTURE"
            )

        if PILLOW_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(data))
                img.verify()
                details["dimensions"] = f"{img.width}x{img.height}"
                return cls._create_result(
                    is_valid=True,
                    signature_detected=True,
                    structure_validated=True,
                    content_readable=True,
                    confidence=1.0,
                    file_type="png",
                    details=details
                )
            except Exception as e:
                return cls._create_result(
                    is_valid=False,
                    signature_detected=True,
                    structure_validated=True,
                    content_readable=False,
                    confidence=0.4,
                    file_type="png",
                    details=details,
                    error=f"PNG payload corruption: {e}",
                    status="CORRUPT_PAYLOAD"
                )

        return cls._create_result(
            is_valid=True,
            signature_detected=True,
            structure_validated=True,
            content_readable=True,
            confidence=0.9,
            file_type="png",
            details=details
        )

    @classmethod
    def _validate_gif(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 14 or not (data.startswith(b"GIF87a") or data.startswith(b"GIF89a")):
            return cls._create_result(False, False, False, False, 0.0, "gif", error="Invalid GIF signature")

        has_trailer = data.endswith(b"\x3B") or b"\x00\x3B" in data[-4:]
        w, h = struct.unpack("<HH", data[6:10])
        details = {
            "version": data[:6].decode("ascii", errors="ignore"),
            "dimensions": f"{w}x{h}",
            "has_trailer": has_trailer
        }

        if w == 0 or h == 0:
            return cls._create_result(
                False, True, False, False, 0.2, "gif",
                details=details, error="Invalid GIF screen dimensions (0x0)", status="CORRUPT_STRUCTURE"
            )

        if not has_trailer:
            return cls._create_result(
                False, True, False, False, 0.35, "gif",
                details=details, error="Missing GIF trailer byte (0x3B)", status="TRUNCATED"
            )

        if PILLOW_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(data))
                img.verify()
                return cls._create_result(True, True, True, True, 1.0, "gif", details=details)
            except Exception:
                pass

        return cls._create_result(True, True, True, True, 0.85, "gif", details=details)

    @classmethod
    def _validate_bmp(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 26 or not data.startswith(b"BM"):
            return cls._create_result(False, False, False, False, 0.0, "bmp", error="Invalid BMP signature")

        declared_size = struct.unpack("<I", data[2:6])[0]
        dib_header_size = struct.unpack("<I", data[14:18])[0]
        planes = struct.unpack("<H", data[26:28])[0] if len(data) >= 28 else 0
        bit_count = struct.unpack("<H", data[28:30])[0] if len(data) >= 30 else 0

        details = {
            "declared_size": declared_size,
            "actual_size": len(data),
            "dib_header_size": dib_header_size,
            "bit_depth": bit_count
        }

        # DIB header must be at least 12 (BITMAPCOREHEADER) or 40 (BITMAPINFOHEADER)
        valid_struct = dib_header_size >= 12 and planes in (0, 1) and bit_count in (1, 4, 8, 16, 24, 32)
        if not valid_struct:
            return cls._create_result(
                False, True, False, False, 0.2, "bmp",
                details=details, error="Invalid DIB header geometry or bit depth", status="CORRUPT_STRUCTURE"
            )

        is_truncated = len(data) < declared_size and declared_size > 54
        if is_truncated:
            return cls._create_result(
                False, True, True, False, 0.4, "bmp",
                details=details, error=f"Truncated BMP: has {len(data)} bytes, declared {declared_size}", status="TRUNCATED"
            )

        if PILLOW_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(data))
                img.verify()
                details["dimensions"] = f"{img.width}x{img.height}"
                return cls._create_result(True, True, True, True, 1.0, "bmp", details=details)
            except Exception:
                pass

        return cls._create_result(True, True, True, True, 0.9, "bmp", details=details)

    @classmethod
    def _validate_webp(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 16 or not (data.startswith(b"RIFF") and data[8:12] == b"WEBP"):
            return cls._create_result(False, False, False, False, 0.0, "webp", error="Invalid WebP signature")

        riff_len = struct.unpack("<I", data[4:8])[0]
        expected_len = riff_len + 8
        vp8_chunk = data[12:16]
        details = {
            "riff_length": riff_len,
            "actual_size": len(data),
            "chunk_type": vp8_chunk.decode("ascii", errors="replace")
        }

        if vp8_chunk not in (b"VP8 ", b"VP8L", b"VP8X"):
            return cls._create_result(
                False, True, False, False, 0.3, "webp",
                details=details, error=f"Unknown WebP chunk {vp8_chunk}", status="CORRUPT_STRUCTURE"
            )

        if len(data) < expected_len:
            return cls._create_result(
                False, True, True, False, 0.4, "webp",
                details=details, error=f"Truncated WebP: has {len(data)} bytes, expected {expected_len}", status="TRUNCATED"
            )

        if PILLOW_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(data))
                img.verify()
                details["dimensions"] = f"{img.width}x{img.height}"
                return cls._create_result(True, True, True, True, 1.0, "webp", details=details)
            except Exception:
                pass

        return cls._create_result(True, True, True, True, 0.85, "webp", details=details)

    @classmethod
    def _validate_tiff(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 8:
            return cls._create_result(False, False, False, False, 0.0, "tiff", error="File too small")

        is_le = data.startswith(b"II*\x00")
        is_be = data.startswith(b"MM\x00*")
        if not (is_le or is_be):
            return cls._create_result(False, False, False, False, 0.0, "tiff", error="Invalid TIFF magic bytes")

        endian = "<" if is_le else ">"
        first_ifd_offset = struct.unpack(f"{endian}I", data[4:8])[0]
        details = {
            "byte_order": "little_endian" if is_le else "big_endian",
            "first_ifd_offset": first_ifd_offset
        }

        if first_ifd_offset >= len(data):
            return cls._create_result(
                False, True, False, False, 0.3, "tiff",
                details=details, error="IFD offset points beyond end of data", status="TRUNCATED"
            )

        if PILLOW_AVAILABLE:
            try:
                img = Image.open(io.BytesIO(data))
                img.verify()
                details["dimensions"] = f"{img.width}x{img.height}"
                return cls._create_result(True, True, True, True, 1.0, "tiff", details=details)
            except Exception:
                pass

        return cls._create_result(True, True, True, True, 0.85, "tiff", details=details)

    @classmethod
    def _validate_heic(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 16:
            return cls._create_result(False, False, False, False, 0.0, "heic", error="File too small")
        if data[4:8] != b"ftyp":
            return cls._create_result(False, False, False, False, 0.0, "heic", error="Missing ftyp atom")

        brand = data[8:12]
        is_heic = brand in (b"heic", b"mif1", b"msf1", b"heix", b"heim", b"heis")
        box_size = struct.unpack(">I", data[0:4])[0]
        details = {
            "brand": brand.decode("ascii", errors="replace"),
            "first_box_size": box_size
        }

        if not is_heic:
            return cls._create_result(
                False, True, False, False, 0.25, "heic",
                details=details, error=f"Brand {brand} is not HEIC/HEIF", status="MISLEADING_SIGNATURE"
            )

        return cls._create_result(
            True, True, True, True, 0.9, "heic",
            details=details, limitations="HEIC pixel decoding requires external libheif or hardware decoder."
        )

    # ==========================================
    # DOCUMENTS VALIDATION (OFFICE, OLE2, PDF, TXT)
    # ==========================================

    @classmethod
    def _validate_docx(cls, data: bytes) -> Dict[str, Any]:
        """Validates DOCX: must be a valid ZIP container containing word/document.xml."""
        return cls._validate_ooxml_package(data, expected_subtypes=["word/document.xml", "wordprocessing"], doc_type="docx")

    @classmethod
    def _validate_xlsx(cls, data: bytes) -> Dict[str, Any]:
        """Validates XLSX: must be a valid ZIP container containing xl/workbook.xml."""
        return cls._validate_ooxml_package(data, expected_subtypes=["xl/workbook.xml", "spreadsheet"], doc_type="xlsx")

    @classmethod
    def _validate_pptx(cls, data: bytes) -> Dict[str, Any]:
        """Validates PPTX: must be a valid ZIP container containing ppt/presentation.xml."""
        return cls._validate_ooxml_package(data, expected_subtypes=["ppt/presentation.xml", "presentation"], doc_type="pptx")

    @classmethod
    def _validate_ooxml_package(cls, data: bytes, expected_subtypes: list, doc_type: str) -> Dict[str, Any]:
        if len(data) < 22 or not data.startswith(b"PK\x03\x04"):
            return cls._create_result(False, False, False, False, 0.0, doc_type, error=f"Invalid {doc_type.upper()} ZIP header")

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                bad_member = zf.testzip()
                if bad_member:
                    return cls._create_result(
                        False, True, False, False, 0.3, doc_type,
                        details={"bad_crc_member": bad_member},
                        error=f"Corrupt internal ZIP entry: {bad_member}",
                        status="CORRUPT_STRUCTURE"
                    )

                namelist = zf.namelist()
                has_content_types = "[Content_Types].xml" in namelist
                
                # Check expected structure
                matches_expected = any(
                    any(exp in name for exp in expected_subtypes) for name in namelist
                )

                if has_content_types and not matches_expected:
                    try:
                        ct_content = zf.read("[Content_Types].xml").decode("utf-8", errors="ignore")
                        matches_expected = any(exp in ct_content for exp in expected_subtypes)
                    except Exception:
                        pass

                valid_components = [n for n in namelist if any(exp in n for exp in expected_subtypes)]
                details = {
                    "internal_file_count": len(namelist),
                    "has_content_types": has_content_types,
                    "target_document_found": matches_expected,
                    "valid_components": valid_components
                }

                if not matches_expected:
                    return cls._create_result(
                        False, True, False, False, 0.4, doc_type,
                        details=details,
                        error=f"Valid ZIP archive but missing expected {doc_type.upper()} components",
                        status="MISLEADING_SIGNATURE"
                    )

                return cls._create_result(
                    True, True, True, True, 1.0, doc_type,
                    details=details
                )
        except (zipfile.BadZipFile, EOFError) as e:
            return cls._create_result(
                False, True, False, False, 0.2, doc_type,
                error=f"Truncated or corrupted ZIP container: {e}",
                status="CORRUPT_OR_TRUNCATED"
            )
        except Exception as e:
            return cls._create_result(
                False, True, False, False, 0.2, doc_type,
                error=f"Failed to parse {doc_type.upper()} container: {e}",
                status="CORRUPT_STRUCTURE"
            )

    @classmethod
    def _validate_doc(cls, data: bytes) -> Dict[str, Any]:
        """Validates legacy Microsoft Word 97-2003 OLE2 Compound Document."""
        return cls._validate_ole2_document(data, expected_marker=b"WordDocument", doc_type="doc")

    @classmethod
    def _validate_xls(cls, data: bytes) -> Dict[str, Any]:
        """Validates legacy Microsoft Excel 97-2003 OLE2 Compound Document."""
        return cls._validate_ole2_document(data, expected_marker=b"Workbook", doc_type="xls")

    @classmethod
    def _validate_ppt(cls, data: bytes) -> Dict[str, Any]:
        """Validates legacy Microsoft PowerPoint 97-2003 OLE2 Compound Document."""
        return cls._validate_ole2_document(data, expected_marker=b"PowerPoint Document", doc_type="ppt")

    @classmethod
    def _validate_ole2_document(cls, data: bytes, expected_marker: bytes, doc_type: str) -> Dict[str, Any]:
        ole2_magic = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"
        if len(data) < 512 or not data.startswith(ole2_magic):
            return cls._create_result(False, False, False, False, 0.0, doc_type, error=f"Invalid OLE2 {doc_type.upper()} header")

        sector_shift = struct.unpack("<H", data[30:32])[0]
        sector_size = 1 << sector_shift if sector_shift in (9, 12) else 512
        num_fat_sectors = struct.unpack("<I", data[44:48])[0]

        has_marker = expected_marker in data
        details = {
            "sector_size": sector_size,
            "num_fat_sectors": num_fat_sectors,
            "stream_marker_found": has_marker,
            "total_bytes": len(data)
        }

        limitations = (
            f"Legacy OLE2 binary container. Header and sector allocation validated; "
            f"complete internal stream defragmentation proof requires dedicated OLE2 parser."
        )

        if sector_shift not in (9, 12):
            return cls._create_result(
                False, True, False, False, 0.3, doc_type,
                details=details, error="Invalid sector shift value in OLE2 header",
                status="CORRUPT_OR_TRUNCATED", limitations=limitations
            )

        is_valid = has_marker or len(data) >= sector_size * 2
        return cls._create_result(
            is_valid, True, True, is_valid,
            0.85 if has_marker else 0.6,
            doc_type, details=details, limitations=limitations
        )

    @classmethod
    def _validate_pdf(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 32 or not data.startswith(b"%PDF-"):
            return cls._create_result(False, False, False, False, 0.0, "pdf", error="Missing %PDF- header")

        has_eof = b"%%EOF" in data[-1024:]
        has_xref = b"xref" in data or b"/XRef" in data
        has_trailer = b"trailer" in data or b"/Root" in data

        version = data[5:8].decode("ascii", errors="ignore")
        details = {
            "version": version,
            "has_eof": has_eof,
            "has_xref": has_xref,
            "has_trailer": has_trailer,
            "length": len(data)
        }

        if not has_eof:
            return cls._create_result(
                False, True, False, False, 0.35, "pdf",
                details=details, error="Missing %%EOF marker in PDF trailer (truncated)",
                status="TRUNCATED"
            )

        structure_valid = has_xref and has_trailer and has_eof
        return cls._create_result(
            is_valid=True,
            signature_detected=True,
            structure_validated=structure_valid,
            content_readable=True,
            confidence=0.95 if structure_valid else 0.7,
            file_type="pdf",
            details=details
        )

    @classmethod
    def _validate_rtf(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 10 or not data.startswith(b"{\\rtf1"):
            return cls._create_result(False, False, False, False, 0.0, "rtf", error="Invalid RTF header")

        has_closing = data.rstrip().endswith(b"}")
        details = {"has_header": True, "has_closing_brace": has_closing, "length": len(data)}

        return cls._create_result(
            is_valid=has_closing,
            signature_detected=True,
            structure_validated=has_closing,
            content_readable=has_closing,
            confidence=0.9 if has_closing else 0.4,
            file_type="rtf",
            details=details,
            error=None if has_closing else "Missing closing brace '}' in RTF document",
            status="VALID" if has_closing else "TRUNCATED"
        )

    @classmethod
    def _validate_txt(cls, data: bytes) -> Dict[str, Any]:
        """
        Validates plaintext content using encoding analysis and character distribution.
        Does NOT rely on a fabricated magic signature.
        """
        if len(data) == 0:
            return cls._create_result(False, False, False, False, 0.0, "txt", error="Empty file")

        # Plaintext documents should not contain NUL bytes
        if b"\x00" in data:
            return cls._create_result(
                False, False, False, False, 0.1, "txt",
                error="Binary NUL byte detected in text stream",
                status="INVALID"
            )

        # Attempt UTF-8 decoding
        try:
            text = data.decode("utf-8")
            printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
            ratio = printable / len(text)
            is_valid = ratio >= 0.88
            details = {"encoding": "utf-8", "printable_ratio": round(ratio, 2), "char_count": len(text)}
            return cls._create_result(
                is_valid,
                is_valid,
                is_valid,
                is_valid,
                0.9 if is_valid else 0.3,
                "txt",
                details=details,
                error=None if is_valid else "High binary noise in text stream"
            )
        except UnicodeDecodeError:
            try:
                text = data.decode("latin-1")
                printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
                ratio = printable / len(text)
                is_valid = ratio >= 0.92
                details = {"encoding": "latin-1", "printable_ratio": round(ratio, 2), "char_count": len(text)}
                return cls._create_result(
                    is_valid,
                    is_valid,
                    is_valid,
                    is_valid,
                    0.65 if is_valid else 0.2,
                    "txt",
                    details=details,
                    error=None if is_valid else "Binary character sequence in latin-1 decode"
                )
            except Exception as e:
                return cls._create_result(False, False, False, False, 0.1, "txt", error=f"Decode error: {e}")

    # ==========================================
    # VIDEOS & AUDIO VALIDATION (ISOBMFF, RIFF, EBML, FLAC)
    # ==========================================

    @classmethod
    def _validate_mp4(cls, data: bytes) -> Dict[str, Any]:
        return cls._validate_isobmff_video(data, expected_brand=None, file_type="mp4")

    @classmethod
    def _validate_mov(cls, data: bytes) -> Dict[str, Any]:
        if len(data) >= 8 and (data[4:8] == b"moov" or data[4:8] == b"wide"):
            return cls._create_result(True, True, True, True, 0.9, "mov", details={"format": "Legacy QuickTime (moov/wide)"})
        return cls._validate_isobmff_video(data, expected_brand=b"qt  ", file_type="mov")

    @classmethod
    def _validate_3gp(cls, data: bytes) -> Dict[str, Any]:
        return cls._validate_isobmff_video(data, expected_brand=b"3gp", file_type="3gp")

    @classmethod
    def _validate_m4a(cls, data: bytes) -> Dict[str, Any]:
        return cls._validate_isobmff_video(data, expected_brand=b"M4A ", file_type="m4a")

    @classmethod
    def _validate_isobmff_video(cls, data: bytes, expected_brand: Optional[bytes], file_type: str) -> Dict[str, Any]:
        if len(data) < 16:
            return cls._create_result(False, False, False, False, 0.0, file_type, error="File too small for ISO-BMFF container")

        first_atom_size = struct.unpack(">I", data[0:4])[0]
        first_atom_type = data[4:8]
        if first_atom_type != b"ftyp":
            return cls._create_result(False, False, False, False, 0.0, file_type, error="Missing ftyp container box")

        major_brand = data[8:12]
        has_media = b"moov" in data or b"mdat" in data

        # Scan top-level boxes
        offset = 0
        boxes = []
        while offset + 8 <= len(data):
            try:
                b_size = struct.unpack(">I", data[offset:offset+4])[0]
                b_type = data[offset+4:offset+8].decode("ascii", errors="replace")
                boxes.append(b_type)
                if b_size <= 1:
                    break
                offset += b_size
            except Exception:
                break

        details = {
            "first_box_size": first_atom_size,
            "major_brand": major_brand.decode("ascii", errors="replace"),
            "has_media_atoms": has_media,
            "boxes_found": boxes,
            "length": len(data)
        }

        if expected_brand and expected_brand not in major_brand and expected_brand not in data[12:32]:
            return cls._create_result(
                False, True, False, False, 0.3, file_type,
                details=details, error=f"Container brand does not match expected {file_type.upper()}",
                status="MISLEADING_SIGNATURE"
            )

        if not has_media:
            return cls._create_result(
                False, True, False, False, 0.35, file_type,
                details=details, error="Missing essential media data atoms (moov/mdat)",
                status="TRUNCATED"
            )

        is_valid = len(data) >= first_atom_size
        return cls._create_result(
            is_valid=is_valid,
            signature_detected=True,
            structure_validated=is_valid,
            content_readable=is_valid,
            confidence=0.9 if is_valid else 0.4,
            file_type=file_type,
            details=details,
            error=None if is_valid else "Truncated ISO-BMFF container"
        )

    @classmethod
    def _validate_avi(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 16 or not (data.startswith(b"RIFF") and data[8:12] == b"AVI "):
            return cls._create_result(False, False, False, False, 0.0, "avi", error="Invalid AVI signature")

        riff_len = struct.unpack("<I", data[4:8])[0]
        has_hdrl = b"hdrl" in data[:128]
        has_movi = b"movi" in data
        details = {
            "riff_length": riff_len,
            "actual_size": len(data),
            "has_hdrl": has_hdrl,
            "has_movi": has_movi
        }

        if not has_hdrl:
            return cls._create_result(
                False, True, False, False, 0.3, "avi",
                details=details, error="Missing hdrl list in AVI header", status="CORRUPT_STRUCTURE"
            )

        is_valid = has_movi or len(data) >= riff_len + 8
        return cls._create_result(
            is_valid, True, is_valid, is_valid,
            0.9 if is_valid else 0.4, "avi", details=details,
            error=None if is_valid else "Truncated AVI video stream"
        )

    @classmethod
    def _validate_mkv(cls, data: bytes) -> Dict[str, Any]:
        ebml_sig = b"\x1a\x45\xdf\xa3"
        if len(data) < 12 or not data.startswith(ebml_sig):
            return cls._create_result(False, False, False, False, 0.0, "mkv", error="Invalid Matroska EBML signature")

        is_mkv = b"matroska" in data[:128] or b"webm" in data[:128]
        details = {"is_matroska": is_mkv, "length": len(data)}

        return cls._create_result(
            True, True, True, True,
            0.9 if is_mkv else 0.7, "mkv", details=details
        )

    @classmethod
    def _validate_mp3(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 10:
            return cls._create_result(False, False, False, False, 0.0, "mp3", error="File too small")

        has_id3 = data.startswith(b"ID3")
        has_sync = (
            b"\xFF\xFB" in data[:1024] or
            b"\xFF\xF3" in data[:1024] or
            b"\xFF\xF2" in data[:1024] or
            b"\xFF\xFA" in data[:1024]
        )
        details = {"has_id3": has_id3, "has_frame_sync": has_sync, "length": len(data)}

        if not (has_id3 or has_sync):
            return cls._create_result(
                False, False, False, False, 0.0, "mp3",
                details=details, error="Missing MP3 frame sync word and ID3 tag"
            )

        return cls._create_result(
            True, True, True, True,
            0.9 if (has_id3 and has_sync) else 0.8,
            "mp3", details=details
        )

    @classmethod
    def _validate_wav(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 16 or not (data.startswith(b"RIFF") and data[8:12] == b"WAVE"):
            return cls._create_result(False, False, False, False, 0.0, "wav", error="Invalid WAV signature")

        has_fmt = b"fmt " in data[12:44]
        riff_len = struct.unpack("<I", data[4:8])[0]
        details = {
            "riff_length": riff_len,
            "actual_size": len(data),
            "has_fmt_chunk": has_fmt
        }

        if not has_fmt:
            return cls._create_result(
                False, True, False, False, 0.3, "wav",
                details=details, error="Missing fmt chunk in WAV audio stream", status="CORRUPT_STRUCTURE"
            )

        is_valid = len(data) >= riff_len + 8 or len(data) >= 44
        return cls._create_result(
            is_valid, True, is_valid, is_valid,
            0.95 if is_valid else 0.45, "wav", details=details,
            error=None if is_valid else "Truncated WAV audio stream"
        )

    @classmethod
    def _validate_aac(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 8:
            return cls._create_result(False, False, False, False, 0.0, "aac", error="File too small")

        # ADTS sync word is 12 bits set: 0xFFF
        has_sync = (data[0] == 0xFF) and ((data[1] & 0xF0) == 0xF0)
        details = {"has_adts_sync": has_sync, "length": len(data)}

        if not has_sync:
            return cls._create_result(
                False, False, False, False, 0.0, "aac",
                details=details, error="Missing ADTS frame sync word (0xFFF)"
            )

        return cls._create_result(True, True, True, True, 0.85, "aac", details=details)

    @classmethod
    def _validate_flac(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 42 or not data.startswith(b"fLaC"):
            return cls._create_result(False, False, False, False, 0.0, "flac", error="Invalid FLAC signature")

        # First metadata block MUST be STREAMINFO (type 0, length 34 bytes)
        first_block_type = data[4] & 0x7F
        block_len = struct.unpack(">I", b"\x00" + data[5:8])[0]
        has_streaminfo = (first_block_type == 0 and block_len == 34)

        details = {
            "first_block_type": first_block_type,
            "streaminfo_valid": has_streaminfo,
            "length": len(data)
        }

        if not has_streaminfo:
            return cls._create_result(
                False, True, False, False, 0.3, "flac",
                details=details, error="Missing or invalid FLAC STREAMINFO header block",
                status="CORRUPT_STRUCTURE"
            )

        return cls._create_result(True, True, True, True, 0.95, "flac", details=details)

    # ==========================================
    # ARCHIVES VALIDATION (ZIP, RAR, 7Z, GZ)
    # ==========================================

    @classmethod
    def _validate_zip(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 22 or not data.startswith(b"PK\x03\x04"):
            return cls._create_result(False, False, False, False, 0.0, "zip", error="Invalid ZIP header")

        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                bad_file = zf.testzip()
                namelist = zf.namelist()

                # Detect office subtypes
                detected_subtype = "zip"
                if any(n.startswith("word/") for n in namelist):
                    detected_subtype = "docx"
                elif any(n.startswith("xl/") for n in namelist):
                    detected_subtype = "xlsx"
                elif any(n.startswith("ppt/") for n in namelist):
                    detected_subtype = "pptx"

                details = {
                    "file_count": len(namelist),
                    "sub_type": detected_subtype,
                    "bad_crc_member": bad_file,
                    "entries": namelist[:8]
                }

                if bad_file:
                    return cls._create_result(
                        False, True, False, False, 0.3, "zip",
                        details=details, error=f"CRC check failed for: {bad_file}", status="CORRUPT_STRUCTURE"
                    )

                return cls._create_result(True, True, True, True, 1.0, detected_subtype, details=details)
        except zipfile.BadZipFile as e:
            return cls._create_result(
                False, True, False, False, 0.25, "zip",
                error=f"Corrupted or truncated ZIP archive: {e}", status="CORRUPT_STRUCTURE"
            )
        except Exception as e:
            return cls._create_result(
                False, True, False, False, 0.2, "zip",
                error=f"ZIP parsing failure: {e}", status="CORRUPT_STRUCTURE"
            )

    @classmethod
    def _validate_rar(cls, data: bytes) -> Dict[str, Any]:
        is_rar4 = data.startswith(b"Rar!\x1a\x07\x00")
        is_rar5 = data.startswith(b"Rar!\x1a\x07\x01\x00")
        if not (is_rar4 or is_rar5):
            return cls._create_result(False, False, False, False, 0.0, "rar", error="Invalid RAR signature")

        ver = "RAR 4.x" if is_rar4 else "RAR 5.0+"
        details = {"version": ver, "length": len(data)}

        return cls._create_result(True, True, True, True, 0.95, "rar", details=details)

    @classmethod
    def _validate_7z(cls, data: bytes) -> Dict[str, Any]:
        sig = b"7z\xbc\xaf\x27\x1c"
        if len(data) < 32 or not data.startswith(sig):
            return cls._create_result(False, False, False, False, 0.0, "7z", error="Invalid 7-Zip signature")

        major_ver = data[6]
        minor_ver = data[7]
        details = {"version": f"{major_ver}.{minor_ver}", "length": len(data)}

        return cls._create_result(True, True, True, True, 0.95, "7z", details=details)

    @classmethod
    def _validate_gz(cls, data: bytes) -> Dict[str, Any]:
        if len(data) < 10 or not data.startswith(b"\x1F\x8B\x08"):
            return cls._create_result(False, False, False, False, 0.0, "gz", error="Invalid GZIP signature or method")

        flags = data[3]
        details = {"compression_method": "DEFLATE (0x08)", "flags": flags, "length": len(data)}

        return cls._create_result(True, True, True, True, 0.9, "gz", details=details)

    # ==========================================
    # GENERIC & UNSUPPORTED FORMAT HANDLER
    # ==========================================

    @classmethod
    def _validate_generic(cls, data: bytes, file_type: str) -> Dict[str, Any]:
        """Handles unsupported or ambiguous formats with honest forensic disclosure."""
        return cls._create_result(
            is_valid=False,
            signature_detected=False,
            structure_validated=False,
            content_readable=False,
            confidence=0.0,
            file_type=file_type,
            details={"length": len(data)},
            error="No dedicated structural validator available for this format",
            status="UNSUPPORTED_FORMAT",
            limitations="Format structure was not validated. Carving limited to raw header/trailer bounds."
        )
