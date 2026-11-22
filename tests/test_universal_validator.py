"""
Tests for Universal Format-Specific Structural File Validation
=============================================================
Labels:
- [Unit]: Tests isolated structural validation logic and container parsing.
- [Synthetic]: Tests crafted valid, truncated, corrupt, and misleading payloads.
- [Integration]: Tests end-to-end validator invocation via FileValidator.
"""

import io
import zipfile
import pytest
from engine.file_validator import FileValidator, ValidationResult


@pytest.fixture
def validator():
    return FileValidator()


# ==============================================================================
# 1. OOXML (DOCX, XLSX, PPTX) Validation Tests
# ==============================================================================

def test_ooxml_docx_valid(validator, tmp_path):
    """[Unit] Verify structurally valid DOCX with [Content_Types].xml and word/document.xml."""
    docx_file = tmp_path / "sample.docx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types><Default Extension='xml'/></Types>")
        zf.writestr("word/document.xml", b"<w:document><w:body><w:p/></w:body></w:document>")
    docx_file.write_bytes(buf.getvalue())

    res: ValidationResult = validator.validate_file(docx_file, "docx")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.content_readable is True
    assert res.status == "VALID"
    assert res.error is None
    assert "word/document.xml" in res.details.get("valid_components", [])


def test_ooxml_xlsx_valid(validator, tmp_path):
    """[Unit] Verify structurally valid XLSX with xl/workbook.xml."""
    xlsx_file = tmp_path / "sample.xlsx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("xl/workbook.xml", b"<workbook/>")
    xlsx_file.write_bytes(buf.getvalue())

    res = validator.validate_file(xlsx_file, "xlsx")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.content_readable is True
    assert res.status == "VALID"


def test_ooxml_pptx_valid(validator, tmp_path):
    """[Unit] Verify structurally valid PPTX with ppt/presentation.xml."""
    pptx_file = tmp_path / "sample.pptx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", b"<Types/>")
        zf.writestr("ppt/presentation.xml", b"<presentation/>")
    pptx_file.write_bytes(buf.getvalue())

    res = validator.validate_file(pptx_file, "pptx")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.content_readable is True
    assert res.status == "VALID"


def test_ooxml_misleading_signature(validator, tmp_path):
    """[Synthetic] Verify valid ZIP without office parts is flagged as MISLEADING_SIGNATURE."""
    fake_docx = tmp_path / "fake.docx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("readme.txt", b"Just a regular archive masquerading as docx.")
    fake_docx.write_bytes(buf.getvalue())

    res = validator.validate_file(fake_docx, "docx")
    assert res.signature_detected is True
    assert res.structure_validated is False
    assert res.status == "MISLEADING_SIGNATURE"
    assert "missing expected docx components" in (res.error or "").lower()


def test_ooxml_truncated(validator, tmp_path):
    """[Synthetic] Verify truncated ZIP header is flagged as CORRUPT_OR_TRUNCATED."""
    trunc_docx = tmp_path / "trunc.docx"
    # PK\x03\x04 with incomplete data
    trunc_docx.write_bytes(b"\x50\x4b\x03\x04\x14\x00\x00\x00\x08\x00SomeRandomContentCutShort")

    res = validator.validate_file(trunc_docx, "docx")
    assert res.signature_detected is True
    assert res.structure_validated is False
    assert res.status == "CORRUPT_OR_TRUNCATED"


# ==============================================================================
# 2. Legacy OLE2 (DOC, XLS, PPT) Validation Tests
# ==============================================================================

def test_ole2_doc_valid_with_limitations(validator, tmp_path):
    """[Unit] Verify OLE2 DOC file with sector shift and WordDocument stream marker."""
    doc_file = tmp_path / "test.doc"
    # OLE2 Header: 8 bytes magic + 22 bytes padding + 2 bytes sector shift (0x09 = 512 bytes)
    header = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + (b"\x00" * 22) + b"\x09\x00" + (b"\x00" * 480)
    # Payload containing stream marker
    content = header + b"Forensic Word Document Data: WordDocument Stream Body Data"
    doc_file.write_bytes(content)

    res = validator.validate_file(doc_file, "doc")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.status == "VALID_WITH_LIMITATIONS"
    assert res.limitations is not None
    assert "Legacy OLE2" in res.limitations


def test_ole2_corrupt_sector_shift(validator, tmp_path):
    """[Synthetic] Verify OLE2 file with invalid sector shift is flagged CORRUPT_OR_TRUNCATED."""
    bad_doc = tmp_path / "bad.doc"
    # Sector shift is 0x07 (illegal, must be 0x09 for 512 or 0x0C for 4096)
    bad_doc.write_bytes(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + (b"\x00" * 22) + b"\x07\x00" + (b"\x00" * 480))

    res = validator.validate_file(bad_doc, "doc")
    assert res.signature_detected is True
    assert res.structure_validated is False
    assert res.status == "CORRUPT_OR_TRUNCATED"


# ==============================================================================
# 3. PDF Structural & Truncation Tests
# ==============================================================================

def test_pdf_valid(validator, tmp_path):
    """[Unit] Verify valid PDF structure with header, xref and %%EOF."""
    pdf_file = tmp_path / "valid.pdf"
    content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"xref\n0 1\n0000000000 65535 f \n"
        b"trailer\n<< /Root 1 0 R >>\n"
        b"startxref\n50\n%%EOF\n"
    )
    pdf_file.write_bytes(content)

    res = validator.validate_file(pdf_file, "pdf")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.status == "VALID"
    assert res.details.get("has_eof") is True


def test_pdf_truncated(validator, tmp_path):
    """[Synthetic] Verify PDF missing %%EOF is identified as TRUNCATED."""
    trunc_pdf = tmp_path / "trunc.pdf"
    content = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\nxref\n"
    trunc_pdf.write_bytes(content)

    res = validator.validate_file(trunc_pdf, "pdf")
    assert res.signature_detected is True
    assert res.structure_validated is False
    assert res.status == "TRUNCATED"
    assert "Missing %%EOF marker" in (res.error or "")


# ==============================================================================
# 4. Text & Plaintext Content Validation Tests
# ==============================================================================

def test_txt_valid_utf8(validator, tmp_path):
    """[Unit] Verify valid plaintext file with printable UTF-8 characters."""
    txt_file = tmp_path / "notes.txt"
    txt_file.write_text("RecoverX Forensic Case Investigation Log.\nStatus: Clean and readable.", encoding="utf-8")

    res = validator.validate_file(txt_file, "txt")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.content_readable is True
    assert res.status == "VALID"
    assert res.details.get("encoding") in ("ascii", "utf-8")


def test_txt_rejected_binary_data(validator, tmp_path):
    """[Synthetic] Verify binary data with NUL bytes is rejected as TXT."""
    bin_file = tmp_path / "not_text.txt"
    bin_file.write_bytes(b"Header\x00\x01\x02\x03BinaryBytes\x00\xff")

    res = validator.validate_file(bin_file, "txt")
    assert res.signature_detected is False
    assert res.structure_validated is False
    assert res.content_readable is False
    assert res.status == "INVALID"
    assert "NUL byte" in (res.error or "")


# ==============================================================================
# 5. Audio & Video Container Structural Tests
# ==============================================================================

def test_mp4_valid_container(validator, tmp_path):
    """[Unit] Verify MP4 container with ftyp, moov and mdat boxes."""
    mp4_file = tmp_path / "video.mp4"
    # Box 1: ftyp (length 16 = \x00\x00\x00\x10, 'ftyp', 'isom', \x00\x00\x02\x00)
    ftyp_box = b"\x00\x00\x00\x10ftypisom\x00\x00\x02\x00"
    # Box 2: moov (length 8)
    moov_box = b"\x00\x00\x00\x08moov"
    # Box 3: mdat (length 16)
    mdat_box = b"\x00\x00\x00\x10mdat12345678"
    mp4_file.write_bytes(ftyp_box + moov_box + mdat_box)

    res = validator.validate_file(mp4_file, "mp4")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.status == "VALID"
    assert "moov" in res.details.get("boxes_found", [])
    assert "mdat" in res.details.get("boxes_found", [])


def test_mp4_truncated(validator, tmp_path):
    """[Synthetic] Verify MP4 missing moov/mdat payload is marked TRUNCATED."""
    mp4_trunc = tmp_path / "video_trunc.mp4"
    ftyp_box = b"\x00\x00\x00\x10ftypmp42\x00\x00\x00\x00"
    mp4_trunc.write_bytes(ftyp_box)

    res = validator.validate_file(mp4_trunc, "mp4")
    assert res.signature_detected is True
    assert res.structure_validated is False
    assert res.status == "TRUNCATED"


def test_wav_riff_valid(validator, tmp_path):
    """[Unit] Verify RIFF/WAVE container structure."""
    wav_file = tmp_path / "audio.wav"
    # RIFF header: 'RIFF', 4-byte size, 'WAVE', 'fmt ', 16-byte chunk, 'data', 4-byte size
    riff_hdr = b"RIFF" + (36).to_bytes(4, "little") + b"WAVE"
    fmt_chunk = b"fmt " + (16).to_bytes(4, "little") + (b"\x01\x00\x01\x00\x44\xac\x00\x00\x88\x58\x01\x00\x02\x00\x10\x00")
    data_chunk = b"data" + (4).to_bytes(4, "little") + b"\x00\x00\x00\x00"
    wav_file.write_bytes(riff_hdr + fmt_chunk + data_chunk)

    res = validator.validate_file(wav_file, "wav")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.status == "VALID"


def test_flac_valid(validator, tmp_path):
    """[Unit] Verify FLAC stream with fLaC header and STREAMINFO block."""
    flac_file = tmp_path / "test.flac"
    # 'fLaC' + 4-byte block header (0x80 = last-metadata-block flag, 0 = STREAMINFO, 34-byte length)
    header = b"fLaC\x80\x00\x00\x22" + (b"\x00" * 34)
    flac_file.write_bytes(header)

    res = validator.validate_file(flac_file, "flac")
    assert res.signature_detected is True
    assert res.structure_validated is True
    assert res.status == "VALID"


# ==============================================================================
# 6. Unsupported / Ambiguous Format Handling
# ==============================================================================

def test_unsupported_format_handled_honestly(validator, tmp_path):
    """[Synthetic] Verify unknown/unsupported extension returns UNSUPPORTED_FORMAT with honest limitations."""
    unknown_file = tmp_path / "payload.custom_ext"
    unknown_file.write_bytes(b"\x99\x88\x77\x66UnknownPayloadData")

    res = validator.validate_file(unknown_file, "custom_ext")
    assert res.signature_detected is False
    assert res.structure_validated is False
    assert res.status == "UNSUPPORTED_FORMAT"
    assert res.limitations is not None
    assert "Format structure was not validated" in res.limitations


# ==============================================================================
# 7. End-to-End Five Distinguished States Verification
# ==============================================================================

def test_distinguished_states_contract(validator, tmp_path):
    """[Integration] Ensure all 5 distinguished states are explicitly exposed in ValidationResult."""
    txt_file = tmp_path / "contract.txt"
    txt_file.write_text("RecoverX Forensic Contract Verification.")

    res = validator.validate_file(txt_file, "txt")
    # State 1: Signature detected
    assert hasattr(res, "signature_detected") and isinstance(res.signature_detected, bool)
    # State 2: Structure validated
    assert hasattr(res, "structure_validated") and isinstance(res.structure_validated, bool)
    # State 3: Content readable
    assert hasattr(res, "content_readable") and isinstance(res.content_readable, bool)
    # State 4: Recovery completed
    assert hasattr(res, "recovery_completed") and isinstance(res.recovery_completed, bool)
    # State 5: Hash verified
    assert hasattr(res, "hash_verified") and isinstance(res.hash_verified, bool)

    # Dictionary serialization check
    d = res.to_dict()
    for state_key in ["signature_detected", "structure_validated", "content_readable", "recovery_completed", "hash_verified"]:
        assert state_key in d
