"""
Test Suite for File Signatures, Carving, and Header/Trailer Identification.
"""
import pytest
import struct
import io
import zipfile
from pathlib import Path

from utils.file_signatures import (
    parse_riff_size,
    parse_png_size,
    parse_zip_size,
    parse_mp4_size,
    parse_jpeg_size,
    parse_pdf_size,
    parse_gif_size,
)
from engine.signature_scanner import SignatureScanner
from utils.hashing import compute_sha256

def create_synthetic_png() -> bytes:
    """Constructs a minimal valid PNG in memory using Pillow if available."""
    try:
        from PIL import Image
        img = Image.new("RGB", (2, 2), color=(255, 0, 0))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        png_hdr = b"\x89PNG\r\n\x1a\n"
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_chunk = struct.pack(">I", len(ihdr_data)) + b"IHDR" + ihdr_data + b"\x00\x00\x00\x00"
        iend_chunk = struct.pack(">I", 0) + b"IEND" + b"\xaeB`\x82"
        return png_hdr + ihdr_chunk + iend_chunk

def create_synthetic_jpg() -> bytes:
    """Constructs a minimal valid JPEG image."""
    try:
        from PIL import Image
        img = Image.new("RGB", (2, 2), color=(0, 255, 0))
        buf = io.BytesIO()
        img.save(buf, format="JPEG")
        return buf.getvalue()
    except Exception:
        soi = b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01\x01\x01\x00`\x00`\x00\x00"
        eoi = b"\xFF\xD9"
        payload = b"\xFF\xDB\x00\x43\x00" + (b"\x01" * 64)
        return soi + payload + eoi

def create_synthetic_gif() -> bytes:
    """Constructs a minimal valid GIF image."""
    try:
        from PIL import Image
        img = Image.new("P", (2, 2), color=0)
        buf = io.BytesIO()
        img.save(buf, format="GIF")
        return buf.getvalue()
    except Exception:
        hdr = b"GIF89a"
        lsd = struct.pack("<HHBBB", 1, 1, 0x80, 0, 0)  # 1x1, global color table
        color_table = b"\x00\x00\x00\xFF\xFF\xFF"
        trailer = b"\x3B"
        return hdr + lsd + color_table + trailer

def create_synthetic_webp() -> bytes:
    """Constructs a minimal WebP RIFF file."""
    try:
        from PIL import Image
        img = Image.new("RGB", (2, 2), color=(0, 0, 255))
        buf = io.BytesIO()
        img.save(buf, format="WEBP")
        return buf.getvalue()
    except Exception:
        vp8_data = b"VP8 " + struct.pack("<I", 10) + (b"\x00" * 10)
        riff_len = 4 + len(vp8_data)
        header = b"RIFF" + struct.pack("<I", riff_len) + b"WEBP"
        return header + vp8_data

def create_synthetic_pdf() -> bytes:
    """Constructs a minimal valid PDF."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj\n"
        b"2 0 obj << /Type /Pages /Kids [] /Count 0 >> endobj\n"
        b"xref\n0 3\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n"
        b"trailer << /Size 3 /Root 1 0 R >>\n"
        b"startxref\n115\n%%EOF\n"
    )

def create_synthetic_zip() -> bytes:
    """Constructs a minimal valid ZIP archive."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("test.txt", "RecoverX Test Payload")
    return buf.getvalue()

def create_synthetic_mp4() -> bytes:
    """Constructs a minimal valid MP4 file."""
    # ftyp atom: 4 bytes len (16) + 'ftyp' + 'isom' + version (0x200)
    ftyp_data = b"isom" + struct.pack(">I", 0x200)
    ftyp_box = struct.pack(">I", 8 + len(ftyp_data)) + b"ftyp" + ftyp_data
    # moov atom: 4 bytes len (8) + 'moov'
    moov_box = struct.pack(">I", 8) + b"moov"
    return ftyp_box + moov_box

def create_synthetic_avi() -> bytes:
    """Constructs a minimal valid AVI file."""
    avi_content = b"AVI LIST" + struct.pack("<I", 4) + b"hdrl"
    riff_len = len(avi_content)
    return b"RIFF" + struct.pack("<I", riff_len) + avi_content

def create_synthetic_mp3() -> bytes:
    """Constructs a minimal MP3 with ID3v2 header."""
    # ID3v2.3: ID3 + 0x03 0x00 + flags(0x00) + size (syncsafe 10 bytes)
    id3_hdr = b"ID3\x03\x00\x00\x00\x00\x00\x0A"
    id3_tag = id3_hdr + (b"\x00" * 10)
    # MPEG frame sync \xFF\xFB (Layer III)
    frame = b"\xFF\xFB\x90\x00" + (b"\x55" * 100)
    return id3_tag + frame

def create_synthetic_wav() -> bytes:
    """Constructs a minimal valid WAV file."""
    fmt_chunk = b"fmt " + struct.pack("<IHHIIHH", 16, 1, 1, 44100, 88200, 2, 16)
    data_chunk = b"data" + struct.pack("<I", 4) + b"\x00\x00\x00\x00"
    wave_content = b"WAVE" + fmt_chunk + data_chunk
    riff_hdr = b"RIFF" + struct.pack("<I", len(wave_content))
    return riff_hdr + wave_content

def test_signature_size_parsers():
    png = create_synthetic_png()
    assert parse_png_size(png) == len(png)

    jpg = create_synthetic_jpg()
    assert parse_jpeg_size(jpg) == len(jpg)

    webp = create_synthetic_webp()
    assert parse_riff_size(webp) == len(webp)

    zip_bytes = create_synthetic_zip()
    assert parse_zip_size(zip_bytes) == len(zip_bytes)

    pdf = create_synthetic_pdf()
    assert parse_pdf_size(pdf) == len(pdf)

    mp4 = create_synthetic_mp4()
    assert parse_mp4_size(mp4) == len(mp4)

    wav = create_synthetic_wav()
    assert parse_riff_size(wav) == len(wav)

def test_synthetic_disk_image_carving(tmp_path: Path):
    """Embeds files in a simulated raw disk image surrounded by null bytes and carves them."""
    png = create_synthetic_png()
    jpg = create_synthetic_jpg()
    zip_bytes = create_synthetic_zip()

    disk_image = bytearray(b"\x00" * 1024)  # 1 KB padding
    disk_image.extend(png)
    disk_image.extend(b"\x00" * 512)
    disk_image.extend(jpg)
    disk_image.extend(b"\x00" * 256)
    disk_image.extend(zip_bytes)
    disk_image.extend(b"\x00" * 1024)

    img_path = tmp_path / "synthetic.img"
    img_path.write_bytes(bytes(disk_image))

    scanner = SignatureScanner()
    carved = scanner.scan_image_file(img_path)

    # We expect at least the 3 carved files
    assert len(carved) >= 3
    carved_types = [c.extension for c in carved]
    assert "png" in carved_types
    assert "jpg" in carved_types
    assert "zip" in carved_types

    # Verify SHA-256 matches
    png_carved = next(c for c in carved if c.extension == "png")
    assert png_carved.sha256 == compute_sha256(png)

    jpg_carved = next(c for c in carved if c.extension == "jpg")
    assert jpg_carved.sha256 == compute_sha256(jpg)
