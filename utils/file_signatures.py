"""
File Signatures and Format Header/Trailer Specifications
Contains forensic magic bytes, trailer patterns, and container size estimators.
Supports 22+ file formats spanning Images, Videos, Audio, Documents, and Archives.
"""
from dataclasses import dataclass
from typing import List, Optional, Tuple, Callable
import struct

@dataclass
class SignatureDefinition:
    extension: str
    description: str
    category: str
    headers: List[bytes]
    header_offset: int = 0
    trailers: Optional[List[bytes]] = None
    min_size: int = 16
    max_size: int = 500 * 1024 * 1024
    mime_type: str = "application/octet-stream"

def parse_riff_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Calculates total file size from a RIFF header (WebP, AVI, WAV)."""
    if len(data) < offset + 12:
        return None
    if data[offset:offset+4] != b"RIFF":
        return None
    riff_len = struct.unpack("<I", data[offset+4:offset+8])[0]
    total_size = riff_len + 8
    return total_size

def parse_bmp_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Calculates total file size from BMP header (offset 2, 4-byte LE uint)."""
    if len(data) < offset + 14:
        return None
    if data[offset:offset+2] != b"BM":
        return None
    bmp_size = struct.unpack("<I", data[offset+2:offset+6])[0]
    if 26 <= bmp_size <= len(data) - offset:
        return bmp_size
    return None

def parse_png_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Walks PNG chunks to determine exact PNG file length."""
    png_header = b"\x89PNG\r\n\x1a\n"
    if len(data) < offset + 8 or data[offset:offset+8] != png_header:
        return None
    
    pos = offset + 8
    max_len = len(data)
    
    while pos + 8 <= max_len:
        chunk_len = struct.unpack(">I", data[pos:pos+4])[0]
        chunk_type = data[pos+4:pos+8]
        pos += 8 + chunk_len + 4  # length(4) + type(4) + data(chunk_len) + crc(4)
        if chunk_type == b"IEND":
            return pos - offset
        if pos > max_len:
            break
    return None

def parse_zip_size(data: bytes, offset: int = 0, search_window: int = 65536) -> Optional[int]:
    """Finds End of Central Directory record (PK\\x05\\x06) to compute exact ZIP length."""
    if len(data) < offset + 4 or data[offset:offset+4] != b"PK\x03\x04":
        return None

    data_slice = data[offset:]
    eocd_sig = b"PK\x05\x06"
    eocd_idx = data_slice.rfind(eocd_sig)
    
    if eocd_idx != -1 and len(data_slice) >= eocd_idx + 22:
        comment_len = struct.unpack("<H", data_slice[eocd_idx+20:eocd_idx+22])[0]
        total_len = eocd_idx + 22 + comment_len
        if total_len <= len(data_slice):
            return total_len
    return None

def parse_7z_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Calculates 7-Zip archive total size from 32-byte header."""
    sig = b"7z\xbc\xaf\x27\x1c"
    if len(data) < offset + 32 or data[offset:offset+6] != sig:
        return None
    # 7z header: 6 sig + 2 ver + 4 startHeaderCRC + 8 nextHeaderOffset + 8 nextHeaderSize + 4 nextHeaderCRC
    next_hdr_offset = struct.unpack("<Q", data[offset+12:offset+20])[0]
    next_hdr_size = struct.unpack("<Q", data[offset+20:offset+28])[0]
    total_len = 32 + next_hdr_offset + next_hdr_size
    if 32 <= total_len <= len(data) - offset:
        return total_len
    return None

def parse_isobmff_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Walks ISO Base Media File Format top-level boxes (MP4, MOV, M4A, HEIC)."""
    if len(data) < offset + 8:
        return None
    
    pos = offset
    max_len = len(data)
    total_size = 0
    found_first_box = False

    while pos + 8 <= max_len:
        box_size = struct.unpack(">I", data[pos:pos+4])[0]
        box_type = data[pos+4:pos+8]

        if not found_first_box:
            if box_type not in (b"ftyp", b"moov", b"mdat", b"wide", b"skip", b"free"):
                return None
            found_first_box = True

        if box_size == 1:
            if pos + 16 > max_len:
                break
            box_size = struct.unpack(">Q", data[pos+8:pos+16])[0]
        elif box_size == 0:
            return max_len - offset

        if box_size < 8:
            break

        total_size += box_size
        pos += box_size
        
        if pos >= max_len:
            return total_size
        if pos + 8 <= max_len:
            next_type = data[pos+4:pos+8]
            if not all(32 <= b <= 126 for b in next_type):
                return total_size

    return total_size if found_first_box and total_size > 0 else None

def parse_mp4_size(data: bytes, offset: int = 0) -> Optional[int]:
    return parse_isobmff_size(data, offset)

def parse_jpeg_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Finds JPEG EOI marker (\\xFF\\xD9)."""
    if len(data) < offset + 3 or data[offset:offset+3] != b"\xFF\xD8\xFF":
        return None
    
    data_slice = data[offset:]
    eoi_sig = b"\xFF\xD9"
    idx = data_slice.find(eoi_sig)
    while idx != -1:
        end_pos = idx + 2
        if end_pos < len(data_slice) and data_slice[end_pos:end_pos+2] == b"\xFF\xD9":
            idx = data_slice.find(eoi_sig, end_pos)
            continue
        return end_pos
    return None

def parse_pdf_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Locates %%EOF in PDF data stream."""
    if len(data) < offset + 5 or data[offset:offset+5] != b"%PDF-":
        return None
    data_slice = data[offset:offset + 50 * 1024 * 1024]
    eof_sig = b"%%EOF"
    idx = data_slice.find(eof_sig)
    if idx != -1:
        end = idx + 5
        while end < len(data_slice) and data_slice[end:end+1] in (b"\r", b"\n"):
            end += 1
        return end
    return None

def parse_gif_size(data: bytes, offset: int = 0) -> Optional[int]:
    """Locates GIF terminal byte (0x3B)."""
    if len(data) < offset + 6:
        return None
    hdr = data[offset:offset+6]
    if hdr not in (b"GIF87a", b"GIF89a"):
        return None
    data_slice = data[offset:]
    idx = data_slice.rfind(b"\x00\x3B")
    if idx != -1:
        return idx + 2
    idx2 = data_slice.rfind(b"\x3B")
    if idx2 != -1:
        return idx2 + 1
    return None

SIGNATURE_DATABASE: List[SignatureDefinition] = [
    # --- Images ---
    SignatureDefinition(
        extension="jpg",
        description="JPEG Image",
        category="Images",
        headers=[b"\xFF\xD8\xFF\xE0", b"\xFF\xD8\xFF\xE1", b"\xFF\xD8\xFF\xE2", b"\xFF\xD8\xFF\xDB", b"\xFF\xD8\xFF\xEE"],
        trailers=[b"\xFF\xD9"],
        mime_type="image/jpeg",
        min_size=32
    ),
    SignatureDefinition(
        extension="png",
        description="Portable Network Graphics",
        category="Images",
        headers=[b"\x89PNG\r\n\x1a\n"],
        trailers=[b"IEND\xaeB`\x82"],
        mime_type="image/png",
        min_size=32
    ),
    SignatureDefinition(
        extension="gif",
        description="Graphics Interchange Format",
        category="Images",
        headers=[b"GIF87a", b"GIF89a"],
        trailers=[b"\x3B"],
        mime_type="image/gif",
        min_size=32
    ),
    SignatureDefinition(
        extension="webp",
        description="WebP Image (RIFF container)",
        category="Images",
        headers=[b"RIFF"],
        mime_type="image/webp",
        min_size=32
    ),
    SignatureDefinition(
        extension="bmp",
        description="Windows Bitmap Image",
        category="Images",
        headers=[b"BM"],
        mime_type="image/bmp",
        min_size=26
    ),
    SignatureDefinition(
        extension="tiff",
        description="Tagged Image File Format",
        category="Images",
        headers=[b"II*\x00", b"MM\x00*"],
        mime_type="image/tiff",
        min_size=32
    ),
    SignatureDefinition(
        extension="heic",
        description="High Efficiency Image Container",
        category="Images",
        headers=[b"ftypheic", b"ftypmif1", b"ftypmsf1", b"ftypheix"],
        header_offset=4,
        mime_type="image/heic",
        min_size=64
    ),

    # --- Videos ---
    SignatureDefinition(
        extension="mp4",
        description="MP4 / ISO Base Media Video",
        category="Videos",
        headers=[b"ftypisom", b"ftypmp42", b"ftypMSNV", b"ftyp"],
        header_offset=4,
        mime_type="video/mp4",
        min_size=64
    ),
    SignatureDefinition(
        extension="mov",
        description="Apple QuickTime Movie",
        category="Videos",
        headers=[b"ftypqt  ", b"moov"],
        header_offset=4,
        mime_type="video/quicktime",
        min_size=64
    ),
    SignatureDefinition(
        extension="3gp",
        description="3GPP Multimedia File",
        category="Videos",
        headers=[b"ftyp3gp", b"ftyp3g2"],
        header_offset=4,
        mime_type="video/3gpp",
        min_size=64
    ),
    SignatureDefinition(
        extension="avi",
        description="Audio Video Interleave (RIFF container)",
        category="Videos",
        headers=[b"RIFF"],
        mime_type="video/x-msvideo",
        min_size=64
    ),
    SignatureDefinition(
        extension="mkv",
        description="Matroska Video Container",
        category="Videos",
        headers=[b"\x1a\x45\xdf\xa3"],
        mime_type="video/x-matroska",
        min_size=64
    ),

    # --- Audio ---
    SignatureDefinition(
        extension="mp3",
        description="MPEG Audio Layer 3",
        category="Audio",
        headers=[b"ID3", b"\xFF\xFB", b"\xFF\xF3", b"\xFF\xF2"],
        mime_type="audio/mpeg",
        min_size=64
    ),
    SignatureDefinition(
        extension="wav",
        description="Waveform Audio (RIFF container)",
        category="Audio",
        headers=[b"RIFF"],
        mime_type="audio/wav",
        min_size=44
    ),
    SignatureDefinition(
        extension="m4a",
        description="MPEG-4 Audio",
        category="Audio",
        headers=[b"ftypM4A "],
        header_offset=4,
        mime_type="audio/mp4",
        min_size=64
    ),
    SignatureDefinition(
        extension="aac",
        description="Advanced Audio Coding (ADTS stream)",
        category="Audio",
        headers=[b"\xFF\xF1", b"\xFF\xF9"],
        mime_type="audio/aac",
        min_size=64
    ),
    SignatureDefinition(
        extension="flac",
        description="Free Lossless Audio Codec",
        category="Audio",
        headers=[b"fLaC"],
        mime_type="audio/flac",
        min_size=42
    ),

    # --- Documents ---
    SignatureDefinition(
        extension="pdf",
        description="Adobe Portable Document Format",
        category="Documents",
        headers=[b"%PDF-"],
        trailers=[b"%%EOF"],
        mime_type="application/pdf",
        min_size=64
    ),
    SignatureDefinition(
        extension="doc",
        description="Microsoft Word 97-2003 Document (OLE2)",
        category="Documents",
        headers=[b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"],
        mime_type="application/msword",
        min_size=512
    ),
    SignatureDefinition(
        extension="xls",
        description="Microsoft Excel 97-2003 Spreadsheet (OLE2)",
        category="Documents",
        headers=[b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"],
        mime_type="application/vnd.ms-excel",
        min_size=512
    ),
    SignatureDefinition(
        extension="ppt",
        description="Microsoft PowerPoint 97-2003 Presentation (OLE2)",
        category="Documents",
        headers=[b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"],
        mime_type="application/vnd.ms-powerpoint",
        min_size=512
    ),
    SignatureDefinition(
        extension="rtf",
        description="Rich Text Format Document",
        category="Documents",
        headers=[b"{\\rtf1"],
        trailers=[b"}"],
        mime_type="application/rtf",
        min_size=10
    ),
    SignatureDefinition(
        extension="zip",
        description="ZIP Archive / Office Open XML (DOCX/XLSX/PPTX)",
        category="Archives",
        headers=[b"PK\x03\x04"],
        trailers=[b"PK\x05\x06"],
        mime_type="application/zip",
        min_size=22
    ),
    SignatureDefinition(
        extension="docx",
        description="Microsoft Word Document",
        category="Documents",
        headers=[b"PK\x03\x04"],
        trailers=[b"PK\x05\x06"],
        mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        min_size=100
    ),
    SignatureDefinition(
        extension="xlsx",
        description="Microsoft Excel Spreadsheet",
        category="Documents",
        headers=[b"PK\x03\x04"],
        trailers=[b"PK\x05\x06"],
        mime_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        min_size=100
    ),
    SignatureDefinition(
        extension="pptx",
        description="Microsoft PowerPoint Presentation",
        category="Documents",
        headers=[b"PK\x03\x04"],
        trailers=[b"PK\x05\x06"],
        mime_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        min_size=100
    ),
    SignatureDefinition(
        extension="txt",
        description="Plain Text Document",
        category="Documents",
        headers=[],
        mime_type="text/plain",
        min_size=1
    ),

    # --- Archives ---
    SignatureDefinition(
        extension="rar",
        description="WinRAR Compressed Archive",
        category="Archives",
        headers=[b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00"],
        mime_type="application/x-rar-compressed",
        min_size=24
    ),
    SignatureDefinition(
        extension="7z",
        description="7-Zip Compressed Archive",
        category="Archives",
        headers=[b"7z\xbc\xaf\x27\x1c"],
        mime_type="application/x-7z-compressed",
        min_size=32
    ),
    SignatureDefinition(
        extension="gz",
        description="Gzip Compressed Archive",
        category="Archives",
        headers=[b"\x1F\x8B\x08"],
        mime_type="application/gzip",
        min_size=18
    )
]

EXTENSION_CATEGORY_MAP = {
    "jpg": "Images",
    "jpeg": "Images",
    "png": "Images",
    "gif": "Images",
    "webp": "Images",
    "bmp": "Images",
    "tiff": "Images",
    "tif": "Images",
    "heic": "Images",
    "mp4": "Videos",
    "mov": "Videos",
    "avi": "Videos",
    "mkv": "Videos",
    "3gp": "Videos",
    "mp3": "Audio",
    "wav": "Audio",
    "m4a": "Audio",
    "opus": "Audio",
    "ogg": "Audio",
    "pdf": "Documents",
    "docx": "Documents",
    "doc": "Documents",
    "xlsx": "Documents",
    "xls": "Documents",
    "pptx": "Documents",
    "ppt": "Documents",
    "txt": "Documents",
    "zip": "Archives",
    "rar": "Archives",
    "7z": "Archives",
    "tar": "Archives",
    "gz": "Archives"
}

def get_file_category(extension: str) -> str:
    """Returns human-readable category for a given file extension."""
    return EXTENSION_CATEGORY_MAP.get(extension.lower().lstrip("."), "Other")
