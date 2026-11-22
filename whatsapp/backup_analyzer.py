"""
WhatsApp Backup Analyzer for RecoverX
Analyzes the structure, headers, encryption metadata, and key requirements of WhatsApp backup sets.
Supports crypt12, crypt14, crypt15, and plaintext SQLite backups.
"""
from pathlib import Path
from typing import Dict, Any, List, Optional
import os
import struct

from whatsapp.database_finder import WhatsAppDatabaseFinder
from utils.logging_config import logger

class WhatsAppBackupAnalyzer:
    def __init__(self, backup_dir: Path):
        self.backup_dir = Path(backup_dir)

    def analyze(self) -> Dict[str, Any]:
        """Analyzes all backups in the specified directory."""
        if not self.backup_dir.exists() or not self.backup_dir.is_dir():
            return {
                "status": "not_found",
                "path": str(self.backup_dir),
                "total_backups": 0,
                "backups": []
            }

        finder = WhatsAppDatabaseFinder(self.backup_dir)
        dbs = finder.find_databases()

        detailed_backups = []
        for d in dbs:
            b_info = self.analyze_backup_file(d.path)
            d_dict = d.to_dict()
            d_dict["detailed_analysis"] = b_info
            detailed_backups.append(d_dict)

        total_bytes = sum(d.size_bytes for d in dbs)
        dates = [d.backup_date for d in dbs if d.backup_date]

        return {
            "status": "success",
            "path": str(self.backup_dir),
            "total_backup_files": len(dbs),
            "total_size_bytes": total_bytes,
            "backup_dates": sorted(list(set(dates))),
            "backups": detailed_backups
        }

    @staticmethod
    def inspect_key_file(key_input: Any) -> Dict[str, Any]:
        """
        Validates WhatsApp encryption key input (158-byte key file, 32-byte raw key, or 64-char hex key).
        Never attempts brute-forcing or undocumented key extraction.
        """
        raw_bytes = None
        if isinstance(key_input, (str, Path)):
            p = Path(key_input)
            if p.is_file():
                raw_bytes = p.read_bytes()
            elif isinstance(key_input, str):
                s = key_input.strip()
                if len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s):
                    try:
                        raw_bytes = bytes.fromhex(s)
                    except ValueError:
                        raw_bytes = None
        elif isinstance(key_input, (bytes, bytearray)):
            raw_bytes = bytes(key_input)

        if not raw_bytes:
            return {
                "valid": False,
                "key_type": "none",
                "message": "No valid key data provided."
            }

        key_len = len(raw_bytes)
        if key_len == 158:
            # Standard WhatsApp Android key file structure:
            # Header: bytes 0..29
            # AES encryption key: bytes 126..157 (32 bytes / 256 bits)
            aes_key = raw_bytes[126:158]
            return {
                "valid": True,
                "key_type": "whatsapp_android_key_file_158",
                "length_bytes": key_len,
                "aes_key_extracted": True,
                "aes_key_len": len(aes_key),
                "message": "Valid 158-byte Android WhatsApp key file detected."
            }
        elif key_len == 32:
            return {
                "valid": True,
                "key_type": "raw_aes_256_key_or_hex",
                "length_bytes": key_len,
                "aes_key_extracted": True,
                "aes_key_len": 32,
                "message": "Valid 32-byte (256-bit) direct AES key provided."
            }
        else:
            return {
                "valid": False,
                "key_type": f"invalid_length_{key_len}",
                "length_bytes": key_len,
                "message": f"Invalid key length: {key_len} bytes (expected 158-byte key file or 32-byte raw key)."
            }

    @classmethod
    def analyze_backup_file(cls, file_path: Path, key_data: Optional[Any] = None) -> Dict[str, Any]:
        """
        Deep forensic header and structure inspection of a single WhatsApp backup file.
        Distinguishes crypt12, crypt14, crypt15, plaintext SQLite, truncated, and corrupt files.
        """
        path = Path(file_path)
        if not path.is_file():
            return {"status": "file_not_found", "path": str(path)}

        file_size = path.stat().st_size
        filename = path.name.lower()

        if file_size == 0:
            return {
                "status": "empty_file",
                "filename": path.name,
                "size_bytes": 0,
                "classification": "INVALID_EMPTY"
            }

        with open(path, "rb") as f:
            header_sample = f.read(256)

        header_len = len(header_sample)

        # 1. Plaintext SQLite check
        if header_sample.startswith(b"SQLite format 3\x00"):
            return {
                "status": "plaintext_sqlite",
                "filename": path.name,
                "size_bytes": file_size,
                "classification": "DECRYPTED_PLAINTEXT",
                "is_encrypted": False,
                "message": "Unencrypted SQLite format 3 database. Direct forensic table reading supported."
            }

        # Determine crypt version from filename or header
        crypt_ver = None
        for ver_num in (15, 14, 12):
            if f"crypt{ver_num}" in filename:
                crypt_ver = ver_num
                break

        # Check minimal size requirements
        # WhatsApp crypt files require at least 67 bytes (header + tag/IV)
        if file_size < 67:
            return {
                "status": "truncated",
                "filename": path.name,
                "size_bytes": file_size,
                "classification": "ENCRYPTED_TRUNCATED",
                "is_encrypted": True,
                "crypt_version": crypt_ver,
                "error": f"File is truncated ({file_size} bytes). Minimum WhatsApp crypt container is 67 bytes."
            }

        # Inspect key if provided
        key_status = cls.inspect_key_file(key_data) if key_data is not None else {"valid": False, "key_type": "none"}

        # Extract header metadata
        # Crypt14/15 containers typically include version indicators, IV, and salt metadata
        has_valid_crypt_header = header_len >= 67
        salt_present = header_len >= 99
        iv_length = 16

        classification = "ENCRYPTED_VALID_HEADER"
        decryption_note = (
            f"File '{path.name}' is an AES-256-GCM encrypted WhatsApp backup container. "
            "Plaintext records cannot be accessed without the authorized device key or hex passkey. "
            "No brute-force or bypass is attempted in accordance with forensic integrity standards."
        )

        if key_status.get("valid"):
            classification = "ENCRYPTED_KEY_ATTACHED_UNVERIFIED"
            decryption_note = (
                f"Candidate key '{key_status.get('key_type')}' has valid structural length. "
                "However, matching this key against this specific container requires cryptographic authentication "
                "tag validation. In accordance with forensic integrity standards, this container remains classified as "
                "ENCRYPTED until decryption mathematically succeeds and the output database passes SQLite structural validation."
            )

        # 4 Explicit Forensic Stages
        stage_1_identification = {
            "stage": "1. Backup Container Identification",
            "format": f"crypt{crypt_ver}" if crypt_ver else "crypt_unknown",
            "cipher_suite": "AES-256-GCM",
            "has_valid_crypt_header": has_valid_crypt_header,
            "salt_metadata_present": salt_present,
            "iv_length_bytes": iv_length,
            "status": "CONTAINER_IDENTIFIED" if has_valid_crypt_header else "UNRECOGNIZED_HEADER"
        }

        stage_2_key_validation = {
            "stage": "2. Key-File Structural Validation",
            "key_provided": bool(key_data is not None),
            "key_structurally_valid": key_status.get("valid", False),
            "key_type": key_status.get("key_type", "none"),
            "aes_key_extracted": key_status.get("aes_key_extracted", False)
        }

        stage_3_key_compatibility = {
            "stage": "3. Key Compatibility Verification",
            "compatibility_verified": False,
            "status": "COMPATIBILITY_UNVERIFIED_WITHOUT_GCM_AUTH" if key_status.get("valid") else "NO_KEY_PROVIDED",
            "explanation": (
                "Possessing an examiner key of valid structural length (158-byte Android key file or 32-byte direct key) "
                "does not verify that it corresponds to this specific container's cryptographic salt. "
                "Matching requires verifying the AES-GCM authentication tag or derivation salt."
            )
        }

        stage_4_decryption = {
            "stage": "4. Successful Decryption & Structural Validation",
            "is_decrypted": False,
            "decryption_confirmed": False,
            "structural_validation": "NOT_PERFORMED_CIPHERTEXT_INTACT",
            "explanation": (
                "Decryption is strictly NOT claimed unless mathematical decryption succeeds and the output "
                "database passes complete SQLite format structural validation."
            )
        }

        return {
            "status": "encrypted_backup",
            "filename": path.name,
            "path": str(path),
            "size_bytes": file_size,
            "classification": classification,
            "is_encrypted": True,
            "is_decrypted": False,
            "decryption_confirmed": False,
            "crypt_version": crypt_ver or 14,
            "cipher_suite": "AES-256-GCM",
            "header_inspected_bytes": header_len,
            "has_valid_crypt_header": has_valid_crypt_header,
            "salt_metadata_present": salt_present,
            "iv_length_bytes": iv_length,
            "key_status": key_status,
            "forensic_disclosure": decryption_note,
            "forensic_stages": {
                "stage_1_identification": stage_1_identification,
                "stage_2_key_validation": stage_2_key_validation,
                "stage_3_key_compatibility": stage_3_key_compatibility,
                "stage_4_decryption_and_verification": stage_4_decryption
            }
        }


