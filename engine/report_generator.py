"""
Report Generator for RecoverX
Compiles comprehensive forensic investigation findings into structured JSON and clean Markdown reports.
"""
from pathlib import Path
from typing import Dict, Any, Optional
import json
import datetime
from config import REPORTS_DIR

class ReportGenerator:
    def __init__(self, output_dir: Optional[Path] = None):
        self.output_dir = Path(output_dir or REPORTS_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(self, data: Dict[str, Any], title: str = "Investigation Report") -> Dict[str, str]:
        """Generates both JSON and readable Markdown reports."""
        timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        sanitized_title = title.lower().replace(" ", "_")
        base_name = f"{sanitized_title}_{timestamp_str}"

        json_path = self.output_dir / f"{base_name}.json"
        md_path = self.output_dir / f"{base_name}.md"

        # 1. Write JSON Report
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)

        # 2. Write Markdown Report
        md_content = self._render_markdown(data, title, timestamp_str)
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md_content)

        return {
            "json_report": str(json_path),
            "markdown_report": str(md_path)
        }

    def _render_markdown(self, data: Dict[str, Any], title: str, timestamp_str: str) -> str:
        md = []
        md.append(f"# RecoverX — Forensic Investigation & Recovery Report")
        md.append(f"**Title**: {title}  ")
        md.append(f"**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ")
        md.append(f"**Engine**: RecoverX v1.0.0 (Forensic Read-Only Core)  \n")
        md.append("---")

        # Device Profile Section (if Android)
        profile = data.get("device_profile")
        if profile:
            md.append("## 1. Target Device Profile")
            md.append(f"- **Manufacturer**: {profile.get('manufacturer')}")
            md.append(f"- **Model**: {profile.get('model')} ({profile.get('device_codename')})")
            md.append(f"- **Android Version**: {profile.get('android_version')} (SDK {profile.get('sdk_version')})")
            md.append(f"- **Security Patch**: {profile.get('security_patch')}")
            md.append(f"- **Build ID**: {profile.get('build_id')}")
            md.append(f"- **Root Status**: {profile.get('root_status')}")
            md.append(f"- **Bootloader**: {profile.get('bootloader_status')}")
            md.append(f"- **SELinux Mode**: {profile.get('selinux_mode')}")
            md.append("\n### Accessible Storage Summary")
            storage_sum = profile.get("storage_summary", [])
            if storage_sum:
                md.append("```text")
                md.extend(storage_sum[:10])
                md.append("```")
            else:
                md.append("*No storage partition information captured.*")
            md.append("")

        # Logical Investigation Section
        media_findings = data.get("media_findings")
        if media_findings:
            md.append("## 2. Logical Storage Investigation")
            folders = media_findings.get("folders", [])
            if folders:
                md.append("| Directory Name | Path | Accessible | File Count |")
                md.append("|---|---|---|---|")
                for f in folders:
                    md.append(f"| {f.get('name')} | `{f.get('path')}` | {f.get('accessible')} | {f.get('file_count')} |")
            md.append("")

        # WhatsApp Findings Section
        wa = data.get("whatsapp_artifacts") or data.get("whatsapp_summary")
        if wa:
            md.append("## 3. WhatsApp Investigation & Artifact Findings")
            roots = wa.get("active_roots", [])
            md.append(f"- **Active WhatsApp Roots Found**: {', '.join(f'`{r}`' for r in roots) if roots else 'None (Clean/Uninstalled State)'}")
            md.append(f"- **Total Discovered Media Items**: {wa.get('total_media_count', 0)}")
            
            breakdown = wa.get("media_breakdown", {})
            if breakdown:
                md.append("\n### Media Breakdown")
                for cat, cnt in breakdown.items():
                    md.append(f"- **{cat}**: {cnt} files")

            dbs = wa.get("databases", [])
            md.append(f"\n### Database Artifacts ({len(dbs)} found)")
            if dbs:
                md.append("| Filename | Size (Bytes) | Path |")
                md.append("|---|---|---|")
                for db in dbs:
                    md.append(f"| `{db.get('filename')}` | {db.get('size_bytes')} | `{db.get('path')}` |")
            else:
                md.append("*No local database artifacts located in accessible directories.*")
            md.append("")

        # Cache & Thumbnails Section
        cache_data = data.get("cache_and_thumbnails")
        if cache_data:
            disc = cache_data.get("discovered", [])
            md.append(f"## 4. Cache and Thumbnail Artifacts ({len(disc)} locations)")
            if disc:
                md.append("| Cache/Thumbnail Path | File Count |")
                md.append("|---|---|")
                for c in disc:
                    md.append(f"| `{c.get('path')}` | {c.get('file_count')} |")
            else:
                md.append("*No accessible thumbnail or cache folders located in shared storage.*")
            md.append("")

        # Exported Chats Section
        chats = data.get("exported_chats") or data.get("chat_exports")
        if chats:
            md.append(f"## 5. Exported Chat Files ({len(chats)} located)")
            for ch in chats:
                fn = ch.get("filename") or ch.get("path")
                lines = ch.get("total_lines", ch.get("size_bytes", "N/A"))
                md.append(f"- `{fn}`: {lines} lines/bytes")
            md.append("")

        # Carving / Recovery Section
        carve = data.get("recovery_results") or data.get("carving_results")
        if carve:
            md.append("## 6. Signature Carving and Recovery Results")
            md.append(f"- **Total Items Processed**: {carve.get('total_carved', carve.get('total_recovered', 0))}")
            md.append(f"- **Duplicates Skipped**: {carve.get('skipped_duplicates', 0)}")
            files = carve.get("files", [])
            if files:
                md.append("\n| Output Filename | Size (Bytes) | SHA-256 | Verified |")
                md.append("|---|---|---|---|")
                for fl in files[:50]:
                    md.append(f"| `{fl.get('filename')}` | {fl.get('size_bytes')} | `{fl.get('sha256')[:16]}...` | {fl.get('verified')} |")
            md.append("")

        # Security & Forensic Limitations Section
        md.append("## 7. Technical Limitations & Forensic Analysis")
        md.append("### Scientific Principles & Storage Constraints:")
        md.append(
            "1. **Android File-Based Encryption (FBE)**: Android 10+ devices enforce File-Based Encryption "
            "backed by hardware TEE/Titan keystores. Deletion of an encrypted file results in cryptographic shredding "
            "of the per-file symmetric key. While raw ciphertext blocks remain in flash memory until wear-leveling "
            "overwrites them, plaintext reconstruction is mathematically infeasible without the destroyed key. "
            "(Exceptions: Unencrypted external SD cards or legacy partitions not covered by FBE)."
        )
        md.append(
            "2. **Scoped Storage & Sandbox Isolation**: Modern Android (API 30+) strictly isolates application "
            "sandboxes (`/data/data/com.whatsapp/`) via Linux DAC UID isolation and SELinux policies. "
            "Unprivileged ADB connections cannot access private databases or keys without authorized local backup "
            "mechanisms or physical chip extraction."
        )
        md.append(
            "3. **SSD TRIM and Flash Deallocate**: On internal NVMe/SATA SSDs and supported UFS partitions, "
            "file deletion triggers filesystem TRIM/Deallocate commands. Modern controllers operating in Deterministic "
            "Read Zero after TRIM (DZAT/RZAT) mode immediately return zeros for deallocated LBAs. "
            "Conversely, removable SD cards, USB drives, and systems where TRIM is disabled or unpassed by USB bridges "
            "retain deleted cluster data until overwritten, enabling physical signature carving."
        )
        md.append(
            "4. **Encrypted WhatsApp Backups (crypt12/14/15)**: Detection of a valid crypt header verifies the "
            "container format (AES-256-GCM), but does NOT constitute decryption. Furthermore, possessing an examiner key "
            "file of valid structural length (158 or 32 bytes) does not guarantee it corresponds to the specific database's "
            "salt. Decryption is only confirmed when cryptographic authentication succeeds and the output passes "
            "SQLite format validation."
        )
        md.append(
            "5. **SQLite Freelist Unallocated Chunks**: Freelist pages indicate database pages released by deleted records. "
            "While freelist buffers may retain partial fragments of deleted messages, RecoverX strictly refuses to report "
            "unallocated chunks as recovered messages without validated record headers and field parsing."
        )
        md.append(
            "6. **SQLite Write-Ahead Log (WAL) Frames**: The total frame count in a `-wal` file includes intermediate "
            "transaction pages, uncommitted updates, and previous checkpoint remnants. Only frames with matching salt "
            "and positive database-size commit markers constitute verified committed transactions."
        )
        md.append("")
        md.append("---")
        md.append("*Report generated by RecoverX. Digital Forensics & Data Recovery Engine.*")

        return "\n".join(md)

