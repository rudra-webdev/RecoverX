# RecoverX — Forensic Data Recovery and Investigation Platform

RecoverX is a Windows-first, non-destructive digital forensics and file recovery suite featuring both a modern **PySide6 Desktop GUI** (rebuilt with a **Premium Light design system**) and a robust **CLI engine**. It is engineered for Android logical investigations, WhatsApp artifact auditing, multi-format raw signature carving, and optional integration with established open-source engines (**PhotoRec** and **The Sleuth Kit**).

---

## Visual Design Reference & Philosophy

The RecoverX desktop interface adheres strictly to the Stitch design specification:
- **Palette**: Clean white (`#ffffff`) and soft slate blue-grey (`#f8fafc`, `#f1f5f9`) backgrounds with subtle borders (`#e2e8f0`).
- **Brand & Action**: Deep indigo / purple (`#4f46e5`, `#6366f1`) for brand identity and primary user actions.
- **Status Indicators**: Emerald green (`#10b981`) for verified integrity / online states, amber (`#f59e0b`) for warnings, and cyan (`#06b6d4`, `#0ea5e9`) for hardware mounts.
- **Forensic Truthfulness**: Displays honest operating states (`OFFLINE AIR-GAP: ACTIVE`, `SOFTWARE READ-ONLY ENFORCED`, `SHA-256 INTEGRITY VERIFIED`) and never fabricates hardware write-blockers or root capabilities.

---

## Architecture Overview

```
RecoverX/
├── main.py                  # Entrypoint: launches PySide6 GUI by default or CLI subcommands
├── requirements.txt         # Core dependencies: pytest, Pillow, PySide6
├── README.md                # System documentation & forensics manual
├── config.py                # Engine configuration, application metadata (v2.1.0) & safety settings
├── recoverx.spec            # PyInstaller Windows build configuration
├── gui/                     # PySide6 Desktop GUI Architecture
│   ├── app.py               # Main window, top session bar, bottom status footer & router
│   ├── theme.py             # Premium Light QSS theme & stylesheet definition
│   ├── models/
│   │   └── file_table_model.py # Progressive item model with multi-column sorting and filtering
│   ├── widgets/
│   │   ├── sidebar.py       # 7-view sidebar with active indicator dot and security card
│   │   ├── stat_card.py     # Rounded metric cards with icon badges and category tags
│   │   ├── donut_chart.py   # Custom QPainter donut chart with center file count and legend
│   │   ├── preview_panel.py # Scaled image thumbnail renderer & metadata inspector
│   │   └── filter_bar.py    # Search, category pills & selection controls
│   └── views/
│       ├── dashboard_view.py# Storage drives, Android status, engine availability & donut chart
│       ├── recover_files_view.py # Multi-source carving, progressive table & selective extraction
│       ├── android_view.py  # Read-only device inspection & logical storage audit
│       ├── whatsapp_view.py # Media discovery, crypt14/15 status, chat transcript viewer
│       ├── history_view.py  # Markdown/JSON investigation report viewer
│       ├── reports_view.py  # Dedicated Reports & Security Audit viewer with export tools
│       └── settings_view.py # Offline mode, ADB allowlist & toolpath configuration
├── engine/
│   ├── orchestrator.py      # Unified multi-engine orchestrator with deduplication
│   ├── device_manager.py    # ADB Android hardware, OS & security profiling
│   ├── android_scanner.py   # Logical storage, media & cache investigation
│   ├── drive_manager.py     # Win32 logical drives, USB, SD, disk image discovery
│   ├── storage_scanner.py   # Disk image & raw storage carving orchestration
│   ├── signature_scanner.py # 22+ format signature carver with container size parsing
│   ├── filesystem_scanner.py# Recursive discovery & mismatch detection
│   ├── file_validator.py    # Structural integrity & magic byte validator
│   ├── recovery_manager.py  # Isolated file extraction & hash verification (Source != Dest)
│   ├── report_generator.py  # Markdown & JSON forensic reporting
│   └── security_auditor.py  # Automated codebase and dependency security auditor
├── integrations/
│   ├── photorec/
│   │   └── runner.py        # PhotoRec execution, version check, output parsing & GPL notice
│   └── sleuthkit/
│       └── runner.py        # The Sleuth Kit (fls, fsstat, icat, mmls) metadata extraction
├── whatsapp/
│   ├── scanner.py           # Unified WhatsApp forensic scanner
│   ├── media_finder.py      # Categorization of images, audio, video, stickers
│   ├── database_finder.py   # Locates unencrypted & crypt12/14/15 databases
│   ├── database_analyzer.py # Read-only SQLite inspector & crypt evaluator
│   ├── backup_analyzer.py   # Evaluates backup retention sets
│   └── chat_export_analyzer.py # Parses exported chat TXT transcripts
├── utils/
│   ├── adb.py               # Safe read-only ADB execution wrapper with allowlist
│   ├── file_signatures.py   # 22+ signature definitions & container size parsers
│   ├── hashing.py           # SHA-256 streaming hashing
│   ├── network_guard.py     # Offline socket interceptor
│   └── logging_config.py    # Timestamped file and console logging
├── tests/
│   ├── test_gui_and_integrations.py # GUI widgets, PhotoRec/TSK mocks, drive detection, selective extraction
│   ├── test_signatures.py   # Signature parsers & disk image carving tests
│   ├── test_validator.py    # Corrupt vs valid checks & deduplication tests
│   ├── test_whatsapp_scanner.py # WhatsApp database & chat parser tests
│   ├── test_android_device.py   # Media validators & Android mock profile
│   └── test_adb_security.py # Offline mode, allowlist & dry-run tests
├── reports/                 # Investigation reports (JSON and Markdown)
└── recovered/               # Isolated destination for recovered artifacts
```

---

## 7 Application Pages (Complete Feature Breakdown)

1. **Dashboard**:
   - 6 Top Metric Cards: Logical Drives, Removable Devices, Android Devices, Files Discovered, Files Recovered, Engines Ready.
   - Recovery Engine Availability: Live status badges for RecoverX Native Carver, PhotoRec, and The Sleuth Kit.
   - Storage Devices Table: Lists detected volumes with Capacity, Free Space, Filesystem, and `[Read-Only]` state.
   - Recent Recovery Activity: Shows recent forensic sessions with timestamps and "Open" folder actions.
   - File Types Distribution: Custom-rendered donut chart with center file count and breakdown legend.
   - Quick Actions: `Refresh System` and `+ New Investigation`.

2. **Recover Files**:
   - Multi-source selector (Windows Logical Drives, External USBs, SD cards, and Forensic Disk Images `.img`, `.raw`, `.dd`).
   - Scan Modes: Deep Signature Carving, Filesystem Metadata Scan (TSK), or Composite Scan.
   - Progressive Table: Sortable columns, file-type icons, category pills, offset, size, and status.
   - Preview Inspector: Pillow/QImage thumbnails, ZIP central directory manifest viewer, text snippet preview, and forensic disclaimer.
   - Selective Recovery: Dedicated `Recover Selected Files (N)` button, separate destination selection dialog, source/destination collision rejection (`Source != Destination`), duplicate collision handling, and SHA-256 verification.

3. **Android Recovery**:
   - Read-only ADB interface with hardware/OS profiling.
   - Discloses hardware-backed FBE (File-Based Encryption) and Scoped Storage constraints.
   - Non-destructive shared storage artifact traversal with dry-run support.

4. **WhatsApp Recovery**:
   - Media classification (Images, Video, Audio, Voice Notes, Documents, Stickers, Profile Photos).
   - Unencrypted SQLite database inspection.
   - Transparent cryptographic disclosure for `.crypt14` and `.crypt15` databases (never claims decryption without keys).
   - Exported chat transcript reader.

5. **Recovery History**:
   - Lists past investigation and carving sessions.
   - In-app Markdown/JSON report viewer.
   - Direct button to open the forensic reports folder.

6. **Reports & Audit**:
   - Browse and preview generated forensic case reports.
   - One-click report export to user-chosen destination.
   - Live Security & Privacy Audit runner inspecting network isolation, ADB allowlists, and dependencies.

7. **Settings**:
   - Security controls: Strict Offline Mode status, ADB allowlist status, and Dry-run default toggle.
   - External recovery backend paths: Configuration and validation for PhotoRec and The Sleuth Kit (TSK).
   - Default output folders configuration.

---

## Supported File Formats (22+ Signatures)

The built-in signature carver detects and structurally validates files across 6 major categories:
- **Images**: JPEG (`jpg`), PNG (`png`), GIF (`gif`), WebP (`webp`), Windows Bitmap (`bmp`), TIFF (`tiff`), High Efficiency Image Container (`heic`).
- **Videos**: MP4 (`mp4`), QuickTime (`mov`), AVI (`avi`), Matroska (`mkv`).
- **Audio**: MP3 (`mp3`), WAV (`wav`), M4A (`m4a`).
- **Documents**: PDF (`pdf`), Microsoft Word (`docx`), Excel (`xlsx`), PowerPoint (`pptx`), Plain Text (`txt`).
- **Archives**: ZIP (`zip`), RAR (`rar`), 7-Zip (`7z`).
- **Databases & Forensic Metadata**: SQLite (`db`), WhatsApp Encrypted Backups (`crypt14`, `crypt15`).

---

## Forensic Safety & Integrity Principles

1. **Strict Read-Only Access**: All drives, disk images, and Android interfaces are opened strictly read-only (`rb` mode).
2. **Source != Destination Invariant**: The recovery manager prohibits recovering into the source path or within the source directory (`PermissionError`).
3. **Protected Windows System Drive**: Drive `C:\` is blocked from automatic or non-confirmed raw sector access.
4. **Offline Isolation Mode**: Network socket calls are blocked at the engine level to ensure privacy and zero external communication.
5. **Read-Only ADB Allowlist**: All ADB commands must match a strict allowlist. Commands that install apps, reboot, push files, or write to partitions are denied.
6. **Explicit Forensic Distinctions**: Metadata records identified via filesystem analysis (e.g., The Sleuth Kit `fls`) are clearly marked as `METADATA_RECORD_IDENTIFIED` until file content is verified and extracted.
7. **Honest Cryptographic Transparency**: Encrypted databases (`.crypt14`, `.crypt15`) are identified, but never claimed as readable without the required decryption keys.

---

## Getting Started

### Prerequisites
- Python 3.12+ (tested on Python 3.13)
- Windows 10 or 11 (64-bit)

### Installation
```bash
git clone https://github.com/your-org/RecoverX.git
cd RecoverX
pip install -r requirements.txt
```

---

## Usage

### 1. Launch PySide6 Desktop GUI (Primary Mode)
```bash
python main.py
# or launch without command prompt window:
pythonw main.py
```

### 2. CLI Subcommands (Full Backward Compatibility)
```bash
# Scan a raw disk image for signatures
python main.py scan-image --source sample.img

# Recover carved files from a disk image to a dedicated folder
python main.py recover --source sample.img --output ./recovered

# Run comprehensive security and privacy audit
python main.py privacy-audit
```

---

## Running the Automated Test Suite

Run the full suite of 33 tests:

```bash
pytest -v
```
