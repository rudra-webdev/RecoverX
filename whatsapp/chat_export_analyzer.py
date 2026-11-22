"""
WhatsApp Exported Chat Analyzer for RecoverX
Parses exported chat text files, extracting timeline, participants, attachments, and metadata.
Robustly handles diverse international date/time formats, bidirectional Unicode markers (LRM/RLM),
and multilingual content (Arabic, Hindi, Chinese, Cyrillic, emojis).
"""
from pathlib import Path
from typing import Dict, Any, List, Set, Optional, Tuple
import re

# Comprehensive regex patterns for WhatsApp chat export headers
# Standard format 1: [DD/MM/YY, HH:MM:SS] or [MM/DD/YYYY, h:mm:ss AM] Name: Message (iOS style)
PATTERN_BRACKETED = re.compile(
    r"^\[(\d{1,4}[\/\.\-]\d{1,2}[\/\.\-]\d{1,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s+[APap][Mm])?)\]\s+([^:]+?):\s+(.*)$"
)

# Standard format 2: DD/MM/YYYY, HH:MM - Name: Message (Android style)
PATTERN_DASH = re.compile(
    r"^(\d{1,4}[\/\.\-]\d{1,2}[\/\.\-]\d{1,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s+[APap][Mm])?)\s+-\s+([^:]+?):\s+(.*)$"
)

# System event pattern (no colon separating author and message): e.g. "31/12/2022, 23:59 - Messages and calls are..."
PATTERN_SYSTEM_EVENT = re.compile(
    r"^(?:\[(\d{1,4}[\/\.\-]\d{1,2}[\/\.\-]\d{1,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s+[APap][Mm])?)\]|(\d{1,4}[\/\.\-]\d{1,2}[\/\.\-]\d{1,4}),?\s+(\d{1,2}:\d{2}(?::\d{2})?(?:\s+[APap][Mm])?)\s+-)\s+(.*)$"
)

ATTACHMENT_PATTERNS = [
    re.compile(r"<attached:\s*([^>]+)>", re.IGNORECASE),
    re.compile(r"\(file attached:\s*([^\)]+)\)", re.IGNORECASE),
    re.compile(r"([A-Za-z0-9_\-\.\s]+\.(?:jpg|jpeg|png|mp4|opus|pdf|webp|mp3|docx|xlsx|zip))\s+\(file attached\)", re.IGNORECASE),
    re.compile(r"<Media omitted>", re.IGNORECASE)
]

# Unicode bidirectional control characters to strip
BIDI_CHARS = re.compile(r"[\u200e\u200f\u202a-\u202e\u202f\ufeff]")

class WhatsAppChatExportAnalyzer:
    @classmethod
    def clean_line(cls, line: str) -> str:
        """Removes hidden Unicode direction and narrow-space characters."""
        return BIDI_CHARS.sub("", line).strip()

    @classmethod
    def analyze_file(cls, txt_path: Path) -> Dict[str, Any]:
        path = Path(txt_path)
        if not path.is_file():
            return {"status": "error", "error": f"File not found: {path}"}

        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                raw_lines = f.readlines()
        except Exception as e:
            return {"status": "error", "error": f"Failed to read file: {e}"}

        total_lines = len(raw_lines)
        messages: List[Dict[str, Any]] = []
        system_events: List[Dict[str, Any]] = []
        unparsed_lines: List[Dict[str, Any]] = []
        participants: Set[str] = set()
        attachments_found: List[str] = []
        media_omitted_count = 0
        dates: List[str] = []

        current_message: Optional[Dict[str, Any]] = None

        for line_idx, raw_line in enumerate(raw_lines, start=1):
            cleaned = cls.clean_line(raw_line)
            if not cleaned:
                continue

            matched = False

            # 1. Try bracketed format [date, time] Author: content
            m = PATTERN_BRACKETED.match(cleaned)
            if m:
                if current_message:
                    messages.append(current_message)
                date_part, time_part, author, content = m.groups()
                author = author.strip()
                participants.add(author)
                dates.append(date_part)

                att_file, omitted = cls._extract_attachments(content)
                if omitted:
                    media_omitted_count += 1
                if att_file:
                    attachments_found.append(att_file)

                current_message = {
                    "index": len(messages) + 1,
                    "line_number": line_idx,
                    "date": date_part,
                    "time": time_part,
                    "sender": author,
                    "message": content,
                    "attachment": att_file
                }
                matched = True

            # 2. Try dash format: date, time - Author: content
            if not matched:
                m = PATTERN_DASH.match(cleaned)
                if m:
                    if current_message:
                        messages.append(current_message)
                    date_part, time_part, author, content = m.groups()
                    author = author.strip()
                    participants.add(author)
                    dates.append(date_part)

                    att_file, omitted = cls._extract_attachments(content)
                    if omitted:
                        media_omitted_count += 1
                    if att_file:
                        attachments_found.append(att_file)

                    current_message = {
                        "index": len(messages) + 1,
                        "line_number": line_idx,
                        "date": date_part,
                        "time": time_part,
                        "sender": author,
                        "message": content,
                        "attachment": att_file
                    }
                    matched = True

            # 3. Check for system notification: e.g. "Messages and calls are end-to-end encrypted..."
            if not matched:
                m_sys = PATTERN_SYSTEM_EVENT.match(cleaned)
                if m_sys and ("Messages and calls" in cleaned or "created group" in cleaned or "added" in cleaned or "changed the" in cleaned or "security code" in cleaned or "left" in cleaned):
                    if current_message:
                        messages.append(current_message)
                        current_message = None
                    g = m_sys.groups()
                    d = g[0] or g[2]
                    t = g[1] or g[3]
                    event_text = g[4]
                    system_events.append({
                        "line_number": line_idx,
                        "date": d,
                        "time": t,
                        "event": event_text
                    })
                    matched = True

            # 4. Continuation line of previous multi-line message
            if not matched:
                if current_message:
                    current_message["message"] += "\n" + cleaned
                else:
                    unparsed_lines.append({
                        "line_number": line_idx,
                        "content": cleaned
                    })

        if current_message:
            messages.append(current_message)

        # Check if attached files exist in the same folder
        parent_dir = path.parent
        resolved_attachments = []
        for att in attachments_found:
            att_path = parent_dir / att
            resolved_attachments.append({
                "filename": att,
                "found_on_disk": att_path.is_file(),
                "path": str(att_path) if att_path.is_file() else None
            })

        return {
            "status": "success",
            "filename": path.name,
            "filepath": str(path),
            "total_lines": total_lines,
            "parsed_messages": len(messages),
            "total_messages": len(messages),
            "system_events_count": len(system_events),
            "unparsed_lines_count": len(unparsed_lines),
            "participants": sorted(list(participants)),
            "date_range": {
                "start": dates[0] if dates else None,
                "end": dates[-1] if dates else None
            },
            "messages": messages[:100],  # sample up to 100 for memory efficiency
            "attachments_referenced": resolved_attachments,
            "media_omitted_count": media_omitted_count
        }

    @classmethod
    def _extract_attachments(cls, content: str) -> Tuple[Optional[str], bool]:
        """Detects attachment filenames and media-omitted notices in message text."""
        if "<Media omitted>" in content or "Media omitted" in content:
            return None, True

        m_att = ATTACHMENT_PATTERNS[0].search(content)
        if m_att:
            return m_att.group(1).strip(), False

        m_file = ATTACHMENT_PATTERNS[1].search(content)
        if m_file:
            return m_file.group(1).strip(), False

        return None, False


