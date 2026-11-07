"""
ml/file_model/features.py
==========================
Feature extraction for metadata-based static file risk analysis.
Extracts structural, heuristic, and entropy features from file metadata
to evaluate download/creation risk before execution.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

# Extensions that represent directly executable binary formats
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".msi", ".pif",
}

# Script formats commonly leveraged in living-off-the-land or phishing drops
SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
}

# Archive formats frequently used to wrap malware
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".img", ".cab",
}

# Document formats that could contain macros or exploits
DOCUMENT_EXTENSIONS = {
    ".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".pdf", ".rtf",
}

# Lure keywords commonly found in phishing attachment filenames
LURE_KEYWORDS = {
    "invoice", "receipt", "payment", "urgent", "swift", "statement",
    "remittance", "order", "document", "salary", "bonus", "payroll",
    "update", "security", "patch", "install", "setup", "crack", "keygen",
    "wire", "contract", "shipping", "fedex", "dhl", "ups", "tracking",
}


def detect_double_extension(filename: str) -> bool:
    """
    Detects double extension masquerading (e.g. invoice.pdf.exe, resume.docx.vbs).
    Returns True if multiple periods exist and the trailing extension is executable/script.
    """
    parts = filename.split(".")
    if len(parts) >= 3:
        last_ext = f".{parts[-1].lower()}"
        if last_ext in (EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS):
            return True
    return False


def extract_file_features(file_data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract a comprehensive feature vector and heuristic flags from a file metadata dict.
    Accepts keys produced by collectors.filesystem.file_watcher or manual file queries.
    """
    filename = str(file_data.get("filename", "") or "")
    path_str = str(file_data.get("path", "") or filename).lower()
    ext = str(file_data.get("extension", "") or Path(filename).suffix).lower()
    if ext and not ext.startswith("."):
        ext = f".{ext}"

    size_bytes = int(file_data.get("size_bytes", 0) or 0)
    entropy = float(file_data.get("entropy", 0.0) or 0.0)

    # Boolean flags
    is_exec = ext in EXECUTABLE_EXTENSIONS
    is_script = ext in SCRIPT_EXTENSIONS
    is_archive = ext in ARCHIVE_EXTENSIONS
    is_doc = ext in DOCUMENT_EXTENSIONS
    is_double_ext = bool(file_data.get("is_double_extension")) or detect_double_extension(filename)
    is_hidden = bool(file_data.get("is_hidden")) or filename.startswith(".")

    # High entropy threshold (>7.2) typically indicates packing, encryption, or compressed payloads
    is_high_entropy = entropy >= 7.2

    # Suspicious paths
    in_temp_dir = any(t in path_str for t in ("temp", "tmp", "appdata\\local\\temp", "/tmp"))
    in_downloads_dir = "download" in path_str
    in_startup_dir = any(s in path_str for s in ("startup", "start menu", "init.d", "runonce"))

    # Dropper / Stager size anomaly (< 30 KB executable is often a downloader stager)
    is_tiny_executable = is_exec and (0 < size_bytes < 30720)

    # Lure keyword match in filename
    clean_name = re.sub(r"[^a-zA-Z0-9]", " ", filename.lower())
    words = set(clean_name.split())
    matched_lures = list(words.intersection(LURE_KEYWORDS))
    has_lure_keywords = len(matched_lures) > 0

    return {
        "filename": filename,
        "extension": ext,
        "size_bytes": size_bytes,
        "entropy": entropy,
        "is_executable": is_exec,
        "is_script": is_script,
        "is_archive": is_archive,
        "is_document": is_doc,
        "is_double_extension": is_double_ext,
        "is_hidden": is_hidden,
        "is_high_entropy": is_high_entropy,
        "in_temp_dir": in_temp_dir,
        "in_downloads_dir": in_downloads_dir,
        "in_startup_dir": in_startup_dir,
        "is_tiny_executable": is_tiny_executable,
        "has_lure_keywords": has_lure_keywords,
        "matched_lures": matched_lures,
    }
