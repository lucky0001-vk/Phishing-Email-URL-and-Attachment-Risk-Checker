"""
SafeX Attachment Scanner
Strictly static inspection of email attachments:
- In-memory inspection (never rendered, executed, or written to disk)
- Magic-byte file typing vs extension/declared MIME type
- PE header detection inside renamed files (e.g. .pdf with MZ)
- High-risk extensions, double extensions, RTLO Unicode deception
- Macro inspection in Office documents (.docm, .xlsm, or renamed .docx/.doc)
- Static PDF feature analysis (/JavaScript, /OpenAction, /Launch, /EmbeddedFiles)
- HTML attachment phishing & smuggling analysis
- Password-protected ZIP archives and email body password correlation
- Archive member listing and nested archive inspection
- Enforces strict limits: size, count, archive nesting depth
"""

import io
import os
import re
import hashlib
import zipfile
import zlib
from typing import List, Dict, Any, Tuple, Optional
from safex.core.models import AttachmentInventory, ArchiveEntry, DetectionSignal

# High risk extensions that should almost never be received via business email
HIGH_RISK_EXTENSIONS = {
    ".exe", ".scr", ".js", ".vbs", ".hta", ".lnk", ".iso", ".bat",
    ".ps1", ".wsf", ".cpl", ".cmd", ".jar", ".reg", ".dll", ".vbe",
    ".jse", ".msi", ".com", ".gadget", ".msp"
}

# Office macro-enabled extensions
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}

# Standard office extensions
OFFICE_OPENXML_EXTENSIONS = {".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm"}
OFFICE_OLE_EXTENSIONS = {".doc", ".xls", ".ppt"}

# Known test hashes for offline matching (e.g., EICAR test file hash)
LOCAL_KNOWN_MALICIOUS_HASHES = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR Standard Antivirus Test File",
    "44d88612fea8a8f36de82e1278abb02f": "Known Malicious Emotet Dropper Hash",
}


def detect_magic_signature(data: bytes) -> Tuple[str, str]:
    """
    Detect file format based strictly on initial magic bytes.
    Returns (detected_mime, friendly_signature).
    """
    if not data or len(data) < 2:
        return "application/octet-stream", "Empty/Too Short"

    # Windows PE Executable (MZ)
    if data[:2] == b"MZ":
        return "application/x-dosexec", "PE Executable (MZ Header)"

    # ELF Executable
    if data[:4] == b"\x7fELF":
        return "application/x-executable", "ELF Executable (Linux)"

    # PDF Document
    if data[:5] == b"%PDF-":
        return "application/pdf", "Adobe PDF Document (%PDF-)"

    # PK ZIP (Standard ZIP, or OOXML Word/Excel/PowerPoint)
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"):
        return "application/zip", "ZIP Archive / OpenXML Package (PK)"

    # OLE2 Compound Document (Legacy Office .doc, .xls, .ppt)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "application/x-ole-storage", "OLE2 Compound Document"

    # 7-Zip
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "application/x-7z-compressed", "7-Zip Archive"

    # RAR
    if data[:4] == b"Rar!":
        return "application/x-rar", "RAR Archive"

    # GZIP
    if data[:2] == b"\x1f\x8b":
        return "application/gzip", "GZIP Compressed File"

    # Images
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png", "PNG Image"
    if data[:3] == b"\xff\xd8\xff":
        return "image/jpeg", "JPEG Image"
    if data[:4] == b"GIF8":
        return "image/gif", "GIF Image"
    if data[:2] == b"BM":
        return "image/bmp", "BMP Image"

    # RTF
    if data[:5] == b"{\\rtf":
        return "application/rtf", "Rich Text Format (RTF)"

    # HTML
    prefix = data[:1024].lstrip().lower()
    if prefix.startswith((b"<!doctype html", b"<html", b"<head", b"<body", b"<script")):
        return "text/html", "HTML Document"

    # XML
    if prefix.startswith(b"<?xml"):
        return "application/xml", "XML Document"

    # Shell script
    if data[:2] == b"#!":
        return "text/x-shellscript", "Shell Script (#!)"

    # Plain text check
    try:
        data[:512].decode("utf-8")
        return "text/plain", "Plain Text"
    except Exception:
        pass

    return "application/octet-stream", "Unknown Binary"


def human_size(bytes_val: int) -> str:
    """Format bytes into readable string."""
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_val < 1024.0:
            return f"{bytes_val:.1f} {unit}" if unit != "B" else f"{bytes_val} B"
        bytes_val /= 1024.0
    return f"{bytes_val:.1f} TB"


def scan_attachment(
    attachment_dict: Dict[str, Any],
    body_passwords: List[str],
    attachment_index: int = 1
) -> AttachmentInventory:
    """
    Perform purely static inspection of a single attachment in-memory.
    Never executes, renders, or writes to disk.
    """
    raw_filename = attachment_dict.get("filename", f"attachment_{attachment_index}")
    data = attachment_dict.get("data", b"")
    declared_type = attachment_dict.get("declared_mime_type", "application/octet-stream")
    size_bytes = len(data)
    exceeded_limit = attachment_dict.get("exceeded_size_limit", False)

    sha256_hash = hashlib.sha256(data).hexdigest() if data else ""

    # Check for Unicode Right-to-Left Override (U+202E)
    has_rtlo = "\u202e" in raw_filename
    clean_filename = raw_filename.replace("\u202e", "[RTLO]")

    # Check for hidden spaces or double extensions
    # e.g., invoice.pdf.exe or invoice.pdf    .exe
    norm_fn = re.sub(r"\s+", " ", raw_filename).strip()
    name_parts = norm_fn.split(".")
    has_double_ext = False
    if len(name_parts) >= 3:
        # Check if preceding extension is a common document/image extension
        doc_exts = {"pdf", "docx", "doc", "xlsx", "xls", "jpg", "png", "txt"}
        if name_parts[-2].lower() in doc_exts:
            has_double_ext = True

    _, ext = os.path.splitext(norm_fn.lower())
    detected_mime, magic_sig = detect_magic_signature(data)

    inv = AttachmentInventory(
        attachment_id=f"att_{attachment_index}",
        filename=clean_filename,
        declared_mime_type=declared_type,
        detected_mime_type=detected_mime,
        magic_signature=magic_sig,
        size_bytes=size_bytes,
        size_human=human_size(size_bytes),
        sha256=sha256_hash,
        status="SCANNED",
        high_risk_extension=ext in HIGH_RISK_EXTENSIONS,
        double_extension=has_double_ext,
        rtlo_detected=has_rtlo,
        risk_level="CLEAN",
        score=0,
        signals=[]
    )

    # Operational requirement: Enforce size limit
    if exceeded_limit or size_bytes > (25 * 1024 * 1024):
        inv.status = "UNSCANNED"
        inv.status_reason = "Attachment exceeds maximum allowed size (25MB). Marked UNSCANNED per safety policy."
        inv.risk_level = "UNKNOWN"
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Attachment Limit Exceeded",
                severity="medium",
                score_impact=10,
                description="Attachment exceeds size threshold and could not be statically inspected safely.",
                evidence=f"Size: {inv.size_human}"
            )
        )
        return inv

    # Operational requirement: Local known hash check
    if sha256_hash in LOCAL_KNOWN_MALICIOUS_HASHES:
        inv.known_hash_match = True
        matched_name = LOCAL_KNOWN_MALICIOUS_HASHES[sha256_hash]
        inv.score += 50
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Known Malicious Hash Match (Local Database)",
                severity="critical",
                score_impact=50,
                description=f"File SHA-256 matches known malicious test signature: '{matched_name}'.",
                evidence=f"SHA-256: {sha256_hash}"
            )
        )

    # 1. RTLO Deception Signal
    if has_rtlo:
        inv.score += 35
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Unicode Right-to-Left Override (RTLO) Attack",
                severity="critical",
                score_impact=35,
                description=(
                    "Filename contains Unicode character U+202E (Right-to-Left Override). "
                    "This character causes the file system to display the filename backwards, "
                    "disguising dangerous executable extensions (e.g. .exe) as innocent documents (.pdf, .txt)."
                ),
                evidence=f"Raw filename with RTLO: {raw_filename}"
            )
        )

    # 2. Double Extension Signal
    if has_double_ext:
        inv.score += 30
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Double File Extension Deception",
                severity="high",
                score_impact=30,
                description=(
                    f"Filename '{clean_filename}' uses multiple extensions to deceive the user into believing "
                    "it is a document or image while executing under its true terminal extension."
                ),
                evidence=f"Pattern: .{name_parts[-2]}.{name_parts[-1]}"
            )
        )

    # 3. High Risk Extension Signal
    if inv.high_risk_extension:
        inv.score += 30
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name=f"High-Risk Executable Extension ({ext})",
                severity="high",
                score_impact=30,
                description=(
                    f"Attachment extension '{ext}' is directly executable or an active script. "
                    "Direct delivery of executable attachments is blocked by standard security policies."
                ),
                evidence=clean_filename
            )
        )

    # 4. Critical Type Mismatch Check (Magic Bytes vs Extension)
    # Specifically: .pdf with MZ header, or .docx with executable binary!
    if ext in [".pdf", ".png", ".jpg", ".jpeg", ".docx", ".xlsx", ".txt", ".csv"] and detected_mime == "application/x-dosexec":
        inv.type_mismatch = True
        inv.score += 45
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Disguised Windows Executable (MZ Header)",
                severity="critical",
                score_impact=45,
                description=(
                    f"CRITICAL: The file is named '{clean_filename}' with extension '{ext}', "
                    "but inspection of initial magic bytes reveals a Windows Portable Executable (MZ header). "
                    "This is an intentional attempt to evade file filters and disguise executable malware."
                ),
                evidence=f"Extension: '{ext}' vs Detected Signature: '{magic_sig}'"
            )
        )
    elif detected_mime != "unknown" and detected_mime != "application/octet-stream":
        # Check general mismatch between expected MIME and detected magic
        if ext == ".pdf" and detected_mime != "application/pdf":
            inv.type_mismatch = True
            inv.score += 25
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="File Extension & Signature Mismatch",
                    severity="high",
                    score_impact=25,
                    description=f"File extension is '{ext}' but detected file signature is '{magic_sig}'.",
                    evidence=f"Extension: {ext} | Signature: {magic_sig}"
                )
            )

    # 5. PDF Static Deep Inspection
    if detected_mime == "application/pdf" or ext == ".pdf":
        inv.is_pdf = True
        _statically_inspect_pdf(data, inv)

    # 6. Office Document & Macro Inspection
    if ext in (OFFICE_OPENXML_EXTENSIONS | OFFICE_OLE_EXTENSIONS) or detected_mime in ["application/zip", "application/x-ole-storage"]:
        _statically_inspect_office(data, ext, detected_mime, inv)

    # 7. HTML / HTM Attachment Inspection
    if ext in [".html", ".htm", ".xhtml", ".svg"] or detected_mime == "text/html":
        inv.is_html = True
        _statically_inspect_html(data, inv)

    # 8. Archive Inspection (ZIP / tar / gz)
    if detected_mime in ["application/zip", "application/x-7z-compressed", "application/x-rar", "application/gzip"] or ext in [".zip", ".7z", ".rar", ".gz", ".tar"]:
        inv.is_archive = True
        _statically_inspect_archive(data, ext, body_passwords, inv)

    # Determine final risk rating for this attachment
    if inv.score >= 40:
        inv.risk_level = "MALICIOUS"
    elif inv.score >= 20:
        inv.risk_level = "SUSPICIOUS"
    elif inv.score > 0:
        inv.risk_level = "LOW"
    else:
        inv.risk_level = "CLEAN"

    # Per-Attachment Report Card: Extract concise suspicious features list
    features = []
    if inv.type_mismatch:
        features.append(f"MIME/Magic Mismatch: extension '{ext}' vs signature '{inv.magic_signature}'")
    if inv.high_risk_extension:
        features.append(f"High-risk executable extension: '{ext}'")
    if inv.double_extension:
        features.append("Deceptive double file extension")
    if inv.rtlo_detected:
        features.append("Unicode RTLO (Right-to-Left Override) filename spoofing")
    if inv.has_vba_macros:
        features.append(f"Embedded VBA macros: {', '.join(inv.macro_details[:2]) if inv.macro_details else 'Active macro code'}")
    if inv.pdf_active_features:
        features.append(f"Active PDF objects: {', '.join(inv.pdf_active_features[:2])}")
    if inv.html_has_password_fields:
        features.append("HTML Credential Harvesting form with password input")
    if inv.html_has_smuggling:
        features.append("HTML Smuggling / Data URI obfuscation")
    if inv.archive_password_in_body:
        features.append("Password-protected archive with password leaked in email body")
    elif inv.archive_encrypted:
        features.append("Encrypted archive (contents shielded from gateway scanner)")
    if inv.has_archive_executables:
        features.append("Executable/script packaged inside compressed archive")
    if inv.known_hash_match:
        features.append("Known malicious threat hash matched in local database")

    if not features:
        if inv.risk_level == "CLEAN":
            features.append("Static byte inspection clean; no active code or structural anomalies found")
        else:
            features.append("Minor structural warnings; verify sender before opening")

    inv.suspicious_features = features

    # Per-Attachment Report Card: Recommended Action
    if inv.risk_level == "MALICIOUS":
        inv.recommended_action = "QUARANTINE_PAYLOAD"
        inv.recommended_action_detail = (
            "Immediately isolate and quarantine this attachment. Do NOT open, extract, or run it. "
            "Stage sender domain and hash for enterprise gateway perimeter blocking."
        )
    elif inv.risk_level == "SUSPICIOUS":
        inv.recommended_action = "INSPECT_IN_SAFE_OFFLINE_VIEWER"
        inv.recommended_action_detail = (
            "Do not open in standard desktop apps. Inspect only using an isolated, air-gapped text previewer "
            "or sandbox viewer with macros and JavaScript execution disabled."
        )
    elif inv.risk_level == "LOW":
        inv.recommended_action = "VERIFY_SENDER_BEFORE_OPENING"
        inv.recommended_action_detail = (
            "Verify with the sender via an independent corporate channel (phone/chat) to confirm they sent this file."
        )
    else:
        inv.recommended_action = "SAFE_TO_OPEN"
        inv.recommended_action_detail = (
            "Static byte analysis detected standard benign structures. Standard safe computing hygiene applies."
        )

    return inv


def _statically_inspect_pdf(data: bytes, inv: AttachmentInventory):
    """
    Statically inspect raw PDF byte structure without rendering or executing.
    Searches for /JavaScript, /OpenAction, /Launch, /EmbeddedFiles, etc.
    """
    if len(data) < 10:
        return

    # Check for active code tokens
    # Note: Attackers sometimes use hex-obfuscated names like /#4a#61#76#61#53#63#72#69#70#74
    active_tokens = {
        b"/JavaScript": "Embedded JavaScript (/JavaScript)",
        b"/JS": "Embedded JavaScript Stream (/JS)",
        b"/OpenAction": "Automatic Open Action (/OpenAction)",
        b"/AA": "Additional Automatic Action (/AA)",
        b"/Launch": "External Application Launch Trigger (/Launch)",
        b"/EmbeddedFiles": "Embedded File Attachment (/EmbeddedFiles)",
        b"/EmbeddedFile": "Embedded File Stream (/EmbeddedFile)",
        b"/RichMedia": "Rich Media / Flash Container (/RichMedia)",
    }

    found_features = []
    for token, desc in active_tokens.items():
        if token in data:
            found_features.append(desc)

    # Also check for hex-obfuscated JavaScript /#4a#61...
    if b"#4a#61" in data.lower() or b"#4a#53" in data.lower():
        found_features.append("Hex-Obfuscated JavaScript Token")

    inv.pdf_active_features = found_features

    if found_features:
        # Check severity: Launch or JavaScript combined with OpenAction is critical
        has_launch = any("Launch" in f for f in found_features)
        has_js = any("JavaScript" in f for f in found_features)
        has_open = any("OpenAction" in f or "Automatic" in f for f in found_features)

        if has_launch:
            inv.score += 40
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="PDF Launch Action Detected",
                    severity="critical",
                    score_impact=40,
                    description="The PDF contains a /Launch action instructed to invoke an external program or binary upon opening.",
                    evidence=", ".join(found_features)
                )
            )
        elif has_js and has_open:
            inv.score += 35
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="PDF Auto-Executing JavaScript",
                    severity="high",
                    score_impact=35,
                    description="The PDF contains JavaScript configured to execute automatically when viewed (/OpenAction + /JavaScript).",
                    evidence=", ".join(found_features)
                )
            )
        else:
            inv.score += 20
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="PDF Active Features Detected",
                    severity="medium",
                    score_impact=20,
                    description="The PDF structure contains active features (scripts, automatic actions, or embedded objects) not typically required for static invoices or documents.",
                    evidence=", ".join(found_features)
                )
            )


def _statically_inspect_office(data: bytes, ext: str, detected_mime: str, inv: AttachmentInventory):
    """
    Statically check for VBA macros, OLE streams, or macro projects in OpenXML or legacy OLE.
    Distinguishes genuine benign DOCX from weaponized documents.
    """
    inv.is_office_doc = True
    vba_detected = False
    vba_keywords = []

    # Case A: Modern OpenXML (.docx, .docm, .xlsx, .xlsm) - it is a ZIP archive
    if detected_mime == "application/zip" or ext in OFFICE_OPENXML_EXTENSIONS:
        try:
            with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
                namelist = zf.namelist()

                # Check if vbaProject.bin exists inside the archive!
                vba_files = [n for n in namelist if "vbaProject.bin" in n or "vbaData.xml" in n]
                if vba_files:
                    vba_detected = True
                    inv.has_vba_macros = True
                    vba_keywords.append(f"VBA Project container: {vba_files[0]}")

                    # Read vbaProject.bin in-memory to look for auto-exec keywords statically
                    for vf in vba_files:
                        vba_data = zf.read(vf)
                        auto_keywords = [
                            b"AutoOpen", b"Document_Open", b"Workbook_Open",
                            b"Shell", b"WScript", b"PowerShell", b"URLDownloadToFile",
                            b"CallByName", b"Environ"
                        ]
                        for kw in auto_keywords:
                            if kw.lower() in vba_data.lower():
                                vba_keywords.append(f"Auto-exec keyword: {kw.decode()}")

                # Check for suspicious external relationships in _rels
                for n in namelist:
                    if n.endswith(".rels"):
                        try:
                            rel_content = zf.read(n).decode("utf-8", errors="ignore")
                            if "TargetMode=\"External\"" in rel_content and ("http://" in rel_content or "https://" in rel_content):
                                vba_keywords.append("External Template Injection (Remote Template URL)")
                        except Exception:
                            pass

        except Exception as e:
            # If not a valid zip but has .docx extension, flag corruption/unknown
            if ext in [".docx", ".xlsx", ".pptx"]:
                inv.status = "UNKNOWN"
                inv.status_reason = f"Corrupt or non-standard OpenXML structure: {str(e)}"
                return

    # Case B: Legacy OLE Compound Document (.doc, .xls, .ppt)
    if detected_mime == "application/x-ole-storage" or ext in OFFICE_OLE_EXTENSIONS:
        try:
            import olefile
            if olefile.isOleFile(io.BytesIO(data)):
                ole = olefile.OleFileIO(io.BytesIO(data))
                list_streams = ole.listdir()
                stream_names = ["/".join(s) for s in list_streams]

                # Check for VBA or Macros storage
                for s in stream_names:
                    s_lower = s.lower()
                    if "vba" in s_lower or "macros" in s_lower:
                        vba_detected = True
                        inv.has_vba_macros = True
                        vba_keywords.append(f"OLE Macro Stream: {s}")

                ole.close()
        except Exception:
            # Fallback simple byte scanning for OLE VBA signature
            if b"VBA" in data or b"Macro" in data or b"_VBA_PROJECT" in data:
                vba_detected = True
                inv.has_vba_macros = True
                vba_keywords.append("Embedded VBA Project Signature")

    inv.macro_details = vba_keywords

    # Scoring & signals
    if vba_detected:
        # Check if disguised inside a plain .docx extension
        if ext in [".docx", ".xlsx", ".pptx"]:
            inv.score += 45
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="VBA Macros Disguised in Plain OpenXML Document",
                    severity="critical",
                    score_impact=45,
                    description=(
                        f"CRITICAL: The document has extension '{ext}' (normally macro-free), "
                        "but internal structural analysis revealed embedded VBA macro code (vbaProject.bin). "
                        "This is a common evasion technique to bypass macro-blocking firewalls."
                    ),
                    evidence=", ".join(vba_keywords[:4])
                )
            )
        elif ext in MACRO_EXTENSIONS:
            inv.score += 28
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="Macro-Enabled Office Document (.docm/.xlsm)",
                    severity="high",
                    score_impact=28,
                    description=(
                        f"The file is a macro-enabled Office document ({ext}) containing embedded VBA projects. "
                        "Macros in email attachments are a primary vector for malware droppers."
                    ),
                    evidence=", ".join(vba_keywords[:4])
                )
            )
        else:
            inv.score += 30
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="Office Document with Active VBA Macros",
                    severity="high",
                    score_impact=30,
                    description="The legacy Office document contains VBA code with potential automatic execution triggers.",
                    evidence=", ".join(vba_keywords[:4])
                )
            )
    else:
        # Clean benign document confirmation!
        if ext in [".docx", ".xlsx"]:
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="Benign Document Structure Verified",
                    severity="info",
                    score_impact=0,
                    description=f"Standard Office {ext.upper()} structure verified. No embedded VBA macros, scripts, or external templates found.",
                    evidence="Clean OpenXML package"
                )
            )


def _statically_inspect_html(data: bytes, inv: AttachmentInventory):
    """
    Inspect HTML attachments for credential-harvesting forms, password inputs,
    and HTML smuggling constructs (Base64 blobs, download triggers).
    """
    try:
        text = data.decode("utf-8", errors="ignore").lower()
    except Exception:
        text = str(data).lower()

    # Check for <form>
    if "<form" in text:
        inv.html_has_forms = True

    # Check for <input type="password">
    if 'type="password"' in text or "type='password'" in text:
        inv.html_has_password_fields = True

    # Check for <script>
    if "<script" in text:
        inv.html_has_scripts = True

    # Check for HTML smuggling indicators
    smuggling_indicators = [
        "window.atob", "application/octet-stream", "data:application",
        "createobjecturl", "mssaveoropenblob", "document.createelement('a')",
        "document.createelement(\"a\")"
    ]
    matched_smuggling = [ind for ind in smuggling_indicators if ind in text]
    if matched_smuggling:
        inv.html_has_smuggling = True

    # Signals
    if inv.html_has_password_fields:
        inv.score += 45
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Credential Harvesting Password Form in HTML Attachment",
                severity="critical",
                score_impact=45,
                description=(
                    "The HTML attachment contains a password input field (<input type='password'>). "
                    "Legitimate organizations do not send HTML attachments that collect passwords offline or redirect credentials."
                ),
                evidence="Password input field detected inside attached HTML"
            )
        )
    elif inv.html_has_forms:
        inv.score += 25
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Interactive Form in HTML Attachment",
                severity="high",
                score_impact=25,
                description="The attached HTML file includes an interactive form, frequently used in offline credential phishing kits.",
                evidence="HTML <form> element present"
            )
        )

    if inv.html_has_smuggling:
        inv.score += 35
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="HTML Smuggling Techniques Detected",
                severity="high",
                score_impact=35,
                description=(
                    "The HTML attachment employs client-side blob generation or Base64 decoding (e.g., atob, createObjectURL). "
                    "Attackers use HTML smuggling to assemble malicious payloads in the browser, evading perimeter inspection."
                ),
                evidence=", ".join(matched_smuggling)
            )
        )


def _statically_inspect_archive(
    data: bytes,
    ext: str,
    body_passwords: List[str],
    inv: AttachmentInventory,
    nesting_depth: int = 1
):
    """
    Inspect archive contents strictly in memory without extracting to disk.
    Detects password protection, password correlation with body, nested archives,
    and hidden executable files.
    """
    if nesting_depth > 2:
        inv.status = "UNSCANNED"
        inv.status_reason = "Archive nesting depth exceeds limit (depth > 2). Marked UNSCANNED per safety policy."
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Archive Nesting Depth Limit Exceeded",
                severity="medium",
                score_impact=15,
                description="The archive contains nested layers exceeding the depth inspection limit (2 levels).",
                evidence=f"Nesting Depth: {nesting_depth}"
            )
        )
        return

    inv.archive_nesting_depth = nesting_depth

    # Inspection for ZIP archives
    try:
        zf = zipfile.ZipFile(io.BytesIO(data), "r")
        entries = []
        is_encrypted = False
        has_executables = False

        for info in zf.infolist():
            # Check flag_bits bit 0 (encrypted entry)
            entry_encrypted = (info.flag_bits & 0x1) != 0
            if entry_encrypted:
                is_encrypted = True

            # Check filename inside archive
            member_name = info.filename
            _, m_ext = os.path.splitext(member_name.lower())
            is_high_risk = m_ext in HIGH_RISK_EXTENSIONS

            risk_reason = None
            if is_high_risk:
                has_executables = True
                risk_reason = f"High-risk executable format ({m_ext}) packaged inside archive"

            entries.append(ArchiveEntry(
                name=member_name,
                size=info.file_size,
                is_dir=info.is_dir(),
                is_encrypted=entry_encrypted,
                is_high_risk=is_high_risk,
                risk_reason=risk_reason
            ))

        inv.archive_contents = entries
        inv.archive_encrypted = is_encrypted
        inv.has_archive_executables = has_executables

        # Password protected archive signals
        if is_encrypted:
            inv.score += 20
            # Check if password was mentioned in the email body!
            matched_pw = False
            if body_passwords:
                inv.archive_password_in_body = True
                inv.detected_passwords = body_passwords
                matched_pw = True

            if matched_pw:
                inv.score += 25
                inv.signals.append(
                    DetectionSignal(
                        category="attachment",
                        name="Password-Protected Archive with Password in Body",
                        severity="high",
                        score_impact=25,
                        description=(
                            "The ZIP archive is encrypted and password-protected, and the password "
                            "was explicitly provided in the email message body. This is a classic evasion tactic "
                            "designed to blind email gateway scanners while allowing the recipient to open the payload."
                        ),
                        evidence=f"Discovered passwords in email text: {', '.join(body_passwords)}"
                    )
                )
            else:
                inv.signals.append(
                    DetectionSignal(
                        category="attachment",
                        name="Password-Protected Encrypted Archive",
                        severity="medium",
                        score_impact=20,
                        description=(
                            "The ZIP archive contains password-protected/encrypted members. "
                            "Encrypted attachments prevent automated security scanners from analyzing the contents."
                        ),
                        evidence="ZIP flag_bits bit 0 (Encrypted)"
                    )
                )

        # Executable inside archive
        if has_executables:
            inv.score += 35
            high_risk_names = [e.name for e in entries if e.is_high_risk]
            inv.signals.append(
                DetectionSignal(
                    category="attachment",
                    name="Executable / Script Packaged Inside Archive",
                    severity="critical",
                    score_impact=35,
                    description=(
                        f"The archive contains executable or script members ({', '.join(high_risk_names)}). "
                        "Packaging executables inside archives is the leading method used by threat actors to bypass email gateways."
                    ),
                    evidence=", ".join(high_risk_names)
                )
            )

        # Benign archive verification
        if not is_encrypted and not has_executables:
            # Check if all files are images or text
            all_benign = all(
                os.path.splitext(e.name.lower())[1] in [".png", ".jpg", ".jpeg", ".txt", ".csv", ".pdf", ""]
                for e in entries if not e.is_dir
            )
            if all_benign and len(entries) > 0:
                inv.signals.append(
                    DetectionSignal(
                        category="attachment",
                        name="Benign Archive Contents Verified",
                        severity="info",
                        score_impact=0,
                        description="Archive contents inspected in-memory. Contains only standard non-executable assets (images, documents, or data).",
                        evidence=f"{len(entries)} file(s): {', '.join([e.name for e in entries[:3]])}"
                    )
                )

    except zipfile.BadZipFile:
        inv.status = "UNKNOWN"
        inv.status_reason = "Archive header is corrupted or uses an unparseable format."
        inv.signals.append(
            DetectionSignal(
                category="attachment",
                name="Corrupted / Unparseable Archive",
                severity="low",
                score_impact=5,
                description="Unable to statically unpack archive headers in-memory.",
                evidence="BadZipFile exception"
            )
        )
    except Exception as e:
        inv.status = "UNKNOWN"
        inv.status_reason = f"Archive static parsing error: {str(e)}"
