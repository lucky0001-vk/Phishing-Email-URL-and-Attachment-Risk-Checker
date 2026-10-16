# 🛡️ SafeX — Static Email, URL & Attachment Threat Defense Platform

> **SafeX** is an advanced, privacy-preserving static decision-support system designed to inspect emails, web links, and file attachments for phishing and malware warning signs. Attachments are inspected purely in-memory through structural characteristics, magic bytes, and metadata — **they are never opened, rendered, or executed**.

---

## ⚡ Quick Start

### 1. Launch the Interactive Web Application (FastAPI + Cyber SOC UI)
```bash
python -m uvicorn safex.web.app:app --host 127.0.0.1 --port 8000
```
Open your browser at: **[http://127.0.0.1:8000](http://127.0.0.1:8000)**

### 2. Run from the Command Line Interface (CLI)
```bash
# Run any built-in scenario (1 through 9)
python safex_cli.py --sample 1   # Legitimate Urgent Notice (Demonstrates False-Positive Reduction)
python safex_cli.py --sample 2   # Disguised Executable (.pdf with MZ header)
python safex_cli.py --sample 3   # Weaponized Office Document (Embedded Macros)
python safex_cli.py --sample 4   # Brand Phishing with Link Mismatch & Spoofing
python safex_cli.py --sample 5   # Password-Protected ZIP with Password in Email Body
python safex_cli.py --sample 6   # Genuine Vendor PDF Invoice (Clean static structure)
python safex_cli.py --sample 7   # Clean DOCX & Benign Image Archive
python safex_cli.py --sample 8   # Unicode Right-to-Left Override (RTLO) Attack
python safex_cli.py --sample 9   # HTML Smuggling & Credential Phishing

# Analyze any .eml file or raw email text
python safex_cli.py safex/samples/1_scenario_1_legitimate_urgent.eml

# Output structured JSON
python safex_cli.py --sample 4 --json
```

### 3. Run the Automated Verification Test Suite
```bash
python -m unittest safex.tests.test_safex
```

---

## 📐 Architecture & Key Capabilities

```
safex/
  ├── core/
  │    ├── models.py             # Pydantic schemas (Signals, Attachments, RiskScores)
  │    ├── email_parser.py       # In-memory RFC822 parser (strict limits: 25MB, 10 atts)
  │    ├── header_analyzer.py    # Display-name spoofing, Reply-To mismatch, SPF/DKIM/DMARC (no live DNS)
  │    ├── url_analyzer.py       # Link text vs target mismatch, IP literals, lookalikes, punycode
  │    ├── body_analyzer.py      # Urgency/financial rhetoric, archive password body extractor
  │    ├── attachment_scanner.py # Static magic bytes, MZ in PDF, macros, PDF tags, encrypted ZIP
  │    ├── risk_engine.py        # Multi-vector balanced scoring engine & safe action guidance
  │    ├── analyzer.py           # Unified analysis coordinator
  │    └── test_samples.py       # 9 pre-configured test scenarios with synthetic payloads
  ├── web/
  │    ├── app.py                # FastAPI REST API & static file server
  │    └── static/               # Mesmerizing Cyber SOC Dashboard (HTML/CSS/JS)
  ├── tests/
  │    └── test_safex.py         # Unit tests covering all 8 prompt verification criteria
  ├── samples/                   # Generated .eml and sample attachments for manual testing
  ├── cli.py                     # Rich terminal CLI analyzer
  └── safex_cli.py               # Root quick-launcher CLI script
```

---

## 🔍 Core Security & Analysis Engines

### 1. Attachment Static Analysis (Zero Execution)
* **True File Type Identification**: Content-based magic-byte inspection (not relying on filename extension or declared MIME type).
* **Disguised Executable Detection**: Detects Windows PE binaries (`MZ` header `0x4D 0x5A`) masquerading as `.pdf`, `.png`, or `.docx`.
* **Filename Deception Prevention**: Flags double extensions (`invoice.pdf.exe`) and Unicode Right-to-Left Override (`\u202e`) used to reverse file extension display.
* **Macro & Office Inspection**: Static OpenXML inspection for `vbaProject.bin` and OLE macro streams with suspicious auto-exec functions (`AutoOpen`, `Shell`, `PowerShell`).
* **PDF Structural Analysis**: Scans raw byte streams for `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFiles`, and `/AA`.
* **HTML Phishing & Smuggling**: Identifies password inputs (`<input type="password">`), off-site form submissions, and JavaScript blob assembly (`window.atob`, `msSaveOrOpenBlob`).
* **Archive Security**: In-memory inspection of ZIP contents; flags encrypted archives, extracts passwords from email body, and flags nested executables without extracting to disk.

### 2. Email & URL Analysis
* **Link Mismatch Detection**: Flags hyperlinks whose visible anchor text displays one trusted domain (e.g. `https://paypal.com`) while destination href leads to a different domain (`paypal.com.account-verify.xyz`).
* **IP Literals & Lookalikes**: Flags bare IP addresses (`http://192.168.1.1/`) and typosquatting/homoglyph brand mimicry.
* **Header Alignment**: Inspects `From`, `Reply-To`, and `Return-Path` for domain mismatches and display-name spoofing.
* **Authentication Headers**: Evaluates recorded SPF, DKIM, and DMARC status without performing live DNS queries.

### 3. Balanced Risk Scoring & False-Positive Prevention
* **Multi-Indicator Weighting**: Avoids false alarms from single weak signals. Routine urgency keywords (e.g. "deadline") in authentic corporate communications with passing SPF/DKIM/DMARC headers receive a **LOW** risk rating.
* **Transparent Reasons**: Every score increase is accompanied by a concrete `DetectionSignal` object containing severity, rule title, human explanation, and raw evidence.
* **Tailored Safe Action Protocol**: Supplies specific, out-of-band verification steps and prohibitions (e.g. never enable macros, verify via internal directory, do not click links).

---

## 🛡️ Operational & Privacy Safeguards
1. **Air-Gapped & Offline**: No URLs are visited automatically; no files or hashes are uploaded to third-party cloud scanners.
2. **In-Memory Only**: Attachments are read into temporary in-memory byte buffers (`io.BytesIO`) and discarded immediately after analysis.
3. **Strict Safety Limits**: Enforces a 25MB attachment size limit, a maximum of 10 attachments per email, and an archive nesting depth limit of 2. Oversized or corrupted inputs are designated `UNSCANNED` or `UNKNOWN`, never `SAFE`.
4. **Decision-Support Tool**: SafeX explicitly provides threat triage indicators and safe verification protocols, functioning as an assistive decision-support tool.
