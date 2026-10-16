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
python -m unittest discover -s safex/tests
python -m safex.tests.audit_all_requirements
```

---

## 🚀 Key Features & 9 Prompt Capabilities

1. **4-Component Transparent Risk Breakdown:**
   * Separately tracks score contributions for **Sender Authentication**, **Email Body Text**, **URLs & Hyperlinks**, and **Attachment Structure** to show exactly what drove the verdict.
2. **Per-Attachment Report Card:**
   * Displays detected file type (via magic bytes), identified structural features, risk level (`CLEAN`, `LOW`, `SUSPICIOUS`, `MALICIOUS`), and a specific recommended action.
3. **Actionable Recommendations:**
   * Interactive, actionable playbooks for:
     - 🛑 **Quarantine Threat & Block Sender** (per-workstation and gateway isolation)
     - 📞 **Verify Sender via Official Channel** (out-of-band verification protocol)
     - 🔍 **Safe Offline / Air-Gapped Viewer Inspection** (macro-free, script-disabled sandbox parameters)
     - 🛡️ **Report to Security Operations (SOC)**
4. **User Feedback & False Positive / Negative Loop:**
   * Built-in classification reporting widget storing user feedback locally in `safex/feedback_store.json` to monitor and tune heuristic accuracy.
5. **Rule-Based vs Machine Learning (ML) Benchmark & Confusion Matrix:**
   * Evaluated across 20 ground-truth scenarios (10 benign vs 10 threats).
   * Calculates **Confusion Matrices ($TP, FP, TN, FN$)**, Accuracy, Precision, Recall, and F1-score side-by-side.
   * Access via the **[ 📊 ML vs Rule Benchmark ]** button in the web dashboard!
6. **Observable Signals with Supporting Evidence:**
   * Every threat flag provides the rule name, point impact, plain-English reason, and an explicit **Technical Supporting Evidence** box (e.g. hex signature match, domain mismatch).
7. **Comprehensive Scenario Corpus:**
   * Validated against legitimate urgent IT maintenance notices, benign vendor invoices, plain DOCX archives, disguised PE executables, macro-enabled documents, and RTLO filename attacks.
8. **Strict Zero-Execution Guarantee:**
   * All files parsed strictly in memory (`io.BytesIO`); never rendered, executed, or written to disk.
9. **Full Technical Documentation:**
   * Complete evaluation report, methodology, and architectural analysis available in [`EVALUATION_REPORT.md`](file:///c:/Users/Dell/Desktop/anti/EVALUATION_REPORT.md).

---

## 📐 Architecture & Key Capabilities

```
safex/
  ├── core/
  │    ├── models.py             # Pydantic schemas (Signals, Attachments, RiskScores, ActionCards)
  │    ├── email_parser.py       # In-memory RFC822 parser (strict limits: 25MB, 10 atts)
  │    ├── header_analyzer.py    # Display-name spoofing, Reply-To mismatch, SPF/DKIM/DMARC (no live DNS)
  │    ├── url_analyzer.py       # Link text vs target mismatch, IP literals, lookalikes, homoglyphs, ports
  │    ├── body_analyzer.py      # Urgency/financial rhetoric, vishing phone patterns, hidden CSS text, quishing
  │    ├── attachment_scanner.py # Static magic bytes, MZ in PDF, macros, PDF tags, encrypted ZIP, RTLO
  │    ├── risk_engine.py        # 4-way balanced scoring engine & actionable safe guidance cards
  │    ├── feedback_store.py     # Local JSON feedback store for tracking FP / FN reports
  │    ├── evaluation_engine.py  # Benchmark dataset, confusion matrices & ML comparison
  │    ├── analyzer.py           # Unified analysis coordinator
  │    └── test_samples.py       # 9 pre-configured test scenarios with synthetic payloads
  ├── web/
  │    ├── app.py                # FastAPI REST API & static file server
  │    └── static/               # Mesmerizing Cyber SOC Dashboard (HTML/CSS/JS)
  ├── tests/
  │    ├── test_safex.py         # 14 Unit tests covering all requirements
  │    └── audit_all_requirements.py # 113-point compliance audit test suite
  ├── samples/                   # Generated .eml and sample attachments for manual testing
  ├── cli.py                     # Rich terminal CLI analyzer
  └── safex_cli.py               # Root quick-launcher CLI script
```

---

## 🛡️ Operational & Privacy Safeguards
1. **Air-Gapped & Offline**: No URLs are visited automatically; no files or hashes are uploaded to third-party cloud scanners.
2. **In-Memory Only**: Attachments are read into temporary in-memory byte buffers (`io.BytesIO`) and discarded immediately after analysis.
3. **Strict Safety Limits**: Enforces a 25MB attachment size limit, a maximum of 10 attachments per email, and an archive nesting depth limit of 2. Oversized or corrupted inputs are designated `UNSCANNED` or `UNKNOWN`, never `SAFE`.
4. **Decision-Support Tool**: SafeX explicitly provides threat triage indicators and safe verification protocols, functioning as an assistive decision-support tool.

