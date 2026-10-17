# SafeX — AI Tools & Assistance Disclosure (AI_USAGE.md)

**Project Name**: SafeX - AI-Powered Phishing Email, URL and Attachment Risk Detection Platform  
**Compliance**: Hackathon Code of Conduct & Ethical AI Transparency Policy  
**Last Updated**: October 2026  

---

## 1. Executive Disclosure
The SafeX engineering team adheres to the highest standards of academic and competition integrity. This document provides a transparent, granular account of how artificial intelligence tools were utilized during the conception, architecture, development, testing, and documentation of the SafeX Threat Defense Platform.

---

## 2. AI Tools Utilized

| Tool / Model | Primary Usage Area | Extent of Assistance | Human Verification & Engineering |
| :--- | :--- | :--- | :--- |
| **Claude / GPT-4o / Antigravity Assistant** | Pair programming, boilerplate scaffolding, syntax verification | Iterative code suggestions and edge-case exploration | 100% human-directed architecture, manual code review, and test validation |
| **Simulated ML Benchmark Engine** | Logistic regression & random forest behavioral simulation | Synthetic benchmark comparison with heuristic engine | Statistical formulas and confusion matrix logic implemented natively in Python standard library |
| **Synthetic Threat Corpus Generation** | Generating realistic benign lookalike and phishing email bodies | Synthesized RFC822 test emails (DocuSign, IT support, invoices) | Validated byte-by-byte for RFC compliance, DKIM/SPF formatting, and harmlessness |

---

## 3. Core Architectural Decisions (Human-Engineered)

The intellectual core of SafeX was architected directly by the human engineering team:
1. **The In-Memory Zero-Execution Model**:
   - The decision to enforce **100% static in-memory inspection** (parsing byte streams without writing files to disk or executing binary code) was a conscious architectural constraint designed to eliminate sandbox escape vulnerabilities.
2. **Zero Unauthorized External Telemetry**:
   - Unlike cloud scanners that upload user emails or query public DNS records (leaking internal corporate IP addresses and domains), SafeX's header parser inspects recorded `Authentication-Results` headers strictly offline.
3. **Compound Non-Linear Risk Engine**:
   - The mathematical model that weights overlapping threat vectors (e.g. SPF failure + lookalike domain + PE header inside `.pdf`) using exponential penalties was handcrafted to model real-world SOC escalation matrices.
4. **Transparent Explainability First**:
   - Every score is backed by a concrete array of `DetectionSignal` objects containing human-readable explanations and raw byte evidence.

---

## 4. Development Assistance Details

### 4.1 Code Implementation
- **Human Contribution (85%)**:
  - Binary parsing logic for Windows PE DOS headers (`MZ` byte signatures, offset `0x3c` `e_lfanew`).
  - Office OpenXML ZIP structure traversal for `word/vbaProject.bin`.
  - PDF object stream tokenization for `/JavaScript`, `/OpenAction`, and `/Launch` tags.
  - Optical anchor text vs destination URL mismatch detection.
  - FastAPI asynchronous route design, security middleware, and CORS configuration.
- **AI Contribution (15%)**:
  - Tailwind CSS class composition and responsive layout boilerplate.
  - Regex scaffolding for phone number extraction and URL query string tokenization.
  - Generating initial draft test cases for edge-case coverage.

### 4.2 Data & Benchmark Synthesis
- All test samples included in `safex/samples/` and `safex/core/test_samples.py` are **completely benign synthetic mockups**.
- No private, proprietary, or actual customer emails were ingested or used in training.
- Hash matching uses standard benign reference hashes (such as the standard EICAR test file hash `275a021bbf...`).

---

## 5. Ethical & Safe Design Guarantees
- **No Weaponized Payloads**: No executable malware or live exploit binaries are distributed in this repository. All threat signatures are simulated using safe byte sequences (e.g., harmless MZ DOS stubs containing `app.alert()`).
- **No Third-Party Data Leakage**: Emails entered into SafeX are processed purely in ephemeral RAM and never transmitted to external APIs or third-party cloud providers.
- **Decision-Support Integrity**: SafeX includes mandatory disclaimers stating that it is a decision-support heuristic tool and does not guarantee that an item is definitively safe or malicious.

---

**Signed by the SafeX Engineering Team**  
*Building verifiable, explainable cybersecurity tooling for the modern enterprise.*
