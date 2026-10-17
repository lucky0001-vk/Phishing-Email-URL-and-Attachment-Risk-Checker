# AI Usage & Disclosure Document (AI_USAGE.md)

**Project Title**: SafeX — AI-Powered Phishing Email, URL and Attachment Risk Detection Platform  
**Compliance Standard**: Hackathon Transparency & Ethical AI Disclosure Guidelines  
**Date**: October 2026  

---

## 1. Overview & Disclosure Statement
The SafeX Threat Defense Platform was developed using a transparent hybrid approach combining human cybersecurity engineering with modern AI-assisted developer tooling. In full alignment with competition guidelines, this document explicitly discloses the AI systems, developer assistants, design tools, and libraries utilized during the development lifecycle.

---

## 2. AI Tools & Developer Assistance

| Tool / Platform | Primary Role & Scope of Usage | Details |
| :--- | :--- | :--- |
| **ChatGPT (OpenAI)** | **Project Planning & Technical Documentation** | Used for structuring initial hackathon proposal documents, brainstorming risk-scoring weights, formatting markdown outlines, and drafting technical architecture descriptions. |
| **Antigravity (Google DeepMind)** | **Pair Programming & Coding Assistance** | Used for rapid code generation, binary parser scaffolding, edge-case test generation, bug diagnosis, and refactoring asynchronous FastAPI endpoints. |
| **Stitch (Google)** | **UI / UX Design & Component Layout** | Used for designing modern, minimalist cybersecurity UI mockups, refining visual hierarchy, selecting color palettes (Obsidian dark theme), and composing responsive dashboard cards. |

---

## 3. Libraries & External APIs Used

SafeX was purposely architected with an **ultra-lightweight footprint** using Python standard libraries to ensure zero-day resistance, zero external network dependency, and air-gapped capability.

### 3.1 Backend & Web Framework
- **FastAPI (`>=0.110.0`)**: High-performance asynchronous REST API framework for handling streaming multipart file uploads and form inputs.
- **Uvicorn (`>=0.29.0`)**: Production-grade ASGI web server running asynchronous event loops.
- **Pydantic v2 (`>=2.6.0`)**: Strict schema validation, data parsing, and serialization for threat detection models.
- **python-multipart (`>=0.0.9`)**: Streaming parser for RFC7578 multipart/form-data payloads (file uploads and raw `.eml` ingestion).
- **python-dotenv (`>=1.0.1`)**: Twelve-factor application environment variable configuration.

### 3.2 Python Standard Libraries (Zero External Dependencies for Core Detection)
- **`hashlib`**: Cryptographic SHA-256 and MD5 fingerprinting for attachment identification and offline blocklist matching.
- **`zipfile`**: Memory-buffered inspection of ZIP central directory structures, encryption flag bits (`flag_bits & 0x01`), and nested compression depth.
- **`email` / `email.policy`**: RFC5322 and RFC822 email message parsing, MIME multipart traversal, and header field decomposition.
- **`re`**: High-performance regular expression matching for urgency phrases, financial keywords, phone numbers, and URL patterns.
- **`struct`**: Raw binary unpacking for Windows PE DOS headers (`MZ` byte checks and offset `0x3c` `e_lfanew` resolution).
- **`urllib.parse`**: Canonical URI decomposition, port extraction, and host normalization.
- **`io.BytesIO`**: In-memory binary buffer streaming ensuring zero files are written to disk.

### 3.3 Frontend Libraries & Assets
- **Tailwind CSS**: Utility-first responsive CSS styling (dark obsidian theme).
- **Google Fonts (Inter & JetBrains Mono)**: Typography for clean enterprise threat readability.
- **Google Material Symbols**: Vector iconography for status tags, gauges, and risk severity indicators.

---

## 4. Human Engineering Contribution vs. AI Scaffolding

| System Area | Human Contribution (85%) | AI Assistance (15%) |
| :--- | :--- | :--- |
| **Static Binary Detection** | Designed DOS/PE magic byte inspection algorithm, OpenXML `vbaProject.bin` discovery, and PDF object stream tokenizers. | Boilerplate syntax generation and helper function framing. |
| **Risk-Scoring Mathematics** | Formulated non-linear compound penalty model balancing Sender, Body, URL, and Attachment risks. | Suggesting initial numeric point distributions. |
| **False-Positive Mitigation** | Engineered cryptographic SPF/DKIM/DMARC status overrides to prevent false alarms on legitimate urgent emails. | Drafting synthetic email text variants for validation. |
| **Security & Privacy** | Enforced zero-execution and zero-egress policies (no live DNS lookups, no cloud file uploads). | Verified error-handling edge cases and exception handling blocks. |
| **Testing & Quality Assurance** | Designed and executed 38 automated test cases and the 113-point compliance audit suite. | Generating parameter variations for test suites. |

---

## 5. Ethical Safeguards & Safety Guarantees

1. **Zero Weaponized Code**: All test samples and attachments included in the repository are completely benign mockups (e.g., harmless ASCII stubs with `MZ` headers, standard EICAR test hashes, and harmless string alerts).
2. **Zero Unauthorized Data Collection**: SafeX operates in ephemeral RAM and never transmits ingested email content, recipient addresses, or passwords to third-party services.
3. **Decision-Support Transparency**: Every alert displays the concrete reason and evidence backing it. SafeX is explicitly presented as a decision-support tool, not a legal or infallible guarantee.
