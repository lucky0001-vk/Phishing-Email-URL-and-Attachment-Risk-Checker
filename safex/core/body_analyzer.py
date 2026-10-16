"""
SafeX Body Analyzer
Inspects email text and HTML for social engineering urgency patterns,
credential solicitation, financial extortion rhetoric, and extracts attachment passwords.
Implements calibrated rules to avoid false positives on legitimate urgent notices.
"""

import re
from typing import List, Dict, Tuple, Optional
from bs4 import BeautifulSoup
from safex.core.models import BodyAnalysis, DetectionSignal, LinkAnalysis
from safex.core.url_analyzer import extract_and_analyze_links

# Urgency and coercion indicators
URGENCY_PATTERNS = [
    r"\bimmediate(?:ly)?\s+action\s+required\b",
    r"\baccount\s+(?:will\s+be\s+)?suspended\b",
    r"\baction\s+required\s+within\s+\d+\s+hours?\b",
    r"\bwithin\s+24\s+hours?\b",
    r"\baccount\s+restricted\b",
    r"\bunauthorized\s+(?:access|login|transaction|activity)\b",
    r"\bsecurity\s+alert:\s+unusual\b",
    r"\bverify\s+your\s+(?:account|identity|billing)\s+immediately\b",
    r"\bfinal\s+notice\b",
    r"\bpayment\s+overdue\s+immediate\b",
    r"\bterminate\s+your\s+access\b",
    r"\bclick\s+here\s+to\s+keep\s+your\s+account\b",
    r"\bpassword\s+expir(?:es|ed)\s+today\b",
]

FINANCIAL_PATTERNS = [
    r"\bwire\s+transfer\b",
    r"\bbitcoin\b|\bbtc\s+wallet\b|\bcrypto(?:currency)?\b",
    r"\bgift\s+cards?\b",
    r"\bremittance\s+advice\b",
    r"\boverdue\s+invoice\b",
    r"\bbanking\s+details\s+update\b",
    r"\bdirect\s+deposit\s+change\b",
]

# Regex patterns to spot attachment passwords declared in email body
# e.g. "Password: 1234", "Pass is: Infected", "ZIP password = Company2024"
ARCHIVE_PASSWORD_PATTERNS = [
    r"(?:zip\s+)?pass(?:word)?\s*[:=\-]\s*[\"']?([A-Za-z0-9!@#$%^&*\-_]{3,30})[\"']?",
    r"(?:pass(?:word)?\s+is\s*[:=\-]?\s*)[\"']?([A-Za-z0-9!@#$%^&*\-_]{3,30})[\"']?",
    r"(?:use\s+password\s*[:=\-]?\s*)[\"']?([A-Za-z0-9!@#$%^&*\-_]{3,30})[\"']?",
    r"(?:file\s+pass(?:word)?\s*[:=\-]?\s*)[\"']?([A-Za-z0-9!@#$%^&*\-_]{3,30})[\"']?",
    r"(?:archive\s+key\s*[:=\-]?\s*)[\"']?([A-Za-z0-9!@#$%^&*\-_]{3,30})[\"']?",
]


def extract_archive_passwords_from_body(text: str) -> List[str]:
    """Extract potential archive passwords stated in the email body."""
    candidates = []
    for pattern in ARCHIVE_PASSWORD_PATTERNS:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            pw = match.group(1).strip()
            if pw and pw not in candidates and pw.lower() not in ["the", "this", "our", "your", "required"]:
                candidates.append(pw)
    return candidates


def analyze_body(plain_text: str, html_text: str) -> BodyAnalysis:
    """
    Perform static inspection of body text and embedded URLs.
    """
    full_text = plain_text or ""
    if html_text and not plain_text:
        # Strip HTML tags for text analysis
        try:
            soup = BeautifulSoup(html_text, "html.parser")
            full_text = soup.get_text(separator=" ")
        except Exception:
            full_text = re.sub(r"<[^>]+>", " ", html_text)

    # 1. Extract and inspect URLs
    links, link_signals = extract_and_analyze_links(html_text, plain_text)

    # 2. Extract potential archive passwords
    extracted_passwords = extract_archive_passwords_from_body(full_text)

    # 3. Urgency and Social Engineering checks
    urgency_detected = []
    for pat in URGENCY_PATTERNS:
        found = re.findall(pat, full_text, re.IGNORECASE)
        if found:
            for item in set(found):
                urgency_detected.append(item if isinstance(item, str) else item[0])

    # 4. Financial phrases check
    financial_detected = []
    for pat in FINANCIAL_PATTERNS:
        found = re.findall(pat, full_text, re.IGNORECASE)
        if found:
            for item in set(found):
                financial_detected.append(item if isinstance(item, str) else item[0])

    # 5. Vishing Callback Detection
    phone_pattern = r"(?:\+?1[-.\s]?)?\(?[2-9]\d{2}\)?[-.\s]?\d{3}[-.\s]?\d{4}"
    phones = re.findall(phone_pattern, full_text)
    vishing_detected = False
    vishing_keywords = ["call", "cancel", "refund", "dispute", "toll-free", "helpdesk", "subscription", "charge"]
    if phones and any(k in full_text.lower() for k in vishing_keywords):
        vishing_detected = True

    # 6. Hidden Text / Anti-Analysis Evasion
    hidden_text_detected = False
    if html_text:
        hidden_patterns = [
            r"font-size\s*:\s*0(?:px|pt|em)?",
            r"display\s*:\s*none",
            r"visibility\s*:\s*hidden",
            r"opacity\s*:\s*0",
            r"color\s*:\s*(?:#fff(?:fff)?|white)\s*;\s*background(?:-color)?\s*:\s*(?:#fff(?:fff)?|white)"
        ]
        if any(re.search(p, html_text, re.IGNORECASE) for p in hidden_patterns):
            hidden_text_detected = True

    # 7. Quishing / QR Code Phishing Indicators
    quishing_pattern = r"\b(?:scan\s*(?:this|the)?\s*qr|qr\s*code|scan\s*with\s*(?:your\s*)?(?:camera|phone)|mfa\s*qr)\b"
    quishing_detected = bool(re.search(quishing_pattern, full_text, re.IGNORECASE))

    # 8. Direct Credential Solicitation
    cred_keywords = ["password", "mfa code", "seed phrase", "secret pin", "social security", "ssn", "two-factor code", "one-time pin"]
    found_creds = [k for k in cred_keywords if re.search(rf"\b{k}\b", full_text, re.IGNORECASE)]

    # Prepare analysis structure
    body_analysis = BodyAnalysis(
        urgency_phrases_detected=urgency_detected,
        financial_phrases_detected=financial_detected,
        call_to_actions=[],
        extracted_archive_passwords=extracted_passwords,
        credential_keywords_detected=found_creds,
        has_vishing_phone=vishing_detected,
        detected_phones=phones[:3] if vishing_detected else [],
        has_hidden_text=hidden_text_detected,
        has_quishing_indicators=quishing_detected,
        links=links,
        text_preview=full_text[:300].strip(),
        is_html=bool(html_text),
        score=0,
        signals=[]
    )

    # Add URL signals
    body_analysis.signals.extend(link_signals)

    # Calculate calibrated score
    score = sum(lk.score_impact for lk in links)

    # Urgency scoring logic:
    # A single urgency phrase alone is weak (low score, informative) so benign alerts aren't flagged
    if urgency_detected:
        if len(urgency_detected) >= 3 or any(lk.score_impact >= 20 for lk in links):
            # Compound risk: urgency combined with suspicious links or heavy repetition
            score += 15
            body_analysis.signals.append(
                DetectionSignal(
                    category="body",
                    name="High-Pressure Urgency Rhetoric",
                    severity="high",
                    score_impact=15,
                    description=(
                        f"Multiple psychological urgency indicators detected ({len(urgency_detected)} instances). "
                        "Phishing attacks rely heavily on simulated panic to prompt hasty, unverified clicks."
                    ),
                    evidence=", ".join(urgency_detected[:4])
                )
            )
        else:
            # Low / Informational impact to prevent false positives on legitimate warnings
            score += 5
            body_analysis.signals.append(
                DetectionSignal(
                    category="body",
                    name="Urgency Phrasing Detected (Moderate)",
                    severity="low",
                    score_impact=5,
                    description=(
                        "Message contains urgency-related terminology. On its own, this is not proof of malice "
                        "(routine IT notices or billing reminders also use urgency), but warrants verification."
                    ),
                    evidence=", ".join(urgency_detected[:3])
                )
            )

    if financial_detected and (urgency_detected or any(lk.score_impact >= 15 for lk in links)):
        score += 12
        body_analysis.signals.append(
            DetectionSignal(
                category="body",
                name="Financial / Wire Transfer Solicitation",
                severity="medium",
                score_impact=12,
                description="Message combines high-pressure urgency with financial, cryptocurrency, or wire transfer keywords.",
                evidence=", ".join(financial_detected[:3])
            )
        )

    if extracted_passwords:
        body_analysis.signals.append(
            DetectionSignal(
                category="body",
                name="Archive Password Provided in Email Body",
                severity="info",
                score_impact=0,
                description=(
                    f"Identified {len(extracted_passwords)} potential archive password string(s) in the message body. "
                    "This pattern will be correlated with any password-protected attachments."
                ),
                evidence=f"Discovered passwords: {', '.join(extracted_passwords)}"
            )
        )

    if vishing_detected:
        score += 18
        body_analysis.signals.append(
            DetectionSignal(
                category="body",
                name="Callback Phishing / Vishing Vector",
                severity="high",
                score_impact=18,
                description="Message requests the recipient to phone a customer support number to dispute an unauthorized charge or renew a subscription.",
                evidence=f"Discovered Phone(s): {', '.join(phones[:2])}"
            )
        )

    if hidden_text_detected:
        score += 20
        body_analysis.signals.append(
            DetectionSignal(
                category="body",
                name="Hidden Text / Zero-Font Spam Evasion",
                severity="high",
                score_impact=20,
                description="HTML body contains invisible/zero-font text elements intentionally designed to bypass security filters.",
                evidence="CSS: font-size:0px or display:none"
            )
        )

    if quishing_detected:
        score += 16
        body_analysis.signals.append(
            DetectionSignal(
                category="body",
                name="QR Code Phishing (Quishing) Solicitation",
                severity="medium",
                score_impact=16,
                description="Message directs the user to scan a QR code using a mobile device, evading traditional endpoint URL filters.",
                evidence="Scan QR code prompt detected"
            )
        )

    if found_creds and (urgency_detected or any(lk.score_impact >= 15 for lk in links)):
        score += 15
        body_analysis.signals.append(
            DetectionSignal(
                category="body",
                name="Sensitive Credential Solicitation",
                severity="high",
                score_impact=15,
                description=f"Message explicitly solicits sensitive authentication secrets: {', '.join(found_creds)}.",
                evidence=", ".join(found_creds)
            )
        )

    url_only_raw = sum(lk.score_impact for lk in links)
    text_only_raw = max(0, score - url_only_raw)

    body_analysis.url_only_score = min(url_only_raw, 50)
    body_analysis.text_only_score = min(text_only_raw, 45)
    body_analysis.score = min(score, 50)
    return body_analysis
