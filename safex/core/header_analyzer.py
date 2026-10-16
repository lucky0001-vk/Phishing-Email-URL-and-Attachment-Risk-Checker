"""
SafeX Header Analyzer
Inspects From, Reply-To, Return-Path, display-name spoofing, and recorded
SPF/DKIM/DMARC status (strictly no live DNS lookups).
"""

import re
import email.utils
from typing import Dict, List, Tuple, Optional
from safex.core.models import HeaderAnalysis, DetectionSignal

# High-profile brands frequently targeted for display-name spoofing
KNOWN_BRANDS = {
    "paypal": ["paypal.com", "paypal.co.uk"],
    "microsoft": ["microsoft.com", "office.com", "office365.com", "live.com", "outlook.com"],
    "google": ["google.com", "gmail.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "amazon.co.uk", "amazon.de"],
    "netflix": ["netflix.com"],
    "chase": ["chase.com", "jpmorgan.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "docusign": ["docusign.com", "docusign.net"],
    "dropbox": ["dropbox.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "fedex": ["fedex.com"],
    "ups": ["ups.com"],
    "geek squad": ["bestbuy.com", "geeksquad.com"],
    "meta": ["meta.com", "facebook.com", "instagram.com"],
}


def _extract_domain(email_str: str) -> str:
    """Extract domain portion of an email address."""
    if "@" in email_str:
        return email_str.split("@")[-1].strip().lower().rstrip(">")
    return ""


def _parse_email_field(field_val: Optional[str]) -> Tuple[str, str, str]:
    """Parse 'Display Name <user@domain.com>' into (display_name, email_address, domain)."""
    if not field_val:
        return "", "", ""
    name, addr = email.utils.parseaddr(field_val)
    addr = addr.strip().lower()
    domain = _extract_domain(addr)
    return name.strip(), addr, domain


def analyze_headers(headers: Dict[str, str], raw_headers: List[Tuple[str, str]]) -> HeaderAnalysis:
    """
    Perform static header inspection.
    """
    from_raw = headers.get("from", "")
    from_name, from_addr, from_domain = _parse_email_field(from_raw)

    reply_to_raw = headers.get("reply-to", "")
    reply_name, reply_addr, reply_domain = _parse_email_field(reply_to_raw)

    return_path_raw = headers.get("return-path", "")
    rp_name, rp_addr, rp_domain = _parse_email_field(return_path_raw)

    subject = headers.get("subject", "")
    date = headers.get("date", None)
    msg_id = headers.get("message-id", None)

    analysis = HeaderAnalysis(
        from_header=from_raw,
        from_name=from_name,
        from_address=from_addr,
        from_domain=from_domain,
        reply_to=reply_to_raw or None,
        reply_to_address=reply_addr or None,
        reply_to_domain=reply_domain or None,
        return_path=return_path_raw or None,
        return_path_address=rp_addr or None,
        return_path_domain=rp_domain or None,
        subject=subject,
        date=date,
        message_id=msg_id,
        score=0,
        signals=[]
    )

    score = 0

    # 1. Reply-To Mismatch Check
    if reply_domain and from_domain:
        # Check if root domains differ
        if reply_domain != from_domain:
            analysis.reply_to_mismatch = True
            score += 18
            analysis.signals.append(
                DetectionSignal(
                    category="header",
                    name="Reply-To Domain Mismatch",
                    severity="high",
                    score_impact=18,
                    description=(
                        f"The Reply-To address domain '{reply_domain}' does not match the sender's From domain '{from_domain}'. "
                        "When replying, responses will be routed to an alternate server, a tactic often used in business email compromise (BEC)."
                    ),
                    evidence=f"From: {from_addr} | Reply-To: {reply_addr}"
                )
            )

    # 2. Return-Path Mismatch Check
    if rp_domain and from_domain:
        if rp_domain != from_domain:
            analysis.return_path_mismatch = True
            score += 10
            analysis.signals.append(
                DetectionSignal(
                    category="header",
                    name="Return-Path Domain Mismatch",
                    severity="medium",
                    score_impact=10,
                    description=(
                        f"The envelope bounce address '{rp_domain}' differs from the visible sender domain '{from_domain}'. "
                        "While sometimes seen in legitimate third-party newsletter relays, in direct corporate messages this often indicates envelope spoofing."
                    ),
                    evidence=f"From: {from_domain} | Return-Path: {rp_domain}"
                )
            )

    # 3. Display Name Spoofing Checks
    if from_name and from_domain:
        # Check A: Display name embeds an email address different from From address
        embedded_email = re.search(r"[\w\.-]+@[\w\.-]+\.\w+", from_name)
        if embedded_email:
            fake_addr = embedded_email.group(0).lower()
            if fake_addr != from_addr:
                analysis.display_name_spoof = True
                score += 25
                analysis.signals.append(
                    DetectionSignal(
                        category="header",
                        name="Embedded Email Display Name Spoofing",
                        severity="high",
                        score_impact=25,
                        description=(
                            f"The sender's display name deliberately contains the email address '{fake_addr}' "
                            f"to deceive recipients, but the actual technical sender is '{from_addr}'."
                        ),
                        evidence=f"Display Name: '{from_name}' vs Technical Sender: '{from_addr}'"
                    )
                )

        # Check B: Brand impersonation in display name
        from_name_lower = from_name.lower()
        for brand, legitimate_domains in KNOWN_BRANDS.items():
            if brand in from_name_lower:
                # Is sender domain legitimate for this brand?
                is_legit = any(from_domain == d or from_domain.endswith("." + d) for d in legitimate_domains)
                if not is_legit:
                    analysis.display_name_spoof = True
                    score += 22
                    analysis.signals.append(
                        DetectionSignal(
                            category="header",
                            name=f"Brand Impersonation in Display Name ({brand.title()})",
                            severity="high",
                            score_impact=22,
                            description=(
                                f"The sender display name claims to represent '{brand.title()}', "
                                f"but the actual sending domain is '{from_domain}', which is not an authorized domain."
                            ),
                            evidence=f"Display: '{from_name}' | Actual Domain: '{from_domain}'"
                        )
                    )
                break

    # 4. Authentication-Results (SPF, DKIM, DMARC) Header Inspection
    # Strictly NO live DNS lookups; read recorded authentication results in header
    auth_header = (
        headers.get("authentication-results", "") + " " +
        headers.get("x-authentication-results", "") + " " +
        headers.get("received-spf", "")
    ).lower()

    # Parse SPF status
    spf_match = re.search(r"(?:spf=|\bspf:\s*)(pass|fail|softfail|neutral|none|temperror|permerror)", auth_header)
    if spf_match:
        analysis.spf_status = spf_match.group(1)
    else:
        # Check received-spf direct header
        rec_spf = headers.get("received-spf", "").lower()
        rec_spf_match = re.search(r"^(pass|fail|softfail|neutral|none|temperror)", rec_spf)
        if rec_spf_match:
            analysis.spf_status = rec_spf_match.group(1)

    # Parse DKIM status
    dkim_match = re.search(r"(?:dkim=|\bdkim:\s*)(pass|fail|neutral|none|temperror|permerror)", auth_header)
    if dkim_match:
        analysis.dkim_status = dkim_match.group(1)

    # Parse DMARC status
    dmarc_match = re.search(r"(?:dmarc=|\bdmarc:\s*)(pass|fail|none|temperror|permerror)", auth_header)
    if dmarc_match:
        analysis.dmarc_status = dmarc_match.group(1)

    # Summarize Auth results and add signals
    auth_summaries = []
    if analysis.spf_status:
        auth_summaries.append(f"SPF: {analysis.spf_status.upper()}")
        if analysis.spf_status == "fail":
            score += 16
            analysis.signals.append(
                DetectionSignal(
                    category="header",
                    name="SPF Authentication Failed",
                    severity="high",
                    score_impact=16,
                    description="The sending server is not authorized by the domain's SPF record to transmit emails.",
                    evidence=f"Recorded header SPF status: {analysis.spf_status}"
                )
            )
        elif analysis.spf_status == "softfail":
            score += 8
            analysis.signals.append(
                DetectionSignal(
                    category="header",
                    name="SPF Softfail Recorded",
                    severity="medium",
                    score_impact=8,
                    description="The sending server is flagged as a softfail (~all) under domain SPF policy.",
                    evidence=f"Recorded header SPF status: {analysis.spf_status}"
                )
            )

    if analysis.dkim_status:
        auth_summaries.append(f"DKIM: {analysis.dkim_status.upper()}")
        if analysis.dkim_status == "fail":
            score += 15
            analysis.signals.append(
                DetectionSignal(
                    category="header",
                    name="DKIM Signature Verification Failed",
                    severity="high",
                    score_impact=15,
                    description="The cryptographic DKIM signature on the email could not be verified or was modified in transit.",
                    evidence=f"Recorded header DKIM status: {analysis.dkim_status}"
                )
            )

    if analysis.dmarc_status:
        auth_summaries.append(f"DMARC: {analysis.dmarc_status.upper()}")
        if analysis.dmarc_status == "fail":
            score += 20
            analysis.signals.append(
                DetectionSignal(
                    category="header",
                    name="DMARC Policy Check Failed",
                    severity="critical",
                    score_impact=20,
                    description="The email failed DMARC alignment and validation, strongly suggesting unauthorized sender spoofing.",
                    evidence=f"Recorded header DMARC status: {analysis.dmarc_status}"
                )
            )

    if auth_summaries:
        analysis.auth_summary = " | ".join(auth_summaries)
    else:
        analysis.auth_summary = "No recorded Authentication-Results headers found in sample."

    analysis.score = min(score, 40)
    return analysis
