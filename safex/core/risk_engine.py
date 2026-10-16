"""
SafeX Risk Engine & Safe Guidance
Combines signals from Header, Body/URL, and Attachment static analyses
into a balanced composite risk score (0-100), with understandable reasons,
component breakdowns, and actionable safe guidance verification steps.
"""

from datetime import datetime, timezone
from typing import List, Dict, Any, Tuple
from safex.core.models import (
    HeaderAnalysis,
    BodyAnalysis,
    AttachmentInventory,
    EmailAnalysisResult,
    SafeGuidance,
    DetectionSignal,
)


def evaluate_email_risk(
    header_analysis: HeaderAnalysis,
    body_analysis: BodyAnalysis,
    attachments: List[AttachmentInventory]
) -> EmailAnalysisResult:
    """
    Synthesize all static signals into a balanced composite risk rating.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 1. Collect all detection signals
    all_signals: List[DetectionSignal] = []
    all_signals.extend(header_analysis.signals)
    all_signals.extend(body_analysis.signals)

    max_attachment_score = 0
    for att in attachments:
        all_signals.extend(att.signals)
        if att.score > max_attachment_score:
            max_attachment_score = att.score

    # 2. Compute category scores
    header_score = header_analysis.score
    body_url_score = body_analysis.score
    attachment_score = min(max_attachment_score, 50)

    # 4-Way Distinct Breakdown
    sender_score = min(header_score, 45)
    url_score = min(sum(lk.score_impact for lk in body_analysis.links), 45)
    body_only_score = min(sum(s.score_impact for s in body_analysis.signals if s.category == "body"), 45)

    # Per-attachment recommended action
    for att in attachments:
        if att.risk_level == "MALICIOUS" or att.type_mismatch or att.rtlo_detected or att.known_hash_match:
            att.recommended_action = "Quarantine immediately — do NOT execute or open. Block sender domain."
        elif att.risk_level == "SUSPICIOUS" or att.has_vba_macros or (att.is_archive and att.archive_encrypted):
            att.recommended_action = "Inspect in an isolated sandbox or safe read-only viewer. Do not enable macros."
        elif att.status in ["UNSCANNED", "UNKNOWN"]:
            att.recommended_action = "Inspect in an isolated safe viewer (file exceeds limits or corrupt)."
        else:
            att.recommended_action = "Safe document verified — standard handling in default viewer."

    # 3. Multi-indicator combination & correlation adjustments
    # Check for strong correlations:
    # A) Display Name Spoof + Authentication Failure
    has_display_spoof = header_analysis.display_name_spoof
    has_auth_fail = (header_analysis.spf_status == "fail" or
                     header_analysis.dmarc_status == "fail" or
                     header_analysis.dkim_status == "fail")

    # B) Urgency + Link Mismatch / Lookalike
    has_urgency = len(body_analysis.urgency_phrases_detected) > 0
    has_suspicious_url = any(
        lk.is_mismatch or lk.is_lookalike or lk.is_ip_literal
        for lk in body_analysis.links
    )

    # C) Password in body + Encrypted ZIP
    has_zip_pw_match = any(att.archive_password_in_body for att in attachments)

    # D) Disguised executable or malicious macro
    has_disguised_file = any(
        att.type_mismatch or att.rtlo_detected or att.has_archive_executables or
        (att.is_office_doc and att.has_vba_macros and att.filename.endswith((".docx", ".xlsx")))
        for att in attachments
    )

    correlation_bonus = 0
    if has_display_spoof and has_auth_fail:
        correlation_bonus += 15
        all_signals.append(
            DetectionSignal(
                category="header",
                name="Correlated Sender Impersonation & Auth Failure",
                severity="critical",
                score_impact=15,
                description="Sender display name impersonation directly coincides with SPF/DMARC authentication failure.",
                evidence="Brand/Email Spoofing + Auth Failure"
            )
        )

    if has_urgency and has_suspicious_url:
        correlation_bonus += 12
        all_signals.append(
            DetectionSignal(
                category="body",
                name="Correlated Urgency & Deceptive Link Pattern",
                severity="high",
                score_impact=12,
                description="Psychological urgency phrases correlate with deceptive or mismatched link destinations.",
                evidence="Urgency rhetoric + Link mismatch/lookalike"
            )
        )

    if has_zip_pw_match:
        correlation_bonus += 20
        all_signals.append(
            DetectionSignal(
                category="attachment",
                name="Correlated Archive Password Evasion Vector",
                severity="high",
                score_impact=20,
                description="Encrypted ZIP archive with password provided in email body deliberately evades automated gateway detection.",
                evidence="Archive Password in Body + Encrypted ZIP"
            )
        )

    # Raw sum
    raw_score = header_score + body_url_score + attachment_score + correlation_bonus

    # If an attachment is a proven disguised executable or credential phishing form, floor the score at high risk
    if has_disguised_file or any(att.html_has_password_fields for att in attachments):
        raw_score = max(raw_score, 75)

    # If known malicious hash matched, floor at 90
    if any(att.known_hash_match for att in attachments):
        raw_score = max(raw_score, 90)

    # False-positive mitigation:
    # If headers are clean/passing (SPF=pass, DKIM=pass), no attachments, no suspicious URLs,
    # and the only signal is moderate urgency (like standard IT notification), keep score in benign LOW range!
    is_auth_clean = (
        header_analysis.spf_status == "pass" and
        header_analysis.dkim_status == "pass" and
        not header_analysis.reply_to_mismatch and
        not header_analysis.display_name_spoof
    )
    if is_auth_clean and not has_suspicious_url and not attachments:
        raw_score = min(raw_score, 20)

    overall_score = min(100, max(0, raw_score))

    # 4. Assign Risk Rating & Verdict
    if overall_score >= 80:
        risk_rating = "CRITICAL"
        verdict = "Critical Threat Detected"
        summary = (
            "High confidence malicious indicators detected. The message exhibits explicit indicators "
            "of deception, weaponized payload delivery, or credential harvesting."
        )
    elif overall_score >= 60:
        risk_rating = "HIGH"
        verdict = "High Phishing / Threat Risk"
        summary = (
            "Multiple significant phishing warning signs were identified. The email displays deceptive headers, "
            "suspicious links, or untrusted attachment characteristics."
        )
    elif overall_score >= 30:
        risk_rating = "MEDIUM"
        verdict = "Suspicious — Verification Advised"
        summary = (
            "Moderate risk indicators detected. While not conclusively malicious, several factors "
            "deviate from standard communication norms and warrant manual verification."
        )
    else:
        risk_rating = "LOW"
        verdict = "Low Risk / Likely Benign"
        summary = (
            "No prominent malicious indicators detected. Communication structures and links appear consistent "
            "with standard benign messages. Continue practicing standard verification habits."
        )

    # 5. Formulate Safe Guidance
    safe_guidance = _generate_safe_guidance(
        risk_rating,
        header_analysis,
        body_analysis,
        attachments,
        has_suspicious_url,
        has_disguised_file,
        has_zip_pw_match
    )

    return EmailAnalysisResult(
        analysis_timestamp=now_str,
        overall_score=overall_score,
        risk_rating=risk_rating,
        verdict=verdict,
        summary=summary,
        score_breakdown={
            "sender_score": sender_score,
            "body_score": body_only_score,
            "url_score": url_score,
            "attachment_score": attachment_score,
            "header_score": header_score,
            "body_url_score": body_url_score,
            "overall_score": overall_score,
        },
        header_analysis=header_analysis,
        body_analysis=body_analysis,
        attachments=attachments,
        all_signals=all_signals,
        safe_guidance=safe_guidance,
    )


def _generate_safe_guidance(
    risk_rating: str,
    header_analysis: HeaderAnalysis,
    body_analysis: BodyAnalysis,
    attachments: List[AttachmentInventory],
    has_suspicious_url: bool,
    has_disguised_file: bool,
    has_zip_pw_match: bool
) -> SafeGuidance:
    """
    Generate tailored, actionable safety steps based on detected indicators.
    """
    verification_steps = [
        "Verify through an official, out-of-band communication channel (e.g., look up the company or colleague via an internal directory or known corporate phone number).",
        "Never enter corporate passwords, financial PINs, or Multi-Factor Authentication (MFA) codes on pages reached from email links.",
        "Report suspicious messages to your IT Security Operations Center (SOC) or designated phishing reporting inbox."
    ]

    recommendations = []
    things_to_avoid = [
        "Do not click links inside the email.",
        "Do not download, extract, or open any attachments."
    ]

    quarantine_recommended = risk_rating in ["HIGH", "CRITICAL"] or has_disguised_file
    sender_verification_required = (
        header_analysis.display_name_spoof or
        header_analysis.reply_to_mismatch or
        header_analysis.spf_status == "fail" or
        header_analysis.dmarc_status == "fail"
    )
    safe_viewer_recommended = len(attachments) > 0

    if risk_rating in ["HIGH", "CRITICAL"]:
        action = "CRITICAL_THREAT_DO_NOT_ENGAGE" if risk_rating == "CRITICAL" else "DO_NOT_ENGAGE"
        headline = "Isolate Message — Quarantine & Official Channel Verification Required"
        recommendations.append("Quarantine payload immediately: move email to isolated junk/quarantine store.")
        recommendations.append("Verify the sender through an official out-of-band corporate directory before taking any action.")

        if has_suspicious_url:
            things_to_avoid.append("Do not navigate to any web address listed in the message body.")
            recommendations.append("If you need to access this service, manually navigate to the known authentic domain by typing it into your browser.")

        if attachments:
            things_to_avoid.append("Do not open attachments on your host operating system.")
            recommendations.append("Inspect file metadata in an isolated safe viewer or offline static analyzer only.")

        if has_disguised_file:
            recommendations.append("File format deception was detected. Alert security administrators immediately to block the sender domain.")

        if any(att.has_vba_macros for att in attachments):
            things_to_avoid.append("If an Office document was opened, NEVER click 'Enable Macros' or 'Enable Content'.")

        if has_zip_pw_match:
            recommendations.append("Sender supplied an archive password to evade gateway security. Do not decrypt.")

    elif risk_rating == "MEDIUM":
        action = "SUSPICIOUS_VERIFY_FIRST"
        headline = "Exercise Caution — Independent Confirmation Recommended"
        recommendations.append("Verify the sender through an official channel (phone/Slack) before responding or clicking.")
        recommendations.append("Inspect any attached file using an appropriate safe plain-text viewer or isolated sandbox.")
        recommendations.append("Compare visible sender address with your organization's known contacts.")
        things_to_avoid.append("Avoid clicking links until the sender's identity has been confirmed.")

    else:
        action = "SAFE_TO_PROCEED"
        headline = "Low Risk Profile — Standard Hygiene Applies"
        recommendations.append("The email passed static safety checks. Always maintain general cybersecurity awareness.")
        recommendations.append("Standard safe document viewing is appropriate.")
        things_to_avoid = [
            "Never share passwords over email regardless of sender legitimacy."
        ]

    return SafeGuidance(
        action=action,
        headline=headline,
        verification_steps=verification_steps,
        recommendations=recommendations,
        things_to_avoid=things_to_avoid,
        quarantine_recommended=quarantine_recommended,
        sender_verification_required=sender_verification_required,
        safe_viewer_recommended=safe_viewer_recommended
    )
