"""
SafeX Core Data Models
Pydantic schemas for email header, body, URL, and attachment static analysis.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class DetectionSignal(BaseModel):
    category: str = Field(..., description="Category: 'header', 'url', 'body', or 'attachment'")
    name: str = Field(..., description="Short identifier/title of the detection rule")
    severity: str = Field(..., description="Severity level: 'info', 'low', 'medium', 'high', 'critical'")
    score_impact: int = Field(..., description="Numeric score contribution (0-100 scale)")
    description: str = Field(..., description="Human-understandable explanation of the risk indicator")
    evidence: Optional[str] = Field(None, description="Concrete evidence extracted from email or attachment")


class LinkAnalysis(BaseModel):
    url: str
    anchor_text: str = ""
    href_domain: str = ""
    display_domain: Optional[str] = None
    is_mismatch: bool = False
    is_ip_literal: bool = False
    is_lookalike: bool = False
    lookalike_target: Optional[str] = None
    is_punycode: bool = False
    has_at_trick: bool = False
    has_suspicious_tld: bool = False
    has_credential_path: bool = False
    has_cyrillic_homoglyphs: bool = False
    has_non_standard_port: bool = False
    has_excessive_subdomains: bool = False
    has_open_redirect: bool = False
    has_url_shortener: bool = False
    has_brand_in_path: bool = False
    risk_score: int = 0
    risk_level: str = "LOW"
    risk_tags: List[str] = Field(default_factory=list)
    score_impact: int = 0
    signals: List[DetectionSignal] = Field(default_factory=list)


class HeaderAnalysis(BaseModel):
    from_header: str = ""
    from_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: Optional[str] = None
    reply_to_address: Optional[str] = None
    reply_to_domain: Optional[str] = None
    return_path: Optional[str] = None
    return_path_address: Optional[str] = None
    return_path_domain: Optional[str] = None
    subject: str = ""
    date: Optional[str] = None
    message_id: Optional[str] = None
    spf_status: Optional[str] = None  # 'pass', 'fail', 'softfail', 'none', 'neutral', 'temperror', 'not_found'
    dkim_status: Optional[str] = None  # 'pass', 'fail', 'none', 'not_found'
    dmarc_status: Optional[str] = None  # 'pass', 'fail', 'none', 'not_found'
    auth_summary: str = "No authentication headers recorded."
    display_name_spoof: bool = False
    reply_to_mismatch: bool = False
    return_path_mismatch: bool = False
    score: int = 0
    signals: List[DetectionSignal] = Field(default_factory=list)


class ArchiveEntry(BaseModel):
    name: str
    size: int
    is_dir: bool = False
    is_encrypted: bool = False
    is_high_risk: bool = False
    risk_reason: Optional[str] = None


class AttachmentInventory(BaseModel):
    attachment_id: str
    filename: str
    declared_mime_type: str = "application/octet-stream"
    detected_mime_type: str = "unknown"
    magic_signature: str = "None"
    size_bytes: int = 0
    size_human: str = "0 B"
    sha256: str = ""
    status: str = "SCANNED"  # 'SCANNED', 'UNSCANNED', 'UNKNOWN'
    status_reason: Optional[str] = None

    # Extension & naming indicators
    high_risk_extension: bool = False
    double_extension: bool = False
    rtlo_detected: bool = False
    type_mismatch: bool = False

    # Archive checks
    is_archive: bool = False
    archive_encrypted: bool = False
    archive_password_in_body: bool = False
    detected_passwords: List[str] = Field(default_factory=list)
    archive_contents: List[ArchiveEntry] = Field(default_factory=list)
    archive_nesting_depth: int = 0
    has_archive_executables: bool = False

    # Office macro checks
    is_office_doc: bool = False
    has_vba_macros: bool = False
    macro_details: List[str] = Field(default_factory=list)

    # PDF active code checks
    is_pdf: bool = False
    pdf_active_features: List[str] = Field(default_factory=list)

    # HTML / HTM checks
    is_html: bool = False
    html_has_forms: bool = False
    html_has_password_fields: bool = False
    html_has_scripts: bool = False
    html_has_smuggling: bool = False

    # Local hash check
    known_hash_match: bool = False

    # Classification & explanation
    risk_level: str = "CLEAN"  # 'CLEAN', 'LOW', 'SUSPICIOUS', 'MALICIOUS', 'UNKNOWN'
    score: int = 0
    signals: List[DetectionSignal] = Field(default_factory=list)


class BodyAnalysis(BaseModel):
    urgency_phrases_detected: List[str] = Field(default_factory=list)
    financial_phrases_detected: List[str] = Field(default_factory=list)
    call_to_actions: List[str] = Field(default_factory=list)
    extracted_archive_passwords: List[str] = Field(default_factory=list)
    credential_keywords_detected: List[str] = Field(default_factory=list)
    has_vishing_phone: bool = False
    detected_phones: List[str] = Field(default_factory=list)
    has_hidden_text: bool = False
    has_quishing_indicators: bool = False
    links: List[LinkAnalysis] = Field(default_factory=list)
    text_preview: str = ""
    is_html: bool = False
    score: int = 0
    signals: List[DetectionSignal] = Field(default_factory=list)


class SafeGuidance(BaseModel):
    action: str  # 'SAFE_TO_PROCEED', 'PROCEED_WITH_CAUTION', 'SUSPICIOUS_VERIFY_FIRST', 'CRITICAL_THREAT_DO_NOT_ENGAGE'
    headline: str
    verification_steps: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    things_to_avoid: List[str] = Field(default_factory=list)


class EmailAnalysisResult(BaseModel):
    analysis_timestamp: str
    overall_score: int  # 0 to 100
    risk_rating: str  # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    verdict: str
    summary: str
    score_breakdown: Dict[str, int] = Field(
        default_factory=lambda: {
            "header_score": 0,
            "body_url_score": 0,
            "attachment_score": 0,
            "overall_score": 0,
        }
    )
    header_analysis: HeaderAnalysis
    body_analysis: BodyAnalysis
    attachments: List[AttachmentInventory] = Field(default_factory=list)
    all_signals: List[DetectionSignal] = Field(default_factory=list)
    safe_guidance: SafeGuidance
    disclaimer: str = (
        "SafeX is an automated static decision-support tool designed for threat triage. "
        "It provides transparent heuristic warning signs and verification recommendations, "
        "not a legal or technical guarantee that content is safe or malicious."
    )
