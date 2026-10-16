"""
SafeX Unified Analyzer Engine
Coordinates the complete static analysis pipeline across headers, body, URLs, and attachments.
"""

from typing import List, Tuple, Optional
from safex.core.models import EmailAnalysisResult
from safex.core.email_parser import parse_email_input
from safex.core.header_analyzer import analyze_headers
from safex.core.body_analyzer import analyze_body
from safex.core.attachment_scanner import scan_attachment
from safex.core.risk_engine import evaluate_email_risk


def analyze_email(
    raw_content: bytes | str,
    external_attachments: Optional[List[Tuple[str, bytes, str]]] = None
) -> EmailAnalysisResult:
    """
    Main entry point for SafeX static analysis.
    Takes raw email bytes (.eml) or text, plus optional standalone attachments.
    Returns comprehensive EmailAnalysisResult.
    """
    # 1. Parse email safely
    parsed = parse_email_input(raw_content, external_attachments)

    # 2. Analyze headers
    header_res = analyze_headers(parsed.headers, parsed.raw_headers)

    # 3. Analyze body & embedded URLs
    body_res = analyze_body(parsed.plain_text_body, parsed.html_body)

    # 4. Scan attachments statically in-memory
    attachments_res = []
    for idx, att in enumerate(parsed.attachments, start=1):
        att_inventory = scan_attachment(
            att,
            body_passwords=body_res.extracted_archive_passwords,
            attachment_index=idx
        )
        attachments_res.append(att_inventory)

    # 5. Compute risk score and guidance
    result = evaluate_email_risk(header_res, body_res, attachments_res)
    return result
