"""
SafeX Email Parser
Parses .eml RFC822 messages or pasted text into headers, body representations,
and static attachment payload buffers safely in-memory without disk execution.
"""

import email
import email.policy
from email.message import EmailMessage
from typing import Tuple, List, Dict, Any, Optional
import io
import re

MAX_ATTACHMENTS_PER_EMAIL = 10
MAX_ATTACHMENT_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB


class ParsedEmail:
    def __init__(self):
        self.headers: Dict[str, str] = {}
        self.raw_headers: List[Tuple[str, str]] = []
        self.plain_text_body: str = ""
        self.html_body: str = ""
        self.attachments: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.is_rfc822: bool = False


def parse_email_input(
    raw_content: bytes | str,
    external_attachments: Optional[List[Tuple[str, bytes, str]]] = None
) -> ParsedEmail:
    """
    Parse an email from either raw bytes (.eml) or text, extracting headers,
    body parts, and in-memory attachment binaries.
    
    `external_attachments` is a list of tuples: (filename, data_bytes, declared_mime_type)
    for attachments provided directly outside of an .eml envelope.
    """
    parsed = ParsedEmail()

    if isinstance(raw_content, str):
        content_bytes = raw_content.encode("utf-8", errors="replace")
        content_str = raw_content
    else:
        content_bytes = raw_content
        content_str = raw_content.decode("utf-8", errors="replace")

    # Try parsing as standard RFC822 MIME message
    try:
        msg = email.message_from_bytes(content_bytes, policy=email.policy.default)
        # Check if it has standard email headers
        has_headers = any(msg.get(h) for h in ["From", "Subject", "To", "Date", "Received"])
        if has_headers:
            parsed.is_rfc822 = True
            for k, v in msg.items():
                parsed.raw_headers.append((k, str(v)))
                # store normalized lowercase header
                k_lower = k.lower()
                if k_lower not in parsed.headers:
                    parsed.headers[k_lower] = str(v)
                else:
                    parsed.headers[k_lower] += f"\n{str(v)}"

            # Extract body parts and attachments
            attachment_count = 0
            for part in msg.walk():
                content_disposition = part.get_content_disposition()
                content_type = part.get_content_type()
                filename = part.get_filename()

                # Check if it's an attachment
                is_attachment = False
                if content_disposition in ["attachment", "inline"] and filename:
                    is_attachment = True
                elif filename:
                    is_attachment = True
                elif content_type not in ["text/plain", "text/html", "multipart/alternative", "multipart/mixed", "multipart/related"]:
                    # Could be binary part without explicit filename
                    filename = filename or f"unnamed_part_{attachment_count + 1}"
                    is_attachment = True

                if is_attachment:
                    attachment_count += 1
                    if attachment_count > MAX_ATTACHMENTS_PER_EMAIL:
                        parsed.warnings.append(
                            f"Attachment count limit reached ({MAX_ATTACHMENTS_PER_EMAIL}). Extra attachments marked UNSCANNED."
                        )
                        break

                    payload = part.get_payload(decode=True) or b""
                    size = len(payload)
                    declared_type = content_type or "application/octet-stream"

                    parsed.attachments.append({
                        "filename": filename or f"attachment_{attachment_count}",
                        "data": payload,
                        "declared_mime_type": declared_type,
                        "size": size,
                        "exceeded_size_limit": size > MAX_ATTACHMENT_SIZE_BYTES
                    })
                else:
                    # Regular body part
                    if content_type == "text/plain":
                        try:
                            charset = part.get_content_charset() or "utf-8"
                            body_payload = part.get_payload(decode=True)
                            if body_payload:
                                parsed.plain_text_body += body_payload.decode(charset, errors="replace") + "\n"
                        except Exception:
                            parsed.plain_text_body += str(part.get_payload()) + "\n"

                    elif content_type == "text/html":
                        try:
                            charset = part.get_content_charset() or "utf-8"
                            html_payload = part.get_payload(decode=True)
                            if html_payload:
                                parsed.html_body += html_payload.decode(charset, errors="replace") + "\n"
                        except Exception:
                            parsed.html_body += str(part.get_payload()) + "\n"

    except Exception as e:
        parsed.warnings.append(f"Standard MIME parsing encountered an issue: {str(e)}. Falling back to plain text analysis.")

    # Fallback / Text analysis if headers weren't found or parsed as plain text
    if not parsed.is_rfc822 or (not parsed.plain_text_body and not parsed.html_body):
        _extract_pasted_headers_and_body(content_str, parsed)

    # Attach any external attachments supplied (e.g. from multi-file upload)
    if external_attachments:
        for ext_fn, ext_data, ext_mime in external_attachments:
            if len(parsed.attachments) >= MAX_ATTACHMENTS_PER_EMAIL:
                parsed.warnings.append(f"Max attachment limit ({MAX_ATTACHMENTS_PER_EMAIL}) reached.")
                break
            size = len(ext_data)
            parsed.attachments.append({
                "filename": ext_fn,
                "data": ext_data,
                "declared_mime_type": ext_mime or "application/octet-stream",
                "size": size,
                "exceeded_size_limit": size > MAX_ATTACHMENT_SIZE_BYTES
            })

    return parsed


def _extract_pasted_headers_and_body(text: str, parsed: ParsedEmail):
    """
    Extract common header lines from pasted text (e.g. From:, Subject:, To:, Date:),
    and treat the rest as plain text body.
    """
    lines = text.splitlines()
    body_lines = []
    in_headers = True

    header_keys = [
        "from", "to", "subject", "date", "reply-to", "return-path",
        "received", "authentication-results", "dkim-signature", "x-mailer", "message-id"
    ]

    for line in lines:
        if in_headers:
            match = re.match(r"^([A-Za-z0-9\-]+):\s*(.*)$", line)
            if match:
                k = match.group(1).lower()
                v = match.group(2).strip()
                parsed.headers[k] = v
                parsed.raw_headers.append((match.group(1), v))
                continue
            elif line.strip() == "":
                # First empty line after header block signals transition to body
                in_headers = False
                continue
            else:
                # If non-header line encountered early, maybe entire text is body
                in_headers = False
                body_lines.append(line)
        else:
            body_lines.append(line)

    body_text = "\n".join(body_lines).strip()
    if not parsed.plain_text_body:
        parsed.plain_text_body = body_text if body_text else text.strip()
