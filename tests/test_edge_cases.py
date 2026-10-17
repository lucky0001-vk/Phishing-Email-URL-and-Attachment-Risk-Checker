"""
SafeX Edge Case & Robustness Test Suite
Validates:
- Empty inputs (empty text, 0-byte attachments)
- Missing sender details & malformed headers
- Broken / malformed URLs
- Unsupported files & corrupted archives
"""

import unittest
from safex.core.analyzer import analyze_email
from safex.core.attachment_scanner import scan_attachment
from safex.core.url_analyzer import _analyze_single_link

class TestEdgeCasesAndRobustness(unittest.TestCase):
    """Rigorous evaluation of system fault-tolerance and input handling."""

    def test_empty_email_text(self):
        """Empty input should be handled gracefully without throwing unhandled exceptions."""
        result = analyze_email(b"")
        self.assertEqual(result.overall_score, 0)
        self.assertEqual(result.risk_rating, "LOW")
        self.assertIn("decision-support", result.disclaimer.lower())

    def test_missing_sender_details(self):
        """Email missing From, Reply-To, and Return-Path headers."""
        raw_email = """Subject: Notification without header sender
Date: Sat, 17 Oct 2026 00:00:00 +0000

Just a message body without From or Authentication headers.
"""
        result = analyze_email(raw_email.encode("utf-8"))
        self.assertIsNotNone(result.header_analysis)
        self.assertEqual(result.header_analysis.from_address, "")
        self.assertGreaterEqual(result.overall_score, 0)

    def test_malformed_broken_url(self):
        """Broken or unusual URLs should be parsed safely."""
        urls = [
            "://missing-scheme.com",
            "http://",
            "https://?query_only=1",
            "not_even_a_url",
            "http://[::ffff:192.168.1.1]/test"
        ]
        for u in urls:
            try:
                res = _analyze_single_link(u, "Click")
                self.assertIsNotNone(res.risk_score)
            except Exception as e:
                self.fail(f"URL analyzer crashed on malformed URL '{u}': {e}")

    def test_zero_byte_attachment(self):
        """0-byte attachment should be reported as UNKNOWN / empty without crashing."""
        inv = scan_attachment({"filename": "empty.pdf", "data": b"", "declared_mime_type": "application/pdf"})
        self.assertEqual(inv.size_bytes, 0)
        self.assertIn(inv.status, ["SCANNED", "UNKNOWN"])

    def test_corrupted_archive(self):
        """Corrupt ZIP archive should be caught and marked as UNKNOWN with reason."""
        corrupt_zip = b"PK\x03\x04" + b"\xff" * 40
        inv = scan_attachment({"filename": "damaged.zip", "data": corrupt_zip, "declared_mime_type": "application/zip"})
        self.assertEqual(inv.status, "UNKNOWN")
        self.assertIsNotNone(inv.status_reason)

if __name__ == "__main__":
    unittest.main()
