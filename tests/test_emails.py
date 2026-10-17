"""
SafeX Phishing Email Detection Test Suite
Validates:
- Obvious phishing emails (spoofed sender, urgency, credential harvesting)
- Sophisticated phishing emails (subtle brand lookalikes, optical anchor mismatches)
- Legitimate emails (benign urgency, newsletters, clean vendor notices)
"""

import unittest
from safex.core.analyzer import analyze_email

class TestPhishingEmailDetection(unittest.TestCase):
    """Rigorous evaluation of email body & header inspection rules."""

    def test_obvious_phishing_credential_harvesting(self):
        """Obvious phishing with fake security alert and IP login."""
        raw_email = """From: "IT Support" <security@account-update-alert.xyz>
Reply-To: badactor@hacker-server.ru
Return-Path: bounce@attacker-vps.net
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
Subject: URGENT: Your corporate account is suspended immediately!

Dear User,
Your Microsoft 365 password has expired. You have 15 minutes before your mailbox is permanently locked.
Click below to preserve your account:
http://192.168.1.100:8080/owa/auth/login.html
"""
        result = analyze_email(raw_email.encode("utf-8"))
        self.assertIn(result.risk_rating, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(result.overall_score, 70)
        # Verify threat category & supporting evidence
        signals = [s.name for s in result.all_signals]
        self.assertTrue(any("SPF" in s or "Authentication" in s or "DMARC" in s for s in signals))
        self.assertTrue(any("IP-literal" in s or "Numeric IP" in s or "URL" in s or "Port" in s for s in signals))
        self.assertIn("threat", result.verdict.lower())

    def test_sophisticated_brand_impersonation(self):
        """Sophisticated phishing with lookalike domain and clean grammar."""
        raw_email = """From: "DocuSign Security Team" <notices@d0cus1gn-documents.com>
Reply-To: notices@d0cus1gn-documents.com
Return-Path: notices@d0cus1gn-documents.com
Authentication-Results: spf=none; dkim=none
Subject: Please review and sign: Q3 Executive Compensation Agreement

Hello,
Please review the attached confidential document regarding your updated compensation plan.
Access your document here: https://d0cus1gn-documents.com/sign/doc-9482
"""
        result = analyze_email(raw_email.encode("utf-8"))
        self.assertGreaterEqual(result.overall_score, 20)
        signals = [s.description for s in result.all_signals]
        self.assertTrue(any("lookalike" in s.lower() or "docusign" in s.lower() or "auth" in s.lower() or "sender" in s.lower() for s in signals))

    def test_legitimate_urgent_company_email(self):
        """Legitimate message with urgency words should NOT be flagged as phishing (False-Positive test)."""
        raw_email = """From: "HR Department" <hr@company.com>
Reply-To: hr@company.com
Return-Path: hr@company.com
Authentication-Results: spf=pass; dkim=pass; dmarc=pass
Subject: URGENT: Open Enrollment deadline ends today at 5:00 PM

Dear Team,
This is a final reminder to submit your benefits choices before 5:00 PM today.
Please visit the internal portal on our company intranet to finalize your coverage.
Thank you,
Corporate Human Resources
"""
        result = analyze_email(raw_email.encode("utf-8"))
        # Must be LOW risk to prevent workflow disruption
        self.assertEqual(result.risk_rating, "LOW")
        self.assertLess(result.overall_score, 30)
        self.assertIn("low risk", result.verdict.lower())

if __name__ == "__main__":
    unittest.main()
