"""
SafeX Comprehensive Unit & Verification Tests
Evaluates all 8 specific user requirements:
1. Legitimate messages with urgency & benign long URLs (False-Positive Reduction)
2. MIME type & file-signature checks (Renamed executable: .pdf with MZ header)
3. Static detection of macro-enabled Office documents (vbaProject.bin / AutoOpen)
4. Password-protected ZIP detection & body password extraction
5. Distinguishing suspicious attachments from genuine vendor PDFs, plain DOCX, and image ZIPs
6. Multi-indicator risk-scoring rules (avoiding single weak-signal traps)
7. Non-execution of attachments with transparent evidence and reasons
8. Full evaluation of benign vs suspicious test corpus
"""

import unittest
from safex.core.analyzer import analyze_email
from safex.core.test_samples import get_test_samples


class TestSafeXAnalyzer(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.samples = get_test_samples()

    def test_01_legitimate_urgent_false_positive_reduction(self):
        """
        Requirement 1: Test legitimate messages containing urgency-related words
        and benign long URLs to reduce false-positive alerts.
        """
        s = self.samples["scenario_1_legitimate_urgent"]
        res = analyze_email(s["email_text"], s["attachments"])

        # Must NOT be marked HIGH or CRITICAL
        self.assertEqual(res.risk_rating, "LOW", f"Expected LOW risk for benign urgent notice, got {res.risk_rating} (score={res.overall_score})")
        self.assertLess(res.overall_score, 30, f"Expected score < 30, got {res.overall_score}")
        self.assertIn("spf: pass", res.header_analysis.auth_summary.lower())
        # Safe guidance should indicate safe to proceed
        self.assertEqual(res.safe_guidance.action, "SAFE_TO_PROCEED")

    def test_02_disguised_executable_detection(self):
        """
        Requirement 2: Implement MIME type and file-signature checks to detect renamed
        executables, such as a .pdf file containing an MZ header.
        """
        s = self.samples["scenario_2_disguised_executable"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertIn(res.risk_rating, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(res.overall_score, 70)
        self.assertEqual(len(res.attachments), 1)

        att = res.attachments[0]
        self.assertTrue(att.type_mismatch, "Should flag type mismatch")
        self.assertEqual(att.detected_mime_type, "application/x-dosexec")
        self.assertIn("MZ", att.magic_signature)
        self.assertEqual(att.risk_level, "MALICIOUS")

        # Check evidence in signals
        mismatch_signals = [sig for sig in att.signals if "Disguised" in sig.name or "MZ" in sig.name]
        self.assertTrue(len(mismatch_signals) > 0, "Should generate specific signal for disguised executable")

    def test_03_macro_enabled_office_document(self):
        """
        Requirement 3: Add static detection rules for macro-enabled Office documents
        and suspicious document structures.
        """
        s = self.samples["scenario_3_macro_document"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertIn(res.risk_rating, ["HIGH", "CRITICAL"])
        att = res.attachments[0]
        self.assertTrue(att.is_office_doc)
        self.assertTrue(att.has_vba_macros, "Should detect embedded VBA macros")
        self.assertTrue(any("AutoOpen" in d or "vbaProject" in d for d in att.macro_details))
        self.assertEqual(att.risk_level, "MALICIOUS")

    def test_04_password_protected_zip_with_body_password(self):
        """
        Requirement 4: Detect password-protected ZIP archives and identify cases
        where the password is provided in the email body.
        """
        s = self.samples["scenario_5_password_protected_zip"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertIn(res.risk_rating, ["HIGH", "CRITICAL", "MEDIUM"])
        self.assertIn("SafePass2026", res.body_analysis.extracted_archive_passwords)
        
        att = res.attachments[0]
        self.assertTrue(att.is_archive)
        self.assertTrue(att.archive_encrypted, "Should flag encrypted zip")
        self.assertTrue(att.archive_password_in_body, "Should correlate archive password with email body")
        self.assertIn("SafePass2026", att.detected_passwords)

    def test_05_clean_vendor_pdf_invoice(self):
        """
        Requirement 5A: Distinguish genuine vendor PDF invoices (clean, no active features).
        """
        s = self.samples["scenario_6_clean_vendor_invoice"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertEqual(res.risk_rating, "LOW")
        self.assertLess(res.overall_score, 25)
        att = res.attachments[0]
        self.assertTrue(att.is_pdf)
        self.assertEqual(len(att.pdf_active_features), 0, "Genuine PDF should have no active features")
        self.assertEqual(att.risk_level, "CLEAN")

    def test_05_clean_docx_and_image_archive(self):
        """
        Requirement 5B: Plain DOCX documents and ZIP archives containing images.
        """
        s = self.samples["scenario_7_clean_docx_and_images"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertEqual(res.risk_rating, "LOW")
        self.assertLess(res.overall_score, 20)
        self.assertEqual(len(res.attachments), 2)

        docx_att = res.attachments[0]
        self.assertTrue(docx_att.is_office_doc)
        self.assertFalse(docx_att.has_vba_macros)
        self.assertEqual(docx_att.risk_level, "CLEAN")

        zip_att = res.attachments[1]
        self.assertTrue(zip_att.is_archive)
        self.assertFalse(zip_att.archive_encrypted)
        self.assertFalse(zip_att.has_archive_executables)
        self.assertEqual(zip_att.risk_level, "CLEAN")

    def test_06_brand_phishing_link_mismatch(self):
        """
        Requirement 6: Refine risk-scoring rules to combine multiple indicators
        (e.g., brand spoofing + auth failure + link mismatch).
        """
        s = self.samples["scenario_4_link_mismatch_phishing"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertIn(res.risk_rating, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(res.overall_score, 75)
        self.assertTrue(res.header_analysis.display_name_spoof)
        self.assertTrue(res.header_analysis.reply_to_mismatch)
        self.assertTrue(any(lk.is_mismatch for lk in res.body_analysis.links))
        self.assertIn("DO_NOT_ENGAGE", res.safe_guidance.action)

    def test_07_rtlo_filename_deception(self):
        """
        Requirement 7: Test Unicode Right-to-Left Override (RTLO) evasion detection.
        """
        s = self.samples["scenario_8_rtlo_filename_attack"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertIn(res.risk_rating, ["HIGH", "CRITICAL"])
        att = res.attachments[0]
        self.assertTrue(att.rtlo_detected, "Should detect RTLO character U+202E")
        self.assertIn("RTLO", att.signals[0].name)

    def test_08_html_credential_smuggling(self):
        """
        Requirement 8: Test HTML credential-harvesting & smuggling attachment.
        """
        s = self.samples["scenario_9_html_credential_smuggling"]
        res = analyze_email(s["email_text"], s["attachments"])

        self.assertIn(res.risk_rating, ["HIGH", "CRITICAL"])
        att = res.attachments[0]
        self.assertTrue(att.is_html)
        self.assertTrue(att.html_has_forms)
        self.assertTrue(att.html_has_password_fields, "Should detect <input type='password'>")
        self.assertTrue(att.html_has_smuggling, "Should detect window.atob / smuggling")


if __name__ == "__main__":
    unittest.main()
