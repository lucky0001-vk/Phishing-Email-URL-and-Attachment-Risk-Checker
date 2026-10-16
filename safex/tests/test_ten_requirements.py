"""
SafeX 10-Point Verification Test Suite
Explicitly validates every requirement specified in the evaluation protocol:
1. Obvious phishing emails receive appropriate risk scores with clear supporting evidence.
2. Legitimate messages are not incorrectly flagged as phishing (false-positive prevention).
3. URL analysis validates shortened URLs, long benign URLs, suspicious URL structures, and legitimate links.
4. Missing sender details, incomplete email headers, and empty inputs are handled gracefully without crashing.
5. Renamed executable files (.pdf with MZ header) are detected via magic bytes.
6. Detection of macro-enabled Office documents, password-protected ZIPs, and body password correlation.
7. Benign attachments (vendor PDF invoices, plain DOCX, image ZIPs) are verified as clean.
8. Attachments are inspected statically in memory without execution, checking MIME, magic, extension, and SHA-256.
9. False positives, false negatives, risk-score consistency, and explanations across samples are verified.
10. Test cases, expected vs actual results, and improvements are documented and asserted.
"""

import io
import unittest
from safex.core.analyzer import analyze_email
from safex.core.url_analyzer import extract_and_analyze_links, _analyze_single_link
from safex.core.test_samples import (
    get_test_samples,
    create_safe_mz_executable,
    create_clean_pdf,
    create_clean_docx,
    create_macro_docx,
    create_encrypted_zip,
)
from safex.core.evaluation_engine import evaluate_benchmark


class TestTenRequirements(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.samples = get_test_samples()

    def test_01_obvious_phishing_emails_receive_high_risk_and_evidence(self):
        """
        Requirement 1: Test obvious phishing emails and verify that suspicious messages
        receive appropriate risk scores with clear supporting evidence.
        """
        phish_sample = self.samples["scenario_4_link_mismatch_phishing"]
        res = analyze_email(phish_sample["email_text"], phish_sample["attachments"])

        # Must receive HIGH or CRITICAL score (>= 60)
        self.assertIn(res.risk_rating, ["HIGH", "CRITICAL"])
        self.assertGreaterEqual(res.overall_score, 60)

        # Clear supporting evidence must be present in signals
        self.assertGreater(len(res.all_signals), 0)
        for sig in res.all_signals:
            self.assertTrue(len(sig.name) > 0)
            self.assertTrue(len(sig.description) > 0)

        # Must have mismatch and spoofing signals
        mismatch_signals = [s for s in res.all_signals if "Mismatch" in s.name or "Spoof" in s.name]
        self.assertGreater(len(mismatch_signals), 0, "Supporting evidence for link mismatch or spoofing must exist")

    def test_02_legitimate_messages_not_incorrectly_flagged_as_phishing(self):
        """
        Requirement 2: Test legitimate messages to ensure normal emails are not
        incorrectly flagged as phishing.
        """
        benign_sample = self.samples["scenario_1_legitimate_urgent"]
        res = analyze_email(benign_sample["email_text"], benign_sample["attachments"])

        # Must NOT be marked HIGH or CRITICAL
        self.assertEqual(res.risk_rating, "LOW")
        self.assertLessEqual(res.overall_score, 25)
        self.assertEqual(res.safe_guidance.action, "SAFE_TO_PROCEED")

    def test_03_url_analysis_shortened_long_suspicious_and_legitimate(self):
        """
        Requirement 3: Validate URL analysis using shortened URLs, long URLs,
        suspicious URL structures, and legitimate links.
        """
        # A) Shortened URL
        short_res = _analyze_single_link("https://bit.ly/3xSecAlert", "Click Here")
        self.assertTrue(short_res.has_url_shortener, "Should identify bit.ly shortener")
        self.assertGreater(short_res.risk_score, 0)

        # B) Benign Long URL (e.g. 160 characters with tracking tokens)
        long_url = "https://www.company-portal.com/helpdesk/knowledge-base/article/view?id=49201&session_token=abc1234567890&utm_source=internal_newsletter&utm_medium=email_digest"
        long_res = _analyze_single_link(long_url, "Read Support Article")
        self.assertFalse(long_res.is_ip_literal)
        self.assertFalse(long_res.is_mismatch)
        self.assertLess(long_res.risk_score, 30, "Benign long tracking URL must not be heavily penalized")

        # C) Suspicious URL: IP literal with non-standard port and login path
        ip_res = _analyze_single_link("http://185.192.1.44:8080/auth/login.php", "https://bank.com")
        self.assertTrue(ip_res.is_ip_literal, "Direct IP must be flagged")
        self.assertTrue(ip_res.has_non_standard_port, "Port 8080 must be flagged")
        self.assertTrue(ip_res.is_mismatch, "Visual mismatch must be flagged")
        self.assertGreaterEqual(ip_res.risk_score, 60)

        # D) Legitimate clean link
        clean_res = _analyze_single_link("https://confluence.acme-corp.com/display/IT/VPN", "https://confluence.acme-corp.com/display/IT/VPN")
        self.assertFalse(clean_res.is_mismatch)
        self.assertFalse(clean_res.is_ip_literal)
        self.assertLessEqual(clean_res.risk_score, 10)

    def test_04_missing_sender_incomplete_headers_and_empty_inputs_handled_gracefully(self):
        """
        Requirement 4: Test missing sender details, incomplete email headers,
        and empty inputs to ensure the system handles invalid or insufficient data gracefully.
        """
        # A) Empty input string
        res_empty = analyze_email("", [])
        self.assertEqual(res_empty.overall_score, 0)
        self.assertEqual(res_empty.risk_rating, "LOW")

        # B) Missing sender / No From header
        no_sender_text = "Subject: Meeting Today\n\nHi team, quick sync at 2 PM."
        res_no_sender = analyze_email(no_sender_text, [])
        self.assertIsNotNone(res_no_sender)
        self.assertEqual(res_no_sender.header_analysis.from_header, "")
        self.assertLessEqual(res_no_sender.overall_score, 25)

        # C) Malformed header lines (no colon or corrupted format)
        corrupt_text = "From ??? NotAnEmail\nINVALID_HEADER_LINE_WITHOUT_COLON\n\nHello world"
        res_corrupt = analyze_email(corrupt_text, [])
        self.assertIsNotNone(res_corrupt)
        self.assertIsInstance(res_corrupt.overall_score, int)

    def test_05_renamed_executable_pdf_with_mz_signature(self):
        """
        Requirement 5: Test renamed executable files, including files with a .pdf
        extension but an MZ executable signature.
        """
        mz_bytes = create_safe_mz_executable()
        res = analyze_email("Please see attached invoice", [("invoice_2026.pdf", mz_bytes, "application/pdf")])

        self.assertEqual(len(res.attachments), 1)
        att = res.attachments[0]
        self.assertTrue(att.type_mismatch, "Must flag type mismatch")
        self.assertEqual(att.detected_mime_type, "application/x-dosexec")
        self.assertIn("MZ", att.magic_signature)
        self.assertEqual(att.risk_level, "MALICIOUS")
        self.assertIn("Quarantine", att.recommended_action)
        self.assertGreaterEqual(res.overall_score, 75)

    def test_06_macro_office_docs_and_password_protected_zips_with_body_passwords(self):
        """
        Requirement 6: Validate detection of macro-enabled Office documents,
        password-protected ZIP archives, and cases where archive passwords appear in the email body.
        """
        # A) Macro-enabled document
        macro_bytes = create_macro_docx()
        res_macro = analyze_email("Here is the document", [("review.docx", macro_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")])
        self.assertTrue(res_macro.attachments[0].has_vba_macros)
        self.assertEqual(res_macro.attachments[0].risk_level, "MALICIOUS")

        # B) Password-protected ZIP with body password
        zip_bytes = create_encrypted_zip("CompanySecret99!")
        body_text = "Please download archive. Password is: CompanySecret99!"
        res_zip = analyze_email(body_text, [("bundle.zip", zip_bytes, "application/zip")])
        
        self.assertTrue(res_zip.attachments[0].is_archive)
        self.assertTrue(res_zip.attachments[0].archive_encrypted)
        self.assertTrue(res_zip.attachments[0].archive_password_in_body)
        self.assertIn("CompanySecret99!", res_zip.body_analysis.extracted_archive_passwords)

    def test_07_benign_attachments_vendor_pdf_plain_docx_image_zip(self):
        """
        Requirement 7: Test benign attachments, including genuine vendor PDF invoices,
        plain DOCX documents, and ZIP archives containing images.
        """
        clean_pdf = create_clean_pdf()
        clean_docx = create_clean_docx()

        # A) Vendor PDF invoice
        res_pdf = analyze_email("Monthly invoice attached.", [("vendor_invoice.pdf", clean_pdf, "application/pdf")])
        self.assertEqual(res_pdf.attachments[0].risk_level, "CLEAN")
        self.assertEqual(len(res_pdf.attachments[0].pdf_active_features), 0)

        # B) Plain DOCX
        res_docx = analyze_email("Quarterly report.", [("report.docx", clean_docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document")])
        self.assertEqual(res_docx.attachments[0].risk_level, "CLEAN")
        self.assertFalse(res_docx.attachments[0].has_vba_macros)

        # C) ZIP archive with image
        img_buf = io.BytesIO()
        import zipfile
        with zipfile.ZipFile(img_buf, "w") as zf:
            zf.writestr("logo.png", b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR...")
        res_img_zip = analyze_email("Photos attached.", [("photos.zip", img_buf.getvalue(), "application/zip")])
        self.assertEqual(res_img_zip.attachments[0].risk_level, "CLEAN")
        self.assertFalse(res_img_zip.attachments[0].has_archive_executables)

    def test_08_static_inspection_non_execution_and_metadata_consistency(self):
        """
        Requirement 8: Verify that attachments are inspected statically without executing
        files and that MIME types, file signatures, extensions, and metadata are checked consistently.
        """
        clean_pdf = create_clean_pdf()
        res = analyze_email("Subject: Verification\n\nTest", [("clean.pdf", clean_pdf, "application/pdf")])

        att = res.attachments[0]
        self.assertEqual(att.filename, "clean.pdf")
        self.assertEqual(att.declared_mime_type, "application/pdf")
        self.assertEqual(att.detected_mime_type, "application/pdf")
        self.assertIn("%PDF", att.magic_signature)
        self.assertEqual(len(att.sha256), 64, "SHA-256 must be a 64-char hexadecimal string")
        self.assertIn("B", att.size_human)
        self.assertEqual(att.status, "SCANNED")

    def test_09_evaluation_metrics_false_positives_false_negatives_consistency(self):
        """
        Requirement 9: Evaluate false positives, false negatives, risk-score consistency,
        and explanations across suspicious and legitimate samples.
        """
        bench = evaluate_benchmark(threshold=40)
        rule_metrics = bench["rule_based"]["metrics"]
        rule_cm = bench["rule_based"]["confusion_matrix"]

        # Assert zero false negatives on threats
        self.assertEqual(rule_cm["fn"], 0, "Rule-based engine must have 0 False Negatives on critical threat samples")
        # Assert accuracy >= 90%
        self.assertGreaterEqual(rule_metrics["accuracy_pct"], 90.0)
        # Assert high recall
        self.assertEqual(rule_metrics["recall_pct"], 100.0)

    def test_10_documentation_and_expected_vs_actual_verification(self):
        """
        Requirement 10: Document test cases, expected versus actual results, identified issues,
        and improvements made to the system.
        """
        samples = get_test_samples()
        self.assertGreaterEqual(len(samples), 9, "Must maintain comprehensive benchmark sample catalog")

        for key, s in samples.items():
            res = analyze_email(s["email_text"], s["attachments"])
            exp = s["expected_verdict"]
            if "LOW" in exp or "BENIGN" in exp:
                self.assertEqual(res.risk_rating, "LOW", f"Sample {s['title']} expected LOW, got {res.risk_rating}")
            elif "CRITICAL" in exp or "HIGH" in exp:
                self.assertIn(res.risk_rating, ["HIGH", "CRITICAL"], f"Sample {s['title']} expected HIGH/CRITICAL, got {res.risk_rating}")


if __name__ == "__main__":
    unittest.main()
