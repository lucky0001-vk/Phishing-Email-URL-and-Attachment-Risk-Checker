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

    def test_09_four_component_risk_breakdown(self):
        """
        Requirement 1: 4-part risk breakdown (Sender, Body, URLs, Attachments).
        """
        s = self.samples["scenario_2_disguised_executable"]
        res = analyze_email(s["email_text"], s["attachments"])
        b = res.score_breakdown

        self.assertIn("sender_score", b)
        self.assertIn("body_score", b)
        self.assertIn("url_score", b)
        self.assertIn("attachment_score", b)
        self.assertIn("overall_score", b)
        self.assertGreaterEqual(b["attachment_score"], 40, "Disguised executable should heavily drive attachment score")

    def test_10_per_attachment_report_card_and_recommendations(self):
        """
        Requirements 2 & 3: Per-attachment report card and actionable recommendations.
        """
        s = self.samples["scenario_2_disguised_executable"]
        res = analyze_email(s["email_text"], s["attachments"])
        att = res.attachments[0]

        # Per-attachment report card
        self.assertTrue(len(att.suspicious_features) > 0, "Should generate list of suspicious features")
        self.assertEqual(att.recommended_action, "QUARANTINE_PAYLOAD")
        self.assertIn("quarantine", att.recommended_action_detail.lower())

        # Actionable recommendations
        self.assertTrue(len(res.safe_guidance.action_cards) >= 2)
        action_types = [c.action_type for c in res.safe_guidance.action_cards]
        self.assertIn("QUARANTINE", action_types)
        self.assertIn("VERIFY_SENDER", action_types)

    def test_11_user_feedback_feature(self):
        """
        Requirement 4: User feedback feature to record false positives and false negatives.
        """
        from safex.core.feedback_store import record_feedback, get_feedback_stats

        rec_fp = record_feedback({
            "sample_id": "test-benign-sample",
            "sample_name": "Test Benign Email",
            "user_verdict": "FALSE_POSITIVE",
            "notes": "Legitimate company announcement flagged as high urgency",
            "assigned_score": 65,
            "assigned_rating": "HIGH"
        })
        self.assertEqual(rec_fp["user_verdict"], "FALSE_POSITIVE")

        rec_acc = record_feedback({
            "sample_id": "test-phish-sample",
            "sample_name": "Credential Harvester",
            "user_verdict": "ACCURATE",
            "notes": "Accurately caught fake login link",
            "assigned_score": 88,
            "assigned_rating": "CRITICAL"
        })
        self.assertEqual(rec_acc["user_verdict"], "ACCURATE")

        stats = get_feedback_stats()
        self.assertGreaterEqual(stats["total_reports"], 2)
        self.assertGreaterEqual(stats["false_positive_count"], 1)
        self.assertGreaterEqual(stats["accurate_count"], 1)

    def test_12_evaluation_benchmark_and_confusion_matrix(self):
        """
        Requirement 5: ML vs Rule-Based detection benchmark & confusion matrix.
        """
        from safex.core.evaluation_engine import evaluate_benchmark

        bench = evaluate_benchmark(threshold=40)
        self.assertIn("rule_based", bench)
        self.assertIn("ml_based", bench)

        # Rule confusion matrix check
        rb_cm = bench["rule_based"]["confusion_matrix"]
        self.assertEqual(rb_cm["tp"] + rb_cm["fn"], 10, "Should evaluate 10 threat samples")
        self.assertEqual(rb_cm["tn"] + rb_cm["fp"], 10, "Should evaluate 10 benign samples")
        self.assertGreaterEqual(bench["rule_based"]["metrics"]["f1_score"], 0.85)

        # ML confusion matrix check
        ml_cm = bench["ml_based"]["confusion_matrix"]
        self.assertEqual(ml_cm["tp"] + ml_cm["fn"], 10)
        self.assertEqual(ml_cm["tn"] + ml_cm["fp"], 10)
        self.assertGreaterEqual(bench["ml_based"]["metrics"]["f1_score"], 0.80)

    def test_13_zero_execution_guarantee(self):
        """
        Requirement 8: Ensure attachments are analysed statically without executing files.
        """
        import inspect
        from safex.core import attachment_scanner

        src = inspect.getsource(attachment_scanner)
        self.assertNotIn("os.system", src, "Attachment scanner must never invoke os.system")
        self.assertNotIn("subprocess.Popen", src, "Attachment scanner must never invoke subprocess.Popen")
        self.assertNotIn("exec(", src, "Attachment scanner must never call exec()")
        self.assertNotIn("eval(", src, "Attachment scanner must never call eval()")


if __name__ == "__main__":
    unittest.main()

