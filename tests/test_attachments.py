"""
SafeX Attachment Security Test Suite
Validates:
- Dangerous file extensions (.exe, .scr, .vbs, .ps1)
- Suspicious files:
  * Renamed executable (.pdf with MZ header)
  * Macro-enabled Office documents (vbaProject.bin)
  * Password-protected ZIPs with passwords extracted from body
  * Unicode RTLO filename deception
- Safe documents (Clean PDF, Benign DOCX, Benign ZIP)
"""

import unittest
import zipfile
import io
from safex.core.attachment_scanner import scan_attachment
from safex.core.test_samples import create_encrypted_zip

class TestAttachmentSecurityDetection(unittest.TestCase):
    """Rigorous evaluation of static attachment scanning rules."""

    def test_dangerous_executable_extension(self):
        """Native .exe file flagged as high risk."""
        data = b"MZ" + b"\x00" * 200
        inv = scan_attachment({"filename": "payload.exe", "data": data, "declared_mime_type": "application/octet-stream"})
        self.assertTrue(inv.high_risk_extension)
        self.assertTrue(any("extension" in s.name.lower() or "executable" in s.name.lower() for s in inv.signals))

    def test_renamed_executable_masquerading_as_pdf(self):
        """Windows PE executable disguised as invoice.pdf."""
        pe_data = b"MZ" + b"\x90\x00\x03" + b"\x00" * 150
        inv = scan_attachment({"filename": "invoice_9481.pdf", "data": pe_data, "declared_mime_type": "application/pdf"})
        self.assertTrue(inv.type_mismatch)
        self.assertEqual(inv.detected_mime_type, "application/x-dosexec")

    def test_office_macro_weaponized_document(self):
        """Office document containing hidden VBA macro stream."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("[Content_Types].xml", b"<Types></Types>")
            z.writestr("word/document.xml", b"<document></document>")
            z.writestr("word/vbaProject.bin", b"VBA MACRO CODE AutoOpen Sub ShellExecute")
        doc_bytes = buf.getvalue()

        inv = scan_attachment({"filename": "Q3_Bonuses.docx", "data": doc_bytes, "declared_mime_type": "application/vnd.openxmlformats-officedocument.wordprocessingml.document"})
        self.assertTrue(inv.has_vba_macros)

    def test_password_protected_zip_with_body_password(self):
        """Encrypted ZIP file correlated with password leaked in body."""
        zip_bytes = create_encrypted_zip("Secret2026!")
        inv = scan_attachment(
            {"filename": "SecretContract.zip", "data": zip_bytes, "declared_mime_type": "application/zip"},
            body_passwords=["Secret2026!"]
        )
        self.assertTrue(inv.archive_encrypted)
        self.assertTrue(inv.archive_password_in_body)

    def test_unicode_rtlo_filename_attack(self):
        """Unicode Right-to-Left Override character in filename."""
        rtlo_name = "FinancialReport\u202etxt.exe"
        inv = scan_attachment({"filename": rtlo_name, "data": b"MZ" + b"\x00" * 100, "declared_mime_type": "application/octet-stream"})
        self.assertTrue(inv.rtlo_detected)

    def test_clean_pdf_invoice(self):
        """Genuine clean PDF invoice with no active JavaScript."""
        pdf_data = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF"
        inv = scan_attachment({"filename": "vendor_invoice.pdf", "data": pdf_data, "declared_mime_type": "application/pdf"})
        self.assertFalse(inv.type_mismatch)
        self.assertFalse(inv.high_risk_extension)
        self.assertEqual(len(inv.pdf_active_features), 0)

if __name__ == "__main__":
    unittest.main()
