"""
SafeX URL Security Test Suite
Validates:
- Shortened URLs (obfuscated targets)
- Long, heavily parameterized URLs
- Suspicious domains (IP literals, high-risk ports, homoglyphs)
- Fake login and credential harvesting paths
- Safe legitimate URLs
"""

import unittest
from safex.core.url_analyzer import _analyze_single_link

class TestUrlSecurityDetection(unittest.TestCase):
    """Rigorous evaluation of URL analysis rules."""

    def test_shortened_url(self):
        """Shortened URLs should be flagged for obfuscation risk."""
        url = "https://bit.ly/3xSecAlert"
        res = _analyze_single_link(url, "Click Here")
        self.assertTrue(res.has_url_shortener)
        self.assertGreaterEqual(res.risk_score, 10)

    def test_long_obfuscated_url(self):
        """Very long URLs packed with query parameters should be flagged."""
        long_url = "https://legit-looking.com/login?token=" + "a" * 150 + "&redirect=http%3A%2F%2Fevil-server.net%2Fsteal"
        res = _analyze_single_link(long_url, "Verify Session")
        self.assertGreaterEqual(res.risk_score, 10)

    def test_suspicious_ip_literal_with_port(self):
        """IP-literal with non-standard administrative port is high risk."""
        url = "http://185.220.101.5:8080/secure/portal"
        res = _analyze_single_link(url, "Banking Portal")
        self.assertTrue(res.is_ip_literal)
        self.assertTrue(res.has_non_standard_port)
        self.assertGreaterEqual(res.risk_score, 30)

    def test_optical_anchor_mismatch_fake_login(self):
        """Visible text shows trusted bank but href leads to Russian phishing host."""
        anchor_text = "https://chase.com/secure/login"
        actual_href = "https://chase-security-verify.ru/login.php"
        res = _analyze_single_link(actual_href, anchor_text)
        self.assertTrue(res.is_mismatch)
        self.assertGreaterEqual(res.risk_score, 30)

    def test_safe_legitimate_url(self):
        """Standard HTTPS enterprise domain should be rated clean."""
        url = "https://github.com/torvalds/linux"
        res = _analyze_single_link(url, "Linux Kernel Repository")
        self.assertFalse(res.is_mismatch)
        self.assertFalse(res.is_ip_literal)
        self.assertLess(res.risk_score, 15)
        self.assertEqual(res.risk_level, "LOW")

if __name__ == "__main__":
    unittest.main()
