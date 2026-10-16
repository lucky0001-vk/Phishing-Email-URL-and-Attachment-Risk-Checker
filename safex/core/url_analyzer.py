"""
SafeX URL & Link Analyzer
Extracts and inspects URLs from HTML and plain text for link mismatches,
IP literals, lookalike/homoglyph domains, punycode, and brand impersonation.
Strictly static inspection — NO auto-visiting or external API calls.
"""

import re
import urllib.parse
from typing import List, Dict, Tuple, Optional
from bs4 import BeautifulSoup
from safex.core.models import LinkAnalysis, DetectionSignal

SUSPICIOUS_TLDS = {
    "xyz", "top", "click", "buzz", "country", "stream", "work",
    "gq", "cf", "tk", "ml", "fit", "icu", "rest", "cam", "quest"
}

TARGETED_BRANDS = [
    "paypal", "microsoft", "google", "apple", "amazon", "netflix",
    "outlook", "office365", "chase", "wellsfargo", "bankofamerica",
    "docusign", "dropbox", "dhl", "fedex", "ups", "facebook", "instagram"
]

# Common homoglyph substitutions
HOMOGLYPH_MAP = {
    '1': 'l', '0': 'o', 'vv': 'w', 'rn': 'm', 'cl': 'd'
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "rebrand.ly", "shorturl.at", "soo.gd", "buff.ly"
}

# Cyrillic characters commonly used in homograph domain spoofing
CYRILLIC_LOOKALIKES = set(
    "\u0430\u0435\u043e\u0440\u0441\u0443\u0445\u0456\u0458\u0410\u0412\u0415\u041a\u041c\u041d\u041e\u0420\u0421\u0422\u0423\u0425"
)


def _extract_domain(url: str) -> str:
    """Extract host domain from a URL safely."""
    try:
        parsed = urllib.parse.urlparse(url)
        netloc = parsed.netloc.split(":")[0].lower()
        if "@" in netloc:
            netloc = netloc.split("@")[-1]
        return netloc
    except Exception:
        return ""


def _is_ip_address(host: str) -> bool:
    """Check if host is an IPv4 or IPv6 address."""
    # IPv4 regex
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        parts = host.split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    # IPv6 regex
    if ":" in host:
        return True
    return False


def _check_lookalike(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Check if a domain impersonates a known brand using homoglyphs or subdomain tricks.
    """
    domain_lower = domain.lower()
    
    # 1. Check subdomain trick: brand.com.evil.com
    for brand in TARGETED_BRANDS:
        pattern = rf"(^|\.){brand}\.(com|net|org|co)\."
        if re.search(pattern, domain_lower):
            return True, f"{brand} (subdomain deception)"

    # 2. Check homoglyph substitutions in domain parts
    # e.g. paypa1.com -> paypal.com
    clean_domain = domain_lower
    for k, v in HOMOGLYPH_MAP.items():
        clean_domain = clean_domain.replace(k, v)

    for brand in TARGETED_BRANDS:
        if brand in clean_domain and brand not in domain_lower:
            return True, f"{brand} (homoglyph/typosquatting)"

    return False, None


def _get_root_domain(domain: str) -> str:
    """Extract root registrable domain (e.g. evil.com from a.b.evil.com)."""
    if not domain:
        return ""
    domain = domain.lower().strip(".")
    parts = domain.split(".")
    if len(parts) <= 2:
        return domain
    # Handle two-part TLDs like co.uk, com.au, org.uk, edu.au
    two_part_tlds = {"co.uk", "com.au", "co.nz", "co.za", "org.uk", "gov.uk", "ac.uk", "com.br"}
    last_two = f"{parts[-2]}.{parts[-1]}"
    if last_two in two_part_tlds and len(parts) >= 3:
        return f"{parts[-3]}.{last_two}"
    return f"{parts[-2]}.{parts[-1]}"


def extract_and_analyze_links(html_content: str, plain_text: str) -> Tuple[List[LinkAnalysis], List[DetectionSignal]]:
    """
    Extract all links from HTML anchor tags and plain text, then perform static heuristic analysis.
    """
    links_seen = set()
    link_results: List[LinkAnalysis] = []
    overall_signals: List[DetectionSignal] = []

    # If html_content is empty but plain_text contains HTML tags, use plain_text as HTML
    if not html_content and plain_text and ("<a " in plain_text or "<html" in plain_text or "<body" in plain_text):
        html_content = plain_text

    # 1. Parse HTML anchor tags
    if html_content:
        try:
            soup = BeautifulSoup(html_content, "html.parser")
            for a_tag in soup.find_all("a", href=True):
                href = a_tag["href"].strip()
                anchor_text = a_tag.get_text().strip()
                if href and href not in links_seen and not href.startswith(("mailto:", "tel:", "javascript:void", "#")):
                    links_seen.add(href)
                    la = _analyze_single_link(href, anchor_text)
                    link_results.append(la)
        except Exception:
            pass

    # 2. Extract plain text URLs using regex
    url_pattern = r'https?://[^\s<>"\')]+'
    plain_urls = re.findall(url_pattern, plain_text or "")
    for url in plain_urls:
        clean_url = url.rstrip(".,;!?)]}")
        if clean_url and clean_url not in links_seen:
            links_seen.add(clean_url)
            la = _analyze_single_link(clean_url, "")
            link_results.append(la)

    # Consolidate signals from individual links
    for lk in link_results:
        overall_signals.extend(lk.signals)

    return link_results, overall_signals


def _analyze_single_link(url: str, anchor_text: str) -> LinkAnalysis:
    """
    Inspect a single URL and its associated anchor text statically.
    """
    host = _extract_domain(url)
    la = LinkAnalysis(
        url=url,
        anchor_text=anchor_text,
        href_domain=host,
        risk_tags=[],
        score_impact=0,
        signals=[]
    )

    if not host:
        return la

    # 1. Link Mismatch Check (Visible text shows one domain, href goes to another)
    if anchor_text:
        # Strip scheme if present in anchor text
        clean_anchor = re.sub(r"^https?://", "", anchor_text.strip(), flags=re.IGNORECASE)
        # Check if anchor text looks like a URL or domain
        text_domain_match = re.search(r"([a-zA-Z0-9\-]+(?:\.[a-zA-Z0-9\-]+)*(?:\.[a-zA-Z]{2,})(?:/[^\s]*)?)", clean_anchor)
        if text_domain_match:
            display_candidate = text_domain_match.group(1).lower()
            display_host = display_candidate.split("/")[0].split(":")[0]
            la.display_domain = display_host

            # Compare root domains: e.g. paypal.com vs account-verify-portal.xyz
            host_root = _get_root_domain(host)
            display_root = _get_root_domain(display_host)

            if display_root and host_root and display_root != host_root:
                la.is_mismatch = True
                la.risk_tags.append("Domain Mismatch")
                la.score_impact += 25
                la.signals.append(
                    DetectionSignal(
                        category="url",
                        name="Anchor Text vs Link Destination Mismatch",
                        severity="high",
                        score_impact=25,
                        description=(
                            f"The visible link text displays '{anchor_text}' (belonging to '{display_root}'), "
                            f"but the actual destination routes to a different domain '{host_root}' ({host})."
                        ),
                        evidence=f"Visible: {anchor_text} -> Actual: {url}"
                    )
                )

    # 2. IP Literal Check (http://192.168.1.1/...)
    if _is_ip_address(host):
        la.is_ip_literal = True
        la.risk_tags.append("IP Literal")
        la.score_impact += 22
        la.signals.append(
            DetectionSignal(
                category="url",
                name="IP Literal in URL Destination",
                severity="high",
                score_impact=22,
                description=(
                    f"The link directs directly to an IP address ({host}) rather than a registered domain name. "
                    "Legitimate organizations rarely use bare IP addresses in consumer or business emails."
                ),
                evidence=url
            )
        )

    # 3. Lookalike / Homoglyph / Subdomain Phishing
    is_lookalike, target = _check_lookalike(host)
    if is_lookalike:
        la.is_lookalike = True
        la.lookalike_target = target
        la.risk_tags.append("Lookalike Domain")
        la.score_impact += 24
        la.signals.append(
            DetectionSignal(
                category="url",
                name="Lookalike / Brand Impersonation Domain",
                severity="high",
                score_impact=24,
                description=(
                    f"The destination host '{host}' mimics brand '{target}' using deceptive subdomains or homoglyphs."
                ),
                evidence=f"Host: {host} (Target: {target})"
            )
        )

    # 4. Punycode / IDN Homograph
    if host.startswith("xn--") or ".xn--" in host:
        la.is_punycode = True
        la.risk_tags.append("Punycode (IDN)")
        la.score_impact += 15
        la.signals.append(
            DetectionSignal(
                category="url",
                name="Internationalized Domain (Punycode)",
                severity="medium",
                score_impact=15,
                description=(
                    f"The domain '{host}' uses Punycode encoding (xn--). "
                    "Attackers often use non-ASCII lookalike characters to spoof authentic brand domains."
                ),
                evidence=host
            )
        )

    # 5. '@' Symbol trick
    if "@" in urllib.parse.urlsplit(url).netloc:
        la.has_at_trick = True
        la.risk_tags.append("@ Symbol Trick")
        la.score_impact += 20
        la.signals.append(
            DetectionSignal(
                category="url",
                name="URL Authority Obfuscation (@ Symbol)",
                severity="high",
                score_impact=20,
                description="The URL uses the '@' character in the authority section to mislead users about the actual destination host.",
                evidence=url
            )
        )

    # 6. Suspicious TLD
    tld = host.split(".")[-1]
    if tld in SUSPICIOUS_TLDS:
        la.has_suspicious_tld = True
        la.risk_tags.append(f"Abused TLD (.{tld})")
        la.score_impact += 8
        la.signals.append(
            DetectionSignal(
                category="url",
                name=f"High-Risk Top-Level Domain (.{tld})",
                severity="low",
                score_impact=8,
                description=f"The domain uses the '.{tld}' extension, which is statistically associated with high rates of disposable phishing infrastructure.",
                evidence=host
            )
        )

    # 7. Credential-Harvesting Path Keywords
    path = urllib.parse.urlsplit(url).path.lower()
    cred_keywords = ["/login", "/signin", "/verify", "/update-account", "/wp-login", "/auth", "/webscr"]
    if any(k in path for k in cred_keywords):
        la.has_credential_path = True
        la.risk_tags.append("Credential Path")
        # Only add score impact if it's on a suspicious or non-standard host
        if la.is_mismatch or la.is_ip_literal or la.is_lookalike or la.has_suspicious_tld:
            la.score_impact += 10
            la.signals.append(
                DetectionSignal(
                    category="url",
                    name="Credential Harvesting Path on Suspicious Host",
                    severity="medium",
                    score_impact=10,
                    description=f"The URL path '{path}' solicits account credentials or identity verification on an untrusted host.",
                    evidence=url
                )
            )

    # 8. Cyrillic / Homoglyph Characters in Host
    if any(c in CYRILLIC_LOOKALIKES for c in host):
        la.has_cyrillic_homoglyphs = True
        la.risk_tags.append("Cyrillic Homoglyph")
        la.score_impact += 25
        la.signals.append(
            DetectionSignal(
                category="url",
                name="Cyrillic Script Homoglyph Deception",
                severity="critical",
                score_impact=25,
                description=f"The domain '{host}' contains Cyrillic characters disguised as standard Latin script to spoof legitimate brand addresses.",
                evidence=host
            )
        )

    # 9. URL Shortener Service
    root_host = _get_root_domain(host)
    if host in URL_SHORTENERS or root_host in URL_SHORTENERS:
        la.has_url_shortener = True
        la.risk_tags.append("URL Shortener")
        la.score_impact += 12
        la.signals.append(
            DetectionSignal(
                category="url",
                name="Masked URL Shortener Service",
                severity="medium",
                score_impact=12,
                description=f"The link routes through a URL shortener '{host}' which obscures the final technical destination.",
                evidence=url
            )
        )

    # 10. Non-Standard Port in URL
    parsed = urllib.parse.urlsplit(url)
    if parsed.port and parsed.port not in (80, 443):
        la.has_non_standard_port = True
        la.risk_tags.append(f"Port :{parsed.port}")
        la.score_impact += 15
        la.signals.append(
            DetectionSignal(
                category="url",
                name="Non-Standard Network Port",
                severity="medium",
                score_impact=15,
                description=f"The link points to a non-standard port (:{parsed.port}), commonly seen in testing/malicious staging servers.",
                evidence=url
            )
        )

    # 11. Excessive Subdomain Stacking
    if host.count(".") >= 4 and not _is_ip_address(host):
        la.has_excessive_subdomains = True
        la.risk_tags.append("Subdomain Stacking")
        la.score_impact += 14
        la.signals.append(
            DetectionSignal(
                category="url",
                name="Excessive Subdomain Stacking (>3 levels)",
                severity="medium",
                score_impact=14,
                description=f"The domain '{host}' utilizes multiple nested subdomains to confuse mobile browsers and hide the real domain.",
                evidence=host
            )
        )

    # 12. Open Redirect Pattern in Query
    query = parsed.query.lower()
    redirect_params = ["redirect=", "redirect_uri=", "url=http", "next=http", "dest=http", "target=http"]
    if any(p in query for p in redirect_params):
        la.has_open_redirect = True
        la.risk_tags.append("Open Redirect")
        la.score_impact += 15
        la.signals.append(
            DetectionSignal(
                category="url",
                name="Potential Open Redirect Query Parameter",
                severity="medium",
                score_impact=15,
                description="The URL contains redirect parameters that may bounce victims from an ostensibly benign domain to a credential phishing site.",
                evidence=url
            )
        )

    # 13. Brand Impersonation in Path / Query
    for brand in TARGETED_BRANDS:
        if (f"/{brand}." in path or f"/{brand}-" in path or f"={brand}." in query) and brand not in host:
            la.has_brand_in_path = True
            la.risk_tags.append(f"Spoofed Path ({brand})")
            la.score_impact += 15
            la.signals.append(
                DetectionSignal(
                    category="url",
                    name=f"Brand Spoofing in URI Path ({brand})",
                    severity="high",
                    score_impact=15,
                    description=f"The URL embeds brand name '{brand}' in its path or query to trick users while hosting on '{host}'.",
                    evidence=url
                )
            )
            break

    # Calculate link risk score and classification
    la.risk_score = min(100, la.score_impact)
    if la.risk_score >= 60 or la.is_mismatch or la.is_ip_literal:
        la.risk_level = "CRITICAL" if la.risk_score >= 75 else "HIGH"
    elif la.risk_score >= 25:
        la.risk_level = "MEDIUM"
    else:
        la.risk_level = "LOW"

    return la
