"""
CyberShield AI - Heuristic Web Threat Detection & Digital Trust Engine
======================================================================
Engine for analyzing URLs, detecting phishing patterns, suspicious TLDs,
homoglyph/typosquatting attacks, IP-based URLs, and calculating an explainable
Digital Trust & Risk Score (0-100).
"""

import re
import math
import ipaddress
from urllib.parse import urlparse, parse_qs
from datetime import datetime

# Abuse-prone or high-risk TLDs frequently seen in disposable phishing campaigns
SUSPICIOUS_TLDS = {
    'xyz', 'top', 'work', 'click', 'loan', 'fit', 'gq', 'cf', 'ml', 'tk',
    'buzz', 'surf', 'stream', 'kim', 'science', 'download', 'accountant',
    'racing', 'win', 'bid', 'date', 'faith', 'review', 'party', 'country',
    'cricket', 'republican', 'democrat', 'monster', 'rest', 'bar', 'icu',
    'cam', 'vip', 'sbs', 'cfd'
}

# Standard highly reputable TLDs that are more regulated
ESTABLISHED_TLDS = {
    'gov', 'edu', 'mil', 'org', 'com', 'net', 'int', 'ac.uk', 'gov.uk'
}

# Credential and account theft keywords
CREDENTIAL_KEYWORDS = [
    'login', 'signin', 'sign-in', 'log-in', 'logon', 'verify', 'verification',
    'authenticate', 'authentication', 'auth', 'password', 'passwd', 'credential',
    'security-update', 'recover-account', 'unlock', 'session-id', 'confirm-identity'
]

# Financial and payment keywords
FINANCIAL_KEYWORDS = [
    'banking', 'online-bank', 'paypal', 'crypto', 'wallet', 'binance',
    'coinbase', 'metamask', 'ledger', 'blockchain', 'billing', 'invoice',
    'checkout', 'creditcard', 'credit-card', 'debit', 'payment-update',
    'wire-transfer', 'reimbursement', 'tax-refund'
]

# Urgency and scam bait keywords
SCAM_BAIT_KEYWORDS = [
    'free-gift', 'giveaway', 'winner', 'claim-reward', 'bonus', 'airdrop',
    'unauthorized-access', 'account-suspended', 'urgent-action', 'limited-time',
    'security-alert', 'immediate-response', 'lottery', 'prize'
]

# Typosquatting / Leetspeak brand patterns
TARGETED_BRANDS = {
    'paypal': [r'paypa[l1i]', r'p[a@]ypal', r'pay-pal', r'paypal-update'],
    'google': [r'g[o0]{2}g[l1]e', r'goog[l1]e', r'google-verify'],
    'microsoft': [r'micr[o0]s[o0]ft', r'm[i1]cr[o0]soft', r'ms-verify'],
    'apple': [r'app[l1]e', r'apple-id-verify', r'apple-support-login'],
    'netflix': [r'netfl[i1]x', r'netflix-billing', r'netflx'],
    'amazon': [r'am[a@]z[o0]n', r'amaz0n', r'amazon-security'],
    'facebook': [r'f[a@]ceb[o0]{2}k', r'faceb00k', r'fb-security'],
    'instagram': [r'[i1]nst[a@]gr[a@]m', r'instagram-verify'],
    'binance': [r'b[i1]n[a@]nce', r'binance-security'],
    'chase': [r'chase-online', r'chase-bank-verify'],
    'wellsfargo': [r'wells-fargo-update', r'wellsfarg0']
}

# Well-known highly reputable authority domains
VERIFIED_SAFE_DOMAINS = {
    'google.com', 'www.google.com',
    'github.com', 'www.github.com',
    'microsoft.com', 'www.microsoft.com',
    'apple.com', 'www.apple.com',
    'wikipedia.org', 'en.wikipedia.org',
    'amazon.com', 'www.amazon.com',
    'cloudflare.com', 'www.cloudflare.com',
    'python.org', 'www.python.org',
    'stackoverflow.com', 'www.stackoverflow.com',
    'mozilla.org', 'www.mozilla.org',
    'linkedin.com', 'www.linkedin.com',
    'youtube.com', 'www.youtube.com',
    'nih.gov', 'www.nih.gov',
    'mit.edu', 'www.mit.edu',
    'harvard.edu', 'www.harvard.edu'
}


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string to detect randomized obfuscation."""
    if not text:
        return 0.0
    entropy = 0.0
    text_len = len(text)
    char_counts = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / text_len
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_ip_address(host: str) -> bool:
    """Check if the hostname is a raw IPv4 or IPv6 address."""
    # Strip port if present
    clean_host = host.split(':')[0].strip('[]')
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # Check for octal or hex encoded IP (e.g. 0x7f.0.0.1 or 2130706433)
    if re.match(r'^(0x[0-9a-fA-F]+\.?)+$', clean_host) or clean_host.isdigit():
        return True

    return False


def validate_and_normalize_url(raw_url: str):
    """
    Validates input URL string and normalizes it.
    Returns (normalized_url, error_message, was_scheme_added).
    """
    if not raw_url or not isinstance(raw_url, str):
        return None, "Please provide a valid website URL to scan.", False

    url = raw_url.strip()

    # Reject obvious non-URLs
    if len(url) < 3 or ' ' in url:
        return None, "The provided input contains invalid spaces or is too short.", False

    was_scheme_added = False
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+\-.]*://', url):
        # Auto-prefix https if user simply typed "paypal-update.xyz"
        url = 'https://' + url
        was_scheme_added = True

    try:
        parsed = urlparse(url)
    except Exception as e:
        return None, f"URL parsing error: {str(e)}", False

    if not parsed.netloc and not parsed.path:
        return None, "Invalid URL structure: Hostname could not be identified.", False

    # Ensure hostname is present
    host = parsed.netloc or parsed.path.split('/')[0]
    if not host:
        return None, "Could not determine hostname from URL.", False

    return url, None, was_scheme_added


def analyze_url(raw_url: str) -> dict:
    """
    Executes a comprehensive, multi-vector heuristic security assessment.
    Returns structured results with risk score (0-100), classification,
    breakdown of indicators, flags, and actionable guidance.
    """
    normalized_url, error, was_scheme_added = validate_and_normalize_url(raw_url)
    if error:
        return {
            'success': False,
            'error': error
        }

    parsed = urlparse(normalized_url)
    hostname = (parsed.hostname or parsed.netloc.split(':')[0]).lower()
    full_path = (parsed.path or '') + ('?' + parsed.query if parsed.query else '')
    raw_lower = normalized_url.lower()

    # Base state
    risk_score = 0
    warnings = []
    positive_signals = []
    category_breakdowns = {
        'protocol': {'score': 0, 'max': 25, 'title': 'Protocol & Transport Security'},
        'hostname': {'score': 0, 'max': 35, 'title': 'Domain & Host Heuristics'},
        'keywords': {'score': 0, 'max': 25, 'title': 'Deceptive Content & Keywords'},
        'structure': {'score': 0, 'max': 15, 'title': 'URL Structure & Obfuscation'}
    }

    # ----------------------------------------------------
    # Vector 1: Protocol Security (HTTP vs HTTPS)
    # ----------------------------------------------------
    is_https = parsed.scheme.lower() == 'https'
    if is_https:
        positive_signals.append({
            'icon': 'shield-check',
            'title': 'HTTPS Enabled',
            'desc': 'Website uses Transport Layer Security (TLS/HTTPS) for encrypted communication.'
        })
    else:
        penalty = 20
        risk_score += penalty
        category_breakdowns['protocol']['score'] += penalty
        warnings.append({
            'severity': 'critical',
            'code': 'NO_HTTPS',
            'title': 'Insecure Plain HTTP Protocol',
            'desc': 'The connection is unencrypted. Login credentials, session tokens, and data can be intercepted via Man-in-the-Middle (MitM) attacks.',
            'points': penalty
        })

    # Port check
    if parsed.port and parsed.port not in (80, 443):
        penalty = 15
        risk_score += penalty
        category_breakdowns['protocol']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'NON_STANDARD_PORT',
            'title': f'Non-Standard Port (:{parsed.port})',
            'desc': f'Traffic is routed through unusual port {parsed.port}, a technique often used by malicious web servers or rogue proxies.',
            'points': penalty
        })

    # ----------------------------------------------------
    # Vector 2: IP-Based URL Detection
    # ----------------------------------------------------
    is_ip = is_ip_address(hostname)
    if is_ip:
        penalty = 40
        risk_score += penalty
        category_breakdowns['hostname']['score'] += penalty
        warnings.append({
            'severity': 'critical',
            'code': 'RAW_IP_HOST',
            'title': 'Direct IP Address Hostname',
            'desc': 'Host utilizes a raw IP address instead of a legitimate registered domain name. This is a prevalent pattern in malware command-and-control and phishing kits.',
            'points': penalty
        })
    else:
        positive_signals.append({
            'icon': 'globe',
            'title': 'Standard Domain Resolution',
            'desc': 'URL uses a standard named domain rather than a raw numeric IP address.'
        })

    # ----------------------------------------------------
    # Vector 3: Domain & TLD Heuristics
    # ----------------------------------------------------
    domain_parts = hostname.split('.')
    tld = domain_parts[-1] if len(domain_parts) > 1 else ''

    if tld in SUSPICIOUS_TLDS:
        penalty = 25
        risk_score += penalty
        category_breakdowns['hostname']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'SUSPICIOUS_TLD',
            'title': f'High-Abuse Top-Level Domain (.{tld})',
            'desc': f'The TLD ".{tld}" has a statistically high correlation with disposable spam, malware staging, and phishing campaigns.',
            'points': penalty
        })
    elif tld in ESTABLISHED_TLDS:
        positive_signals.append({
            'icon': 'award',
            'title': f'Established Top-Level Domain (.{tld})',
            'desc': f'Operates on a well-governed, standard TLD registry (.{tld}).'
        })

    # Check for excessive subdomains (e.g., paypal.com.update.user.xyz)
    if len(domain_parts) > 3 and not is_ip:
        penalty = 15
        risk_score += penalty
        category_breakdowns['hostname']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'EXCESSIVE_SUBDOMAINS',
            'title': f'Excessive Subdomain Stacking ({len(domain_parts) - 2} levels)',
            'desc': 'Unusually deep subdomain hierarchy detected. Attackers frequently stack subdomains to simulate trusted brand names.',
            'points': penalty
        })

    # Hyphen overloading in domain
    hyphen_count_domain = hostname.count('-')
    if hyphen_count_domain >= 3:
        penalty = 15
        risk_score += penalty
        category_breakdowns['hostname']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'HYPHEN_OVERLOAD',
            'title': f'Multiple Hyphens in Hostname ({hyphen_count_domain})',
            'desc': 'Hostname contains excessive hyphens, a signature characteristic of spoofed domains (e.g., "bank-login-secure-portal").',
            'points': penalty
        })

    # Punycode / IDN Homograph check
    if 'xn--' in hostname:
        penalty = 30
        risk_score += penalty
        category_breakdowns['hostname']['score'] += penalty
        warnings.append({
            'severity': 'critical',
            'code': 'PUNYCODE_HOMOGRAPH',
            'title': 'Punycode Internationalized Domain (IDN)',
            'desc': 'Host utilizes punycode representation ("xn--"), which can visually mimic legitimate alphabets while redirecting to an imposter server (IDN homograph attack).',
            'points': penalty
        })

    # ----------------------------------------------------
    # Vector 4: Brand Impersonation & Typosquatting
    # ----------------------------------------------------
    brand_spoofed = None
    for brand, patterns in TARGETED_BRANDS.items():
        # Check if brand appears in hostname when the domain is NOT the official brand
        if brand not in hostname:
            for pat in patterns:
                if re.search(pat, hostname):
                    brand_spoofed = brand
                    break
        elif not any(hostname.endswith(f"{brand}.{ext}") or hostname == f"{brand}.{ext}" for ext in ['com', 'org', 'net', 'co']):
            # Brand is embedded as a subdomain or keyword (e.g., paypal.security-alert.com)
            brand_spoofed = brand
            break

    if brand_spoofed:
        penalty = 35
        risk_score += penalty
        category_breakdowns['keywords']['score'] += penalty
        warnings.append({
            'severity': 'critical',
            'code': 'BRAND_TYPOSQUATTING',
            'title': f'Suspected Brand Impersonation ({brand_spoofed.capitalize()})',
            'desc': f'Detected lookalike character substitutions or subdomains imitating "{brand_spoofed.capitalize()}". This strongly indicates credential harvesting.',
            'points': penalty
        })

    # ----------------------------------------------------
    # Vector 5: Suspicious Keywords Analysis
    # ----------------------------------------------------
    found_credential_kw = [kw for kw in CREDENTIAL_KEYWORDS if kw in raw_lower]
    found_financial_kw = [kw for kw in FINANCIAL_KEYWORDS if kw in raw_lower]
    found_scam_kw = [kw for kw in SCAM_BAIT_KEYWORDS if kw in raw_lower]

    if found_credential_kw:
        penalty = min(20, len(found_credential_kw) * 10)
        risk_score += penalty
        category_breakdowns['keywords']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'CREDENTIAL_KEYWORDS',
            'title': 'Authentication & Credential Keywords Found',
            'desc': f'URL references sensitive auth patterns: [{", ".join(found_credential_kw[:3])}]. High risk if domain is unrecognized.',
            'points': penalty
        })

    if found_financial_kw:
        penalty = min(20, len(found_financial_kw) * 10)
        risk_score += penalty
        category_breakdowns['keywords']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'FINANCIAL_KEYWORDS',
            'title': 'Financial / Banking Terminology Detected',
            'desc': f'URL incorporates financial identifiers: [{", ".join(found_financial_kw[:3])}].',
            'points': penalty
        })

    if found_scam_kw:
        penalty = min(25, len(found_scam_kw) * 12)
        risk_score += penalty
        category_breakdowns['keywords']['score'] += penalty
        warnings.append({
            'severity': 'critical',
            'code': 'SCAM_BAIT_KEYWORDS',
            'title': 'Social Engineering / Urgent Bait Keywords',
            'desc': f'Suspicious urgency or giveaway phrases detected: [{", ".join(found_scam_kw[:3])}].',
            'points': penalty
        })

    # ----------------------------------------------------
    # Vector 6: URL Structure, Length & Obfuscation
    # ----------------------------------------------------
    url_len = len(normalized_url)
    if url_len > 100:
        penalty = 15
        risk_score += penalty
        category_breakdowns['structure']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'EXCESSIVE_URL_LENGTH',
            'title': f'Excessive URL Length ({url_len} characters)',
            'desc': 'Excessively long URLs are often crafted to hide the true destination or embed encoded payloads beyond mobile address bar boundaries.',
            'points': penalty
        })
    elif url_len > 75:
        penalty = 8
        risk_score += penalty
        category_breakdowns['structure']['score'] += penalty
        warnings.append({
            'severity': 'informational',
            'code': 'MODERATE_URL_LENGTH',
            'title': f'Above-Average URL Length ({url_len} characters)',
            'desc': 'URL path is noticeably longer than average standard navigation paths.',
            'points': penalty
        })
    else:
        positive_signals.append({
            'icon': 'check-circle',
            'title': 'Optimal URL Length',
            'desc': f'Standard compact length ({url_len} characters).'
        })

    # Embedded '@' trick (credential redirect attack)
    if '@' in normalized_url:
        penalty = 30
        risk_score += penalty
        category_breakdowns['structure']['score'] += penalty
        warnings.append({
            'severity': 'critical',
            'code': 'EMBEDDED_AT_SYMBOL',
            'title': 'Deceptive "@" Symbol Detected',
            'desc': 'The "@" character in URLs causes standard user agents to discard preceding content and direct users to the destination following "@". Major phishing vector.',
            'points': penalty
        })

    # Double forward slash in path or embedded http (Open Redirect trick)
    if '//' in full_path or 'http:' in full_path or 'https:' in full_path:
        penalty = 20
        risk_score += penalty
        category_breakdowns['structure']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'OPEN_REDIRECT_PATTERN',
            'title': 'Embedded Secondary URL / Open Redirect Vector',
            'desc': 'Path contains secondary protocol declarations or double slashes, often indicating open redirect exploitation.',
            'points': penalty
        })

    # Excessive hex/percent encoding
    percent_count = full_path.count('%')
    if percent_count >= 4:
        penalty = 12
        risk_score += penalty
        category_breakdowns['structure']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'HEAVY_PERCENT_ENCODING',
            'title': f'Obfuscated Character Encoding ({percent_count} escaped sequences)',
            'desc': 'Frequent percentage-encoding detected in URL parameters, likely obfuscating executable scripts or tracking parameters.',
            'points': penalty
        })

    # Shannon Entropy check on host and path
    entropy = calculate_entropy(hostname)
    if entropy > 4.2 and not is_ip:
        penalty = 15
        risk_score += penalty
        category_breakdowns['structure']['score'] += penalty
        warnings.append({
            'severity': 'warning',
            'code': 'HIGH_ENTROPY_HOST',
            'title': f'High Shannon Entropy Domain ({entropy} bits)',
            'desc': 'Hostname exhibits random character distributions resembling Domain Generation Algorithms (DGA) used by botnets.',
            'points': penalty
        })

    # ----------------------------------------------------
    # Vector 7: Whitelist / Authority Reputation Dampener
    # ----------------------------------------------------
    is_whitelisted = False
    clean_host_for_whitelist = hostname.removeprefix('www.')
    for safe_d in VERIFIED_SAFE_DOMAINS:
        if clean_host_for_whitelist == safe_d or hostname == safe_d or hostname.endswith('.' + safe_d):
            is_whitelisted = True
            break

    if is_whitelisted and not ('//' in full_path or '@' in normalized_url or found_scam_kw):
        # Reputable domain with clean signals
        risk_score = min(risk_score, 12)
        positive_signals.insert(0, {
            'icon': 'verified',
            'title': 'Reputable Authority Domain',
            'desc': f'"{hostname}" matches a globally recognized, high-trust digital authority with established cryptographic reputation.'
        })

    # Ensure risk score is capped within 0-100 range
    risk_score = max(5, min(99, risk_score)) if warnings else 5

    # If whitelisted authority domain and no warnings, give solid trust score of 5
    if is_whitelisted and not warnings:
        risk_score = 5

    # ----------------------------------------------------
    # Classification & Digital Trust Index
    # ----------------------------------------------------
    if risk_score <= 34:
        risk_level = 'Low'
        risk_label = 'Low Risk (Preliminary Safe)'
        color = '#00f5d4'  # Neon Cyan
        badge_class = 'status-low'
    elif risk_score <= 69:
        risk_level = 'Medium'
        risk_label = 'Medium Risk (Suspicious)'
        color = '#f59e0b'  # Warning Amber
        badge_class = 'status-medium'
    else:
        risk_level = 'High'
        risk_label = 'High Risk (Critical Threat)'
        color = '#ef4444'  # Threat Red
        badge_class = 'status-high'

    # Trust Score is the complement of Risk Score (0-100)
    trust_score = max(1, 100 - risk_score)

    # ----------------------------------------------------
    # Dynamic Actionable Recommendations
    # ----------------------------------------------------
    recommendations = []
    if risk_level == 'High':
        recommendations.append("DO NOT proceed to this website or enter credentials.")
        recommendations.append("Do not download attachments, execute files, or click embedded links.")
        if is_ip:
            recommendations.append("Accessing direct IP endpoints bypasses domain verification and certificate checks.")
        if brand_spoofed:
            recommendations.append(f"Visit the legitimate {brand_spoofed.capitalize()} service directly by typing its official URL in your browser bookmark.")
        recommendations.append("Report this URL to your internal IT security department or browser safe browsing database.")
    elif risk_level == 'Medium':
        recommendations.append("Exercise heightened caution: verify the legitimacy of this link before interacting.")
        recommendations.append("Do not provide passwords, credit cards, or two-factor authentication codes.")
        if not is_https:
            recommendations.append("Avoid transacting on unencrypted HTTP connections where data can be sniffed.")
        recommendations.append("Carefully cross-check the top-level domain and spelling in your address bar.")
    else:
        recommendations.append("Standard preliminary safety checks passed.")
        recommendations.append("Always verify multi-factor authentication (MFA) prompts independently.")
        recommendations.append("Stay vigilant for unsolicited requests for personal identification or payment.")

    # Format why score was assigned
    score_reasons = []
    for w in warnings:
        score_reasons.append({
            'factor': w['title'],
            'impact': f"+{w['points']} Risk",
            'type': 'warning',
            'detail': w['desc']
        })
    for p in positive_signals:
        score_reasons.append({
            'factor': p['title'],
            'impact': "Positive Trust",
            'type': 'positive',
            'detail': p['desc']
        })

    return {
        'success': True,
        'url': normalized_url,
        'hostname': hostname,
        'is_https': is_https,
        'is_ip': is_ip,
        'tld': tld,
        'risk_score': risk_score,
        'trust_score': trust_score,
        'risk_level': risk_level,
        'risk_label': risk_label,
        'badge_class': badge_class,
        'color': color,
        'entropy': entropy,
        'warnings': warnings,
        'positive_signals': positive_signals,
        'score_reasons': score_reasons,
        'category_breakdowns': category_breakdowns,
        'recommendations': recommendations,
        'scan_timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
        'disclaimer': (
            "CyberShield AI Preliminary Security Assessment: This evaluation is generated using heuristic pattern analysis, "
            "threat signatures, and protocol verification. No automated tool can guarantee 100% safety. "
            "Exercise vigilance before submitting personal credentials or financial details."
        )
    }
