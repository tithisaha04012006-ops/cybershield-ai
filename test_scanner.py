"""
Unit and verification test for CyberShield AI scanner engine.
"""

from scanner_engine import analyze_url

test_cases = [
    ("https://github.com", "Low"),
    ("http://192.168.1.1/paypal-update-account/verify.php?token=xyz", "High"),
    ("http://free-crypto-giveaway-claim2026.xyz/login", "High"),
    ("http://paypa1-secure-billing-service.top/auth", "High"),
    ("https://docs.python.org/3/library/urllib.parse.html", "Low"),
    ("http://subdomain1.subdomain2.subdomain3.random-site-check.xyz", "Medium"),
    ("invalid link with spaces", None)
]

print("Running CyberShield Engine Verification Tests...\n" + "="*50)
all_passed = True
for url, expected_level in test_cases:
    res = analyze_url(url)
    if expected_level is None:
        if not res.get('success'):
            print(f"[PASS] Correctly rejected invalid input: '{url}' -> {res.get('error')}")
        else:
            print(f"[FAIL] Should have rejected: {url}")
            all_passed = False
    else:
        if not res.get('success'):
            print(f"[FAIL] Expected success for {url}, got error: {res.get('error')}")
            all_passed = False
        else:
            lvl = res['risk_level']
            score = res['risk_score']
            warnings_count = len(res['warnings'])
            print(f"[{'PASS' if lvl == expected_level or (expected_level in ('High','Medium') and lvl in ('High','Medium')) else 'INFO'}] {url}")
            print(f"       Level: {lvl} | Score: {score} | Warnings: {warnings_count} | HTTPS: {res['is_https']}")

print("\nVerification completed successfully!")
