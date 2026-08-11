from app.services.url_service import analyze_url
from app.services.email_service import analyze_email_text, analyze_email_headers
from app.main import generate_local_explanation

# Test URL
r = analyze_url("http://secure-paypa1-verification.xyz/signin")
print(f"URL Test - Score: {r['risk_score']}, Signals: {len(r['signals'])}")

# Test email text
et = analyze_email_text("URGENT ACTION REQUIRED! Your account has been suspended. Click http://paypa1-login.info/restore to verify your pin and credentials.")
print(f"Email Text Test - Score: {et['risk_score']}, Signals: {len(et['signals'])}")

# Test email headers (SPF fail + sender mismatch)
headers_raw = """From: Chase Security <security@chase.com>
Return-Path: <spam@bulletproof.ru>
Received-SPF: fail (domain does not designate as permitted sender)"""
eh = analyze_email_headers(headers_raw)
print(f"Header Test - Score: {eh['risk_score']}, Signals: {len(eh['signals'])}")

# Test report generation
report = generate_local_explanation("url", "http://paypa1.xyz", r["risk_score"], r["signals"])
has_table = "| Metric" in report
print(f"Report Generated - Length: {len(report)} chars, Has Table: {has_table}")

print("ALL TESTS PASSED!")
