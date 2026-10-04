import pytest
from app.services.email_auth_service import (
    parse_email_authentication,
    parse_received_spf,
    parse_authentication_results,
    extract_domain,
    extract_email_address,
)
from app.services.email_service import analyze_email_headers


def test_extract_domain_and_public_suffix():
    """Verify robust public suffix extraction and subdomain normalization."""
    # Subdomain of standard TLD
    full, reg = extract_domain("user@mail.paypal.com")
    assert full == "mail.paypal.com"
    assert reg == "paypal.com"

    # Multi-part TLD (e.g. .co.uk)
    full_uk, reg_uk = extract_domain("billing@security.service.co.uk")
    assert full_uk == "security.service.co.uk"
    assert reg_uk == "service.co.uk"

    # Bare domain with angles/quotes
    full_bare, reg_bare = extract_domain("<alerts@bank-verify.xyz>")
    assert full_bare == "bank-verify.xyz"
    assert reg_bare == "bank-verify.xyz"

    # Malformed / None inputs
    assert extract_domain(None) == (None, None)
    assert extract_domain("") == (None, None)


def test_parse_received_spf_all_statuses():
    """Verify RFC 7208 Received-SPF parser handles all standard status tokens."""
    # 1. Pass
    res_pass = parse_received_spf("pass (google.com: domain of sender@example.com designates 1.2.3.4 as permitted sender) client-ip=1.2.3.4;")
    assert res_pass.status == "pass"
    assert res_pass.client_ip == "1.2.3.4"

    # 2. Fail
    res_fail = parse_received_spf("Fail (domain of bad.org does not designate 5.6.7.8) client-ip=5.6.7.8;")
    assert res_fail.status == "fail"

    # 3. Softfail
    res_soft = parse_received_spf("SoftFail (mail.example.org: transitioning domain) client-ip=9.10.11.12;")
    assert res_soft.status == "softfail"

    # 4. Neutral
    res_neutral = parse_received_spf("neutral (domain of neutral.org)")
    assert res_neutral.status == "neutral"

    # 5. None
    res_none = parse_received_spf("none (no SPF record found)")
    assert res_none.status == "none"

    # 6. Temperror & Permerror
    res_temp = parse_received_spf("temperror (DNS timeout)")
    assert res_temp.status == "temperror"

    res_perm = parse_received_spf("permerror (multiple SPF records)")
    assert res_perm.status == "permerror"

    # 7. Empty / Malformed
    assert parse_received_spf("").status == "unknown"
    assert parse_received_spf(None).status == "unknown"
    assert parse_received_spf("random-non-status text").status == "unknown"


def test_parse_authentication_results_rfc8601():
    """Verify RFC 8601 Authentication-Results parser extracts SPF, DKIM, and DMARC properties."""
    raw_ar = (
        "mx.google.com; "
        "dkim=pass header.i=@legit-bank.com header.s=2026_s1; "
        "spf=pass (google.com: domain of security@legit-bank.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=security@legit-bank.com; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legit-bank.com"
    )
    spf, dkim, dmarc = parse_authentication_results(raw_ar)

    assert spf.status == "pass"
    assert spf.domain == "legit-bank.com"

    assert dkim.status == "pass"
    assert dkim.domain == "legit-bank.com"
    assert dkim.selector == "2026_s1"

    assert dmarc.status == "pass"
    assert dmarc.domain == "legit-bank.com"


def test_parse_authentication_results_failures():
    """Verify RFC 8601 parsing handles failed / missing methods."""
    raw_ar = (
        "mail.receiving.com; "
        "spf=fail smtp.mailfrom=attacker@spoofer.net; "
        "dkim=fail header.d=spoofer.net; "
        "dmarc=fail action=quarantine header.from=impersonated-brand.com"
    )
    spf, dkim, dmarc = parse_authentication_results(raw_ar)

    assert spf.status == "fail"
    assert spf.domain == "spoofer.net"

    assert dkim.status == "fail"
    assert dkim.domain == "spoofer.net"

    assert dmarc.status == "fail"
    assert dmarc.domain == "impersonated-brand.com"
    assert dmarc.action == "quarantine"


def test_email_alignment_same_and_subdomain():
    """Verify DMARC relaxed alignment logic: subdomains share same registered root domain."""
    headers_subdomain = (
        "From: Notifications <alerts@mail.service.paypal.com>\n"
        "Return-Path: <bounce@bounces.paypal.com>\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass header.d=mail.service.paypal.com; dmarc=pass"
    )
    auth = parse_email_authentication(headers_subdomain)

    assert auth.alignment.from_registered_domain == "paypal.com"
    assert auth.alignment.return_path_registered_domain == "paypal.com"
    assert auth.alignment.sender_mismatch is False
    assert auth.alignment.spf_aligned is True
    assert auth.alignment.dkim_aligned is True
    assert auth.alignment.dmarc_aligned is True


def test_email_alignment_sender_mismatch():
    """Verify distinct root domains trigger sender_mismatch."""
    headers_mismatch = (
        "From: PayPal Support <support@paypal.com>\n"
        "Return-Path: <invoices@unrelated-hacker-domain.xyz>\n"
        "Subject: Urgent: Account Suspended\n"
        "Authentication-Results: mx.target.com; spf=pass smtp.mailfrom=unrelated-hacker-domain.xyz; dkim=none"
    )
    auth = parse_email_authentication(headers_mismatch)

    assert auth.alignment.from_registered_domain == "paypal.com"
    assert auth.alignment.return_path_registered_domain == "unrelated-hacker-domain.xyz"
    assert auth.alignment.sender_mismatch is True
    assert auth.alignment.spf_aligned is False


def test_analyze_email_headers_all_pass():
    """Verify fully authenticated email produces low risk score and no failure signals."""
    headers = (
        "From: GitHub Support <support@github.com>\n"
        "Return-Path: <support@github.com>\n"
        "Subject: Your security key was updated\n"
        "Authentication-Results: mx.google.com; spf=pass; dkim=pass header.d=github.com; dmarc=pass"
    )
    res = analyze_email_headers(headers)
    assert res["risk_score"] == 0
    assert len(res["signals"]) == 0
    assert res["details"]["spf_status"] == "pass"
    assert res["details"]["dkim_status"] == "pass"
    assert res["details"]["dmarc_status"] == "pass"
    assert res["details"]["sender_mismatch"] is False


def test_analyze_email_headers_spf_fail_and_sender_spoof():
    """Verify critical compounding risk when sender is forged and SPF fails."""
    headers = (
        "From: Apple Security <security@apple.com>\n"
        "Return-Path: <badguy@malicious-relay.org>\n"
        "Subject: Urgent: iCloud Account Access Restricted\n"
        "Received-SPF: fail (relay.net: domain of apple.com does not designate 192.0.2.1 as permitted sender)\n"
        "Authentication-Results: mx.google.com; dkim=fail; dmarc=fail"
    )
    res = analyze_email_headers(headers)
    assert res["risk_score"] >= 95
    signal_ids = [s["id"] for s in res["signals"]]
    assert "sender_domain_mismatch" in signal_ids
    assert "spf_fail" in signal_ids
    assert "dkim_fail" in signal_ids
    assert "dmarc_fail" in signal_ids
    assert "compound_sender_spoof_and_spf_fail" in signal_ids


def test_analyze_email_headers_unknown_and_missing_are_not_failures():
    """Verify missing DKIM or unknown SPF does NOT penalize benign unsigned emails."""
    headers = (
        "From: Friend <friend@example.org>\n"
        "Return-Path: <friend@example.org>\n"
        "Subject: Meeting tomorrow\n"
    )
    res = analyze_email_headers(headers)
    assert res["risk_score"] == 0
    # No fail signals should be present
    signal_ids = [s["id"] for s in res["signals"]]
    assert "spf_fail" not in signal_ids
    assert "dkim_fail" not in signal_ids
    assert "dmarc_fail" not in signal_ids
    assert "sender_domain_mismatch" not in signal_ids


def test_analyze_email_headers_malformed_input_safety():
    """Verify fuzzed / malformed header input fails safely without raising unhandled exceptions."""
    fuzzed_inputs = [
        "Authentication-Results: ;;;;;===;;;;",
        "From: <<<<<@>>>>>\nReturn-Path: invalid-no-at-sign",
        "Received-SPF: " + "A" * 10000,
        "Authentication-Results: (" * 50 + "spf=pass" + ")" * 50,
        "",
        "\x00\x01\x02\x03\x04",
    ]
    for raw in fuzzed_inputs:
        res = analyze_email_headers(raw)
        assert isinstance(res, dict)
        assert "risk_score" in res
        assert 0 <= res["risk_score"] <= 100
        assert "signals" in res
        assert "details" in res
