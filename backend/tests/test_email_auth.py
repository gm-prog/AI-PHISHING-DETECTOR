import pytest
from app.services.email_auth_service import (
    parse_email_authentication,
    parse_received_spf,
    parse_authentication_results,
    parse_single_authentication_results,
    extract_domain,
    extract_email_address,
)
from app.services.email_service import analyze_email_headers
from app.config import settings


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
    assert res_pass.mailfrom_domain == "example.com"

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
        "spf=pass (google.com: domain of security@legit-bank.com designates 1.2.3.4 as permitted sender) smtp.mailfrom=security@legit-bank.com smtp.helo=mail.legit-bank.com; "
        "dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=legit-bank.com"
    )
    authserv, spf, dkim, dmarc = parse_single_authentication_results(raw_ar)

    assert authserv == "mx.google.com"
    assert spf.status == "pass"
    assert spf.mailfrom_domain == "legit-bank.com"
    assert spf.helo_domain == "mail.legit-bank.com"

    assert dkim.status == "pass"
    assert dkim.selector == "2026_s1"
    assert dkim.identity == "@legit-bank.com"

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
    assert spf.mailfrom_domain == "spoofer.net"

    assert dkim.status == "fail"
    assert dkim.domain == "spoofer.net"

    assert dmarc.status == "fail"
    assert dmarc.domain == "impersonated-brand.com"
    assert dmarc.action == "quarantine"


def test_structural_rfc_grammar_not_confused_by_quoted_reason_or_comments():
    """
    Verify structural parser distinguishes method results from quoted values like reason='dkim=fail'
    or comments containing deceptive keywords.
    """
    raw_ar = (
        'mx.google.com; '
        'dkim=pass (comment containing dkim=fail and spf=fail) reason="dkim=fail" header.d=example.com header.i=@example.com; '
        'spf=pass (comment with spf=permerror) smtp.mailfrom=user@example.com'
    )
    authserv, spf, dkim, dmarc = parse_single_authentication_results(raw_ar)
    assert authserv == "mx.google.com"
    assert dkim.status == "pass"
    assert dkim.domain == "example.com"
    assert spf.status == "pass"
    assert spf.mailfrom_domain == "example.com"


def test_dkim_d_present_i_present_alignment():
    """Verify RFC 7489 DKIM alignment uses d= (signing domain) when both d= and i= are present."""
    headers = (
        "From: Alice <alice@example.com>\n"
        "Return-Path: <alice@example.com>\n"
        "Authentication-Results: mx.google.com; "
        "dkim=pass header.d=example.com header.i=agent1@dept.corp.example.com; "
        "spf=pass smtp.mailfrom=alice@example.com\n"
    )
    auth = parse_email_authentication(headers)
    assert auth.dkim.domain == "example.com"
    assert auth.dkim.identity == "agent1@dept.corp.example.com"
    assert auth.alignment.dkim_registered_domain == "example.com"
    assert auth.alignment.dkim_aligned is True
    assert auth.alignment.dmarc_aligned is True


def test_dkim_d_missing_i_present_no_fallback():
    """
    Requirement A5: If d= is missing, signing_domain MUST NOT be derived from i=.
    """
    raw_ar = "mx.google.com; dkim=pass header.i=agent1@dept.corp.example.com header.s=s1"
    authserv, spf, dkim, dmarc = parse_single_authentication_results(raw_ar)
    assert dkim.identity == "agent1@dept.corp.example.com"
    assert dkim.domain is None  # Must NOT infer domain from i=

    headers = (
        "From: Alice <alice@example.com>\n"
        "Return-Path: <alice@example.com>\n"
        f"Authentication-Results: {raw_ar}\n"
    )
    auth = parse_email_authentication(headers)
    assert auth.dkim.domain is None
    assert auth.alignment.dkim_aligned is False


def test_dkim_i_unrelated_domain_does_not_break_d_alignment():
    """Verify i= having an unrelated domain does not corrupt valid d= alignment."""
    headers = (
        "From: Notifications <alerts@paypal.com>\n"
        "Return-Path: <alerts@paypal.com>\n"
        "Authentication-Results: mx.google.com; "
        "dkim=pass header.d=paypal.com header.i=external-agent@third-party-relay.org; "
        "spf=pass smtp.mailfrom=alerts@paypal.com\n"
    )
    auth = parse_email_authentication(headers)
    assert auth.dkim.domain == "paypal.com"
    assert auth.dkim.identity == "external-agent@third-party-relay.org"
    assert auth.alignment.dkim_aligned is True


def test_multiple_dkim_signatures_preserved():
    """
    Requirement A6: Multiple DKIM signatures must all be preserved in dkim_signatures.
    """
    headers = (
        "From: Newsletter <news@company.com>\n"
        "Return-Path: <news@company.com>\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=company.com; s=2026k1; i=@company.com; b=sig1;\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=marketing-esp.net; s=esp1; i=@marketing-esp.net; b=sig2;\n"
    )
    auth = parse_email_authentication(headers)
    assert len(auth.dkim_signatures) == 2
    assert auth.dkim_signatures[0].domain == "company.com"
    assert auth.dkim_signatures[1].domain == "marketing-esp.net"
    assert auth.alignment.dkim_aligned is True


def test_spf_mailfrom_vs_return_path_and_helo():
    """
    Requirement A8 & A9:
    - SPF alignment uses authenticated MAIL FROM (smtp.mailfrom), not Return-Path.
    - HELO is preserved purely as diagnostic context.
    """
    # Case 1: MAIL FROM differs from Return-Path
    headers_diff = (
        "From: Billing <billing@trusted.com>\n"
        "Return-Path: <bounce@unrelated-bounce-host.net>\n"
        "Authentication-Results: mx.google.com; "
        "spf=pass smtp.mailfrom=billing@trusted.com smtp.helo=smtp-out.relay.org; "
        "dkim=pass header.d=trusted.com\n"
    )
    auth1 = parse_email_authentication(headers_diff)
    assert auth1.alignment.spf_mailfrom_domain == "trusted.com"
    assert auth1.alignment.spf_helo_domain == "smtp-out.relay.org"
    assert auth1.alignment.spf_aligned is True
    assert auth1.alignment.sender_mismatch is True  # From (trusted.com) != Return-Path (unrelated-bounce-host.net)

    # Case 2: MAIL FROM missing in SPF record -> no SPF alignment
    headers_no_mf = (
        "From: Billing <billing@trusted.com>\n"
        "Return-Path: <billing@trusted.com>\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.helo=smtp-out.relay.org; dkim=none\n"
    )
    auth2 = parse_email_authentication(headers_no_mf)
    assert auth2.alignment.spf_mailfrom_domain is None
    assert auth2.alignment.spf_aligned is False

    # Case 3: HELO aligned with From, but MAIL FROM is unaligned
    headers_helo_aligned = (
        "From: Billing <billing@trusted.com>\n"
        "Return-Path: <attacker@evil.com>\n"
        "Authentication-Results: mx.google.com; "
        "spf=pass smtp.mailfrom=attacker@evil.com smtp.helo=trusted.com; dkim=none\n"
    )
    auth3 = parse_email_authentication(headers_helo_aligned)
    assert auth3.alignment.spf_mailfrom_domain == "evil.com"
    assert auth3.alignment.spf_helo_domain == "trusted.com"
    assert auth3.alignment.spf_aligned is False  # Must NOT use HELO for DMARC SPF alignment


def test_authserv_id_trust_boundary_and_multiple_headers():
    """
    Verify trust boundary:
    1. Untrusted authserv-id sets authserv_id_matched=False and is_authserv_trusted=False.
    2. In raw untrusted mode, even matching authserv-id remains unauthoritative (is_authoritative=False).
    3. In trusted_ingress mode, matching authserv-id establishes authoritative trust (is_authoritative=True).
    """
    trusted_set = {"mx.google.com", "protection.outlook.com"}

    # Case 1: Untrusted authserv ID
    headers_untrusted = (
        "From: User <user@example.com>\n"
        "Authentication-Results: untrusted-internal-hop.local; dkim=pass header.d=example.com; spf=pass\n"
    )
    auth1 = parse_email_authentication(headers_untrusted, trusted_authserv_ids=trusted_set, evidence_provenance="trusted_ingress")
    assert auth1.authserv_id == "untrusted-internal-hop.local"
    assert auth1.authserv_id_matched is False
    assert auth1.is_authserv_trusted is False
    assert auth1.is_authoritative is False
    assert auth1.evidence_source == "untrusted_auth_results"
    assert auth1.auth_headers_present is True

    # Case 2: In untrusted message mode, matching authserv-id is recognized but remains unauthoritative
    headers_multiple = (
        "From: User <user@example.com>\n"
        "Authentication-Results: untrusted-relay.net; dkim=pass header.d=attacker.com\n"
        "Authentication-Results: mx.google.com; dkim=pass header.d=example.com; spf=pass smtp.mailfrom=user@example.com; dmarc=pass\n"
    )
    auth2_raw = parse_email_authentication(headers_multiple, trusted_authserv_ids=trusted_set, evidence_provenance="untrusted_message")
    assert auth2_raw.authserv_id == "mx.google.com"
    assert auth2_raw.authserv_id_matched is True
    assert auth2_raw.is_authoritative is False
    assert auth2_raw.is_authserv_trusted is False

    # Case 3: In trusted ingress mode, matching authserv-id establishes authoritative trust
    auth2_trusted = parse_email_authentication(headers_multiple, trusted_authserv_ids=trusted_set, evidence_provenance="trusted_ingress")
    assert auth2_trusted.authserv_id == "mx.google.com"
    assert auth2_trusted.authserv_id_matched is True
    assert auth2_trusted.is_authoritative is True
    assert auth2_trusted.is_authserv_trusted is True
    assert auth2_trusted.evidence_source == "trusted_auth_results"
    assert auth2_trusted.dkim.domain == "example.com"
    assert auth2_trusted.alignment.dkim_aligned is True


def test_attacker_crafted_trusted_authserv_in_raw_headers_remains_untrusted(monkeypatch):
    """
    CRITICAL SECURITY INVARIANT:
    Prove that an attacker submitting fake failure claims in user-uploaded raw headers
    using a recognized authserv-id (e.g. mx.google.com) CANNOT manufacture trusted provenance
    or trigger authoritative penalties (+95 compound score).
    """
    monkeypatch.setattr("app.config.settings.TRUSTED_AUTHSERV_IDS", "mx.google.com")

    attacker_headers = (
        "From: CEO <ceo@example.com>\n"
        "Return-Path: <ceo@example.com>\n"
        "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n"
        "Received-SPF: fail (google.com: domain of ceo@example.com does not designate 1.2.3.4) envelope-from=ceo@example.com;\n"
    )

    # In raw upload mode (default evidence_provenance="untrusted_message")
    res_untrusted = analyze_email_headers(attacker_headers, evidence_provenance="untrusted_message")

    # Risk score must remain low (<= 10), NOT the critical 95+ from verified receiver failures
    assert res_untrusted["risk_score"] <= 10
    signal_ids = [s["id"] for s in res_untrusted["signals"]]
    assert "spf_fail" not in signal_ids
    assert "dkim_fail" not in signal_ids
    assert "dmarc_fail" not in signal_ids
    assert "compound_sender_spoof_and_spf_fail" not in signal_ids
    assert "compound_spf_and_dkim_fail" not in signal_ids
    assert "untrusted_auth_claim" in signal_ids


def test_trusted_ingress_provenance_enables_authoritative_scoring(monkeypatch):
    """
    Prove that when server-controlled trusted ingress provenance is explicitly established,
    matching TRUSTED_AUTHSERV_IDS authorizes authoritative SPF/DKIM/DMARC failure scoring.
    """
    monkeypatch.setattr("app.config.settings.TRUSTED_AUTHSERV_IDS", "mx.google.com")

    trusted_headers = (
        "From: CEO <ceo@example.com>\n"
        "Return-Path: <attacker@evil.com>\n"
        "Authentication-Results: mx.google.com; spf=fail; dkim=fail; dmarc=fail\n"
    )
    # Server-side MTA / trusted gateway establishes trusted ingress provenance
    res_trusted = analyze_email_headers(trusted_headers, evidence_provenance="trusted_ingress")

    assert res_trusted["risk_score"] >= 95
    signal_ids = [s["id"] for s in res_trusted["signals"]]
    assert "spf_fail" in signal_ids
    assert "dkim_fail" in signal_ids
    assert "dmarc_fail" in signal_ids
    assert "sender_domain_mismatch" in signal_ids


def test_received_spf_in_raw_message_cannot_trigger_authoritative_scoring():
    """
    Prove that Received-SPF header inside user-supplied raw message does NOT
    grant trusted authority or trigger authoritative penalties.
    """
    raw_headers = (
        "From: Alice <alice@example.com>\n"
        "Return-Path: <alice@example.com>\n"
        "Received-SPF: fail (domain of alice@example.com does not designate 5.6.7.8) envelope-from=alice@example.com;\n"
    )
    res = analyze_email_headers(raw_headers, evidence_provenance="untrusted_message")
    assert res["risk_score"] <= 10
    signal_ids = [s["id"] for s in res["signals"]]
    assert "spf_fail" not in signal_ids
    assert "compound_sender_spoof_and_spf_fail" not in signal_ids


def test_dkim_i_cannot_become_d_and_missing_d_produces_unknown_signing_domain():
    """Prove d= is never derived from i= and missing d= means unknown signing domain."""
    ar_header = "Authentication-Results: mx.test.com; dkim=pass header.i=user@spoofed-brand.com"
    _, _, dkim, _ = parse_single_authentication_results(ar_header)
    assert dkim.identity == "user@spoofed-brand.com"
    assert dkim.domain is None

    auth = parse_email_authentication(
        "From: User <user@spoofed-brand.com>\n" + ar_header,
        evidence_provenance="trusted_ingress",
        trusted_authserv_ids={"mx.test.com"}
    )
    assert auth.alignment.dkim_domain is None
    assert auth.alignment.dkim_aligned is False


def test_helo_and_return_path_cannot_satisfy_spf_dmarc_alignment():
    """Prove HELO and Return-Path cannot substitute for authenticated SPF MAIL FROM."""
    # From is paypal.com, Return-Path is paypal.com, but SPF mailfrom is evil.com and HELO is paypal.com
    headers = (
        "From: PayPal <support@paypal.com>\n"
        "Return-Path: <bounce@paypal.com>\n"
        "Authentication-Results: mx.test.com; spf=pass smtp.mailfrom=attacker@evil.com smtp.helo=mail.paypal.com"
    )
    auth = parse_email_authentication(headers, evidence_provenance="trusted_ingress", trusted_authserv_ids={"mx.test.com"})
    assert auth.alignment.spf_mailfrom_domain == "evil.com"
    assert auth.alignment.spf_aligned is False
    assert auth.alignment.dmarc_aligned is False


def test_email_alignment_same_and_subdomain():
    """Verify DMARC relaxed alignment logic: subdomains share same registered root domain."""
    headers_subdomain = (
        "From: Notifications <alerts@mail.service.paypal.com>\n"
        "Return-Path: <bounce@bounces.paypal.com>\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=bounce@bounces.paypal.com; dkim=pass header.d=mail.service.paypal.com; dmarc=pass"
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
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=support@github.com; dkim=pass header.d=github.com; dmarc=pass"
    )
    res = analyze_email_headers(headers)
    assert res["risk_score"] == 0
    assert len(res["signals"]) == 0
    assert res["details"]["spf_status"] == "pass"
    assert res["details"]["dkim_status"] == "pass"
    assert res["details"]["dmarc_status"] == "pass"
    assert res["details"]["sender_mismatch"] is False


def test_analyze_email_headers_unknown_and_missing_are_not_failures():
    """Verify missing DKIM or unknown SPF does NOT penalize benign unsigned emails."""
    headers = (
        "From: Friend <friend@example.org>\n"
        "Return-Path: <friend@example.org>\n"
        "Subject: Meeting tomorrow\n"
    )
    res = analyze_email_headers(headers)
    assert res["risk_score"] == 0
    signal_ids = [s["id"] for s in res["signals"]]
    assert "spf_fail" not in signal_ids
    assert "dkim_fail" not in signal_ids
    assert "dmarc_fail" not in signal_ids
    assert "sender_domain_mismatch" not in signal_ids


def test_email_header_privacy_boundary_zero_raw_headers_persisted():
    """
    Verify privacy boundary: details dictionary must NEVER contain raw From header,
    raw Return-Path header, raw Subject header, or raw Authentication-Results text.
    """
    sensitive_from = 'CEO Executive <secret.ceo@internal-bank.com>'
    sensitive_subject = 'CONFIDENTIAL: Internal M&A discussions on Project Alpha'
    sensitive_rp = '<tracking-id-987654321@relay.internal-bank.com>'

    headers = (
        f"From: {sensitive_from}\n"
        f"Return-Path: {sensitive_rp}\n"
        f"Subject: {sensitive_subject}\n"
        "Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=relay.internal-bank.com; dkim=pass header.d=internal-bank.com; dmarc=pass"
    )
    res = analyze_email_headers(headers)
    details = res["details"]

    assert "from" not in details or details["from"] != sensitive_from
    assert "return_path" not in details or details["return_path"] != sensitive_rp
    assert "subject" not in details or details["subject"] != sensitive_subject
    assert sensitive_from not in str(details)
    assert "Project Alpha" not in str(details)
    assert "987654321" not in str(details)

    assert details["from_domain"] == "internal-bank.com"
    assert details["from_registered_domain"] == "internal-bank.com"
    assert details["spf_status"] == "pass"
    assert details["dkim_status"] == "pass"


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
