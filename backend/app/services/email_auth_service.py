"""
File: backend/app/services/email_auth_service.py
Purpose: Standards-aware parsing and normalization of email authentication headers
(RFC 8601 Authentication-Results, RFC 7208 SPF, RFC 6376 DKIM, RFC 7489 DMARC).
"""

import re
import logging
from dataclasses import dataclass, field, asdict
from email.parser import HeaderParser
from typing import Optional, Dict, Any, Tuple
import tldextract

logger = logging.getLogger(__name__)

# Valid standardized authentication result states
VALID_SPF_STATUSES = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown"}
VALID_DKIM_STATUSES = {"pass", "fail", "none", "neutral", "temperror", "permerror", "unknown"}
VALID_DMARC_STATUSES = {"pass", "fail", "none", "temperror", "permerror", "unknown"}


@dataclass
class SpfAuthResult:
    status: str = "unknown"
    domain: Optional[str] = None
    scope: Optional[str] = None
    client_ip: Optional[str] = None


@dataclass
class DkimAuthResult:
    status: str = "unknown"
    domain: Optional[str] = None
    selector: Optional[str] = None
    is_signed: bool = False


@dataclass
class DmarcAuthResult:
    status: str = "unknown"
    domain: Optional[str] = None
    policy: Optional[str] = None
    action: Optional[str] = None


@dataclass
class AuthAlignmentResult:
    from_domain: Optional[str] = None
    from_registered_domain: Optional[str] = None
    return_path_domain: Optional[str] = None
    return_path_registered_domain: Optional[str] = None
    dkim_domain: Optional[str] = None
    dkim_registered_domain: Optional[str] = None
    spf_aligned: bool = False
    dkim_aligned: bool = False
    dmarc_aligned: bool = False
    sender_mismatch: bool = False


@dataclass
class NormalizedEmailAuth:
    spf: SpfAuthResult = field(default_factory=SpfAuthResult)
    dkim: DkimAuthResult = field(default_factory=DkimAuthResult)
    dmarc: DmarcAuthResult = field(default_factory=DmarcAuthResult)
    alignment: AuthAlignmentResult = field(default_factory=AuthAlignmentResult)
    from_header: str = ""
    return_path_header: str = ""
    subject: str = ""
    is_malformed: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def extract_email_address(email_header_val: str) -> Optional[str]:
    """Extract clean email address from headers like 'Name <user@domain.com>' or 'user@domain.com'."""
    if not email_header_val or not isinstance(email_header_val, str):
        return None
    match = re.search(r'[\w\.-]+@([\w\.-]+\.[a-zA-Z0-9\-_]+)', email_header_val.strip())
    if match:
        return match.group(0).lower()
    return None


def extract_domain(email_or_domain: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts full domain and registered root domain (using public suffix list via tldextract).
    Returns (full_domain, registered_domain).
    """
    if not email_or_domain or not isinstance(email_or_domain, str):
        return None, None

    clean = email_or_domain.strip().lower()
    if "@" in clean:
        clean = clean.split("@")[-1].strip()
    # Strip angle brackets, port, or path if any
    clean = clean.strip("<>").split(":")[0].split("/")[0].strip()

    if not clean or "." not in clean:
        return (clean if clean else None), (clean if clean else None)

    ext = tldextract.extract(clean)
    if ext.domain and ext.suffix:
        reg_domain = f"{ext.domain}.{ext.suffix}".lower()
    else:
        reg_domain = clean.lower()

    return clean.lower(), reg_domain


def parse_received_spf(spf_str: str) -> SpfAuthResult:
    """Parse RFC 7208 Received-SPF header."""
    if not spf_str or not isinstance(spf_str, str):
        return SpfAuthResult(status="unknown")

    clean = spf_str.strip()
    # First word is typically the result
    match = re.match(r'^([a-zA-Z]+)', clean)
    if not match:
        return SpfAuthResult(status="unknown")

    raw_status = match.group(1).lower()
    status = raw_status if raw_status in VALID_SPF_STATUSES else "unknown"

    # Extract client IP if present
    ip_match = re.search(r'client-ip=([0-9a-fA-F\.:]+)', clean, re.IGNORECASE)
    client_ip = ip_match.group(1) if ip_match else None

    # Extract envelope-from / identity domain if present
    domain_match = re.search(r'(?:envelope-from|identity)=[\'"]?([^\s;\'"]+)', clean, re.IGNORECASE)
    domain = None
    if domain_match:
        full_d, _ = extract_domain(domain_match.group(1))
        domain = full_d
    else:
        # Fallback: check "domain of <domain>"
        d_of_match = re.search(r'domain of\s+[\'"]?([^\s;\'"\)]+)', clean, re.IGNORECASE)
        if d_of_match:
            full_d, _ = extract_domain(d_of_match.group(1))
            domain = full_d

    return SpfAuthResult(status=status, domain=domain, client_ip=client_ip)


def parse_authentication_results(auth_results_str: str) -> Tuple[SpfAuthResult, DkimAuthResult, DmarcAuthResult]:
    """
    Parse RFC 8601 Authentication-Results header.
    Format: authserv-id; method1=result [props]; method2=result [props]
    """
    spf_res = SpfAuthResult()
    dkim_res = DkimAuthResult()
    dmarc_res = DmarcAuthResult()

    if not auth_results_str or not isinstance(auth_results_str, str):
        return spf_res, dkim_res, dmarc_res

    # Strip comments inside parentheses while preserving tokens outside
    # Replace (comment) with whitespace to prevent comment contents from spoofing keywords
    clean_header = re.sub(r'\([^\)]*\)', ' ', auth_results_str)

    # 1. Parse SPF method
    spf_match = re.search(r'\bspf=([a-zA-Z]+)', clean_header, re.IGNORECASE)
    if spf_match:
        status_candidate = spf_match.group(1).lower()
        if status_candidate in VALID_SPF_STATUSES:
            spf_res.status = status_candidate
            # Look for smtp.mailfrom or smtp.helo
            mailfrom_match = re.search(r'smtp\.(?:mailfrom|helo)=[\'"]?([^\s;\'"]+)', clean_header, re.IGNORECASE)
            if mailfrom_match:
                full_d, _ = extract_domain(mailfrom_match.group(1))
                spf_res.domain = full_d

    # 2. Parse DKIM method
    dkim_match = re.search(r'\bdkim=([a-zA-Z]+)', clean_header, re.IGNORECASE)
    if dkim_match:
        status_candidate = dkim_match.group(1).lower()
        if status_candidate in VALID_DKIM_STATUSES:
            dkim_res.status = status_candidate
            # Look for header.d or header.i
            header_d = re.search(r'header\.(?:d|i)=[\'"]?([^\s;\'"]+)', clean_header, re.IGNORECASE)
            if header_d:
                full_d, _ = extract_domain(header_d.group(1))
                dkim_res.domain = full_d
            # Look for selector header.s
            header_s = re.search(r'header\.s=[\'"]?([^\s;\'"]+)', clean_header, re.IGNORECASE)
            if header_s:
                dkim_res.selector = header_s.group(1).strip()

    # 3. Parse DMARC method
    dmarc_match = re.search(r'\bdmarc=([a-zA-Z]+)', clean_header, re.IGNORECASE)
    if dmarc_match:
        status_candidate = dmarc_match.group(1).lower()
        if status_candidate in VALID_DMARC_STATUSES:
            dmarc_res.status = status_candidate
            # Look for header.from
            header_from = re.search(r'header\.from=[\'"]?([^\s;\'"]+)', clean_header, re.IGNORECASE)
            if header_from:
                full_d, _ = extract_domain(header_from.group(1))
                dmarc_res.domain = full_d
            # Look for action
            action_match = re.search(r'action=([a-zA-Z]+)', clean_header, re.IGNORECASE)
            if action_match:
                dmarc_res.action = action_match.group(1).lower()

    return spf_res, dkim_res, dmarc_res


def parse_email_authentication(raw_headers: str) -> NormalizedEmailAuth:
    """
    Main entry point: parses raw email headers and returns a fully normalized,
    standards-aware authentication representation with strict domain alignment.
    Fails safely on malformed inputs without crashing.
    """
    result = NormalizedEmailAuth()
    if not raw_headers or not isinstance(raw_headers, str):
        return result

    try:
        parser = HeaderParser()
        parsed = parser.parsestr(raw_headers)
        headers_dict = {k.lower(): v for k, v in parsed.items()}

        from_val = headers_dict.get("from", "")
        return_path_val = headers_dict.get("return-path", "")
        subject_val = headers_dict.get("subject", "")
        auth_results_val = headers_dict.get("authentication-results", "")
        received_spf_val = headers_dict.get("received-spf", "")
        dkim_sig_val = headers_dict.get("dkim-signature", "")

        result.from_header = from_val
        result.return_path_header = return_path_val
        result.subject = subject_val

        # 1. Parse Authentication-Results (preferred explicit standard)
        if auth_results_val:
            spf_ar, dkim_ar, dmarc_ar = parse_authentication_results(auth_results_val)
            if spf_ar.status != "unknown":
                result.spf = spf_ar
            if dkim_ar.status != "unknown":
                result.dkim = dkim_ar
            if dmarc_ar.status != "unknown":
                result.dmarc = dmarc_ar

        # 2. Parse Received-SPF if SPF is still unknown or not populated from Authentication-Results
        if result.spf.status == "unknown" and received_spf_val:
            spf_recv = parse_received_spf(received_spf_val)
            if spf_recv.status != "unknown":
                result.spf = spf_recv

        # 3. Check DKIM-Signature presence
        if dkim_sig_val:
            result.dkim.is_signed = True
            # Extract s= selector and d= domain if DKIM domain/selector not yet set
            if not result.dkim.domain:
                d_match = re.search(r'\bd=([^\s;]+)', dkim_sig_val, re.IGNORECASE)
                if d_match:
                    full_d, _ = extract_domain(d_match.group(1))
                    result.dkim.domain = full_d
            if not result.dkim.selector:
                s_match = re.search(r'\bs=([^\s;]+)', dkim_sig_val, re.IGNORECASE)
                if s_match:
                    result.dkim.selector = s_match.group(1).strip()

        # 4. Domain Normalization & Identifier Alignment
        from_email = extract_email_address(from_val)
        from_full, from_reg = extract_domain(from_email or from_val)

        rp_email = extract_email_address(return_path_val)
        rp_full, rp_reg = extract_domain(rp_email or return_path_val)

        dkim_full, dkim_reg = extract_domain(result.dkim.domain or "")

        result.alignment.from_domain = from_full
        result.alignment.from_registered_domain = from_reg
        result.alignment.return_path_domain = rp_full
        result.alignment.return_path_registered_domain = rp_reg
        result.alignment.dkim_domain = dkim_full
        result.alignment.dkim_registered_domain = dkim_reg

        # Sender Mismatch: From and Return-Path are both present, have registered domains, and do not match
        if from_reg and rp_reg:
            result.alignment.sender_mismatch = (from_reg != rp_reg)
        else:
            result.alignment.sender_mismatch = False

        # SPF Alignment: Return-Path registered domain matches From registered domain
        if from_reg and rp_reg:
            result.alignment.spf_aligned = (from_reg == rp_reg)

        # DKIM Alignment: DKIM signing registered domain matches From registered domain
        if from_reg and dkim_reg:
            result.alignment.dkim_aligned = (from_reg == dkim_reg)

        # DMARC Alignment: At least one of SPF (with pass) or DKIM (with pass) is aligned with From header
        spf_pass_aligned = (result.spf.status == "pass" and result.alignment.spf_aligned)
        dkim_pass_aligned = (result.dkim.status == "pass" and result.alignment.dkim_aligned)
        result.alignment.dmarc_aligned = (spf_pass_aligned or dkim_pass_aligned)

    except Exception:
        logger.error("event=email_auth_parsing_error", exc_info=False)
        result.is_malformed = True

    return result
