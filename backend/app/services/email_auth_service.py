"""
File: backend/app/services/email_auth_service.py
Purpose: Standards-aware parsing and normalization of email authentication headers
(RFC 8601 / RFC 7601 Authentication-Results, RFC 7208 SPF, RFC 6376 DKIM, RFC 7489 DMARC).
"""

import re
import logging
from dataclasses import dataclass, field, asdict
from email.parser import HeaderParser
from typing import Optional, Dict, Any, Tuple, List, Set
import tldextract

from app.config import settings

logger = logging.getLogger(__name__)

# Valid standardized authentication result states
VALID_SPF_STATUSES = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "unknown"}
VALID_DKIM_STATUSES = {"pass", "fail", "none", "neutral", "temperror", "permerror", "unknown"}
VALID_DMARC_STATUSES = {"pass", "fail", "none", "temperror", "permerror", "unknown"}


@dataclass
class SpfAuthResult:
    status: str = "unknown"
    mailfrom_domain: Optional[str] = None
    helo_domain: Optional[str] = None
    client_ip: Optional[str] = None


@dataclass
class DkimAuthResult:
    status: str = "unknown"
    domain: Optional[str] = None       # d= signing domain used for alignment
    identity: Optional[str] = None     # i= AUID / agent identity
    selector: Optional[str] = None     # s= selector
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
    spf_mailfrom_domain: Optional[str] = None
    spf_mailfrom_registered_domain: Optional[str] = None
    spf_helo_domain: Optional[str] = None
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
    dkim_signatures: List[DkimAuthResult] = field(default_factory=list)
    dmarc: DmarcAuthResult = field(default_factory=DmarcAuthResult)
    alignment: AuthAlignmentResult = field(default_factory=AuthAlignmentResult)
    authserv_id: Optional[str] = None
    is_authserv_trusted: bool = False
    authserv_trusted: bool = False
    authentication_results_present: bool = False
    evidence_source: str = "none"  # "trusted_auth_results", "untrusted_auth_results", "received_spf_header", "dkim_signature_present", "none"
    auth_headers_present: bool = False
    is_malformed: bool = False
    subject_urgent_flags: List[str] = field(default_factory=list)

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


def extract_domain(email_or_domain: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
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


def strip_comments(header_val: str) -> str:
    """Strip RFC 5322 parenthesized comments (e.g. '(comment)') not inside double quotes."""
    out = []
    in_quote = False
    depth = 0
    escape = False
    for ch in header_val:
        if escape:
            if not in_quote and depth > 0:
                pass
            else:
                out.append(ch)
            escape = False
            continue
        if ch == '\\':
            escape = True
            if not in_quote and depth > 0:
                pass
            else:
                out.append(ch)
            continue
        if ch == '"' and depth == 0:
            in_quote = not in_quote
            out.append(ch)
            continue
        if not in_quote:
            if ch == '(':
                depth += 1
                continue
            elif ch == ')':
                if depth > 0:
                    depth -= 1
                continue
        if depth == 0:
            out.append(ch)
    return "".join(out)


def split_outside_quotes(text: str, delimiter: str = ';') -> List[str]:
    """Split text by delimiter, ignoring delimiters that appear inside double quotes."""
    parts = []
    current = []
    in_quote = False
    escape = False
    for ch in text:
        if escape:
            current.append(ch)
            escape = False
            continue
        if ch == '\\':
            escape = True
            current.append(ch)
            continue
        if ch == '"':
            in_quote = not in_quote
            current.append(ch)
            continue
        if ch == delimiter and not in_quote:
            parts.append("".join(current).strip())
            current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current).strip())
    return [p for p in parts if p]


def parse_segment_tokens(segment: str) -> Dict[str, str]:
    """Parse key=val or prop=val tokens in a segment, respecting double quotes."""
    tokens = {}
    pattern = r'([a-zA-Z0-9_\.-]+)=(?:"([^"]*)"|([^\s;]+))'
    for match in re.finditer(pattern, segment):
        k = match.group(1).lower()
        v = match.group(2) if match.group(2) is not None else match.group(3)
        tokens[k] = v
    return tokens


def parse_received_spf(spf_str: str) -> SpfAuthResult:
    """Parse RFC 7208 Received-SPF header."""
    if not spf_str or not isinstance(spf_str, str):
        return SpfAuthResult(status="unknown")

    clean = strip_comments(spf_str.strip())
    # First word is typically the result
    match = re.match(r'^([a-zA-Z]+)', clean)
    if not match:
        return SpfAuthResult(status="unknown")

    raw_status = match.group(1).lower()
    status = raw_status if raw_status in VALID_SPF_STATUSES else "unknown"

    tokens = parse_segment_tokens(clean)

    # Extract client IP if present
    client_ip = tokens.get("client-ip")

    # Extract envelope-from / identity / mailfrom domain if present
    mailfrom_raw = tokens.get("envelope-from") or tokens.get("identity") or tokens.get("smtp.mailfrom")
    mailfrom_domain = None
    if mailfrom_raw:
        full_d, _ = extract_domain(mailfrom_raw)
        mailfrom_domain = full_d
    else:
        # Fallback: check "domain of <domain>"
        d_of_match = re.search(r'domain of\s+[\'"]?([^\s;\'"\)]+)', spf_str, re.IGNORECASE)
        if d_of_match:
            full_d, _ = extract_domain(d_of_match.group(1))
            mailfrom_domain = full_d

    helo_raw = tokens.get("helo") or tokens.get("smtp.helo")
    helo_domain = None
    if helo_raw:
        full_h, _ = extract_domain(helo_raw)
        helo_domain = full_h

    return SpfAuthResult(
        status=status,
        mailfrom_domain=mailfrom_domain,
        helo_domain=helo_domain,
        client_ip=client_ip,
    )


def parse_single_authentication_results(auth_results_str: str) -> Tuple[Optional[str], SpfAuthResult, DkimAuthResult, DmarcAuthResult]:
    """
    Parse a single RFC 8601 Authentication-Results header into:
    (authserv_id, spf_result, dkim_result, dmarc_result)
    """
    spf_res = SpfAuthResult()
    dkim_res = DkimAuthResult()
    dmarc_res = DmarcAuthResult()

    if not auth_results_str or not isinstance(auth_results_str, str):
        return None, spf_res, dkim_res, dmarc_res

    clean_header = strip_comments(auth_results_str.strip())
    segments = split_outside_quotes(clean_header, delimiter=';')
    if not segments:
        return None, spf_res, dkim_res, dmarc_res

    # First segment contains authserv-id (and optional version)
    first_seg = segments[0].strip()
    authserv_tokens = first_seg.split()
    authserv_id = authserv_tokens[0].rstrip(';').lower() if authserv_tokens else None

    # Remaining segments contain method-result specs
    for seg in segments[1:]:
        tokens = parse_segment_tokens(seg)

        # 1. SPF method
        if "spf" in tokens:
            st = tokens["spf"].lower()
            if st in VALID_SPF_STATUSES:
                spf_res.status = st
            mf = tokens.get("smtp.mailfrom") or tokens.get("envelope-from")
            if mf:
                full_d, _ = extract_domain(mf)
                spf_res.mailfrom_domain = full_d
            helo = tokens.get("smtp.helo") or tokens.get("helo")
            if helo:
                full_h, _ = extract_domain(helo)
                spf_res.helo_domain = full_h

        # 2. DKIM method
        if "dkim" in tokens:
            st = tokens["dkim"].lower()
            if st in VALID_DKIM_STATUSES:
                dkim_res.status = st
                dkim_res.is_signed = True
            # header.d is the signing domain used for alignment
            d_val = tokens.get("header.d") or tokens.get("d")
            if d_val:
                full_d, _ = extract_domain(d_val)
                dkim_res.domain = full_d
            # header.i is the AUID / agent identity (NEVER substitutes for d=)
            i_val = tokens.get("header.i") or tokens.get("i")
            if i_val:
                dkim_res.identity = i_val
            # header.s is the selector
            s_val = tokens.get("header.s") or tokens.get("s")
            if s_val:
                dkim_res.selector = s_val.strip()

        # 3. DMARC method
        if "dmarc" in tokens:
            st = tokens["dmarc"].lower()
            if st in VALID_DMARC_STATUSES:
                dmarc_res.status = st
            h_from = tokens.get("header.from") or tokens.get("from")
            if h_from:
                full_d, _ = extract_domain(h_from)
                dmarc_res.domain = full_d
            act = tokens.get("action")
            if act:
                dmarc_res.action = act.lower()
            pol = tokens.get("policy") or tokens.get("p")
            if pol:
                dmarc_res.policy = pol.lower()

    return authserv_id, spf_res, dkim_res, dmarc_res


def parse_authentication_results(auth_results_str: str) -> Tuple[SpfAuthResult, DkimAuthResult, DmarcAuthResult]:
    """Backward-compatible helper returning (spf, dkim, dmarc) tuple from a single header string."""
    _, spf, dkim, dmarc = parse_single_authentication_results(auth_results_str)
    return spf, dkim, dmarc


def parse_email_authentication(
    raw_headers: str,
    trusted_authserv_ids: Optional[Set[str]] = None,
) -> NormalizedEmailAuth:
    """
    Main entry point: parses raw email headers and returns a fully normalized,
    standards-aware authentication representation with strict domain alignment,
    trusted authserv evaluation, multiple DKIM signature tracking, and zero raw header leaks.
    """
    result = NormalizedEmailAuth()
    if not raw_headers or not isinstance(raw_headers, str):
        return result

    trusted_ids = trusted_authserv_ids if trusted_authserv_ids is not None else settings.trusted_authserv_ids_set

    try:
        parser = HeaderParser()
        parsed = parser.parsestr(raw_headers)

        from_list = parsed.get_all("From", [])
        return_path_list = parsed.get_all("Return-Path", [])
        auth_results_list = parsed.get_all("Authentication-Results", [])
        received_spf_list = parsed.get_all("Received-SPF", [])
        dkim_sig_list = parsed.get_all("DKIM-Signature", [])

        # 1. Parse all DKIM-Signature headers
        dkim_sigs: List[DkimAuthResult] = []
        if dkim_sig_list:
            result.auth_headers_present = True
            for sig_val in dkim_sig_list:
                tokens = parse_segment_tokens(strip_comments(sig_val))
                sig_res = DkimAuthResult(is_signed=True, status="signed")
                if "d" in tokens:
                    full_d, _ = extract_domain(tokens["d"])
                    sig_res.domain = full_d
                if "s" in tokens:
                    sig_res.selector = tokens["s"].strip()
                if "i" in tokens:
                    sig_res.identity = tokens["i"].strip()
                dkim_sigs.append(sig_res)
        result.dkim_signatures = dkim_sigs

        # 2. Parse Authentication-Results with precedence for trusted authserv-ids
        if auth_results_list:
            result.auth_headers_present = True
            result.authentication_results_present = True
            chosen_authserv_id: Optional[str] = None
            chosen_spf = SpfAuthResult()
            chosen_dkim = DkimAuthResult()
            chosen_dmarc = DmarcAuthResult()
            found_trusted = False

            # First pass: check for any trusted authserv ID match
            for ar_val in auth_results_list:
                authserv_id, spf_ar, dkim_ar, dmarc_ar = parse_single_authentication_results(ar_val)
                if authserv_id and trusted_ids and authserv_id.lower() in trusted_ids:
                    chosen_authserv_id = authserv_id
                    chosen_spf, chosen_dkim, chosen_dmarc = spf_ar, dkim_ar, dmarc_ar
                    found_trusted = True
                    break

            # Second pass: if no trusted match, take the top/first valid header as untrusted claim
            if not found_trusted and auth_results_list:
                for ar_val in auth_results_list:
                    authserv_id, spf_ar, dkim_ar, dmarc_ar = parse_single_authentication_results(ar_val)
                    if authserv_id or spf_ar.status != "unknown" or dkim_ar.status != "unknown" or dmarc_ar.status != "unknown":
                        chosen_authserv_id = authserv_id
                        chosen_spf, chosen_dkim, chosen_dmarc = spf_ar, dkim_ar, dmarc_ar
                        break

            result.authserv_id = chosen_authserv_id
            result.is_authserv_trusted = found_trusted
            result.authserv_trusted = found_trusted
            result.evidence_source = "trusted_auth_results" if found_trusted else "untrusted_auth_results"

            if chosen_spf.status != "unknown":
                result.spf = chosen_spf
            if chosen_dkim.status != "unknown":
                result.dkim = chosen_dkim
            if chosen_dmarc.status != "unknown":
                result.dmarc = chosen_dmarc

        # 3. Parse Received-SPF if SPF is still unknown
        if result.spf.status == "unknown" and received_spf_list:
            result.auth_headers_present = True
            if result.evidence_source == "none":
                result.evidence_source = "received_spf_header"
            for spf_val in received_spf_list:
                spf_recv = parse_received_spf(spf_val)
                if spf_recv.status != "unknown":
                    result.spf = spf_recv
                    break

        # If SPF was never present or parsed, set to "none" rather than converting to "fail"
        if result.spf.status == "unknown":
            result.spf.status = "none"

        # 4. If DKIM status was not determined from Authentication-Results, check DKIM signatures
        if result.dkim.status == "unknown":
            if dkim_sigs:
                result.dkim = dkim_sigs[0]
                if result.evidence_source == "none":
                    result.evidence_source = "dkim_signature_present"
            else:
                result.dkim.status = "none"

        # If DMARC was never present or parsed, set to "none"
        if result.dmarc.status == "unknown":
            result.dmarc.status = "none"

        # 5. Extract sender and return path addresses/domains
        from_raw = from_list[0] if from_list else ""
        return_path_raw = return_path_list[0] if return_path_list else ""

        from_email = extract_email_address(from_raw)
        from_full, from_reg = extract_domain(from_email or from_raw)

        rp_email = extract_email_address(return_path_raw)
        rp_full, rp_reg = extract_domain(rp_email or return_path_raw)

        # Authenticated SPF MailFrom domain (DO NOT fallback to Return-Path for authenticated SPF!)
        spf_mf_domain = result.spf.mailfrom_domain
        spf_mf_full, spf_mf_reg = extract_domain(spf_mf_domain) if spf_mf_domain else (None, None)

        # DKIM domain alignment (uses d= signing domain)
        dkim_full, dkim_reg = extract_domain(result.dkim.domain) if result.dkim.domain else (None, None)

        result.alignment.from_domain = from_full
        result.alignment.from_registered_domain = from_reg
        result.alignment.return_path_domain = rp_full
        result.alignment.return_path_registered_domain = rp_reg
        result.alignment.spf_mailfrom_domain = spf_mf_full
        result.alignment.spf_mailfrom_registered_domain = spf_mf_reg
        result.alignment.spf_helo_domain = result.spf.helo_domain
        result.alignment.dkim_domain = dkim_full
        result.alignment.dkim_registered_domain = dkim_reg

        # Sender Mismatch: From registered domain != Return-Path registered domain
        if from_reg and rp_reg:
            result.alignment.sender_mismatch = (from_reg != rp_reg)
        else:
            result.alignment.sender_mismatch = False

        # SPF Alignment (RFC 7489 Section 3.1.2): From registered domain == SPF MailFrom registered domain
        if from_reg and spf_mf_reg:
            result.alignment.spf_aligned = (from_reg == spf_mf_reg)
        else:
            result.alignment.spf_aligned = False

        # DKIM Alignment (RFC 7489 Section 3.1.1): From registered domain == DKIM signing registered domain (d=)
        dkim_aligned = False
        if from_reg and dkim_reg and from_reg == dkim_reg:
            dkim_aligned = True
        elif from_reg and dkim_sigs:
            # Check all DKIM signatures for alignment
            for sig in dkim_sigs:
                if sig.domain:
                    _, sig_reg = extract_domain(sig.domain)
                    if sig_reg == from_reg:
                        dkim_aligned = True
                        break
        result.alignment.dkim_aligned = dkim_aligned

        # DMARC Alignment: At least one of SPF (with pass) or DKIM (with pass) is aligned with From header
        # Note: DMARC pass alignment requires trusted/authoritative pass or direct signature alignment
        spf_pass_aligned = (result.spf.status == "pass" and result.alignment.spf_aligned)
        dkim_pass_aligned = (result.dkim.status == "pass" and result.alignment.dkim_aligned)
        result.alignment.dmarc_aligned = (spf_pass_aligned or dkim_pass_aligned)

    except Exception:
        logger.error("event=email_auth_parsing_error", exc_info=False)
        result.is_malformed = True

    return result
