import re
from email.parser import HeaderParser
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Tuple
from app.config import settings
from app.services.url_service import analyze_url
from app.services.email_auth_service import parse_email_authentication, extract_domain

# Keywords indicating urgency, fear, or financial pressure typical in phishing
PHISHING_KEYWORDS = {
    r"\burgent\b": ("medium", 15, "Urgency Cues Detected", "The text uses urgent language to induce immediate, unreflective action."),
    r"\bsuspend(ed)?\b": ("medium", 20, "Account Suspension Threats", "Mentions of account suspension are standard tactics to create panic."),
    r"\bverify\b.{0,150}\b(account|password|pin|credential)\b": ("high", 30, "Credential Verification Request", "Attempts to verify credentials via links are extremely high risk."),
    r"\bunauthorized\b.{0,150}\b(transaction|login|activity)\b": ("medium", 20, "Unauthorized Activity Alert", "Uses fear of financial loss or hacking to prompt the user to click a link."),
    r"\baction\b.{0,150}\brequired\b": ("medium", 15, "Action Required Call", "Explicitly commands the user to complete an immediate action."),
    r"\bbilling\b.{0,150}\b(update|issue|failed)\b": ("medium", 15, "Billing Issues Mentioned", "Claims that a payment failed to trick the user into inputting credit card info."),
    r"\bfree\b.{0,150}\b(gift|card|reward|winner)\b": ("low", 15, "Baiting / Reward Offers", "Bating the user with free prizes or compensation is a classic social engineering trick."),
    r"\bsecure\b.{0,150}\blogin\b": ("medium", 20, "Security Portal Reference", "Promises a 'secure' login page, which is frequently the label of a credential harvester.")
}

def extract_bounded_urls(text: str, max_urls: int = 25) -> Tuple[List[str], bool, int]:
    """
    Extracts unique standardized URLs from a string block up to max_urls without unbounded memory accumulation.
    Returns (urls, was_truncated, total_found_estimate).
    """
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    seen = set()
    standardized = []
    total_found = 0
    was_truncated = False

    for match in re.finditer(url_pattern, text):
        raw = match.group(0)
        u = 'http://' + raw if raw.startswith('www.') else raw
        if u not in seen:
            seen.add(u)
            if len(standardized) < max_urls:
                standardized.append(u)
            else:
                was_truncated = True
                total_found += 1
                if total_found >= 1000:
                    break

    total_count = len(standardized) + total_found
    return standardized, was_truncated, total_count

def extract_urls(text: str, max_urls: Optional[int] = None) -> List[str]:
    """Extracts unique URLs from a string block up to max_urls (defaults to settings.MAX_EXTRACTED_URLS)."""
    limit = max_urls if max_urls is not None else settings.MAX_EXTRACTED_URLS
    urls, _, _ = extract_bounded_urls(text, max_urls=limit)
    return urls

def analyze_email_text(text: str, max_urls: Optional[int] = None) -> Dict[str, Any]:
    """
    Analyzes email body text for keywords and embedded URLs using weighted scoring rules.
    """
    signals = []
    base_risk = 0
    
    has_urgency_keywords = False
    has_suspicious_links = False
    
    # 1. Keyword check with precise weights
    for pattern, (severity, weight, title, desc) in PHISHING_KEYWORDS.items():
        if re.search(pattern, text, re.IGNORECASE):
            if severity in ["medium", "high"]:
                has_urgency_keywords = True
            base_risk += weight
            signal_id = pattern.replace("\\b", "").replace("?", "").replace("*", "").replace("(", "").replace(")", "").replace("|", "_")[:15]
            signals.append({
                "id": f"keyword_{signal_id}",
                "severity": severity,
                "title": title,
                "description": desc
            })
            
    # 2. Extract and analyze nested URLs within configured budget
    limit = max_urls if max_urls is not None else settings.MAX_EXTRACTED_URLS
    urls, links_truncated, total_links_count = extract_bounded_urls(text, max_urls=limit)
    nested_analyses = []
    high_risk_urls_count = 0
    link_score_acc = 0
    
    for url in urls:
        analysis = analyze_url(url)
        nested_analyses.append({
            "url": url,
            "risk_score": analysis["risk_score"],
            "signals_count": len(analysis["signals"])
        })
        if analysis["risk_score"] >= 60:
            high_risk_urls_count += 1
            has_suspicious_links = True
            # Add 30 points per high-risk link, up to a max of 50
            link_score_acc += 30
            for sig in analysis["signals"]:
                signals.append({
                    "id": f"nested_{sig['id']}",
                    "severity": sig["severity"],
                    "title": f"Nested Link: {sig['title']}",
                    "description": f"An embedded link ({url[:40]}...) triggered: {sig['description']}"
                })
                
    if has_suspicious_links:
        base_risk += min(link_score_acc, 50)
        signals.append({
            "id": "contains_phishing_links",
            "severity": "high",
            "title": "Suspicious Links Embedded",
            "description": f"The email contains {high_risk_urls_count} links that triggered critical heuristic warnings."
        })
    elif len(urls) > 0:
        base_risk += 10 # small baseline risk for unknown links

    # Compounding Boost: Urgency keywords + suspicious links
    if has_urgency_keywords and has_suspicious_links:
        base_risk += 15
        signals.append({
            "id": "compound_urgency_and_link",
            "severity": "high",
            "title": "Compounded Risk: Urgency with Phishing Links",
            "description": "This email couples strong social-engineering pressure statements with suspicious links, representing an active attack vector."
        })
        
    risk_score = min(base_risk, 100)
    
    return {
        "risk_score": risk_score,
        "signals": signals,
        "details": {
            "links_found": urls,
            "links_analyzed": len(urls),
            "links_truncated": links_truncated,
            "links_analysis": nested_analyses,
            "keyword_flags_count": len(signals) - len(nested_analyses)
        }
    }

def extract_domain_from_email(email_str: str) -> str:
    """Helper to extract domain from emails like 'Sender Name <user@domain.com>' or 'user@domain.com'."""
    match = re.search(r'[\w\.-]+@([\w\.-]+\.\w+)', email_str)
    if match:
        return match.group(1).lower()
    return ""

def analyze_email_headers(raw_headers: str) -> Dict[str, Any]:
    """
    Parses email headers and performs standards-aware SPF, DKIM, DMARC, and domain alignment verification.
    Sanitizes all outputs: raw header blocks and raw PII strings are never retained in details.
    """
    signals = []
    base_risk = 0

    auth = parse_email_authentication(raw_headers)

    dkim_display_status = (
        auth.dkim.status
        if auth.dkim.status != "unknown"
        else ("signed" if auth.dkim.is_signed else "none")
    )

    # 1. Subject line urgency evaluation (privacy-preserving: detect flag without persisting raw text)
    urgent_flags: List[str] = []
    try:
        parser = HeaderParser()
        parsed = parser.parsestr(raw_headers)
        raw_subject = parsed.get("Subject", "")
        if raw_subject:
            subject_lower = raw_subject.lower()
            urgent_words = ["urgent", "action required", "suspended", "notice", "alert", "security update"]
            for word in urgent_words:
                if word in subject_lower:
                    urgent_flags.append(word)
                    base_risk += 15
                    signals.append({
                        "id": f"subject_urgent_{word.replace(' ', '_')}",
                        "severity": "medium",
                        "title": f"Urgent Topic in Subject ({word.capitalize()})",
                        "description": f"The email subject line uses the trigger word '{word}' to induce stress and fast clicking.",
                    })
                    break
    except Exception:
        logger.debug("event=subject_urgency_parse_suppressed", exc_info=False)

    details = {
        "from_domain": auth.alignment.from_domain,
        "from_registered_domain": auth.alignment.from_registered_domain,
        "return_path_domain": auth.alignment.return_path_domain,
        "return_path_registered_domain": auth.alignment.return_path_registered_domain,
        "spf_mailfrom_domain": auth.alignment.spf_mailfrom_domain,
        "spf_helo_domain": auth.alignment.spf_helo_domain,
        "spf_status": auth.spf.status,
        "dkim_status": dkim_display_status,
        "dkim_domain": auth.alignment.dkim_domain,
        "dkim_selector": auth.dkim.selector,
        "dmarc_status": auth.dmarc.status,
        "spf_aligned": auth.alignment.spf_aligned,
        "dkim_aligned": auth.alignment.dkim_aligned,
        "dmarc_aligned": auth.alignment.dmarc_aligned,
        "sender_mismatch": auth.alignment.sender_mismatch,
        "authserv_id": auth.authserv_id,
        "is_authserv_trusted": auth.is_authserv_trusted,
        "auth_headers_present": auth.auth_headers_present,
        "subject_urgent_flags": urgent_flags,
    }

    # 2. Sender Spoofing Check (From vs Return-Path registered domain mismatch)
    has_sender_mismatch = auth.alignment.sender_mismatch
    if has_sender_mismatch:
        from_d = auth.alignment.from_registered_domain or "unknown"
        rp_d = auth.alignment.return_path_registered_domain or "unknown"
        base_risk += 35
        signals.append({
            "id": "sender_domain_mismatch",
            "severity": "high",
            "title": "Sender Address Spoofing",
            "description": f"The visual sender domain ({from_d}) does not match the delivery address domain ({rp_d}). This is a strong indicator of header spoofing.",
        })

    # 3. Check SPF status
    has_spf_fail = auth.spf.status == "fail"
    if has_spf_fail:
        base_risk += 35
        signals.append({
            "id": "spf_fail",
            "severity": "high",
            "title": "SPF Authentication Failure",
            "description": "The Sender Policy Framework (SPF) check failed. The sending server is NOT authorized to send emails on behalf of this domain.",
        })
    elif auth.spf.status == "softfail":
        base_risk += 15
        signals.append({
            "id": "spf_softfail",
            "severity": "medium",
            "title": "SPF Authentication Softfail",
            "description": "SPF records suggest the sending server is not fully authorized, but the policy is set to soft-fail.",
        })
    elif auth.spf.status in ("temperror", "permerror"):
        base_risk += 10
        signals.append({
            "id": f"spf_{auth.spf.status}",
            "severity": "medium",
            "title": f"SPF Evaluation {auth.spf.status.capitalize()}",
            "description": f"The SPF record evaluation resulted in a {auth.spf.status}.",
        })

    # 4. Check DKIM Status (Note: missing/none is NOT scored as a failure)
    has_dkim_fail = auth.dkim.status == "fail"
    if has_dkim_fail:
        base_risk += 25
        signals.append({
            "id": "dkim_fail",
            "severity": "high",
            "title": "DKIM Verification Failed",
            "description": "The DKIM digital signature is invalid, meaning the email body or headers were modified in transit or signed with an invalid key.",
        })

    # 5. Check DMARC Status
    has_dmarc_fail = auth.dmarc.status == "fail"
    if has_dmarc_fail:
        base_risk += 25
        signals.append({
            "id": "dmarc_fail",
            "severity": "high",
            "title": "DMARC Policy Failure",
            "description": "The message failed DMARC authentication and alignment policy checks.",
        })

    # Compounding Boost Rules for Headers
    # Rule A: Sender Domain Mismatch + SPF Fail = Critical Threat
    if has_sender_mismatch and has_spf_fail:
        base_risk = max(base_risk, 95)
        signals.append({
            "id": "compound_sender_spoof_and_spf_fail",
            "severity": "high",
            "title": "Critical Risk: Forged Sender with SPF Failure",
            "description": "The sending server failed SPF authentication AND the visual sender domain is spoofed. This is certain header forgery.",
        })
    # Rule B: SPF Fail + DKIM Fail = Add +15 points compound boost
    elif has_spf_fail and has_dkim_fail:
        base_risk += 15
        signals.append({
            "id": "compound_spf_and_dkim_fail",
            "severity": "high",
            "title": "Compounded Risk: SPF & DKIM Authentication Failure",
            "description": "Both SPF and DKIM checks failed. The message is completely unauthenticated and likely forged.",
        })

    risk_score = min(base_risk, 100)

    return {
        "risk_score": risk_score,
        "signals": signals,
        "details": details,
    }
