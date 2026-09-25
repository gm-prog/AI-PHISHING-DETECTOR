import re
from email.parser import HeaderParser
from urllib.parse import urlparse
from typing import List, Dict, Any
from app.services.url_service import analyze_url

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

def extract_urls(text: str) -> List[str]:
    """Extracts all URLs from a string block using regex."""
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+'
    urls = re.findall(url_pattern, text)
    standardized = []
    for u in urls:
        if u.startswith('www.'):
            standardized.append('http://' + u)
        else:
            standardized.append(u)
    return list(set(standardized))

def analyze_email_text(text: str) -> Dict[str, Any]:
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
            
    # 2. Extract and analyze nested URLs
    urls = extract_urls(text)
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
    Parses email headers and checks SPF, DKIM, and From/Return-Path sender mismatches using weighted metrics.
    """
    signals = []
    base_risk = 0
    
    parser = HeaderParser()
    headers = parser.parsestr(raw_headers)
    headers_dict = {key.lower(): val for key, val in headers.items()}
    
    from_header = headers_dict.get("from", "")
    return_path = headers_dict.get("return-path", "")
    subject = headers_dict.get("subject", "")
    auth_results = headers_dict.get("authentication-results", "")
    spf_header = headers_dict.get("received-spf", "")
    dkim_signature = headers_dict.get("dkim-signature", "")
    
    details = {
        "from": from_header,
        "return_path": return_path,
        "subject": subject,
        "spf_status": "unknown",
        "dkim_status": "unknown"
    }

    has_sender_mismatch = False
    has_spf_fail = False
    has_dkim_fail = False

    # 1. Sender Spoofing Check (From vs Return-Path domain mismatch) - Weight: 45
    if from_header and return_path:
        from_domain = extract_domain_from_email(from_header)
        return_domain = extract_domain_from_email(return_path)
        
        if from_domain and return_domain and from_domain != return_domain:
            if not (from_domain.endswith("." + return_domain) or return_domain.endswith("." + from_domain)):
                has_sender_mismatch = True
                base_risk += 45
                signals.append({
                    "id": "sender_domain_mismatch",
                    "severity": "high",
                    "title": "Sender Address Spoofing",
                    "description": f"The visual sender domain ({from_domain}) does not match the actual delivery address domain ({return_domain}). This is a classic indicator of header forgery."
                })
                details["sender_mismatch"] = True
                
    # 2. Check SPF status - Weight: 40
    if spf_header:
        spf_header_lower = spf_header.lower()
        if "fail" in spf_header_lower or "deny" in spf_header_lower:
            has_spf_fail = True
            details["spf_status"] = "fail"
        elif "softfail" in spf_header_lower:
            base_risk += 20
            signals.append({
                "id": "spf_softfail",
                "severity": "medium",
                "title": "SPF Authentication Softfail",
                "description": "SPF records suggest the sending server is not fully authorized, but the policy is set to soft-fail."
            })
            details["spf_status"] = "softfail"
        elif "pass" in spf_header_lower:
            details["spf_status"] = "pass"
            
    if auth_results and details["spf_status"] == "unknown":
        auth_results_lower = auth_results.lower()
        if "spf=fail" in auth_results_lower:
            has_spf_fail = True
            details["spf_status"] = "fail"
        elif "spf=pass" in auth_results_lower:
            details["spf_status"] = "pass"
        elif "spf=none" in auth_results_lower:
            details["spf_status"] = "none"
            
    if has_spf_fail:
        base_risk += 40
        signals.append({
            "id": "spf_fail",
            "severity": "high",
            "title": "SPF Authentication Failure",
            "description": "The Sender Policy Framework (SPF) check failed. The sending server is NOT authorized to send emails on behalf of this domain."
        })
        
    # 3. Check DKIM Status - Weight: 20
    if dkim_signature:
        details["dkim_status"] = "signed"
    else:
        details["dkim_status"] = "missing"
        
    if auth_results:
        auth_results_lower = auth_results.lower()
        if "dkim=fail" in auth_results_lower:
            has_dkim_fail = True
            details["dkim_status"] = "fail"
        elif "dkim=pass" in auth_results_lower:
            details["dkim_status"] = "pass"
            
    if has_dkim_fail:
        base_risk += 20
        signals.append({
            "id": "dkim_fail",
            "severity": "medium",
            "title": "DKIM Verification Failed",
            "description": "The DKIM digital signature is invalid, meaning the email body or headers were modified in transit or signed with a bad key."
        })
    elif details["dkim_status"] in ["missing", "unknown"]:
        base_risk += 10
        signals.append({
            "id": "dkim_missing",
            "severity": "low",
            "title": "No Cryptographic DKIM Signature",
            "description": "The email lacks a digital DKIM signature. While common for newsletters or personal mails, major corporate domains always sign messages."
        })

    # 4. Urgency in Subject - Weight: 15
    if subject:
        subject_lower = subject.lower()
        urgent_words = ["urgent", "action required", "suspended", "notice", "alert", "security update"]
        for word in urgent_words:
            if word in subject_lower:
                base_risk += 15
                signals.append({
                    "id": f"subject_urgent_{word.replace(' ', '_')}",
                    "severity": "medium",
                    "title": f"Urgent Topic in Subject ({word.capitalize()})",
                    "description": f"The email subject line uses the trigger word '{word}' to induce stress and fast clicking."
                })
                break

    # Compounding Boost Rules for Headers
    # Rule A: Sender Domain Mismatch + SPF Fail = Threat Score 95 immediately
    if has_sender_mismatch and has_spf_fail:
        base_risk = 95
        signals.append({
            "id": "compound_sender_spoof_and_spf_fail",
            "severity": "high",
            "title": "Critical Risk: Forged Sender with SPF Failure",
            "description": "The sending server failed authentication AND the visual sender domain is spoofed. This is certain header forgery."
        })
        
    # Rule B: SPF Fail + DKIM Fail = Add +15 points
    elif has_spf_fail and has_dkim_fail:
        base_risk += 15
        signals.append({
            "id": "compound_spf_and_dkim_fail",
            "severity": "high",
            "title": "Compounded Risk: SPF & DKIM Authentication Failure",
            "description": "Both SPF and DKIM checks failed. The message is completely unauthenticated and likely forged."
        })

    risk_score = min(base_risk, 100)
    
    return {
        "risk_score": risk_score,
        "signals": signals,
        "details": details
    }
