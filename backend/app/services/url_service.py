import re
from urllib.parse import urlparse
import tldextract
from typing import List, Dict, Any

# Popular brands targetted by phishing campaigns
POPULAR_BRANDS = [
    "paypal", "chase", "bankofamerica", "wellsfargo", "citibank", 
    "microsoft", "apple", "google", "netflix", "amazon", "facebook", 
    "instagram", "linkedin", "yahoo", "outlook", "office365", "steam",
    "binance", "coinbase"
]

# TLDs commonly abused for phishing (cheap or free registrations)
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "click", "tk", "ml", "ga", "cf", "gq", 
    "fit", "live", "info", "club", "buzz", "country", "gdn"
}

def calculate_levenshtein(s1: str, s2: str) -> int:
    """Calculates the Levenshtein distance between two strings to detect typosquatting."""
    if len(s1) < len(s2):
        return calculate_levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

def analyze_url(url: str) -> Dict[str, Any]:
    """
    Performs weighted threat analysis on a given URL.
    Returns a dict with 'risk_score' (0-100), 'signals' list, and 'details' metadata.
    """
    signals = []
    base_risk = 0
    
    # Standardize URL
    clean_url = url.strip()
    if not re.match(r'^https?://', clean_url, re.IGNORECASE):
        # Default to http if no scheme provided for parsing purposes
        clean_url = "http://" + clean_url
        
    try:
        parsed_url = urlparse(clean_url)
        domain_info = tldextract.extract(clean_url)
    except Exception as e:
        return {
            "risk_score": 95,
            "signals": [{
                "id": "invalid_url_format",
                "severity": "high",
                "title": "Invalid URL Structure",
                "description": f"The URL is deformed or failed parsing: {str(e)}"
            }],
            "details": {"error": "Failed to parse URL"}
        }

    domain = domain_info.domain
    suffix = domain_info.suffix
    subdomain = domain_info.subdomain
    full_host = parsed_url.netloc.lower()
    
    has_no_https = False
    has_suspicious_tld = False
    has_typosquatting = False
    has_ip_host = False

    # 1. Check Protocol (HTTPS vs HTTP) - Weight: 15
    is_https = parsed_url.scheme.lower() == "https"
    if not is_https:
        has_no_https = True
        base_risk += 15
        signals.append({
            "id": "no_https",
            "severity": "medium",
            "title": "Insecure Protocol (No HTTPS)",
            "description": "This website does not use SSL/TLS encryption. Legitimate login and financial pages always encrypt traffic."
        })
        
    # 2. Check for IP-based Address (e.g. http://192.168.1.1 or hex equivalents) - Weight: 50
    ip_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    host_no_port = full_host.split(':')[0]
    if re.match(ip_pattern, host_no_port) or host_no_port.startswith("0x"):
        has_ip_host = True
        base_risk += 50
        signals.append({
            "id": "ip_host",
            "severity": "high",
            "title": "Raw IP Address Hosting",
            "description": "The URL uses a raw IP address instead of a domain name. Phishers frequently use this to hide their true server identity."
        })
        
    # 3. Check for User Info Spoofing (e.g. paypal.com@malicious.com) - Weight: 40
    if "@" in parsed_url.netloc:
        base_risk += 40
        signals.append({
            "id": "user_info_spoofing",
            "severity": "high",
            "title": "Credential Spoofing Attempt",
            "description": "The URL contains an '@' symbol in the authority block, which forces the browser to treat everything before it as credentials, leading the user to a different host."
        })
        
    # 4. Check for Typosquatting and Brand Jacking - Weights: 45 / 25 / 40
    for brand in POPULAR_BRANDS:
        # Brand in domain but domain isn't exactly the brand (e.g. paypal-update.com) - Weight: 45
        if brand in domain and domain != brand:
            has_typosquatting = True
            base_risk += 45
            signals.append({
                "id": "brand_jacking_domain",
                "severity": "high",
                "title": f"Suspicious Brand Referencing ({brand.capitalize()})",
                "description": f"The domain reference containing '{brand}' is registered under a secondary domain structure (not the official site). This is a strong indicator of phishing."
            })
            
        # Brand in subdomain or path (e.g. paypal.com.signin.info) - Weight: 25
        elif brand in subdomain.split('.') or brand in parsed_url.path.lower():
            base_risk += 25
            signals.append({
                "id": "brand_in_subdomain_or_path",
                "severity": "medium",
                "title": f"Brand Keyword in Subdomain/Path ({brand.capitalize()})",
                "description": f"The official brand name '{brand}' is placed inside a subdomain or path directory to trick users, while the actual host is different."
            })
            
        # Levenshtein distance check for typos (e.g., paypa1, chasee) - Weight: 40
        elif len(domain) > 3 and abs(len(domain) - len(brand)) <= 2:
            distance = calculate_levenshtein(domain, brand)
            if distance in [1, 2]:
                has_typosquatting = True
                base_risk += 40
                signals.append({
                    "id": "typosquatting_detected",
                    "severity": "high",
                    "title": f"Typosquatting Detected (Target: {brand.capitalize()})",
                    "description": f"The domain '{domain}' is visually almost identical to the legitimate brand '{brand.capitalize()}', using common character substitutions or typos."
                })

    # 5. Check for excessive subdomains (e.g. auth.login.secure.pay.paypal.com.badsite.com) - Weight: 20
    dots_count = subdomain.count('.') if subdomain else 0
    if dots_count >= 3:
        base_risk += 20
        signals.append({
            "id": "excessive_subdomains",
            "severity": "medium",
            "title": "Deep Subdomain Nesting",
            "description": f"The host contains {dots_count + 1} subdomains. Phishing campaigns chain subdomains to push the actual domain suffix off-screen or mimic deep trust structures."
        })
        
    # 6. Check for suspicious TLDs - Weight: 25
    if suffix in SUSPICIOUS_TLDS:
        has_suspicious_tld = True
        base_risk += 25
        signals.append({
            "id": "suspicious_tld",
            "severity": "medium",
            "title": f"High-Risk TLD (.{suffix})",
            "description": f"The top-level domain '.{suffix}' is statistically abused for malicious links and spam, due to cheap or anonymous registration policies."
        })

    # 7. Check URL Length - Weight: 10
    if len(url) > 90:
        base_risk += 10
        signals.append({
            "id": "excessive_length",
            "severity": "low",
            "title": "Unusually Long URL",
            "description": f"The URL is very long ({len(url)} characters). Phishers use long parameters or URL shortening to mask malicious redirection targets."
        })

    # Compounding Boost Rules
    # Rule A: If both missing HTTPS AND suspicious TLD, add +10 points
    if has_no_https and has_suspicious_tld:
        base_risk += 10
        signals.append({
            "id": "compound_no_https_suspicious_tld",
            "severity": "medium",
            "title": "Compounded Risk: Insecure High-Risk TLD",
            "description": "This website operates on a cheap/suspicious TLD AND lacks HTTPS encryption, representing a compounded phishing risk."
        })
        
    # Rule B: If both typosquatting/brand spoofing AND missing HTTPS, add +15 points
    if has_typosquatting and has_no_https:
        base_risk += 15
        signals.append({
            "id": "compound_typosquat_no_https",
            "severity": "high",
            "title": "Compounded Risk: Unencrypted Brand Impersonator",
            "description": "The URL is typosquatted to impersonate a brand, and it is completely unencrypted. Official login portals are never unencrypted."
        })

    # Rule C: If both IP address AND missing HTTPS, add +15 points
    if has_ip_host and has_no_https:
        base_risk += 15
        signals.append({
            "id": "compound_ip_no_https",
            "severity": "high",
            "title": "Compounded Risk: Unencrypted IP Address Host",
            "description": "The host is a raw IP and is unencrypted, indicating an unauthorized private server attempting credential gathering."
        })

    # Cap risk score at 100
    risk_score = min(base_risk, 100)
    
    return {
        "risk_score": risk_score,
        "signals": signals,
        "details": {
            "domain": domain,
            "suffix": suffix,
            "subdomain": subdomain,
            "host": full_host,
            "is_https": is_https,
            "length": len(url),
            "is_ip_address": has_ip_host
        }
    }
