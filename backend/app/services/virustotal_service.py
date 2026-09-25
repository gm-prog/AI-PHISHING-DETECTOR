"""
File: backend/app/services/virustotal_service.py
Purpose: VirusTotal API integration for URL threat intelligence
"""

import asyncio
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


async def analyze_url_with_virustotal(url: str, api_key: str) -> Dict[str, Any]:
    """
    Analyze a URL using the VirusTotal v3 API (free tier: 500 requests/day).

    Args:
        url: The URL string to analyze.
        api_key: VirusTotal API key.

    Returns:
        Dict with keys: status, url, malicious_count, suspicious_count,
        reputation_score, vendors, last_scan_date, categories, vt_scan_id.
    """
    if not api_key or not api_key.strip():
        return {
            "status": "skipped",
            "reason": "VirusTotal API key not configured",
            "url": url,
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 100,
            "vendors": [],
        }

    try:
        import aiohttp
    except ImportError:
        logger.error("aiohttp not installed. Run: pip install aiohttp>=3.9.0")
        return {"status": "error", "url": url, "error": "aiohttp not installed"}

    try:
        async with aiohttp.ClientSession() as session:
            headers = {"x-apikey": api_key.strip()}
            form = aiohttp.FormData()
            form.add_field("url", url)

            # Step 1: Submit URL for scanning
            async with session.post(
                "https://www.virustotal.com/api/v3/urls",
                data=form,
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp:
                if resp.status == 429:
                    logger.warning("VirusTotal rate limit hit.")
                    return {
                        "status": "rate_limited",
                        "url": url,
                        "message": "VirusTotal daily quota exceeded",
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }
                if resp.status == 401:
                    logger.error("Invalid VirusTotal API key.")
                    return {
                        "status": "error",
                        "url": url,
                        "message": "Invalid VirusTotal API key",
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }
                if resp.status != 200:
                    return {
                        "status": "error",
                        "url": url,
                        "code": resp.status,
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }

                submit_result = await resp.json()
                scan_id = submit_result.get("data", {}).get("id", "")

            if not scan_id:
                return {"status": "error", "url": url, "error": "No scan ID returned"}

            # Step 2: Fetch scan results
            async with session.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp2:
                if resp2.status != 200:
                    return {
                        "status": "error",
                        "url": url,
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }

                data = await resp2.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("stats", {})
                last_results = attrs.get("results", {})

                malicious_count = stats.get("malicious", 0)
                suspicious_count = stats.get("suspicious", 0)

                # Reputation: 100 = clean, reduced by detections
                reputation_score = max(0, 100 - (malicious_count * 10) - (suspicious_count * 3))

                # Collect vendor names that flagged as malware/phishing (top 5)
                malicious_vendors = [
                    vendor
                    for vendor, result in last_results.items()
                    if result.get("category") in ("malware", "phishing")
                ][:5]

                return {
                    "status": "success",
                    "url": url,
                    "vt_scan_id": scan_id,
                    "malicious_count": malicious_count,
                    "suspicious_count": suspicious_count,
                    "reputation_score": reputation_score,
                    "vendors": malicious_vendors,
                    "last_scan_date": str(attrs.get("date", "")),
                    "categories": attrs.get("categories", {}),
                }

    except asyncio.TimeoutError:
        logger.warning("VirusTotal provider timeout")
        return {
            "status": "timeout",
            "url": url,
            "message": "VirusTotal request timed out",
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 50,
            "vendors": [],
        }
    except Exception as e:
        logger.error("VirusTotal provider failure")
        return {
            "status": "error",
            "url": url,
            "error": str(e),
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 50,
            "vendors": [],
        }
