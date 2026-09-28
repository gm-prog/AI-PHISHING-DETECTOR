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
    Analyze a URL using the VirusTotal v3 API.

    Returns normalized contract with keys:
        status, malicious_count, suspicious_count, reputation_score, vendors.
    """
    if not api_key or not api_key.strip():
        return {
            "status": "skipped",
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 100,
            "vendors": [],
        }

    try:
        import aiohttp
    except ImportError:
        logger.error("provider=virustotal event=missing_dependency")
        return {
            "status": "error",
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 50,
            "vendors": [],
        }

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
                    logger.warning("provider=virustotal event=rate_limited")
                    return {
                        "status": "rate_limited",
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }
                if resp.status == 401:
                    logger.warning("provider=virustotal event=auth_failed")
                    return {
                        "status": "error",
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }
                if resp.status != 200:
                    logger.warning("provider=virustotal event=submit_failed status=%s", resp.status)
                    return {
                        "status": "error",
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }

                submit_result = await resp.json()
                scan_id = submit_result.get("data", {}).get("id", "")

            if not scan_id:
                return {
                    "status": "error",
                    "malicious_count": 0,
                    "suspicious_count": 0,
                    "reputation_score": 50,
                    "vendors": [],
                }

            # Step 2: Fetch scan results
            async with session.get(
                f"https://www.virustotal.com/api/v3/analyses/{scan_id}",
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=8),
            ) as resp2:
                if resp2.status != 200:
                    logger.warning("provider=virustotal event=fetch_failed status=%s", resp2.status)
                    return {
                        "status": "error",
                        "malicious_count": 0,
                        "suspicious_count": 0,
                        "reputation_score": 50,
                        "vendors": [],
                    }

                data = await resp2.json()
                attrs = data.get("data", {}).get("attributes", {})
                stats = attrs.get("stats", {})
                last_results = attrs.get("results", {})

                malicious_count = int(stats.get("malicious", 0))
                suspicious_count = int(stats.get("suspicious", 0))

                # Reputation: 100 = clean, reduced by detections
                reputation_score = max(0, 100 - (malicious_count * 10) - (suspicious_count * 3))

                # Collect vendor names that flagged as malware/phishing (top 5)
                malicious_vendors = [
                    str(vendor)
                    for vendor, result in last_results.items()
                    if isinstance(result, dict) and result.get("category") in ("malware", "phishing")
                ][:5]

                return {
                    "status": "success",
                    "malicious_count": malicious_count,
                    "suspicious_count": suspicious_count,
                    "reputation_score": reputation_score,
                    "vendors": malicious_vendors,
                }

    except asyncio.TimeoutError:
        logger.warning("provider=virustotal event=timeout")
        return {
            "status": "timeout",
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 50,
            "vendors": [],
        }
    except Exception:
        logger.error("provider=virustotal event=unexpected_error")
        return {
            "status": "error",
            "malicious_count": 0,
            "suspicious_count": 0,
            "reputation_score": 50,
            "vendors": [],
        }
