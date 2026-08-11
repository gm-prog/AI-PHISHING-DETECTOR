"""
File: backend/app/services/urlhaus_service.py
Purpose: URLhaus malware/phishing database check — no authentication required
API: https://urlhaus-api.abuse.ch/v1/
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


async def check_url_with_urlhaus(url: str) -> Dict[str, Any]:
    """
    Check a URL against the URLhaus malware/phishing database.

    No API key required. Unlimited requests. 5s timeout.

    Returns:
        Dict with keys: status, url, in_database, threat_type,
        date_added, malware_families, raw_response.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://urlhaus-api.abuse.ch/v1/url/",
                data={"url": url},
                timeout=aiohttp.ClientTimeout(total=5),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            ) as response:
                if response.status != 200:
                    logger.warning(f"URLhaus API error: {response.status}")
                    return {
                        "status": "error",
                        "url": url,
                        "code": response.status,
                        "in_database": False,
                        "threat_type": None,
                        "date_added": "",
                        "malware_families": [],
                    }

                result = await response.json(content_type=None)
                query_status = result.get("query_status")

                if query_status == "no_results":
                    return {
                        "status": "success",
                        "url": url,
                        "in_database": False,
                        "threat_type": None,
                        "date_added": "",
                        "malware_families": [],
                    }

                elif query_status == "ok":
                    urls_data = result.get("urls", [])
                    # Aggregate threat types and tags across all URL entries
                    threat_type = result.get("threat") or (urls_data[0].get("threat") if urls_data else "unknown")
                    tags: list = []
                    for entry in urls_data:
                        for tag in (entry.get("tags") or []):
                            if tag not in tags:
                                tags.append(tag)
                    date_added = result.get("date_added") or (urls_data[0].get("date_added") if urls_data else "")

                    return {
                        "status": "success",
                        "url": url,
                        "in_database": True,
                        "threat_type": threat_type or "unknown",
                        "date_added": date_added,
                        "malware_families": tags,
                        "raw_response": result,
                    }

                else:
                    return {
                        "status": "error",
                        "url": url,
                        "message": f"Unexpected query_status: {query_status}",
                        "in_database": False,
                        "threat_type": None,
                        "date_added": "",
                        "malware_families": [],
                    }

    except asyncio.TimeoutError:
        logger.warning(f"URLhaus timeout for URL: {url}")
        return {
            "status": "timeout",
            "url": url,
            "message": "URLhaus request timed out",
            "in_database": False,
            "threat_type": None,
            "date_added": "",
            "malware_families": [],
        }
    except Exception as e:
        logger.error(f"URLhaus unexpected error: {str(e)}")
        return {
            "status": "error",
            "url": url,
            "error": str(e),
            "in_database": False,
            "threat_type": None,
            "date_added": "",
            "malware_families": [],
        }
