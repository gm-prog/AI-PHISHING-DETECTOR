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

    Returns normalized contract with keys:
        status, in_database, threat_type, date_added, malware_families.
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
                    logger.warning("provider=urlhaus event=api_error status=%s", response.status)
                    return {
                        "status": "error",
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
                        "in_database": False,
                        "threat_type": None,
                        "date_added": "",
                        "malware_families": [],
                    }

                elif query_status == "ok":
                    urls_data = result.get("urls", [])
                    threat_type = result.get("threat") or (urls_data[0].get("threat") if urls_data else "unknown")
                    tags: list = []
                    for entry in urls_data:
                        for tag in (entry.get("tags") or []):
                            if tag not in tags:
                                tags.append(str(tag))
                    date_added = str(result.get("date_added") or (urls_data[0].get("date_added") if urls_data else ""))

                    return {
                        "status": "success",
                        "in_database": True,
                        "threat_type": str(threat_type) if threat_type else "unknown",
                        "date_added": date_added,
                        "malware_families": tags,
                    }

                else:
                    logger.warning("provider=urlhaus event=unexpected_query_status")
                    return {
                        "status": "error",
                        "in_database": False,
                        "threat_type": None,
                        "date_added": "",
                        "malware_families": [],
                    }

    except asyncio.TimeoutError:
        logger.warning("provider=urlhaus event=timeout")
        return {
            "status": "timeout",
            "in_database": False,
            "threat_type": None,
            "date_added": "",
            "malware_families": [],
        }
    except Exception:
        logger.error("provider=urlhaus event=unexpected_error")
        return {
            "status": "error",
            "in_database": False,
            "threat_type": None,
            "date_added": "",
            "malware_families": [],
        }
