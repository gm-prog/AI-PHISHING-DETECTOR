"""
File: backend/app/services/webrisk_service.py
Purpose: Google Web Risk Lookup API integration for URL threat intelligence
API: https://webrisk.googleapis.com/v1/uris:search
Terms Notice: Google Web Risk intelligence is queried server-side for real-time
threat detection and must not be redistributed outside the constraints of Google's service terms.
"""

import aiohttp
import asyncio
import logging
from typing import Dict, Any, List
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

WEBRISK_LOOKUP_URL = "https://webrisk.googleapis.com/v1/uris:search"

SUPPORTED_THREAT_TYPES = [
    "SOCIAL_ENGINEERING",
    "MALWARE",
    "UNWANTED_SOFTWARE",
]


def _is_valid_url(url: str) -> bool:
    """Validate that input has a valid http(s) scheme and netloc before making network requests."""
    try:
        parsed = urlsplit(url.strip())
        return parsed.scheme in {"http", "https"} and bool(parsed.netloc)
    except Exception:
        return False


async def check_url_with_webrisk(url: str, api_key: str) -> Dict[str, Any]:
    """
    Check a URL against the Google Web Risk Lookup API.

    Returns normalized sanitized contract:
        status: "success" | "skipped" | "timeout" | "error"
        url: target URL string
        in_database: bool
        threat_types: List[str]
    """
    clean_url = url.strip() if url else ""

    if not api_key or not api_key.strip():
        return {
            "status": "skipped",
            "url": clean_url,
            "in_database": False,
            "threat_types": [],
        }

    if not clean_url or not _is_valid_url(clean_url):
        logger.warning("provider=webrisk event=invalid_url")
        return {
            "status": "error",
            "url": clean_url,
            "in_database": False,
            "threat_types": [],
        }

    params = [
        ("key", api_key.strip()),
        ("uri", clean_url),
    ]
    for threat_type in SUPPORTED_THREAT_TYPES:
        params.append(("threatTypes", threat_type))

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                WEBRISK_LOOKUP_URL,
                params=params,
                timeout=aiohttp.ClientTimeout(total=5),
            ) as response:
                if response.status in {400, 401, 403}:
                    logger.warning("provider=webrisk event=auth_or_client_error status=%s", response.status)
                    return {
                        "status": "error",
                        "url": clean_url,
                        "in_database": False,
                        "threat_types": [],
                    }

                if response.status != 200:
                    logger.warning("provider=webrisk event=api_error status=%s", response.status)
                    return {
                        "status": "error",
                        "url": clean_url,
                        "in_database": False,
                        "threat_types": [],
                    }

                result = await response.json(content_type=None)
                if not isinstance(result, dict):
                    logger.warning("provider=webrisk event=unexpected_response_format")
                    return {
                        "status": "error",
                        "url": clean_url,
                        "in_database": False,
                        "threat_types": [],
                    }

                threat = result.get("threat")
                if threat and isinstance(threat, dict):
                    raw_types = threat.get("threatTypes", [])
                    threat_types: List[str] = [str(t) for t in raw_types if isinstance(t, str)]
                    return {
                        "status": "success",
                        "url": clean_url,
                        "in_database": len(threat_types) > 0,
                        "threat_types": threat_types,
                    }
                else:
                    return {
                        "status": "success",
                        "url": clean_url,
                        "in_database": False,
                        "threat_types": [],
                    }

    except asyncio.TimeoutError:
        logger.warning("provider=webrisk event=timeout")
        return {
            "status": "timeout",
            "url": clean_url,
            "in_database": False,
            "threat_types": [],
        }
    except Exception:
        logger.error("provider=webrisk event=unexpected_error")
        return {
            "status": "error",
            "url": clean_url,
            "in_database": False,
            "threat_types": [],
        }
