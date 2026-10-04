"""
File: backend/app/services/threat_feed_service.py
Purpose: Production Normalized Threat Intelligence Feed Ingestion, Storage, Deduplication,
Lifecycle, Freshness, and Evidence Fusion Layer.
"""

import asyncio
import bz2
import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Protocol, Tuple, runtime_checkable, Union
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import aiohttp
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, or_, func

from app.config import settings
from app.models.domain import ThreatIndicator, ThreatFeedState
from app.services.provider_guard import threat_feed_semaphore

logger = logging.getLogger(__name__)

# Hierarchy of classification severity for deterministic primary classification
SEVERITY_HIERARCHY = {
    "malware": 1,
    "c2": 2,
    "credential_harvesting": 3,
    "phishing": 4,
    "scam": 5,
    "suspicious": 6,
}


@dataclass
class NormalizedThreatIndicator:
    source: str
    indicator_type: str  # "url", "domain", "ip", "hash"
    indicator: str
    classification: str  # "phishing", "malware", "c2", "scam", "credential_harvesting"
    confidence: float = 1.0
    observed_at: Optional[Union[str, datetime]] = None
    expires_at: Optional[Union[str, datetime]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ThreatEvidence:
    source: str
    evidence_type: str  # "verified_feed_match", "confirmed_provider_match", "strong_authentication_failure", "weak_untrusted_claim", "heuristic_signal", "provider_unavailable", "clear"
    indicator_type: str
    indicator: str
    classification: str
    confidence: float
    freshness: str
    observed_at: Optional[str] = None
    expires_at: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@runtime_checkable
class ThreatFeedProvider(Protocol):
    source_name: str
    indicator_types: List[str]
    supports_etag: bool
    supports_last_modified: bool
    default_refresh_interval_seconds: int
    fetch_limit: int
    is_enabled: bool

    async def fetch_indicators(
        self,
        limit: int = 1000,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> Tuple[List[NormalizedThreatIndicator], Optional[str], Optional[str], bool]:
        """
        Fetch indicators from feed provider.
        Returns: (indicators, new_etag, new_last_modified, not_modified_flag)
        """
        ...


_source_locks: Dict[str, asyncio.Lock] = {}
_source_locks_guard = asyncio.Lock()


async def get_source_refresh_lock(source_name: str) -> asyncio.Lock:
    """Returns per-source mutex to prevent concurrent refresh races on the same feed source."""
    async with _source_locks_guard:
        if source_name not in _source_locks:
            _source_locks[source_name] = asyncio.Lock()
        return _source_locks[source_name]


async def bounded_fetch_stream(
    session: aiohttp.ClientSession,
    url: str,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Any] = None,
    max_bytes: int = 33554432,
    timeout_seconds: float = 10.0,
    method: str = "GET",
    json_body: Optional[Any] = None,
) -> Tuple[int, bytes, Dict[str, str]]:
    """
    Fetch a remote feed resource with a hard streaming byte limit and connection/read timeout.
    Returns: (status_code, content_bytes, response_headers).
    Raises ValueError if content exceeds max_bytes.
    """
    timeout = aiohttp.ClientTimeout(total=timeout_seconds, connect=5.0)
    async with session.request(
        method,
        url,
        headers=headers,
        params=params,
        json=json_body,
        timeout=timeout,
        allow_redirects=False,
    ) as response:
        status = response.status
        resp_headers = {k.lower(): v for k, v in response.headers.items()}
        if status == 304:
            return 304, b"", resp_headers
        if status != 200:
            return status, b"", resp_headers

        chunks = []
        total_read = 0
        while True:
            chunk = await response.content.read(65536)
            if not chunk:
                break
            total_read += len(chunk)
            if total_read > max_bytes:
                raise ValueError(f"Provider response exceeded maximum allowed size of {max_bytes} bytes")
            chunks.append(chunk)

        return status, b"".join(chunks), resp_headers


def decompress_bz2_bounded(
    compressed_bytes: bytes,
    max_decompressed_bytes: int = 67108864,
) -> bytes:
    """
    Decompresses a BZ2 stream in bounded chunks to protect against decompression bombs and malformed streams.
    Enforces that the stream reaches a valid EOF marker.
    Raises ValueError on invalid stream, truncated stream, or if decompressed size exceeds max_decompressed_bytes.
    """
    if not compressed_bytes:
        raise ValueError("Invalid BZ2 stream: empty payload")

    decompressor = bz2.BZ2Decompressor()
    decompressed_chunks = []
    total_decompressed = 0
    chunk_size = 65536

    try:
        offset = 0
        input_len = len(compressed_bytes)
        while offset < input_len:
            in_slice = compressed_bytes[offset:offset + chunk_size]
            offset += len(in_slice)
            out_chunk = decompressor.decompress(in_slice)
            if out_chunk:
                total_decompressed += len(out_chunk)
                if total_decompressed > max_decompressed_bytes:
                    raise ValueError(
                        f"Decompressed feed size exceeded maximum limit of {max_decompressed_bytes} bytes"
                    )
                decompressed_chunks.append(out_chunk)
            if decompressor.eof:
                break

        if not decompressor.eof:
            raise ValueError("Invalid or truncated BZ2 stream: stream did not reach EOF marker")

    except ValueError:
        raise
    except (OSError, EOFError) as e:
        raise ValueError(f"Invalid BZ2 stream: {type(e).__name__}") from e

    return b"".join(decompressed_chunks)


def build_phishtank_url(base_url: str, api_key: Optional[str]) -> str:
    """
    Constructs the documented PhishTank downloadable feed URL.
    - If API key is present: http(s)://data.phishtank.com/data/<app_key>/online-valid.json.bz2 (or .json)
    - If no API key: http(s)://data.phishtank.com/data/online-valid.json.bz2 (or .json)
    """
    clean_url = (base_url or "").strip()
    if not api_key or not str(api_key).strip():
        return clean_url
    clean_key = str(api_key).strip()

    if "/data/online-valid." in clean_url:
        return clean_url.replace("/data/online-valid.", f"/data/{clean_key}/online-valid.")
    elif "<key>" in clean_url:
        return clean_url.replace("<key>", clean_key)
    elif "{app_key}" in clean_url:
        return clean_url.replace("{app_key}", clean_key)
    elif f"/data/{clean_key}/" in clean_url:
        return clean_url
    elif clean_url.endswith("/data") or clean_url.endswith("/data/"):
        return f"{clean_url.rstrip('/')}/{clean_key}/online-valid.json.bz2"
    return clean_url


class PhishTankFeedProvider:
    """Production provider for PhishTank verified/online phishing URL feed."""
    source_name = "phishtank"
    indicator_types = ["url"]
    supports_etag = True
    supports_last_modified = True
    default_refresh_interval_seconds = 7200
    fetch_limit = 10000
    is_enabled = True
    allow_empty_snapshot = False

    def __init__(self, api_key: Optional[str] = None, feed_url: Optional[str] = None):
        self.api_key = api_key or settings.PHISHTANK_API_KEY
        self.feed_url = feed_url or settings.PHISHTANK_FEED_URL

    async def fetch_indicators(
        self,
        limit: int = 10000,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> Tuple[List[NormalizedThreatIndicator], Optional[str], Optional[str], bool]:
        headers = {
            "User-Agent": "phishtank/sentinel-ai (PhishingDetector; security@sentinel.local)",
            "Accept": "application/json, application/x-bzip2, */*",
        }
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        target_url = build_phishtank_url(self.feed_url, self.api_key)

        async with aiohttp.ClientSession() as session:
            status, body, resp_headers = await bounded_fetch_stream(
                session,
                target_url,
                headers=headers,
                max_bytes=settings.THREAT_FEED_MAX_RESPONSE_BYTES,
                timeout_seconds=settings.THREAT_FEED_TIMEOUT_SECONDS,
            )

            if status == 304:
                return [], etag, last_modified, True

            if status != 200:
                raise RuntimeError(f"PhishTank upstream HTTP error: {status}")

            new_etag = resp_headers.get("etag")
            new_last_modified = resp_headers.get("last-modified")

            # Check if payload is BZ2 compressed
            is_bz2 = body.startswith(b"BZh") or target_url.endswith(".bz2") or "bzip2" in resp_headers.get("content-type", "")
            if is_bz2:
                decompressed_bytes = decompress_bz2_bounded(
                    body,
                    max_decompressed_bytes=settings.THREAT_FEED_MAX_DECOMPRESSED_BYTES,
                )
            else:
                decompressed_bytes = body

            try:
                raw_data = json.loads(decompressed_bytes.decode("utf-8", errors="replace"))
            except Exception as exc:
                raise ValueError("Malformed JSON after decompression") from exc

            if not isinstance(raw_data, list):
                raise ValueError("Unexpected PhishTank feed structure; expected list of phish records")

            indicators: List[NormalizedThreatIndicator] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for item in raw_data:
                if len(indicators) >= limit:
                    break
                if not isinstance(item, dict):
                    continue

                raw_url = item.get("url")
                if not raw_url or not isinstance(raw_url, str):
                    continue

                raw_verified = item.get("verified")
                raw_online = item.get("online")
                if raw_verified is None or raw_online is None:
                    continue
                v_str = str(raw_verified).lower()
                o_str = str(raw_online).lower()
                if v_str not in ("yes", "true", "1", "y") or o_str not in ("yes", "true", "1", "y"):
                    continue

                clean_url, _ = normalize_indicator_value("url", raw_url)
                if not clean_url or not clean_url.startswith(("http://", "https://")):
                    continue

                obs_time = parse_and_normalize_utc_iso(
                    item.get("verification_time") or item.get("submission_time")
                ) or now_iso

                phish_id = item.get("phish_id")
                target = item.get("target")

                indicators.append(
                    NormalizedThreatIndicator(
                        source="phishtank",
                        indicator_type="url",
                        indicator=clean_url,
                        classification="phishing",
                        confidence=0.95,
                        observed_at=obs_time,
                        metadata={"phish_id": phish_id, "target": target} if (phish_id or target) else {},
                    )
                )

            return indicators, new_etag, new_last_modified, False


class OpenPhishFeedProvider:
    """Production provider for OpenPhish community feed."""
    source_name = "openphish"
    indicator_types = ["url"]
    supports_etag = True
    supports_last_modified = True
    default_refresh_interval_seconds = 21600
    fetch_limit = 10000
    is_enabled = True
    allow_empty_snapshot = False

    def __init__(self, feed_url: Optional[str] = None):
        self.feed_url = feed_url or settings.OPENPHISH_FEED_URL

    async def fetch_indicators(
        self,
        limit: int = 10000,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> Tuple[List[NormalizedThreatIndicator], Optional[str], Optional[str], bool]:
        headers = {
            "User-Agent": "SENTINEL-ThreatIntel/1.0 (OpenPhish Community Feed; security@sentinel.local)",
            "Accept": "text/plain",
        }
        if etag:
            headers["If-None-Match"] = etag
        if last_modified:
            headers["If-Modified-Since"] = last_modified

        async with aiohttp.ClientSession() as session:
            status, body, resp_headers = await bounded_fetch_stream(
                session,
                self.feed_url,
                headers=headers,
                max_bytes=settings.THREAT_FEED_MAX_RESPONSE_BYTES,
                timeout_seconds=settings.THREAT_FEED_TIMEOUT_SECONDS,
            )

            if status == 304:
                return [], etag, last_modified, True

            if status != 200:
                raise RuntimeError(f"OpenPhish upstream HTTP error: {status}")

            new_etag = resp_headers.get("etag")
            new_last_modified = resp_headers.get("last-modified")

            text = body.decode("utf-8", errors="replace")
            indicators: List[NormalizedThreatIndicator] = []
            seen_hashes = set()
            now_iso = datetime.now(timezone.utc).isoformat()

            for line in text.splitlines():
                if len(indicators) >= limit:
                    break
                raw_line = line.strip()
                if not raw_line or raw_line.startswith("#"):
                    continue

                clean_url, url_hash = normalize_indicator_value("url", raw_line)
                if not clean_url or not clean_url.startswith(("http://", "https://")):
                    continue

                if url_hash in seen_hashes:
                    continue
                seen_hashes.add(url_hash)

                indicators.append(
                    NormalizedThreatIndicator(
                        source="openphish",
                        indicator_type="url",
                        indicator=clean_url,
                        classification="phishing",
                        confidence=0.85,
                        observed_at=now_iso,
                        metadata={"feed": "community"},
                    )
                )

            return indicators, new_etag, new_last_modified, False


class MISPFeedProvider:
    """Production-capable adapter for MISP threat sharing instances."""
    source_name = "misp"
    indicator_types = ["url", "domain", "ip", "hash"]
    supports_etag = False
    supports_last_modified = False
    default_refresh_interval_seconds = 86400
    fetch_limit = 5000
    allow_empty_snapshot = False

    def __init__(self, api_key: Optional[str] = None, server_url: Optional[str] = None):
        self.api_key = api_key if api_key is not None else settings.MISP_API_KEY
        self.server_url = (server_url if server_url is not None else settings.MISP_SERVER_URL).rstrip("/")

    @property
    def is_enabled(self) -> bool:
        return bool(self.server_url and self.api_key)

    async def fetch_indicators(
        self,
        limit: int = 5000,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> Tuple[List[NormalizedThreatIndicator], Optional[str], Optional[str], bool]:
        if not self.is_enabled:
            logger.info("provider=misp event=disabled_not_configured")
            return [], None, None, False

        endpoint = f"{self.server_url}/attributes/restSearch"
        headers = {
            "Authorization": self.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "SENTINEL-ThreatIntel/1.0",
        }
        payload = {
            "returnFormat": "json",
            "type": ["url", "domain", "ip-dst", "sha256"],
            "limit": limit,
            "enforceWarninglist": True,
        }

        async with aiohttp.ClientSession() as session:
            status, body, resp_headers = await bounded_fetch_stream(
                session,
                endpoint,
                headers=headers,
                method="POST",
                json_body=payload,
                max_bytes=settings.THREAT_FEED_MAX_RESPONSE_BYTES,
                timeout_seconds=settings.THREAT_FEED_TIMEOUT_SECONDS,
            )

            if status != 200:
                raise RuntimeError(f"MISP upstream HTTP error: {status}")

            data = json.loads(body.decode("utf-8", errors="replace"))
            response_attr = data.get("response", {}).get("Attribute", []) if isinstance(data, dict) else []
            if not isinstance(response_attr, list):
                response_attr = []

            indicators: List[NormalizedThreatIndicator] = []
            now_iso = datetime.now(timezone.utc).isoformat()

            for attr in response_attr:
                if len(indicators) >= limit:
                    break
                if not isinstance(attr, dict):
                    continue

                attr_type = attr.get("type", "")
                raw_val = attr.get("value", "")
                if not raw_val or not isinstance(raw_val, str):
                    continue

                if attr_type == "url":
                    ind_type = "url"
                elif attr_type == "domain":
                    ind_type = "domain"
                elif attr_type in ("ip-dst", "ip"):
                    ind_type = "ip"
                elif attr_type in ("sha256", "md5", "sha1"):
                    ind_type = "hash"
                else:
                    continue

                clean_val, _ = normalize_indicator_value(ind_type, raw_val)
                if not clean_val:
                    continue

                category = str(attr.get("category", "")).lower()
                classification = "phishing" if "phish" in category else ("malware" if "payload" in category or "malware" in category else "suspicious")
                obs = parse_and_normalize_utc_iso(attr.get("timestamp")) or now_iso

                indicators.append(
                    NormalizedThreatIndicator(
                        source="misp",
                        indicator_type=ind_type,
                        indicator=clean_val,
                        classification=classification,
                        confidence=0.9,
                        observed_at=obs,
                        metadata={"category": category, "event_id": attr.get("event_id")},
                    )
                )

            return indicators, None, None, False

            type_mapping = {
                "url": "url",
                "domain": "domain",
                "ip-dst": "ip",
                "sha256": "hash",
            }

            for attr in response_attr:
                if len(indicators) >= limit:
                    break
                if not isinstance(attr, dict):
                    continue

                raw_val = attr.get("value")
                attr_type = attr.get("type")
                if not raw_val or not isinstance(raw_val, str) or attr_type not in type_mapping:
                    continue

                ind_type = type_mapping[attr_type]
                clean_val, _ = normalize_indicator_value(ind_type, raw_val)
                if not clean_val:
                    continue

                category = str(attr.get("category", "")).lower()
                classification = "phishing" if "phish" in category else ("malware" if "payload" in category or "malware" in category else "suspicious")
                obs = parse_and_normalize_utc_iso(attr.get("timestamp")) or now_iso

                indicators.append(
                    NormalizedThreatIndicator(
                        source="misp",
                        indicator_type=ind_type,
                        indicator=clean_val,
                        classification=classification,
                        confidence=0.9,
                        observed_at=obs,
                        metadata={"category": category, "event_id": attr.get("event_id")},
                    )
                )

            return indicators, None, None, False


def get_registered_providers() -> Dict[str, ThreatFeedProvider]:
    """Returns registry of configured threat feed providers."""
    return {
        "phishtank": PhishTankFeedProvider(),
        "openphish": OpenPhishFeedProvider(),
        "misp": MISPFeedProvider(),
    }


def parse_and_normalize_utc_iso(val: Any) -> Optional[str]:
    """
    Parses datetime, float/int epoch timestamp, or ISO string and returns canonical UTC ISO string.
    Format: YYYY-MM-DDTHH:MM:SS.ffffff+00:00 (or YYYY-MM-DDTHH:MM:SS+00:00).
    Returns None on invalid or None input.
    """
    if val is None:
        return None
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(val, tz=timezone.utc).isoformat()
        except Exception:
            return None
    if isinstance(val, datetime):
        if val.tzinfo is None:
            val = val.replace(tzinfo=timezone.utc)
        return val.astimezone(timezone.utc).isoformat()
    if isinstance(val, str):
        clean = val.strip()
        if not clean:
            return None
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(clean)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc).isoformat()
        except Exception:
            return None
    return None


def normalize_indicator_value(indicator_type: str, raw_value: str) -> Tuple[str, str]:
    """
    Normalizes an indicator value and produces a deterministic SHA-256 lookup hash.
    For URLs:
      - Lowercases scheme and hostname
      - Strips default ports (80 for http, 443 for https)
      - Normalizes empty path to '/' and collapses multiple slashes
      - Strips trailing slash on non-root paths (e.g. /path/ -> /path)
      - Strips URL fragments
      - Sorts query parameters deterministically by key and value
    For domains / IPs:
      - Lowercases and strips trailing dots/whitespace
    For hashes:
      - Lowercases and strips whitespace
    Returns (normalized_value, sha256_hash).
    """
    clean = (raw_value or "").strip()
    if not clean:
        return "", hashlib.sha256(b"").hexdigest()

    ind_type = indicator_type.lower()
    if ind_type == "url":
        try:
            parsed = urlsplit(clean)
            scheme = (parsed.scheme or "").lower()
            hostname = (parsed.hostname or "").lower()
            if not hostname or scheme not in ("http", "https"):
                return "", hashlib.sha256(b"").hexdigest()

            port = parsed.port
            if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
                netloc = f"{hostname}:{port}"
            else:
                netloc = hostname

            if parsed.username:
                userinfo = parsed.username
                if parsed.password:
                    userinfo += f":{parsed.password}"
                netloc = f"{userinfo}@{netloc}"

            # Path normalization
            path = parsed.path
            if not path or path == "":
                path = "/"
            else:
                path = re.sub(r'/{2,}', '/', path)
                if len(path) > 1 and path.endswith("/"):
                    path = path.rstrip("/")

            # Query parameter normalization: sorted by key and value
            query = ""
            if parsed.query:
                params = parse_qsl(parsed.query, keep_blank_values=True)
                sorted_params = sorted(params, key=lambda kv: (kv[0], kv[1]))
                query = urlencode(sorted_params)

            clean = urlunsplit((scheme, netloc, path, query, ""))
        except Exception:
            clean = clean.strip()
    elif ind_type in ("domain", "ip"):
        clean = clean.lower().rstrip(".")
    elif ind_type == "hash":
        clean = clean.lower()

    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()
    return clean, digest


def compute_freshness(
    last_success_at: Optional[str],
    last_attempt_at: Optional[str],
    last_error: Optional[str],
    refresh_interval_seconds: int = 86400,
    enabled: bool = True,
) -> str:
    """
    Computes deterministic freshness status:
    'disabled' | 'never_synced' | 'fresh' | 'stale' | 'expired' | 'failed'
    Contract:
    - fresh: elapsed <= 2 * refresh_interval
    - stale: 2 * interval < elapsed <= 4 * interval
    - expired: elapsed > 4 * interval
    - never_synced: no success, no error
    - failed: no success, error recorded
    - disabled: enabled is False
    """
    if not enabled:
        return "disabled"
    if not last_success_at:
        return "failed" if last_error else "never_synced"

    try:
        succ_iso = parse_and_normalize_utc_iso(last_success_at)
        if not succ_iso:
            return "never_synced"
        succ_dt = datetime.fromisoformat(succ_iso)
        now_dt = datetime.now(timezone.utc)
        elapsed = (now_dt - succ_dt).total_seconds()

        if elapsed <= refresh_interval_seconds * 2.0:
            return "fresh"
        elif elapsed <= refresh_interval_seconds * 4.0:
            return "stale"
        else:
            return "expired"
    except Exception:
        return "never_synced"


def get_all_feed_states(db: Session) -> List[Dict[str, Any]]:
    """
    Returns sanitized status list of all configured and registered threat feed sources.
    No secrets, API keys, or raw provider URLs are exposed.
    """
    providers = get_registered_providers()
    states_dict = {s.source: s for s in db.query(ThreatFeedState).all()}

    result = []
    for source_name, provider in providers.items():
        state = states_dict.get(source_name)
        enabled = getattr(provider, "is_enabled", True)

        last_success = state.last_success_at if state else None
        last_attempt = state.last_attempt_at if state else None
        last_error = state.last_error if state else None
        status = state.status if state else ("idle" if enabled else "disabled")
        interval = state.refresh_interval_seconds if state else getattr(provider, "default_refresh_interval_seconds", 86400)
        curr_gen = state.current_generation_id if state else None

        count = 0
        if curr_gen:
            count = db.query(func.count(ThreatIndicator.id)).filter(
                ThreatIndicator.source == source_name,
                ThreatIndicator.generation_id == curr_gen,
            ).scalar() or 0

        freshness = compute_freshness(last_success, last_attempt, last_error, interval, enabled)

        result.append({
            "source": source_name,
            "enabled": enabled,
            "status": status,
            "freshness": freshness,
            "last_success_at": last_success,
            "last_attempt_at": last_attempt,
            "indicator_count": count,
            "current_generation_id": curr_gen,
            "last_error_code": last_error,
        })

    return result


def lookup_threat_indicator(db: Session, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
    """
    Perform an indexed lookup using the SHA-256 hash index on ThreatIndicator.indicator_hash
    for active generation threat indicators across enabled threat feeds.
    Consolidates multi-source provenance deterministically.
    """
    if not value or not isinstance(value, str):
        return None

    clean_val, val_hash = normalize_indicator_value(indicator_type, value)
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()

    try:
        # Retrieve active current_generation_ids for all enabled threat feeds
        enabled_states = db.query(ThreatFeedState).filter(
            ThreatFeedState.enabled == True,
            ThreatFeedState.current_generation_id.isnot(None),
        ).all()
        if not enabled_states:
            return None

        active_gens = {s.source: s.current_generation_id for s in enabled_states}
        active_gen_ids = list(active_gens.values())

        # Query matching records by indexed indicator_hash, indicator_type, and active generation_id
        records = db.query(ThreatIndicator).filter(
            ThreatIndicator.indicator_type == indicator_type,
            ThreatIndicator.indicator_hash == val_hash,
            ThreatIndicator.generation_id.in_(active_gen_ids),
        ).all()

        if not records:
            return None

        # Double check generation matches source's active generation and filter out expired records
        active_records: List[ThreatIndicator] = []
        for r in records:
            if r.generation_id != active_gens.get(r.source):
                continue
            if r.expires_at is None:
                active_records.append(r)
            else:
                exp_iso = parse_and_normalize_utc_iso(r.expires_at)
                if exp_iso:
                    exp_dt = datetime.fromisoformat(exp_iso)
                    if exp_dt > now_utc:
                        active_records.append(r)

        if not active_records:
            return None

        sources = sorted(list({r.source for r in active_records}))

        # Sort classifications deterministically by severity hierarchy, then alphabetically
        unique_classes = list({r.classification for r in active_records if r.classification})
        sorted_classes = sorted(
            unique_classes,
            key=lambda c: (SEVERITY_HIERARCHY.get(c.lower(), 99), c.lower())
        )
        primary_class = sorted_classes[0] if sorted_classes else "phishing"

        max_confidence = max(r.confidence for r in active_records)
        observed_timestamps = [parse_and_normalize_utc_iso(r.observed_at) for r in active_records if r.observed_at]
        latest_observed = max(observed_timestamps) if observed_timestamps else now_iso

        expiry_timestamps = [parse_and_normalize_utc_iso(r.expires_at) for r in active_records if r.expires_at]
        earliest_expiry = min(expiry_timestamps) if expiry_timestamps else None

        # Determine overall feed freshness
        feed_states = db.query(ThreatFeedState).filter(ThreatFeedState.source.in_(sources)).all()
        freshness_values = [s.freshness for s in feed_states if s.freshness]
        overall_freshness = "fresh" if ("fresh" in freshness_values or not freshness_values) else ("stale" if "stale" in freshness_values else "expired")

        explanation = (
            f"Multiple independent threat intelligence feeds ({', '.join(sources)}) flag this resource as {primary_class}."
            if len(sources) > 1
            else f"Flagged by threat intelligence feed '{sources[0]}' as {primary_class}."
        )

        return {
            "is_match": True,
            "indicator_type": indicator_type,
            "indicator": clean_val,
            "sources": sources,
            "sources_summary": ", ".join(sources),
            "classification": primary_class,
            "all_classifications": sorted_classes,
            "confidence": max_confidence,
            "freshness": overall_freshness,
            "observed_at": latest_observed,
            "expires_at": earliest_expiry,
            "matched_records_count": len(active_records),
            "explanation": explanation,
        }
    except Exception:
        logger.error("event=threat_indicator_lookup_error", exc_info=False)
        return None


async def refresh_threat_feed(
    db: Session,
    provider: ThreatFeedProvider,
    max_records: Optional[int] = None,
    indicators: Optional[List[NormalizedThreatIndicator]] = None,
    timeout_seconds: Optional[float] = None,
) -> Dict[str, Any]:
    """
    Atomic refresh lifecycle:
    1. Acquire per-source refresh lock to serialize executions for this feed
    2. Fetch from provider under global concurrency semaphore
    3. Validate snapshot sanity (record counts, non-empty, valid fields)
    4. Stage records in isolated generation_id without mutating active generation
    5. Atomic activation: switch current_generation_id, prune old generation records, commit
    6. Rollback & Fail-safe: on any error, roll back staging, retain previous healthy generation
    """
    source_name = getattr(provider, "source_name", "unknown")
    limit = max_records or getattr(provider, "fetch_limit", settings.THREAT_FEED_MAX_RECORDS)
    timeout = timeout_seconds or settings.THREAT_FEED_TIMEOUT_SECONDS
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()
    start_time = asyncio.get_event_loop().time()
    allow_empty = getattr(provider, "allow_empty_snapshot", False)

    source_lock = await get_source_refresh_lock(source_name)
    async with source_lock:
        state = db.query(ThreatFeedState).filter_by(source=source_name).first()
        if not state:
            state = ThreatFeedState(
                source=source_name,
                enabled=getattr(provider, "is_enabled", True),
                status="idle",
                freshness="never_synced",
                refresh_interval_seconds=getattr(provider, "default_refresh_interval_seconds", 86400),
                updated_at=now_iso,
            )
            db.add(state)
            db.commit()
            db.refresh(state)

        state.last_attempt_at = now_iso
        state.status = "fetching"
        db.commit()

        items: List[NormalizedThreatIndicator] = []
        not_modified = False
        new_etag = state.etag
        new_last_modified = state.last_modified

        if indicators is not None:
            items = indicators[:limit]
        else:
            if not getattr(provider, "is_enabled", True):
                state.status = "disabled"
                state.freshness = "disabled"
                db.commit()
                return {
                    "source": source_name,
                    "status": "disabled",
                    "records_processed": 0,
                    "records_inserted": 0,
                    "records_updated": 0,
                    "duration_ms": 0,
                    "generation_id": state.current_generation_id,
                    "freshness": "disabled",
                }

            try:
                async with threat_feed_semaphore:
                    fetch_coro = provider.fetch_indicators(
                        limit=limit,
                        etag=state.etag if getattr(provider, "supports_etag", False) else None,
                        last_modified=state.last_modified if getattr(provider, "supports_last_modified", False) else None,
                    )
                    items, new_etag, new_last_modified, not_modified = await asyncio.wait_for(
                        fetch_coro, timeout=timeout
                    )
            except asyncio.TimeoutError:
                state.status = "failed"
                state.last_error = "timeout"
                state.freshness = compute_freshness(state.last_success_at, now_iso, "timeout", state.refresh_interval_seconds, state.enabled)
                state.updated_at = now_iso
                db.commit()
                duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
                return {
                    "source": source_name,
                    "status": "timeout",
                    "error_code": "timeout",
                    "records_processed": 0,
                    "records_inserted": 0,
                    "records_updated": 0,
                    "duration_ms": duration_ms,
                    "generation_id": state.current_generation_id,
                    "freshness": state.freshness,
                }
            except ValueError as ve:
                err_str = str(ve).lower()
                if "decompressed" in err_str:
                    err_code = "decompression_too_large"
                elif "bz2" in err_str:
                    err_code = "decompression_invalid"
                elif "exceeded" in err_str:
                    err_code = "too_large"
                else:
                    err_code = "invalid_payload"
                state.status = "failed"
                state.last_error = err_code
                state.freshness = compute_freshness(state.last_success_at, now_iso, err_code, state.refresh_interval_seconds, state.enabled)
                state.updated_at = now_iso
                db.commit()
                duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
                return {
                    "source": source_name,
                    "status": "failed",
                    "error_code": err_code,
                    "records_processed": 0,
                    "records_inserted": 0,
                    "records_updated": 0,
                    "duration_ms": duration_ms,
                    "generation_id": state.current_generation_id,
                    "freshness": state.freshness,
                }
            except Exception as exc:
                err_msg = str(exc).lower()
                if "401" in err_msg or "403" in err_msg or "auth" in err_msg:
                    err_code = "auth_error"
                elif "http" in err_msg or "connection" in err_msg or "client" in err_msg:
                    err_code = "network_error"
                else:
                    err_code = "invalid_payload"
                state.status = "failed"
                state.last_error = err_code
                state.freshness = compute_freshness(state.last_success_at, now_iso, err_code, state.refresh_interval_seconds, state.enabled)
                state.updated_at = now_iso
                db.commit()
                duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
                return {
                    "source": source_name,
                    "status": "failed",
                    "error_code": err_code,
                    "records_processed": 0,
                    "records_inserted": 0,
                    "records_updated": 0,
                    "duration_ms": duration_ms,
                    "generation_id": state.current_generation_id,
                    "freshness": state.freshness,
                }

        if not_modified:
            state.status = "success"
            state.last_success_at = now_iso
            state.last_error = None
            state.freshness = "fresh"
            state.updated_at = now_iso
            db.commit()
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            return {
                "source": source_name,
                "status": "not_modified",
                "records_processed": 0,
                "records_inserted": 0,
                "records_updated": 0,
                "duration_ms": duration_ms,
                "generation_id": state.current_generation_id,
                "freshness": "fresh",
            }

        # Step 3: Snapshot Sanity Validation
        state.status = "validating"
        db.commit()

        if len(items) == 0 and not allow_empty:
            state.status = "failed"
            state.last_error = "snapshot_validation_failed_empty"
            state.freshness = compute_freshness(state.last_success_at, now_iso, "snapshot_validation_failed_empty", state.refresh_interval_seconds, state.enabled)
            state.updated_at = now_iso
            db.commit()
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            return {
                "source": source_name,
                "status": "failed",
                "error_code": "snapshot_validation_failed_empty",
                "records_processed": 0,
                "records_inserted": 0,
                "records_updated": 0,
                "duration_ms": duration_ms,
                "generation_id": state.current_generation_id,
                "freshness": state.freshness,
            }

        # Step 4: Staging into new isolated generation
        state.status = "staging"
        db.commit()

        generation_id = str(uuid.uuid4())
        valid_records: List[ThreatIndicator] = []
        seen_in_batch = set()

        for item in items:
            if not isinstance(item, NormalizedThreatIndicator):
                continue
            clean_ind, ind_hash = normalize_indicator_value(item.indicator_type, item.indicator)
            if not clean_ind:
                continue

            cls = (item.classification or "").lower()
            if cls not in SEVERITY_HIERARCHY and cls != "suspicious":
                cls = "phishing"

            conf = max(0.0, min(1.0, float(item.confidence) if item.confidence is not None else 1.0))

            dedup_key = (item.indicator_type, ind_hash)
            if dedup_key in seen_in_batch:
                continue
            seen_in_batch.add(dedup_key)

            observed = parse_and_normalize_utc_iso(item.observed_at) or now_iso
            expires = parse_and_normalize_utc_iso(item.expires_at)

            rec = ThreatIndicator(
                id=str(uuid.uuid4()),
                source=source_name,
                generation_id=generation_id,
                indicator_type=item.indicator_type,
                indicator=clean_ind,
                indicator_hash=ind_hash,
                classification=cls,
                confidence=conf,
                observed_at=observed,
                expires_at=expires,
                created_at=now_iso,
                updated_at=now_iso,
            )
            valid_records.append(rec)

        if len(valid_records) == 0 and not allow_empty:
            state.status = "failed"
            state.last_error = "snapshot_validation_failed_no_valid_records"
            state.freshness = compute_freshness(state.last_success_at, now_iso, "snapshot_validation_failed_no_valid_records", state.refresh_interval_seconds, state.enabled)
            state.updated_at = now_iso
            db.commit()
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            return {
                "source": source_name,
                "status": "failed",
                "error_code": "snapshot_validation_failed_no_valid_records",
                "records_processed": len(items),
                "records_inserted": 0,
                "records_updated": 0,
                "duration_ms": duration_ms,
                "generation_id": state.current_generation_id,
                "freshness": state.freshness,
            }

        # Step 5: Atomic Activation & Pruning
        state.status = "committing"
        db.commit()

        try:
            if valid_records:
                db.bulk_save_objects(valid_records)

            state.current_generation_id = generation_id
            state.status = "success"
            state.last_success_at = now_iso
            state.last_success_count = len(valid_records)
            state.last_error = None
            state.etag = new_etag
            state.last_modified = new_last_modified
            state.freshness = "fresh"
            state.updated_at = now_iso

            db.query(ThreatIndicator).filter(
                ThreatIndicator.source == source_name,
                ThreatIndicator.generation_id != generation_id,
            ).delete(synchronize_session=False)

            db.commit()

            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            logger.info(
                "event=threat_feed_refresh_success source=%s gen=%s count=%d",
                source_name,
                generation_id,
                len(valid_records),
            )
            return {
                "source": source_name,
                "status": "success",
                "records_processed": len(items),
                "records_inserted": len(valid_records),
                "records_updated": 0,
                "duration_ms": duration_ms,
                "generation_id": generation_id,
                "freshness": "fresh",
            }
        except Exception:
            db.rollback()
            state.status = "failed"
            state.last_error = "db_commit_error"
            state.freshness = compute_freshness(state.last_success_at, now_iso, "db_commit_error", state.refresh_interval_seconds, state.enabled)
            state.updated_at = now_iso
            try:
                db.commit()
            except Exception:
                logger.debug("event=threat_feed_state_rollback_failed", exc_info=False)
            duration_ms = int((asyncio.get_event_loop().time() - start_time) * 1000)
            return {
                "source": source_name,
                "status": "failed",
                "error_code": "db_commit_error",
                "records_processed": 0,
                "records_inserted": 0,
                "records_updated": 0,
                "duration_ms": duration_ms,
                "generation_id": state.current_generation_id,
                "freshness": state.freshness,
            }


async def refresh_all_threat_feeds(
    db: Session,
    providers: Optional[List[ThreatFeedProvider]] = None,
) -> List[Dict[str, Any]]:
    """Synchronize all registered threat feeds sequentially with bounded execution."""
    feed_providers = providers or list(get_registered_providers().values())
    results = []
    for prov in feed_providers:
        res = await refresh_threat_feed(db, prov)
        results.append(res)
    return results
