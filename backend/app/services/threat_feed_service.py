"""
File: backend/app/services/threat_feed_service.py
Purpose: Normalized Threat Intelligence Feed aggregation, storage, deduplication, and lookup layer.
"""

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Protocol, Tuple, runtime_checkable, Union
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, or_

from app.models.domain import ThreatIndicator

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


@runtime_checkable
class ThreatFeedProvider(Protocol):
    source_name: str

    async def fetch_indicators(self, limit: int = 1000) -> List[NormalizedThreatIndicator]:
        """Fetch and return a list of normalized threat indicators from the feed."""
        ...


class PhishTankFeedProvider:
    """Provider placeholder for PhishTank verified phishing feed."""
    source_name = "phishtank"

    def __init__(self, api_key: Optional[str] = None, feed_url: Optional[str] = None):
        self.api_key = api_key
        self.feed_url = feed_url or "https://data.phishtank.com/data/online-valid.json"

    async def fetch_indicators(self, limit: int = 1000) -> List[NormalizedThreatIndicator]:
        # Placeholder for network crawler ingestion
        return []


class MISPFeedProvider:
    """Provider placeholder for MISP threat sharing feed."""
    source_name = "misp"

    def __init__(self, api_key: Optional[str] = None, server_url: Optional[str] = None):
        self.api_key = api_key
        self.server_url = server_url

    async def fetch_indicators(self, limit: int = 1000) -> List[NormalizedThreatIndicator]:
        # Placeholder for network crawler ingestion
        return []


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
            scheme = (parsed.scheme or "http").lower()
            hostname = (parsed.hostname or "").lower()

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


def lookup_threat_indicator(db: Session, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
    """
    Perform an indexed lookup using the SHA-256 hash index on ThreatIndicator.indicator_hash
    for active (non-expired) threat indicators in the local intelligence database.
    Consolidates multi-source provenance deterministically.
    """
    if not value or not isinstance(value, str):
        return None

    clean_val, val_hash = normalize_indicator_value(indicator_type, value)
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()

    try:
        # Query matching records by indexed indicator_hash and indicator_type
        records = db.query(ThreatIndicator).filter(
            ThreatIndicator.indicator_type == indicator_type,
            ThreatIndicator.indicator_hash == val_hash,
        ).all()

        if not records:
            return None

        # Filter out expired records using strict UTC parsing
        active_records: List[ThreatIndicator] = []
        for r in records:
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

        return {
            "is_match": True,
            "indicator_type": indicator_type,
            "indicator": clean_val,
            "sources": sources,
            "sources_summary": ", ".join(sources),
            "classification": primary_class,
            "all_classifications": sorted_classes,
            "confidence": max_confidence,
            "observed_at": latest_observed,
            "expires_at": earliest_expiry,
            "matched_records_count": len(active_records),
        }
    except Exception:
        logger.error("event=threat_indicator_lookup_error", exc_info=False)
        return None


async def refresh_threat_feed(
    db: Session,
    provider: ThreatFeedProvider,
    max_records: int = 1000,
    indicators: Optional[List[NormalizedThreatIndicator]] = None,
    timeout_seconds: float = 10.0,
) -> Dict[str, Any]:
    """
    Synchronizes local threat database with indicators from a feed provider.
    - If `indicators` is provided, processes injected indicator list directly.
    - Otherwise, invokes `await provider.fetch_indicators(limit=max_records)` with bounded timeout.
    - Normalizes UTC timestamps and indicator values deterministically.
    """
    source_name = getattr(provider, "source_name", "unknown")
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()

    items: List[NormalizedThreatIndicator] = []
    if indicators is not None:
        items = indicators[:max_records]
    else:
        try:
            fetch_coro = provider.fetch_indicators(limit=max_records)
            fetched = await asyncio.wait_for(fetch_coro, timeout=timeout_seconds)
            if isinstance(fetched, list):
                items = fetched[:max_records]
        except asyncio.TimeoutError:
            logger.warning("event=threat_feed_fetch_timeout source=%s", source_name)
            return {
                "source": source_name,
                "inserted": 0,
                "updated": 0,
                "total_processed": 0,
                "status": "timeout",
            }
        except Exception:
            logger.error("event=threat_feed_fetch_error source=%s", source_name, exc_info=False)
            return {
                "source": source_name,
                "inserted": 0,
                "updated": 0,
                "total_processed": 0,
                "status": "error",
            }

    inserted_count = 0
    updated_count = 0

    try:
        for item in items:
            clean_ind, ind_hash = normalize_indicator_value(item.indicator_type, item.indicator)
            observed = parse_and_normalize_utc_iso(item.observed_at) or now_iso
            expires = parse_and_normalize_utc_iso(item.expires_at)

            # Check if record already exists
            existing = db.query(ThreatIndicator).filter(
                ThreatIndicator.source == source_name,
                ThreatIndicator.indicator_type == item.indicator_type,
                ThreatIndicator.indicator_hash == ind_hash,
            ).first()

            if existing:
                existing.indicator = clean_ind
                existing.classification = item.classification
                existing.confidence = item.confidence
                existing.observed_at = observed
                existing.expires_at = expires
                existing.updated_at = now_iso
                updated_count += 1
            else:
                new_record = ThreatIndicator(
                    source=source_name,
                    indicator_type=item.indicator_type,
                    indicator=clean_ind,
                    indicator_hash=ind_hash,
                    classification=item.classification,
                    confidence=item.confidence,
                    observed_at=observed,
                    expires_at=expires,
                    created_at=now_iso,
                    updated_at=now_iso,
                )
                db.add(new_record)
                inserted_count += 1

        db.commit()

        logger.info(
            "event=threat_feed_refresh source=%s inserted=%d updated=%d total_processed=%d",
            source_name,
            inserted_count,
            updated_count,
            len(items),
        )

        return {
            "source": source_name,
            "inserted": inserted_count,
            "updated": updated_count,
            "total_processed": len(items),
            "status": "success",
        }
    except Exception:
        db.rollback()
        logger.error("event=threat_feed_refresh_error source=%s", source_name, exc_info=False)
        return {
            "source": source_name,
            "inserted": 0,
            "updated": 0,
            "total_processed": 0,
            "status": "error",
        }


async def refresh_all_threat_feeds(
    db: Session,
    providers: Optional[List[ThreatFeedProvider]] = None,
) -> List[Dict[str, Any]]:
    """Synchronize all registered threat feeds sequentially with bounded execution."""
    feed_providers = providers or [PhishTankFeedProvider(), MISPFeedProvider()]
    results = []
    for prov in feed_providers:
        res = await refresh_threat_feed(db, prov)
        results.append(res)
    return results
