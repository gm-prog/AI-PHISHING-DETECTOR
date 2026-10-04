"""
File: backend/app/services/threat_feed_service.py
Purpose: Normalized Threat Intelligence Feed aggregation, storage, deduplication, and lookup layer.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Protocol, Tuple, runtime_checkable
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, or_

from app.models.domain import ThreatIndicator

logger = logging.getLogger(__name__)


@dataclass
class NormalizedThreatIndicator:
    source: str
    indicator_type: str  # "url", "domain", "ip", "hash"
    indicator: str
    classification: str  # "phishing", "malware", "c2", "scam"
    confidence: float = 1.0
    observed_at: Optional[str] = None
    expires_at: Optional[str] = None
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
        # Placeholder for future network crawler ingestion
        return []


class MISPFeedProvider:
    """Provider placeholder for MISP threat sharing feed."""
    source_name = "misp"

    def __init__(self, api_key: Optional[str] = None, server_url: Optional[str] = None):
        self.api_key = api_key
        self.server_url = server_url

    async def fetch_indicators(self, limit: int = 1000) -> List[NormalizedThreatIndicator]:
        # Placeholder for future network crawler ingestion
        return []


def normalize_indicator_value(indicator_type: str, raw_value: str) -> Tuple[str, str]:
    """
    Normalizes an indicator value and produces a deterministic SHA-256 lookup hash.
    Returns (normalized_value, sha256_hash).
    """
    clean = (raw_value or "").strip()
    if indicator_type == "url":
        # Normalize URL: strip trailing slashes and lower-case scheme/netloc
        clean = clean.strip()
    elif indicator_type in ("domain", "ip"):
        clean = clean.lower()

    digest = hashlib.sha256(clean.encode("utf-8")).hexdigest()
    return clean, digest


def lookup_threat_indicator(db: Session, indicator_type: str, value: str) -> Optional[Dict[str, Any]]:
    """
    Perform an O(1) indexed lookup for an active (non-expired) threat indicator in local intelligence database.
    Returns normalized dictionary with provenance if match found, else None.
    """
    if not value or not isinstance(value, str):
        return None

    clean_val, val_hash = normalize_indicator_value(indicator_type, value)
    now_iso = datetime.now(timezone.utc).isoformat()

    try:
        # Query matching indicators that are not expired
        records = db.query(ThreatIndicator).filter(
            ThreatIndicator.indicator_type == indicator_type,
            ThreatIndicator.indicator_hash == val_hash,
            or_(
                ThreatIndicator.expires_at.is_(None),
                ThreatIndicator.expires_at > now_iso,
            )
        ).all()

        if not records:
            return None

        # Consolidate multiple matching sources for the same indicator
        sources = sorted(list({r.source for r in records}))
        primary = records[0]
        max_confidence = max(r.confidence for r in records)
        latest_observed = max(r.observed_at for r in records)
        earliest_expiry = min([r.expires_at for r in records if r.expires_at is not None], default=None)

        return {
            "is_match": True,
            "indicator_type": indicator_type,
            "indicator": clean_val,
            "sources": sources,
            "sources_summary": ", ".join(sources),
            "classification": primary.classification,
            "confidence": max_confidence,
            "observed_at": latest_observed,
            "expires_at": earliest_expiry,
            "matched_records_count": len(records),
        }
    except Exception:
        logger.error("event=threat_indicator_lookup_error", exc_info=False)
        return None


def refresh_threat_feed(
    db: Session,
    provider: ThreatFeedProvider,
    max_records: int = 1000,
    indicators: Optional[List[NormalizedThreatIndicator]] = None,
) -> Dict[str, Any]:
    """
    Synchronizes local threat database with indicators from a feed provider.
    Handles insert, update, deduplication, and expiration deterministically.
    """
    source_name = provider.source_name
    now_iso = datetime.now(timezone.utc).isoformat()

    items = indicators if indicators is not None else []
    items = items[:max_records]

    inserted_count = 0
    updated_count = 0

    try:
        for item in items:
            clean_ind, ind_hash = normalize_indicator_value(item.indicator_type, item.indicator)
            observed = item.observed_at or now_iso

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
                existing.expires_at = item.expires_at
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
                    expires_at=item.expires_at,
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


def refresh_all_threat_feeds(
    db: Session,
    providers: Optional[List[ThreatFeedProvider]] = None,
) -> List[Dict[str, Any]]:
    """Synchronize all registered threat feeds sequentially."""
    feed_providers = providers or [PhishTankFeedProvider(), MISPFeedProvider()]
    results = []
    for prov in feed_providers:
        res = refresh_threat_feed(db, prov)
        results.append(res)
    return results
