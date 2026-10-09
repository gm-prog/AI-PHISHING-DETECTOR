"""One-shot runner; scheduling and cross-process exclusion belong to the operator."""
import asyncio
import logging

from app import telemetry


# Lazy imports keep configuration/driver failures inside the sanitized job boundary.
def open_session():
    from app.db import SessionLocal
    return SessionLocal()


def verify_schema():
    from app.db import verify_schema_invariants
    verify_schema_invariants()


def registered_providers():
    from app.services.threat_feed_service import get_registered_providers
    return list(get_registered_providers().values())


async def refresh_all(db, providers):
    from app.services.threat_feed_service import refresh_all_threat_feeds
    return await refresh_all_threat_feeds(db, providers)


async def run() -> int:
    telemetry.initialize("sentinel-ai-feed-job")
    telemetry.event("feed_job_started")
    outcome = "failed"
    try:
        # Same read-only startup contract as the API; never create/repair schema.
        verify_schema()
        with open_session() as db:
            results = await refresh_all(db, registered_providers())
            for result in results:
                telemetry.event("feed_job_source_completed", source=result.get("source"),
                                outcome=result.get("status"))
            if all(r.get("status") in {"success", "not_modified", "disabled"} for r in results):
                outcome = "success"
                return 0
            return 1
    except Exception:
        telemetry.event("feed_job_failed", **{"error.type": "unexpected"})
        return 1
    finally:
        telemetry.event("feed_job_completed", outcome=outcome)
        telemetry.shutdown()


def main() -> int:
    logging.basicConfig(level=logging.INFO)
    return asyncio.run(run())


if __name__ == "__main__":
    raise SystemExit(main())
