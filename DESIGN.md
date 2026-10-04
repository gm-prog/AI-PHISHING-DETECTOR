# DESIGN.md — SENTINEL AI Threat Intelligence Gateway

## 1. Product Context & Purpose
- **Product Name**: SENTINEL AI — Threat Intelligence Gateway
- **Domain**: Cyber Defense & Security Operations Center (SOC) Threat Analysis
- **Target Audience**: Cybersecurity Analysts, SOC Incident Responders, Security Researchers, and Vigilant Web Users evaluating suspicious URLs, raw email bodies, and MIME headers.
- **Primary Job to be Done**: Analyze potential phishing vectors, extract technical & social engineering threat indicators, calculate verifiable risk scores, and generate actionable incident response guidance.
- **Trust Requirement**: Absolute. The UI must feel authoritative, precise, transparent, and operational — like professional cybersecurity tooling (e.g. CrowdStrike, VirusTotal Enterprise, Splunk Enterprise Security) — not a generic marketing SaaS.

---

## 2. UX Character (Observable Qualities)
1. **Tactical & High-Density**: Information is presented in organized data grids, tabular metrics, and technical inspectors with minimal decorative whitespace padding.
2. **Deterministic & Transparent**: Clear distinction between local deterministic rule-based heuristics and AI-assisted deep semantic evaluation.
3. **High-Contrast Precision**: Critical threats pop instantly in alert red (`#FF3366`), warnings in warning amber (`#FFB800`), and clean assets in verified green (`#00E699`) against a dark slate tactical background (`#080C14`).
4. **Accessible & Keyboard-First**: Full keyboard navigation support with explicit high-contrast focus rings (`focus-visible`), aria labels, and `Ctrl + Enter` execution shortcuts.

---

## 3. Visual Direction & Design Tokens

### 3.1 Typography Scale
- **Header & Display Font**: `Plus Jakarta Sans` (weights: 600, 700, 800)
- **Body & UI Font**: `Plus Jakarta Sans` (weights: 400, 500)
- **Telemetry & Technical Font**: `JetBrains Mono` (weights: 400, 500, 700)

#### Type Hierarchy Tokens:
- `Display` (Page Header): `20px` / `24px` | `Plus Jakarta Sans 700` | uppercase, tracked
- `H1` (Console Section Title): `16px` / `20px` | `Plus Jakarta Sans 700`
- `H2` (Card / Box Header): `14px` / `18px` | `Plus Jakarta Sans 600`
- `Body` (Main Text): `13px` / `18px` | `Plus Jakarta Sans 400`
- `Caption / Monospace Telemetry`: `11px` / `16px` | `JetBrains Mono 400` | tabular numbers
- `Badge / Label`: `10px` / `14px` | `JetBrains Mono 700` | uppercase, tracked

### 3.2 Color Tokens (SOC Palette)
```css
/* Background & Surfaces */
--color-bg-root: #080c14;
--color-surface-base: #0f172a;
--color-surface-panel: #131c31;
--color-surface-elevated: #1a243d;

/* Borders & Separators */
--color-border-subtle: rgba(255, 255, 255, 0.08);
--color-border-tactical: rgba(255, 255, 255, 0.15);
--color-border-active: #00f0ff;

/* Text Tiers */
--color-text-primary: #f8fafc;
--color-text-secondary: #94a3b8;
--color-text-muted: #64748b;

/* Threat Severity Semantics */
--color-threat-danger: #ff3366;
--color-threat-warning: #ffb800;
--color-threat-safe: #00e699;
--color-threat-info: #00f0ff;
```

### 3.3 Layout & Grid Rhythm
- **Density**: Compact padding (`px-3 py-2.5` to `px-4 py-3.5`).
- **Corner Radius**: Sharp `rounded-md` (4px to 6px). No hyper-rounded pills or `rounded-3xl` cards.
- **Grid Layout**: 12-column responsive layout:
  - Left Console (5 cols): Input Vector Tabs + History Vault
  - Right Inspector (7 cols): Global Metrics Banner + Threat Radar + Detailed Inspector (Risk Gauge, Signal Breakdown, AI Report)

---

## 4. Forbidden Anti-References (Guardrails)
❌ **No Generic Purple/Blue Gradients**: Avoid standard landing-page mesh gradients. Use solid tactical slate with subtle glowing alert borders.  
❌ **No Card-in-Card Nesting**: Contain content using crisp border grid lines and distinct surface shades rather than stacking multiple rounded cards.  
❌ **No Floating Blobs / Decorative Orbs**: Every visual element must serve a operational diagnostic purpose.  
❌ **No Generic SaaS Copy**: Replace "Supercharge your security" with technical SOC terminology ("EXECUTE THREAT SCAN", "MIME HEADER DECODER", "AUTHENTICATE OPERATOR").  
❌ **No Missing Interaction States**: Every button and input must have idle, hover, active, focus-visible, and disabled states.

---

## 5. Accessibility & Motion Guidelines
- **Focus Rings**: `focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#00F0FF] focus-visible:ring-offset-2 focus-visible:ring-offset-[#080C14]`.
- **Contrast**: Text contrast ratio >= 4.5:1 against surfaces.
- **Motion**: Minimal transitions (150ms-250ms ease-out) for tab switches and scan progress updates. Respect `prefers-reduced-motion`.

---

## 4. Threat Intelligence & Email Authentication Subsystem

### 4.1 Threat Intelligence Ingestion & Generation Snapshot Lifecycle
SENTINEL AI uses a decoupled, defense-in-depth threat intelligence pipeline with true generation snapshots:

```text
                 ┌──────────────────────┐
                 │ Provider Connector   │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Fetch / Bounds      │
                 │ timeout / size      │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Parse / Normalize   │
                 └──────────┬───────────┘
                            │
                            ▼
                 ┌──────────────────────┐
                 │ Validate Snapshot   │
                 └──────────┬───────────┘
                            │
                     valid? │
                    ┌───────┴────────┐
                    │                │
                   NO               YES
                    │                │
                    ▼                ▼
              keep current     Stage generation
              generation           │
                                   ▼
                              Atomic activation
                                   │
                                   ▼
                              Current generation
                                   │
                                   ▼
                               Prune old
```

**Architectural Rationale**:
- **True Generation Snapshots**: Every successful refresh stages records into a new isolated `generation_id`. Threat lookups query strictly against the active generation (`ThreatIndicator.generation_id == ThreatFeedState.current_generation_id`). Indicators removed in an upstream snapshot disappear immediately upon activation.
- **Fail-Safe Generation Retention**: If a refresh fails (network error, timeout, HTTP 500, corrupt payload, or unexpected empty snapshot), the transaction rolls back cleanly, and the previous healthy generation remains active and searchable.
- **Per-Source Serialization & Global Concurrency Bounds**: Outbound fetch requests are guarded by `threat_feed_semaphore` (concurrency cap = 2), while per-source mutex locks serialize refresh executions on the same source to eliminate race conditions.
- **Durable Provenance & Multi-Source Reconciliation**: When multiple feeds flag the same indicator (e.g. PhishTank, OpenPhish, and MISP), the fusion engine consolidates provenance into a single +35 risk boost, selecting the most severe classification (`malware` > `c2` > `credential_harvesting` > `phishing` > `scam`).
- **Resource Bounds & Memory Safety**: Streaming download chunking with hard maximum byte thresholds (32MB) prevents decompression bombs or memory exhaustion.

- **Web Risk Lookup Provider**: Queries `https://webrisk.googleapis.com/v1/uris:search` with server-side `GOOGLE_WEB_RISK_API_KEY`. Enforces strict URL scheme validation, 4-permit concurrency semaphore, 2.0s acquire timeout, 5.0s execution timeout, and SHA-256 hashed TTL caching with provider expiration hints where effective TTL is strictly bounded by remaining provider validity (`min(remaining_seconds, 600)`) and expired results (remaining <= 0) receive TTL=0. Matches contribute a capped +30 risk score.
### 4.3 Database Migration & Generation Coexistence Architecture

```text
Legacy Pre-Alembic Schema:
  scan_history: id, timestamp, input_type, content, risk_score, status, etc. (no user_id, no guest_session_hash)
  threat_indicators: UNIQUE(source, indicator_type, indicator_hash), generation_id: NULL

          ↓ Authoritative Alembic Batch Migration (alembic upgrade head)

Migrated Canonical Schema:
  scan_history:
    - user_id: VARCHAR REFERENCES users(id) [Index: ix_scan_history_user_id]
    - guest_session_hash: VARCHAR [Index: ix_scan_history_guest_session_hash]
    - Preserves all historical scan records and existing columns
  threat_indicators:
    - generation_id: VARCHAR(36) NOT NULL / backfilled to 'legacy-gen-<source>'
    - UNIQUE constraint: uq_source_gen_type_indicator (source, generation_id, indicator_type, indicator_hash)
    - Legacy constraint uq_source_type_indicator: EXPLICITLY REMOVED
    - Full functional index coverage: (source, indicator_type, indicator_hash, classification, expires_at, generation_id)
  threat_feed_states:
    - current_generation_id: 'legacy-gen-<source>' (or NULL before first synchronization)
    - freshness: 'stale'
    - status: 'idle'
    - last_success_at: NULL (truthful, non-fabricated state)
```

**Architectural Guarantees**:
1. **Sole Schema Evolution Authority**: Alembic is the single source of truth for database DDL/DML evolution (`alembic upgrade head`). `Base.metadata.create_all()` is removed from production runtime startup.
2. **Decoupled Import & Startup Pipeline**: Importing `app.db` or domain models does not execute schema checks. Application startup follows a strict three-phase contract:
   ```text
   Alembic migration (alembic upgrade head)
           ↓
   Read-only invariant verification (lifespan hook via verify_schema_invariants())
           ↓
   FastAPI application startup
   ```
   If the schema is missing, uninitialized, or incompatible, startup fails closed with an actionable error.
3. **Legacy Scan History & Indicator Reconciliation**: Pre-Alembic databases with legacy `scan_history` (missing ownership fields) and legacy `threat_indicators` (missing `generation_id`) are upgraded idempotently. Historical records are preserved, deterministic `legacy-gen-<source>` identifiers are assigned, and `threat_feed_states` are initialized truthfully with `freshness = "stale"` and `last_success_at = None`.
4. **Strictly Read-Only Runtime Invariant & Alembic Head Verification**: `verify_schema_invariants()` uses read-only PRAGMA and SQLite metadata inspections to validate table existence (`users`, `user_sessions`, `scan_history`, `threat_indicators`, `threat_feed_states`), NOT NULL column constraints, unique constraints (`uq_source_gen_type_indicator`), functional indexes, and requires exactly one Alembic revision row in `alembic_version` matching the expected head revision (`b4a49925f0e5`) without executing runtime mutations.
5. **True Generation Coexistence & Downgrade Safety**: Indicators can be staged into a new generation while identical indicators remain active in older generations. Alembic `downgrade()` detects cross-generation duplicate records and explicitly refuses destructive rollbacks, failing closed with an informative migration error without deleting data.
6. **Bounded BZ2 Decompression, EOF & Trailing Byte Validation**: Streaming decompression enforces a 32MB compressed limit and 64MB decompressed limit in 64KB chunks. Streams must reach EOF and contain zero unexpected trailing data; truncated or malformed streams are rejected with sanitized error codes (`decompression_too_large`, `decompression_invalid`).
7. **Concurrency & Multi-Instance Operational Contract**: Outbound provider crawls are guarded by `threat_feed_semaphore` (concurrency cap = 2) and process-local per-source mutex locks. Note: In multi-instance cluster deployments, an external distributed lock (e.g. Redis-based Redlock) is required to coordinate crawler execution across worker nodes.

### 4.2 Standards-Aware Email Authentication & Provenance Boundary

```text
raw message headers
       ↓
untrusted_message
       ↓
diagnostic only (no authoritative failure penalties)

trusted server-controlled ingress
       ↓
trusted_ingress
       ↓
authoritative upstream result (authoritative penalties applied)
```

- **Standards-Aware Parser (`email_auth_service.py`)**: Structured interpretation of `Authentication-Results` (RFC 8601 / RFC 7601), `Received-SPF` (RFC 7208), `DKIM-Signature` (RFC 6376), and DMARC (RFC 7489) with comments stripped, multiple DKIM signatures preserved, and quoted property strings (`reason="dkim=fail"`) distinguished from method results.
- **Explicit Provenance Boundaries**: Differentiates parsed user-supplied message claims (`untrusted_message`) from verified server-side gateway evidence (`trusted_ingress`). Matching `TRUSTED_AUTHSERV_IDS` alone does NOT grant authoritative status to user-uploaded headers; only trusted ingress provenance allows authoritative failure penalties (+35/+25/+25).
- **Strict Identifier Alignment & No False Fallbacks**: Uses Public Suffix List via `tldextract` to compare registered root domains (`example.com`). DMARC SPF alignment strictly compares authenticated `MAIL FROM` (not `HELO`, and never falling back to `Return-Path` for authenticated SPF proof), and DKIM alignment strictly compares signing domain `d=` (never deriving `d=` from `i=`).
- **Privacy Boundary**: Zero raw email header blocks, raw From, Return-Path, or Subject strings are persisted in `ScanHistory.details` or returned in API responses; only normalized domain identities, authentication flags, and urgent subject triggers are stored.
- **Explainable Scoring**: Unknown authentication status or missing unsigned DKIM headers are preserved as `none`/`unknown` and not treated as failures; verified failures produce explicit, high-confidence threat signals with deterministic score impacts.
