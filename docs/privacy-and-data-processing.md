# Privacy and data processing

## Summary

`POST /api/analyze` sends the submitted input to the SENTINEL backend. In the
default local-only mode (`allow_external_processing` omitted or `false`), the
backend runs local heuristics and local stored threat-indicator lookups without
calling VirusTotal, URLhaus, Google Web Risk, or Gemini. External analysis
requires an explicit, per-scan opt-in and only uses applicable, configured
integrations.

Scan history is not a verbatim copy of the submission. It stores a bounded,
sanitized content preview plus structured analysis results, including a
validated `ai_explanation`. The sections below describe each of those values.

## Default behavior: local-only analysis

Each `POST /api/analyze` request defaults `allow_external_processing` to
`false`. In this mode the API runs its local URL/email heuristics and, for
URLs, may query threat indicators already stored in the application's local
database. It does not invoke the VirusTotal, URLhaus, Google Web Risk, or
Gemini analysis clients. Configuring provider API keys does not override this
per-request decision.

The response includes `external_processing_allowed: false`, and the scan's
stored `details` include the same value so the mode is visible when history is
reopened. The report and UI identify the result as local-only. This does not
mean that the browser-to-SENTINEL request or database persistence is offline:
the submitted input still reaches the SENTINEL backend, and the application
stores the sanitized preview and structured result described in
[What SENTINEL stores](#what-sentinel-stores).

## Explicit opt-in

The user may enable **Allow external threat intelligence and AI for this scan**
before submitting. The UI defaults to unchecked and sends
`allow_external_processing: true` only for that scan. The backend remains
authoritative: omitting the field or sending false must skip every external
analysis provider even when API keys are configured.

For URL scans, opt-in allows the configured VirusTotal, URLhaus, and Google Web
Risk checks to run. For URL, email-body, and email-header scans, opt-in also
permits Gemini analysis when configured; the Gemini prompt carries the submitted
content up to the configured `LLM_MAX_INPUT_CHARS` bound. The response and
persisted history record the consent value. Consent is per request, not stored
as a permanent account preference.

Provider responses and Gemini results are cached in process memory using a key
derived from the input, so a cache hit can avoid a new outbound request. The
response disclosure lists eligible, configured integrations for that scan; it
does not assert that every listed provider received a request, and it does not
prove that a provider stored nothing.

Do not send confidential URLs, one-time links, private tenant paths, personal
data, credentials, or other sensitive content to external providers. Provider
data handling differs:
- [VirusTotal API documentation](https://docs.virustotal.com/reference/scan-url) warns that indicators queried or submitted via its API may be added to its dataset and made accessible to its community.
- [Google Web Risk Lookup API](https://docs.cloud.google.com/web-risk/docs/overview) states that the Lookup API sends the actual URL and that URLs are not hashed.
- [Gemini API usage policies](https://ai.google.dev/gemini-api/docs/usage-policies) describe prompt/output retention for abuse monitoring; applicable terms depend on service and billing configuration.
- [URLhaus API](https://urlhaus.abuse.ch/api/) documents the external service used for URL lookups.

Review each provider's current terms and privacy policy before enabling external
processing in production. A consent checkbox is not a guarantee of zero provider
retention.

## What SENTINEL stores

### 1. Original scan input (transient analysis value)

The submitted URL, email body, or header block is used unmodified for the
analysis performed during the request and, when the user has opted in, for the
applicable provider calls described above. The API does not write the original
input to scan history verbatim or log it. Values derived from it are stored as
described below, and additional copies can remain inside structured result
fields (for example a URL list or a model-written explanation).

### 2. Stored content preview (`scan_history.content`)

The history content field is a **bounded, sanitized input preview**, not the
original input:

- It is capped at 100 characters plus a trailing `...` (103 characters maximum).
- Before storage, credential material is masked:
  - URL user-information, e.g. `https://user:password@example.test/path`
    becomes `https://[MASKED]@example.test/path`;
  - values of secret-bearing query and fragment parameters, matched
    case-insensitively, including `token`, `access_token`, `refresh_token`,
    `id_token`, `api_key`, `apikey`, `secret`, `client_secret`, `password`,
    `passwd`, `authorization`, `auth`, `bearer`, `session`, `sessionid`,
    signed-URL fields such as `X-Amz-Signature`, `X-Amz-Credential`,
    `X-Amz-Security-Token`, `X-Goog-Signature`, and `X-Goog-Credential`;
  - generic `key`, `code`, `ticket`, and `credential` parameters only when the
    value looks like a machine-issued credential, so ordinary context such as
    `?key=value` remains readable;
  - values of `Authorization`, `Proxy-Authorization`, `Cookie`, and
    `Set-Cookie` header lines;
  - bearer-token, JWT, Google-API-key, password/token assignment, and
    card-number-like shapes already covered by the previous preview filter.
- Scheme, hostname, path, parameter names, and harmless parameters are
  preserved so a user can still recognize the indicator.
- Percent-encoded parameter names and assignments, repeated parameters, nested
  URLs inside query values, schemeless URLs, RFC 5322 folded header
  continuations, and malformed URLs take a documented safe path; an input that
  cannot be parsed is still redacted as text and bounded.

### 3. Stored structured results

A `ScanHistory` row also persists:

- ownership and routing metadata: `user_id` for authenticated scans, otherwise
  a SHA-256 hash of the server-issued guest cookie (the raw guest token is not
  stored), plus `input_type` and `timestamp`;
- `risk_score` and `status`;
- `phishing_signals`: signal id, severity, title, and description;
- `details`: structured diagnostic metadata. URL-bearing fields (such as
  `host`, `links_found`, and `links_analysis[].url`) have URL user-information
  and secret query/fragment values masked before storage, and the analyst
  copies used for the API response are not mutated;
- `ai_explanation`: the validated analysis report. In local mode it is
  generated by the local heuristic engine; when external processing is enabled
  it contains the validated Gemini output (or the documented heuristic
  fallback) plus the data-handling disclosure. This field **is persisted**, and
  the same URL-credential/secret-assignment masking is applied to the stored
  copy. The API response returned to the requester is not truncated or
  redacted by this storage projection;
- `details.external_processing_allowed`, recording the per-scan consent mode.

### 4. What is not guaranteed to be redacted

Redaction is a best-effort, pattern-based control, not a guarantee that stored
history is secret-free:

- secrets in unrecognized formats or placements, and credentials embedded in
  free-form prose that do not match the patterns above;
- personal data such as names, email addresses, message bodies, URL paths,
  tenant identifiers, and non-secret query values;
- quoted input inside a model-generated explanation, beyond the URL/credential
  masking applied on storage.

Do not treat scan history as a credential or secret store, and do not submit
secrets you do not need analyzed.

### 5. Retention and deletion

The application code does not implement automatic expiry for `scan_history`
rows. A signed-in user or guest session can delete individual records through
`DELETE /api/history/{scan_id}` or clear its own history through
`DELETE /api/history`; administrators can read recent records through the
admin endpoints. Database backups, replica lag, and any organisation-level
retention or purge policy are operator-controlled and are not defined by this
repository. This document does not claim a retention duration.

Application telemetry is content-free and does not attach submitted content,
query strings, cookies, or user identifiers; excluded fields are listed in
[the deployment contract](deployment.md#privacy-correlation-and-spans). Raw
HTTP request bodies are not written by the application's scan code. An
operator's reverse proxy or access log configuration is outside that boundary.

## Administrator threat-feed refreshes

Threat-feed refreshes are a separate administrator-initiated operational flow
(`POST /api/admin/threat-feeds/{source}/refresh` and the scheduled job). They
fetch provider feed snapshots and update the local indicator store. They are
not governed by the per-scan `allow_external_processing` checkbox and do not
transmit user scan input to feed providers.

## Verification requirements

The regression suite must prove that:
1. Missing consent and explicit false consent do not call any external analysis provider, even with provider keys configured.
2. Explicit true consent enables configured providers.
3. The response, report, UI, and stored scan details accurately identify the selected processing mode.
4. Legacy request payloads remain compatible and safely default to local-only.
5. URL user-information, secret-bearing query/fragment values, sensitive header
   values, and common credential shapes are absent from the stored preview and
   from URL-bearing persisted result fields, while harmless context survives.
6. Analysis receives the unmodified input during the request even though the
   stored preview is redacted.
7. The stored preview stays within its configured length bound after redaction.
8. Both history endpoints return the stored preview and preserve user/guest
   ownership scoping.
