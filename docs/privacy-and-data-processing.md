# Privacy and external analysis

## Default behavior: local-only analysis

Each `POST /api/analyze` request defaults `allow_external_processing` to `false`. In this mode the API runs its local URL/email heuristics and, for URLs, may query threat indicators already stored in the application's local database. It does not invoke the VirusTotal, URLhaus, Google Web Risk, or Gemini analysis clients. Configuring provider API keys does not override this per-request decision.

The response includes `external_processing_allowed: false`, and the scan's stored `details` include the same value so the mode is visible when history is reopened. The report and UI identify the result as local-only. This does not mean that the browser-to-SENTINEL request or database persistence is offline: the submitted input still reaches the SENTINEL backend and the application stores a sanitized history preview and structured result.

## Explicit opt-in

The user may enable **Allow external threat intelligence and AI for this scan** before submitting. The UI defaults to unchecked and sends `allow_external_processing: true` only for that scan. The backend remains authoritative: omitting the field or sending false must skip every external analysis provider even when API keys are configured.

For URL scans, opt-in allows the configured VirusTotal, URLhaus, and Google Web Risk checks to run. For URL, email-body, and email-header scans, opt-in also permits Gemini analysis when configured. The response and persisted history record the consent value. Consent is per request, not stored as a permanent account preference.

Do not send confidential URLs, one-time links, private tenant paths, personal data, credentials, or other sensitive content to external providers. Provider data handling differs:
- [VirusTotal API documentation](https://docs.virustotal.com/reference/scan-url) warns that indicators queried or submitted via its API may be added to its dataset and made accessible to its community.
- [Google Web Risk Lookup API](https://docs.cloud.google.com/web-risk/docs/overview) states that the Lookup API sends the actual URL and that URLs are not hashed.
- [Gemini API usage policies](https://ai.google.dev/gemini-api/docs/usage-policies) describe prompt/output retention for abuse monitoring; applicable terms depend on service and billing configuration.
- [URLhaus API](https://urlhaus.abuse.ch/api/) documents the external service used for URL lookups.

Review each provider's current terms and privacy policy before enabling external processing in production. A consent checkbox is not a guarantee of zero provider retention.

## Verification requirements

The regression suite must prove that:
1. Missing consent and explicit false consent do not call any external analysis provider, even with provider keys configured.
2. Explicit true consent enables configured providers.
3. The response, report, UI, and stored scan details accurately identify the selected processing mode.
4. Legacy request payloads remain compatible and safely default to local-only.
