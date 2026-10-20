/**
 * SENTINEL AI — build-time validation of `VITE_API_BASE_URL`.
 *
 * Why this exists
 * ---------------
 * The frontend resolves its API origin from a single build-time Vite variable,
 * `VITE_API_BASE_URL`, and appends concrete `/api/...` paths to it
 * (see `src/context/AuthContext.tsx`, `src/hooks/usePhishingScanner.ts`,
 * `src/components/Header.tsx`):
 *
 *     const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000"
 *     fetch(`${API_BASE}/api/health`)
 *
 * Vite inlines `import.meta.env.VITE_API_BASE_URL` as a string literal at build
 * time. Whenever the variable has a non-empty value the `||` fallback is dead
 * code, so *whatever* value is supplied is frozen into the bundle and used for
 * every request. A committed placeholder such as
 * `https://your-render-backend-url.onrender.com` therefore produces a bundle
 * that builds successfully but cannot reach any backend.
 *
 * This module makes that class of mistake observable:
 *
 *   - a *placeholder* or otherwise unusable origin fails the build everywhere;
 *   - a missing / loopback / non-HTTPS origin fails the build only when the
 *     build is known to be a deployment build (`VERCEL=1`, or
 *     `SENTINEL_REQUIRE_API_BASE_URL=1`), so local and CI builds that
 *     intentionally fall back to the loopback default keep working.
 *
 * The guard never guesses a production origin. When it cannot prove the
 * configured value is usable it stops the build and asks the operator to
 * supply one.
 */

/**
 * Substrings that indicate a value was never replaced with a real origin.
 * Matched case-insensitively against the whole configured value.
 */
export const PLACEHOLDER_MARKERS = Object.freeze([
  "your-render-backend-url",
  "your-backend-url",
  "your-backend",
  "your-domain",
  "your-deployment",
  "your-api",
  "change-me",
  "changeme",
  "replace-me",
  "placeholder",
  "todo:",
]);

/**
 * Reserved TLDs (RFC 2606 / RFC 6761) that can never resolve publicly.
 * `.localhost` is deliberately absent: it is classified as loopback below,
 * which is the more accurate and more actionable diagnosis.
 */
export const RESERVED_TLDS = Object.freeze([
  ".example",
  ".invalid",
  ".test",
]);

/** Hostnames that only ever resolve on the machine running the process. */
export const LOOPBACK_HOSTNAMES = Object.freeze(["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0"]);

export const LEVEL_OK = "ok";
export const LEVEL_WARNING = "warning";
export const LEVEL_ERROR = "error";

function result(level, code, message) {
  return { level, code, message };
}

/**
 * Normalize a hostname for loopback comparison: URL keeps IPv6 hosts bracketed.
 */
function normalizeHostname(hostname) {
  // URL keeps IPv6 hosts bracketed. A trailing DNS dot is equivalent to the
  // same absolute hostname without the dot (including localhost special-use).
  return hostname.toLowerCase().replace(/^\[(.*)\]$/, "$1").replace(/\.+$/, "");
}

function isLoopback(hostname) {
  const host = normalizeHostname(hostname);
  if (LOOPBACK_HOSTNAMES.includes(host) || host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }
  // 127.0.0.0/8 is entirely loopback. WHATWG URL parsing canonicalizes IPv4
  // numeric forms before this check.
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
}

/**
 * Validate the configured API base origin.
 *
 * @param {string | undefined | null} rawValue Value of `VITE_API_BASE_URL` as
 *   Vite will inline it. `undefined` means the variable is not configured.
 * @param {{ deployment?: boolean }} [options] `deployment: true` marks a build
 *   that is intended to be published; it escalates missing/loopback/plain-HTTP
 *   origins from warning to error.
 * @returns {{ level: "ok" | "warning" | "error", code: string, message: string }}
 */
export function validateApiBaseUrl(rawValue, options = {}) {
  const deployment = options.deployment === true;
  const raw = typeof rawValue === "string" ? rawValue.trim() : "";

  // 1. Not configured at all -> the `||` fallback in the app is live.
  if (raw === "") {
    if (deployment) {
      return result(
        LEVEL_ERROR,
        "missing",
        "VITE_API_BASE_URL is not set for this deployment build. The bundle would fall back to " +
          "http://127.0.0.1:8000 and every API call would fail. Set VITE_API_BASE_URL to the " +
          "public backend origin (scheme + host, no path).",
      );
    }
    return result(
      LEVEL_WARNING,
      "missing",
      "VITE_API_BASE_URL is not set. The bundle will fall back to http://127.0.0.1:8000, which is " +
        "only usable for local development. This build is NOT deployable.",
    );
  }

  // 2. Structural checks.
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return result(
      LEVEL_ERROR,
      "malformed",
      `VITE_API_BASE_URL is not an absolute URL: "${raw}". Expected an absolute scheme + host origin.`,
    );
  }

  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    return result(LEVEL_ERROR, "scheme", `VITE_API_BASE_URL must use http or https, got "${parsed.protocol}"`);
  }

  if (parsed.username || parsed.password) {
    return result(
      LEVEL_ERROR,
      "credentials",
      "VITE_API_BASE_URL must not embed credentials. Every VITE_* value is compiled into the public " +
        "browser bundle and is not secret.",
    );
  }

  // 3. Shape checks: the app builds URLs as `${base}/api/...`, so a base with a
  //    path would produce doubled or wrong prefixes (e.g. /api/api/health).
  const path = parsed.pathname.replace(/\/+$/, "");
  if (path !== "") {
    return result(
      LEVEL_ERROR,
      "path",
      `VITE_API_BASE_URL must be a bare origin without a path, got path "${parsed.pathname}". ` +
        "The client already appends /api/..., so a path here produces a wrong request URL.",
    );
  }

  if (parsed.search !== "" || parsed.hash !== "") {
    return result(
      LEVEL_ERROR,
      "query",
      "VITE_API_BASE_URL must not contain a query string or fragment.",
    );
  }

  // URL.pathname is "/" for both a bare origin and an explicitly supplied
  // trailing slash. The frontend appends "/api/..." verbatim, so reject the
  // explicit slash instead of approving a base that can yield "//api/..." URLs.
  if (raw.endsWith("/")) {
    return result(
      LEVEL_ERROR,
      "trailing-slash",
      "VITE_API_BASE_URL must not end with a slash. Supply only scheme + host; the client appends /api/...",
    );
  }

  const hostname = normalizeHostname(parsed.hostname);

  // 4. Unreplaced placeholder values.
  const loweredRaw = raw.toLowerCase();
  const marker = PLACEHOLDER_MARKERS.find((candidate) => loweredRaw.includes(candidate));
  if (marker) {
    return result(
      LEVEL_ERROR,
      "placeholder",
      `VITE_API_BASE_URL still contains the placeholder text "${marker}". Set it to the real public ` +
        "backend origin before building.",
    );
  }

  const reservedTld = RESERVED_TLDS.find((tld) => hostname === tld.slice(1) || hostname.endsWith(tld));
  if (reservedTld || hostname === "example.com" || hostname.endsWith(".example.com")) {
    return result(
      LEVEL_ERROR,
      "placeholder",
      `VITE_API_BASE_URL points at the reserved host "${hostname}", which can never serve a real backend.`,
    );
  }

  // 5. Loopback: fine for local preview builds, never for a deployment.
  if (isLoopback(parsed.hostname)) {
    if (deployment) {
      return result(
        LEVEL_ERROR,
        "loopback",
        `VITE_API_BASE_URL points at loopback ("${parsed.host}"): a deployed bundle cannot reach the ` +
          "visitor's own machine. Set the public backend origin.",
      );
    }
    return result(
      LEVEL_WARNING,
      "loopback",
      `VITE_API_BASE_URL points at loopback ("${parsed.host}"). Expected for local development; ` +
        "this build is NOT deployable as-is.",
    );
  }

  // 6. A deployed HTTPS frontend cannot call a plain-HTTP backend (mixed content).
  if (deployment && parsed.protocol !== "https:") {
    return result(
      LEVEL_ERROR,
      "insecure",
      "VITE_API_BASE_URL must use https for a deployment build; browsers block mixed-content " +
        "requests from an https frontend to an http backend.",
    );
  }

  return result(LEVEL_OK, "ok", `VITE_API_BASE_URL resolves to ${parsed.protocol}//${parsed.host}`);
}

/**
 * True when this build is known to be a published deployment build.
 *
 * @param {Record<string, string | undefined>} env
 */
export function isDeploymentBuild(env = {}) {
  return env.VERCEL === "1" || env.SENTINEL_REQUIRE_API_BASE_URL === "1";
}

/**
 * Vite plugin that runs {@link validateApiBaseUrl} before the bundle is written.
 *
 * @param {{
 *   value?: string | undefined,
 *   env?: Record<string, string | undefined>,
 * }} [options]
 */
export function apiBaseUrlGuard(options = {}) {
  const env = options.env ?? {};
  const value = options.value;

  return {
    name: "sentinel:api-base-url-guard",
    apply: "build",
    buildStart() {
      const deployment = isDeploymentBuild(env);
      const outcome = validateApiBaseUrl(value, { deployment });
      if (outcome.level === LEVEL_ERROR) {
        this.error(outcome.message);
      } else if (outcome.level === LEVEL_WARNING) {
        this.warn(outcome.message);
      }
    },
  };
}
