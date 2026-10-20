import assert from "node:assert/strict";
import test from "node:test";

import {
  apiBaseUrlGuard,
  isDeploymentBuild,
  validateApiBaseUrl,
} from "./validate-api-base-url.mjs";

/** The exact value that used to be committed in `frontend/.env.production`. */
const HISTORICAL_PLACEHOLDER = "https://your-render-backend-url.onrender.com";

test("accepts a real https backend origin", () => {
  const res = validateApiBaseUrl("https://ai-phishing-detector-backend.onrender.com");
  assert.equal(res.level, "ok");
  assert.equal(res.code, "ok");
});

test("rejects a trailing slash so request paths cannot become double-slash URLs", () => {
  const res = validateApiBaseUrl("https://api.sentinel-defense.com/");
  assert.equal(res.level, "error");
  assert.equal(res.code, "trailing-slash");
});

test("rejects the historical committed placeholder in every build mode", () => {
  for (const deployment of [false, true]) {
    const res = validateApiBaseUrl(HISTORICAL_PLACEHOLDER, { deployment });
    assert.equal(res.level, "error", `deployment=${deployment}`);
    assert.equal(res.code, "placeholder");
  }
});

test("rejects other unreplaced placeholder shapes", () => {
  for (const value of [
    "https://your-domain.example",
    "https://backend.changeme",
    "https://api.example.com",
    "https://sentinel.invalid",
    "https://sentinel.test",
  ]) {
    assert.equal(validateApiBaseUrl(value).level, "error", value);
  }
});

test("an unset variable warns for local builds and fails a deployment build", () => {
  for (const value of [undefined, null, "", "   "]) {
    const local = validateApiBaseUrl(value, { deployment: false });
    assert.equal(local.level, "warning");
    assert.equal(local.code, "missing");

    const deployed = validateApiBaseUrl(value, { deployment: true });
    assert.equal(deployed.level, "error");
    assert.equal(deployed.code, "missing");
  }
});

test("loopback is a warning locally but blocks a deployment build", () => {
  for (const value of [
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://127.0.1.5:8000",
    "http://[::1]:8000",
  ]) {
    const local = validateApiBaseUrl(value, { deployment: false });
    assert.equal(local.level, "warning", value);
    assert.equal(local.code, "loopback");

    const deployed = validateApiBaseUrl(value, { deployment: true });
    assert.equal(deployed.level, "error", value);
    assert.equal(deployed.code, "loopback");
  }
});

test("localhost subdomains and trailing-dot localhost are blocked in deployment builds", () => {
  for (const value of [
    "https://api.localhost",
    "https://localhost.",
    "https://api.localhost.",
  ]) {
    const deployed = validateApiBaseUrl(value, { deployment: true });
    assert.equal(deployed.level, "error", value);
    assert.equal(deployed.code, "loopback", value);
  }
});

test("rejects a path in the base URL because the client appends /api/...", () => {
  const res = validateApiBaseUrl("https://api.sentinel-defense.com/api");
  assert.equal(res.level, "error");
  assert.equal(res.code, "path");
});

test("rejects query strings and fragments", () => {
  assert.equal(validateApiBaseUrl("https://api.sentinel-defense.com?x=1").code, "query");
  assert.equal(validateApiBaseUrl("https://api.sentinel-defense.com#f").code, "query");
});

test("rejects malformed, non-http and credentialed values", () => {
  assert.equal(validateApiBaseUrl("not-a-url").code, "malformed");
  assert.equal(validateApiBaseUrl("api.sentinel-defense.com").code, "malformed");
  assert.equal(validateApiBaseUrl("ftp://api.sentinel-defense.com").code, "scheme");
  assert.equal(validateApiBaseUrl("https://user:pass@api.sentinel-defense.com").code, "credentials");
});

test("plain http is allowed locally but rejected for a deployment build", () => {
  const local = validateApiBaseUrl("http://api.sentinel-defense.com", { deployment: false });
  assert.equal(local.level, "ok");

  const deployed = validateApiBaseUrl("http://api.sentinel-defense.com", { deployment: true });
  assert.equal(deployed.level, "error");
  assert.equal(deployed.code, "insecure");
});

test("deployment builds are detected from the environment, not assumed", () => {
  assert.equal(isDeploymentBuild({}), false);
  assert.equal(isDeploymentBuild({ VERCEL: "1" }), true);
  assert.equal(isDeploymentBuild({ VERCEL: "0" }), false);
  assert.equal(isDeploymentBuild({ SENTINEL_REQUIRE_API_BASE_URL: "1" }), true);
});

function runGuard(value, env = {}) {
  const contexts = [];
  const plugin = apiBaseUrlGuard({ value, env });
  const context = {
    error(message) {
      contexts.push({ kind: "error", message });
      throw new Error(message);
    },
    warn(message) {
      contexts.push({ kind: "warning", message });
    },
  };
  assert.equal(plugin.name, "sentinel:api-base-url-guard");
  assert.equal(plugin.apply, "build");
  let thrown;
  try {
    plugin.buildStart.call(context);
  } catch (err) {
    thrown = err;
  }
  return { contexts, thrown };
}

test("guard fails a deployment build that still holds the placeholder", () => {
  const { contexts, thrown } = runGuard(HISTORICAL_PLACEHOLDER, { VERCEL: "1" });
  assert.ok(thrown, "build must abort");
  assert.equal(contexts[0].kind, "error");
  assert.match(contexts[0].message, /placeholder/i);
});

test("guard only warns a local build without a configured origin", () => {
  const { contexts, thrown } = runGuard(undefined, {});
  assert.equal(thrown, undefined);
  assert.equal(contexts.length, 1);
  assert.equal(contexts[0].kind, "warning");
});

test("guard stays silent for a valid configured origin", () => {
  const { contexts, thrown } = runGuard("https://api.sentinel-defense.com", { VERCEL: "1" });
  assert.equal(thrown, undefined);
  assert.deepEqual(contexts, []);
});
