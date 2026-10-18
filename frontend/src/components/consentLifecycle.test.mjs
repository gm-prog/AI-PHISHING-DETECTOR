import assert from "node:assert/strict";
import test from "node:test";
import { transitionExternalProcessingConsent } from "./consentLifecycle.js";

test("submit snapshots an explicit opt-in for this scan and clears next state", () => {
  assert.deepEqual(transitionExternalProcessingConsent(true, "submit"), {
    reason: "submit", nextValue: false, forCurrentScan: true,
  });
});

test("submit without opt-in remains local-only and clears next state", () => {
  assert.deepEqual(transitionExternalProcessingConsent(false, "submit"), {
    reason: "submit", nextValue: false, forCurrentScan: false,
  });
});

for (const [reason, action] of [
  ["tab-change", "switching tabs"],
  ["autofill", "loading an example"],
  ["reset-input", "resetting input"],
]) {
  test("revokes prior consent when " + action, () => {
    assert.deepEqual(transitionExternalProcessingConsent(true, reason), {
      reason, nextValue: false,
    });
  });
}
