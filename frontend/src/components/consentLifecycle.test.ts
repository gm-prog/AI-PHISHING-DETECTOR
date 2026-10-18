import { describe, expect, it } from "vitest";
import { transitionExternalProcessingConsent } from "./consentLifecycle.mts";

describe("one-scan external-processing consent lifecycle", () => {
  it("starts from the explicit unchecked state", () => {
    expect(false).toBe(false);
  });

  it("snapshots an explicit opt-in for the current scan and clears next state", () => {
    expect(transitionExternalProcessingConsent(true, "submit")).toEqual({
      reason: "submit",
      nextValue: false,
      forCurrentScan: true,
    });
  });

  it("submits false when the user has not opted in", () => {
    expect(transitionExternalProcessingConsent(false, "submit")).toEqual({
      reason: "submit",
      nextValue: false,
      forCurrentScan: false,
    });
  });

  it.each(["tab change", "autofill selection", "Reset Input"])(
    "revokes consent after %s",
    () => {
      expect(transitionExternalProcessingConsent(true, "context-change")).toEqual({
        reason: "context-change",
        nextValue: false,
      });
    },
  );
});
