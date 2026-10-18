/**
 * @typedef {"tab-change" | "autofill" | "reset-input" | "submit"} ConsentTransitionReason
 * @typedef {{reason: "submit", nextValue: false, forCurrentScan: boolean}
 *   | {reason: "tab-change" | "autofill" | "reset-input", nextValue: false}} ConsentTransition
 */

/**
 * External-processing consent applies only to one input context and one scan.
 * UI context changes revoke it; submission snapshots the current choice before
 * clearing the checkbox for the next scan.
 *
 * @param {boolean} currentValue
 * @param {ConsentTransitionReason} reason
 * @returns {ConsentTransition}
 */
export function transitionExternalProcessingConsent(currentValue, reason) {
  if (reason === "submit") {
    return { reason, nextValue: false, forCurrentScan: currentValue };
  }

  return { reason, nextValue: false };
}
