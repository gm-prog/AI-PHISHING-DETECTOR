export type ConsentTransitionReason = "context-change" | "submit";

export type ConsentTransition =
  | { reason: "submit"; nextValue: false; forCurrentScan: boolean }
  | { reason: "context-change"; nextValue: false };

/**
 * External-processing consent is scoped to one input context and one scan.
 * A context change revokes it; submit snapshots the current choice and resets
 * the checkbox for the next scan.
 */
export function transitionExternalProcessingConsent(
  currentValue: boolean,
  reason: "submit",
): { reason: "submit"; nextValue: false; forCurrentScan: boolean };
export function transitionExternalProcessingConsent(
  currentValue: boolean,
  reason: "context-change",
): { reason: "context-change"; nextValue: false };
export function transitionExternalProcessingConsent(
  currentValue: boolean,
  reason: ConsentTransitionReason,
): ConsentTransition {
  if (reason === "submit") {
    return { reason, nextValue: false, forCurrentScan: currentValue };
  }

  return { reason, nextValue: false };
}
