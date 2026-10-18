export type ConsentTransitionReason = "context-change" | "submit";

export interface ConsentTransition {
  nextValue: boolean;
  forCurrentScan?: boolean;
}

/**
 * External-processing consent is scoped to one input context and one scan.
 * A context change revokes it; submit snapshots the current choice and resets
 * the checkbox for the next scan.
 */
export function transitionExternalProcessingConsent(
  currentValue: boolean,
  reason: ConsentTransitionReason,
): ConsentTransition {
  if (reason === "submit") {
    return { nextValue: false, forCurrentScan: currentValue };
  }

  return { nextValue: false };
}
