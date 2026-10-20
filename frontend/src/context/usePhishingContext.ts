import { useContext } from "react";
import { PhishingContext } from "./phishingContextDefinition";

export function usePhishingContext() {
  const context = useContext(PhishingContext);
  if (!context) {
    throw new Error("usePhishingContext must be used within a PhishingProvider");
  }
  return context;
}
