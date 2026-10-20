import { useState } from "react";
import { PhishingContext } from "./phishingContextDefinition";
import type { FullHistoryItem } from "./phishingContextDefinition";
import type { AnalysisResponse } from "../types";
import type { ReactNode } from "react";


export function PhishingProvider({ children }: { children: ReactNode }) {
  const [history, setHistory] = useState<FullHistoryItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeResponse, setActiveResponse] = useState<AnalysisResponse | null>(null);
  const [scanStepIndex, setScanStepIndex] = useState<number>(0);

  return (
    <PhishingContext.Provider
      value={{
        history,
        setHistory,
        isLoading,
        setIsLoading,
        error,
        setError,
        activeResponse,
        setActiveResponse,
        scanStepIndex,
        setScanStepIndex,
      }}
    >
      {children}
    </PhishingContext.Provider>
  );
}

