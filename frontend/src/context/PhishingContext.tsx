import { createContext, useContext, useState } from "react";
import type { ReactNode } from "react";
import type { AnalysisResponse, ScanHistoryItem } from "../types";

export interface FullHistoryItem extends ScanHistoryItem {
  response: AnalysisResponse;
}

interface PhishingContextType {
  history: FullHistoryItem[];
  setHistory: (history: FullHistoryItem[]) => void;
  apiKey: string;
  setApiKey: (key: string) => void;
  isLoading: boolean;
  setIsLoading: (val: boolean) => void;
  error: string | null;
  setError: (err: string | null) => void;
  activeResponse: AnalysisResponse | null;
  setActiveResponse: (res: AnalysisResponse | null) => void;
  scanStepIndex: number;
  setScanStepIndex: (idx: number) => void;
}

const PhishingContext = createContext<PhishingContextType | undefined>(undefined);

export function PhishingProvider({ children }: { children: ReactNode }) {
  const [history, setHistory] = useState<FullHistoryItem[]>([]);
  const [apiKey, setApiKey] = useState<string>("");
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [activeResponse, setActiveResponse] = useState<AnalysisResponse | null>(null);
  const [scanStepIndex, setScanStepIndex] = useState<number>(0);


  return (
    <PhishingContext.Provider
      value={{
        history,
        setHistory,
        apiKey,
        setApiKey,
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

export function usePhishingContext() {
  const context = useContext(PhishingContext);
  if (!context) {
    throw new Error("usePhishingContext must be used within a PhishingProvider");
  }
  return context;
}
