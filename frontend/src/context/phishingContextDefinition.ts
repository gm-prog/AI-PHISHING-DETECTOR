import { createContext } from "react";
import type { AnalysisResponse, ScanHistoryItem } from "../types";

export interface FullHistoryItem extends ScanHistoryItem {
  response: AnalysisResponse;
}

interface PhishingContextType {
  history: FullHistoryItem[];
  setHistory: (history: FullHistoryItem[]) => void;
  isLoading: boolean;
  setIsLoading: (val: boolean) => void;
  error: string | null;
  setError: (err: string | null) => void;
  activeResponse: AnalysisResponse | null;
  setActiveResponse: (res: AnalysisResponse | null) => void;
  scanStepIndex: number;
  setScanStepIndex: (idx: number) => void;
}

export const PhishingContext = createContext<PhishingContextType | undefined>(undefined);
