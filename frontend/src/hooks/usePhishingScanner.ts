import { useEffect, useRef } from "react";
import { usePhishingContext } from "../context/PhishingContext";
import type { FullHistoryItem } from "../context/PhishingContext";
import type { AnalysisResponse } from "../types";

export interface ScanStep {
  label: string;
  duration: number; // ms to hold
}

export const SCANNING_STEPS: ScanStep[] = [
  { label: "Initializing Threat Gateway Connection", duration: 400 },
  { label: "Executing Rule Heuristics & Typosquat Math", duration: 600 },
  { label: "Scrutinizing Urgency & Social Engineering Cues", duration: 600 },
  { label: "Generating Threat Intelligence Report", duration: 800 }
];

export function usePhishingScanner(addToast: (msg: string, type: "success" | "error" | "info") => void) {
  const {
    history, setHistory,
    apiKey,
    setIsLoading,
    setError,
    setActiveResponse,
    setScanStepIndex
  } = usePhishingContext();

  const stepTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Load history from backend on mount
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:8000";
        const res = await fetch(`${API_BASE}/api/history`);
        if (res.ok) {
          const data = await res.json();
          setHistory(data);
        }
      } catch (err) {
        console.error("Failed to load history from backend:", err);
      }
    };
    fetchHistory();
  }, [setHistory]);

  const handleAnalyze = async (type: "url" | "email_text" | "email_header", content: string) => {
    setIsLoading(true);
    setError(null);
    setActiveResponse(null);
    setScanStepIndex(0);

    const progressSteps = (index: number) => {
      if (index >= SCANNING_STEPS.length - 1) return;
      stepTimerRef.current = setTimeout(() => {
        setScanStepIndex(index + 1);
        progressSteps(index + 1);
      }, SCANNING_STEPS[index].duration);
    };
    progressSteps(0);

    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:8000";
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          input_type: type,
          content: content,
          api_key: apiKey || undefined
        })
      });

      if (!response.ok) {
        const errorData = await response.json();
        throw new Error(errorData.detail || "Server failed to process analysis request.");
      }

      const data: AnalysisResponse = await response.json();
      
      clearTimeout(stepTimerRef.current);
      setScanStepIndex(SCANNING_STEPS.length - 1);
      await new Promise((resolve) => setTimeout(resolve, 300));
      
      setActiveResponse(data);
      addToast(`Threat Scan completed successfully. Threat Level: ${data.status.toUpperCase()}`, "success");

      // Add to context history (backend already saved it, but we can optimistically add it)
      const previewText = content.length > 55 ? content.substring(0, 55) + "..." : content;
      const historyItem: FullHistoryItem = {
        id: crypto.randomUUID ? crypto.randomUUID() : Date.now().toString(),
        timestamp: new Date().toISOString(),
        input_type: type,
        content: previewText,
        risk_score: data.risk_score,
        status: data.status,
        response: data
      };
      setHistory([historyItem, ...history.slice(0, 29)]);
    } catch (err: any) {
      console.error(err);
      clearTimeout(stepTimerRef.current);
      setError(err.message || "Could not connect to the backend server.");
      addToast("Threat inspection scan failed.", "error");
    } finally {
      setIsLoading(false);
    }
  };

  return { handleAnalyze };
}
