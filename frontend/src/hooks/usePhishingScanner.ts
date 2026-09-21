import { useEffect, useRef } from "react";
import { usePhishingContext } from "../context/PhishingContext";
import { useAuth } from "../context/AuthContext";
import type { AnalysisResponse } from "../types";

export interface ScanStep {
  label: string;
  duration: number; // ms to hold
}

export const SCANNING_STEPS: ScanStep[] = [
  { label: "Initializing Sentinel Threat Gateway", duration: 350 },
  { label: "Running Typosquat Entropy & Domain Anomaly Heuristics", duration: 500 },
  { label: "Correlating Threat Intel & Urgency Vectors", duration: 500 },
  { label: "Compiling Intelligence Report", duration: 600 }
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

  const { authFetch, isAuthenticated } = useAuth();
  const stepTimerRef = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);

  // Load history from backend whenever auth status changes
  const fetchHistory = async () => {
    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
      const res = await authFetch(`${API_BASE}/api/history`);
      if (res.ok) {
        const data = await res.json();
        setHistory(data);
      }
    } catch (err) {
      console.error("Failed to load history from backend:", err);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [isAuthenticated, setHistory]);

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
      const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
      const response = await authFetch(`${API_BASE}/api/analyze`, {
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
      await new Promise((resolve) => setTimeout(resolve, 250));
      
      setActiveResponse(data);
      addToast(`Threat Scan Complete: Classification ${data.status.toUpperCase()} (${data.risk_score}/100)`, "success");

      // Refetch history from backend to ensure synchronization
      fetchHistory();
    } catch (err: any) {
      console.error(err);
      clearTimeout(stepTimerRef.current);
      setError(err.message || "Could not connect to the backend server.");
      addToast(err.message || "Threat inspection scan failed.", "error");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearHistory = async () => {
    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
      const res = await authFetch(`${API_BASE}/api/history`, { method: "DELETE" });
      if (res.ok) {
        setHistory([]);
        addToast("Threat scan vault history cleared.", "info");
      }
    } catch (err) {
      console.error("Failed to clear history:", err);
    }
  };

  const handleDeleteSingle = async (id: string) => {
    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
      const res = await authFetch(`${API_BASE}/api/history/${id}`, { method: "DELETE" });
      if (res.ok) {
        setHistory(history.filter(item => item.id !== id));
        addToast("Record deleted from vault.", "info");
      }
    } catch (err) {
      console.error("Failed to delete record:", err);
    }
  };

  return { handleAnalyze, handleClearHistory, handleDeleteSingle };
}
