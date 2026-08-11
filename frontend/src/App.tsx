import { useState } from "react";
import { Header } from "./components/Header";
import { AnalyzerInput } from "./components/AnalyzerInput";
import { RiskGauge } from "./components/RiskGauge";
import { SignalList } from "./components/SignalList";
import { LlmReport } from "./components/LlmReport";
import { HistoryTracker } from "./components/HistoryTracker";
import { SettingsModal } from "./components/SettingsModal";
import { Toast } from "./components/Toast";
import type { ToastItem } from "./components/Toast";
import type { ScanHistoryItem } from "./types";
import { ShieldCheck, ShieldAlert, Terminal } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

import { usePhishingContext } from "./context/PhishingContext";
import { usePhishingScanner, SCANNING_STEPS } from "./hooks/usePhishingScanner";

export default function App() {
  const {
    history, setHistory,
    apiKey, setApiKey,
    isLoading,
    error, setError,
    activeResponse, setActiveResponse,
    scanStepIndex
  } = usePhishingContext();

  // Settings Modal & Toasts
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [backendGeminiConfigured, setBackendGeminiConfigured] = useState(false);
  const [toasts, setToasts] = useState<ToastItem[]>([]);

  const addToast = (message: string, type: "success" | "error" | "info") => {
    const id = crypto.randomUUID ? crypto.randomUUID() : Date.now().toString() + Math.random().toString();
    setToasts((prev) => [...prev, { id, message, type }]);
  };

  const removeToast = (id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const handleApiKeyChange = (newKey: string) => {
    setApiKey(newKey);
  };

  const { handleAnalyze } = usePhishingScanner(addToast);

  const handleSelectHistoryItem = (item: ScanHistoryItem) => {
    const fullItem = history.find((h) => h.id === item.id);
    if (fullItem) {
      setActiveResponse(fullItem.response);
      setError(null);
      addToast("Loaded scan from history logs.", "info");
    }
  };

  const handleClearHistory = () => {
    setHistory([]);
    addToast("Scan history cleared successfully.", "info");
  };

  return (
    <div className="bg-mesh min-h-screen text-slate-100 p-4 md:p-8 selection:bg-blue-600/30 selection:text-white">
      <div className="max-w-7xl mx-auto">
        {/* Header Navigation */}
        <Header 
          onOpenSettings={() => setIsSettingsOpen(true)} 
          userApiKey={apiKey}
          backendGeminiConfigured={backendGeminiConfigured}
          setBackendGeminiConfigured={setBackendGeminiConfigured}
        />

        {/* Global Error Banner */}
        {error && (
          <div className="mb-6 p-4 rounded-xl bg-red-950/30 border border-red-500/20 text-red-300 text-xs font-mono flex items-center gap-3 animate-in fade-in duration-300">
            <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center">
              <ShieldAlert className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <p className="font-bold">SECURITY GATEWAY ERROR</p>
              <p className="text-slate-400 mt-0.5">{error}</p>
            </div>
          </div>
        )}

        {/* Workspace Layout Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
          
          {/* Left Column: Inputs & History (Span 5) */}
          <div className="lg:col-span-5 space-y-8">
            <AnalyzerInput onAnalyze={handleAnalyze} isLoading={isLoading} />
            <HistoryTracker 
              history={history} 
              onSelect={handleSelectHistoryItem} 
              onClear={handleClearHistory} 
            />
          </div>

          {/* Right Column: Visualization & Reports (Span 7) */}
          <div className="lg:col-span-7">
            <AnimatePresence mode="wait">
              {isLoading ? (
                /* Cinematic Scanning Overlay */
                <motion.div
                  key="loading"
                  initial={{ opacity: 0, scale: 0.98 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.98 }}
                  className="glass-panel p-8 rounded-2xl flex flex-col items-center justify-center text-center shadow-3xl min-h-[500px] border-blue-500/20 relative overflow-hidden"
                >
                  <div className="scan-line" />
                  
                  {/* Radar Ring Visual */}
                  <div className="relative w-20 h-20 flex items-center justify-center mb-8">
                    <div className="absolute inset-0 rounded-full border border-blue-500/20 animate-ping opacity-60" />
                    <div className="absolute inset-2 rounded-full border border-cyan-500/30 animate-[spin_6s_linear_infinite]" />
                    <div className="w-12 h-12 rounded-xl bg-slate-950 border border-blue-500/30 flex items-center justify-center relative z-10 glow-safe">
                      <Terminal className="w-5 h-5 text-cyan-400 animate-pulse" />
                    </div>
                  </div>

                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-widest animate-pulse">
                    Threat Cyber-Inspection Active
                  </h3>
                  
                  {/* Step-by-Step Progress Checkmarks */}
                  <div className="mt-8 space-y-3.5 max-w-sm w-full text-left bg-slate-950/45 p-5 rounded-2xl border border-white/5 font-mono text-[11px]">
                    {SCANNING_STEPS.map((step, idx) => {
                      const isDone = scanStepIndex > idx;
                      const isActive = scanStepIndex === idx;
                      
                      return (
                        <div
                          key={idx}
                          className={`flex items-center justify-between gap-3 transition-colors duration-200 ${
                            isDone ? "text-green-400 font-bold" : isActive ? "text-cyan-400 font-bold" : "text-slate-500"
                          }`}
                        >
                          <span className="truncate pr-2">{step.label}</span>
                          <span className="flex-shrink-0">
                            {isDone ? (
                              "✓ COMPLETE"
                            ) : isActive ? (
                              <span className="flex items-center gap-1">
                                <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-ping" />
                                RUNNING...
                              </span>
                            ) : (
                              "PENDING"
                            )}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                </motion.div>
              ) : activeResponse ? (
                /* Results Dashboard Visuals */
                <motion.div
                  key="results"
                  initial={{ opacity: 0, y: 15 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -15 }}
                  transition={{ duration: 0.35, ease: "easeOut" }}
                  className="space-y-8"
                >
                  <div className="grid grid-cols-1 md:grid-cols-12 gap-8">
                    <div className="md:col-span-5">
                      <RiskGauge score={activeResponse.risk_score} status={activeResponse.status} />
                    </div>
                    <div className="md:col-span-7">
                      <SignalList signals={activeResponse.phishing_signals} analysisData={activeResponse} />
                    </div>
                  </div>

                  <div className="w-full">
                    <LlmReport explanation={activeResponse.ai_explanation} />
                  </div>

                  {activeResponse.details && Object.keys(activeResponse.details).length > 0 && (
                    <div className="glass-panel p-5 rounded-2xl text-left border-white/5">
                      <div className="flex items-center gap-2 border-b border-white/5 pb-2 mb-3">
                        <Terminal className="w-4 h-4 text-slate-400" />
                        <h4 className="text-[10px] font-bold font-mono text-slate-400 uppercase tracking-widest">
                          Technical Inspection Metadata
                        </h4>
                      </div>
                      <pre className="text-[10px] font-mono text-slate-400 bg-slate-950/40 p-3 rounded-lg overflow-x-auto max-h-[150px] leading-relaxed">
                        {JSON.stringify(activeResponse.details, null, 2)}
                      </pre>
                    </div>
                  )}
                </motion.div>
              ) : (
                /* Awaiting Input Visuals */
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="glass-panel p-12 rounded-2xl flex flex-col items-center justify-center text-center shadow-2xl min-h-[500px]"
                >
                  <div className="w-14 h-14 rounded-2xl bg-slate-950 border border-white/5 flex items-center justify-center mb-6 shadow-inner">
                    <ShieldCheck className="w-7 h-7 text-slate-500 animate-pulse" />
                  </div>
                  
                  <h3 className="text-sm font-bold text-slate-300 font-mono uppercase tracking-widest">
                    Awaiting Inspection Input
                  </h3>
                  <p className="text-xs text-slate-500 mt-2 max-w-sm leading-relaxed">
                    Input a website domain address, email text body content, or email protocol header block to verify security indexes and generate explanations.
                  </p>

                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mt-8 max-w-md w-full">
                    <div className="p-3 rounded-xl bg-slate-950/30 border border-white/5 text-left">
                      <span className="text-[9px] font-mono font-bold text-slate-400 block mb-1">STEP 1</span>
                      <span className="text-[11px] text-slate-500 leading-normal">Paste your content or select a sample case.</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950/30 border border-white/5 text-left">
                      <span className="text-[9px] font-mono font-bold text-slate-400 block mb-1">STEP 2</span>
                      <span className="text-[11px] text-slate-500 leading-normal">Heuristics identify spoofs and domain typo signatures.</span>
                    </div>
                    <div className="p-3 rounded-xl bg-slate-950/30 border border-white/5 text-left">
                      <span className="text-[9px] font-mono font-bold text-slate-400 block mb-1">STEP 3</span>
                      <span className="text-[11px] text-slate-500 leading-normal">AI engine explains tactics and risk rating.</span>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Centered Centered Settings Modal */}
      <SettingsModal 
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        userApiKey={apiKey}
        onSave={handleApiKeyChange}
        onAddToast={addToast}
      />

      {/* Floating Toast Notification Portal */}
      <Toast toasts={toasts} onClose={removeToast} />
    </div>
  );
}
