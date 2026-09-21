import { useState } from "react";
import { Header } from "./components/Header";
import { AnalyzerInput } from "./components/AnalyzerInput";
import { RiskGauge } from "./components/RiskGauge";
import { SignalList } from "./components/SignalList";
import { ThreatRadar } from "./components/ThreatRadar";
import { LlmReport } from "./components/LlmReport";
import { HistoryTracker } from "./components/HistoryTracker";
import { SettingsModal } from "./components/SettingsModal";
import { AuthModal } from "./components/AuthModal";
import { Toast } from "./components/Toast";
import type { ToastItem } from "./components/Toast";
import type { ScanHistoryItem } from "./types";
import { ShieldCheck, ShieldAlert, Terminal, Activity, Database } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import GlassSurface from "./components/GlassSurface";

import { usePhishingContext } from "./context/PhishingContext";
import { usePhishingScanner, SCANNING_STEPS } from "./hooks/usePhishingScanner";

export default function App() {
  const {
    history,
    apiKey, setApiKey,
    isLoading,
    error, setError,
    activeResponse, setActiveResponse,
    scanStepIndex
  } = usePhishingContext();

  // Modals & Toasts
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

  const { handleAnalyze, handleClearHistory, handleDeleteSingle } = usePhishingScanner(addToast);

  const handleSelectHistoryItem = (item: ScanHistoryItem) => {
    if (item.response) {
      setActiveResponse(item.response);
      setError(null);
      addToast("Loaded threat telemetry from vault.", "info");
    } else {
      const fullItem = history.find((h) => h.id === item.id);
      if (fullItem && fullItem.response) {
        setActiveResponse(fullItem.response);
        setError(null);
        addToast("Loaded threat telemetry from vault.", "info");
      }
    }
  };

  // Telemetry Metrics
  const totalScans = history.length;
  const criticalThreats = history.filter(h => h.status === "danger").length;
  const moderateThreats = history.filter(h => h.status === "warning").length;
  const cleanScans = history.filter(h => h.status === "safe").length;

  return (
    <div className="bg-tactical-grid min-h-screen text-slate-100 p-4 md:p-6 font-sans">
      <div className="max-w-7xl mx-auto">
        {/* Header Navigation */}
        <Header 
          onOpenSettings={() => setIsSettingsOpen(true)} 
          userApiKey={apiKey}
          backendGeminiConfigured={backendGeminiConfigured}
          setBackendGeminiConfigured={setBackendGeminiConfigured}
          onAddToast={addToast}
        />

        {/* Global Security Metrics Bar */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
          <GlassSurface width="100%" height={70} borderRadius={8} brightness={30} opacity={0.7} className="tactical-panel border border-white/10">
            <div className="flex items-center gap-3 w-full px-3">
              <div className="p-2 rounded bg-[#00F0FF]/10 border border-[#00F0FF]/20 text-[#00F0FF]">
                <Database className="w-4 h-4" />
              </div>
              <div className="text-left">
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Vault Scans</p>
                <p className="text-base font-bold font-mono text-white">{totalScans}</p>
              </div>
            </div>
          </GlassSurface>

          <GlassSurface width="100%" height={70} borderRadius={8} brightness={30} opacity={0.7} className="tactical-panel border border-white/10">
            <div className="flex items-center gap-3 w-full px-3">
              <div className="p-2 rounded bg-[#FF3366]/10 border border-[#FF3366]/20 text-[#FF3366]">
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div className="text-left">
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Critical Threats</p>
                <p className="text-base font-bold font-mono text-[#FF3366]">{criticalThreats}</p>
              </div>
            </div>
          </GlassSurface>

          <GlassSurface width="100%" height={70} borderRadius={8} brightness={30} opacity={0.7} className="tactical-panel border border-white/10">
            <div className="flex items-center gap-3 w-full px-3">
              <div className="p-2 rounded bg-[#FFB800]/10 border border-[#FFB800]/20 text-[#FFB800]">
                <Activity className="w-4 h-4" />
              </div>
              <div className="text-left">
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Warnings</p>
                <p className="text-base font-bold font-mono text-[#FFB800]">{moderateThreats}</p>
              </div>
            </div>
          </GlassSurface>

          <GlassSurface width="100%" height={70} borderRadius={8} brightness={30} opacity={0.7} className="tactical-panel border border-white/10">
            <div className="flex items-center gap-3 w-full px-3">
              <div className="p-2 rounded bg-[#00E699]/10 border border-[#00E699]/20 text-[#00E699]">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <div className="text-left">
                <p className="text-[10px] font-mono text-slate-400 uppercase tracking-wider">Verified Clean</p>
                <p className="text-base font-bold font-mono text-[#00E699]">{cleanScans}</p>
              </div>
            </div>
          </GlassSurface>
        </div>

        {/* Global Gateway Alert */}
        {error && (
          <div className="mb-5 p-3.5 rounded bg-[#FF3366]/10 border border-[#FF3366]/30 text-[#FF3366] text-xs font-mono flex items-center gap-3 text-left">
            <ShieldAlert className="w-4 h-4 text-[#FF3366] flex-shrink-0" />
            <div>
              <p className="font-bold uppercase tracking-wider">SECURITY GATEWAY ALERT</p>
              <p className="text-slate-300 mt-0.5">{error}</p>
            </div>
          </div>
        )}

        {/* Workspace Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
          
          {/* Left Column: Console & History Vault */}
          <div className="lg:col-span-5 space-y-5">
            <AnalyzerInput onAnalyze={handleAnalyze} isLoading={isLoading} />
            <HistoryTracker 
              history={history} 
              onSelect={handleSelectHistoryItem} 
              onClear={handleClearHistory}
              onDeleteSingle={handleDeleteSingle}
            />
          </div>

          {/* Right Column: Telemetry & Report Inspector */}
          <div className="lg:col-span-7">
            <AnimatePresence mode="wait">
              {isLoading ? (
                /* Scanning HUD Indicator */
                <motion.div
                  key="loading"
                  initial={{ opacity: 0, scale: 0.98 }}
                  animate={{ opacity: 1, scale: 1 }}
                  exit={{ opacity: 0, scale: 0.98 }}
                  className="tactical-panel p-8 rounded flex flex-col items-center justify-center text-center min-h-[500px] border border-[#00F0FF]/30 relative overflow-hidden"
                >
                  <div className="scan-line-tactical" />
                  
                  <div className="relative w-16 h-16 flex items-center justify-center mb-5">
                    <div className="absolute inset-0 rounded-full border border-[#00F0FF]/30 animate-ping" />
                    <div className="w-10 h-10 rounded bg-[#090D16] border border-[#00F0FF]/40 flex items-center justify-center relative z-10">
                      <Terminal className="w-5 h-5 text-[#00F0FF] animate-pulse" />
                    </div>
                  </div>

                  <h3 className="text-sm font-bold text-white font-mono uppercase tracking-widest">
                    EXECUTING ZERO-TRUST SCAN
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1">Multi-vector heuristic extraction active</p>
                  
                  {/* Scanning Checklist */}
                  <div className="mt-6 space-y-2.5 max-w-sm w-full text-left bg-[#090D16] p-4 rounded border border-white/10 font-mono text-[11px]">
                    {SCANNING_STEPS.map((step, idx) => {
                      const isDone = scanStepIndex > idx;
                      const isActive = scanStepIndex === idx;
                      
                      return (
                        <div
                          key={idx}
                          className={`flex items-center justify-between gap-3 ${
                            isDone ? "text-[#00E699] font-bold" : isActive ? "text-[#00F0FF] font-bold" : "text-slate-500"
                          }`}
                        >
                          <span className="truncate pr-2">{step.label}</span>
                          <span className="flex-shrink-0">
                            {isDone ? (
                              "✓ COMPLETE"
                            ) : isActive ? (
                              "SCANNING..."
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
                /* Live Telemetry Inspector */
                <motion.div
                  key="results"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                  transition={{ duration: 0.25 }}
                  className="space-y-5"
                >
                  {/* Gauge & Radar Grid */}
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
                    <RiskGauge score={activeResponse.risk_score} status={activeResponse.status} />
                    <ThreatRadar response={activeResponse} />
                  </div>

                  {/* Signal Breakdown List */}
                  <SignalList signals={activeResponse.phishing_signals} />

                  {/* AI Report Inspector */}
                  <LlmReport explanation={activeResponse.ai_explanation} onAddToast={addToast} />
                </motion.div>
              ) : (
                /* Empty Telemetry State */
                <motion.div
                  key="empty"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="tactical-panel p-12 rounded flex flex-col items-center justify-center text-center min-h-[460px] border border-white/10"
                >
                  <div className="w-12 h-12 rounded bg-[#00F0FF]/10 border border-[#00F0FF]/30 flex items-center justify-center mb-4">
                    <ShieldCheck className="w-6 h-6 text-[#00F0FF]" />
                  </div>
                  <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider">
                    SOC Threat Intelligence Gateway
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-1 max-w-md">
                    Select an input vector on the left console (URL, Email Body, or MIME Header) and execute a threat scan to view real-time risk assessment and AI briefings.
                  </p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>

      {/* Settings Modal */}
      <SettingsModal
        isOpen={isSettingsOpen}
        onClose={() => setIsSettingsOpen(false)}
        userApiKey={apiKey}
        onSave={handleApiKeyChange}
        onAddToast={addToast}
      />

      {/* Auth Modal */}
      <AuthModal onAddToast={addToast} />

      {/* Toast Notification Container */}
      <Toast toasts={toasts} onClose={removeToast} />
    </div>
  );
}
