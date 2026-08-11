import React, { useState, useEffect } from "react";
import { ShieldCheck, Settings, Wifi, WifiOff, Sparkles, AlertCircle } from "lucide-react";

interface HeaderProps {
  onOpenSettings: () => void;
  userApiKey: string;
  backendGeminiConfigured: boolean;
  setBackendGeminiConfigured: (val: boolean) => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenSettings,
  userApiKey,
  backendGeminiConfigured,
  setBackendGeminiConfigured
}) => {
  const [backendStatus, setBackendStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");

  // Poll backend health status on mount and every 10 seconds
  const checkHealth = async () => {
    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:8000";
      const res = await fetch(`${API_BASE}/api/health`);
      if (res.ok) {
        const data = await res.json();
        setBackendStatus("connected");
        setBackendGeminiConfigured(data.gemini_configured_in_backend || false);
      } else {
        setBackendStatus("disconnected");
      }
    } catch {
      setBackendStatus("disconnected");
    }
  };

  useEffect(() => {
    checkHealth();
    const interval = setInterval(checkHealth, 10000);
    return () => clearInterval(interval);
  }, []);

  const hasApiKey = !!userApiKey || backendGeminiConfigured;

  return (
    <header className="relative w-full z-40 mb-8">
      <div className="glass-panel px-6 py-4 rounded-2xl flex items-center justify-between shadow-2xl">
        {/* Brand Logo and Title */}
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center w-10 h-10 rounded-xl bg-blue-600/20 border border-blue-500/30 glow-safe">
            <ShieldCheck className="w-6 h-6 text-blue-400 animate-pulse" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
              SENTINEL <span className="text-xs bg-blue-500/20 text-blue-300 border border-blue-500/30 px-2 py-0.5 rounded-full font-semibold font-mono uppercase tracking-wider">AI Phishing</span>
            </h1>
            <p className="text-xs text-slate-400">Cyber Threat Heuristic & Language Inspector</p>
          </div>
        </div>

        {/* Status Indicators & Settings button */}
        <div className="flex items-center gap-4">
          {/* Health check badge */}
          <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/60 border border-white/5 text-xs">
            {backendStatus === "connected" ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-green-400" />
                <span className="text-slate-300">API: Connected</span>
              </>
            ) : backendStatus === "connecting" ? (
              <>
                <div className="w-2 h-2 rounded-full bg-amber-400 animate-ping" />
                <span className="text-slate-400">Connecting API...</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-red-400 animate-bounce" />
                <span className="text-red-400 font-semibold">API: Offline</span>
              </>
            )}
          </div>

          {/* AI Engine Status badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900/60 border border-white/5 text-xs">
            <Sparkles className={`w-3.5 h-3.5 ${hasApiKey ? "text-cyan-400" : "text-amber-400 animate-pulse"}`} />
            {hasApiKey ? (
              <span className="text-cyan-300">AI: Active</span>
            ) : (
              <span className="text-amber-400 flex items-center gap-1 font-mono font-semibold">
                AI Offline
                <AlertCircle className="w-3 h-3 text-amber-500" />
              </span>
            )}
          </div>

          {/* Settings Trigger */}
          <button
            onClick={onOpenSettings}
            className="flex items-center gap-2 p-2 rounded-lg bg-slate-800/40 hover:bg-slate-800/80 border border-white/5 hover:border-white/10 text-slate-300 transition-all cursor-pointer"
            aria-label="Settings"
            id="settings_btn"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
