import React, { useState, useEffect } from "react";
import { ShieldCheck, Settings, Wifi, WifiOff, Sparkles, User as UserIcon, LogOut, Cpu } from "lucide-react";
import { useAuth } from "../context/AuthContext";

interface HeaderProps {
  onOpenSettings: () => void;
  backendGeminiConfigured: boolean;
  setBackendGeminiConfigured: (val: boolean) => void;
  onAddToast: (msg: string, type: "success" | "error" | "info") => void;
}

export const Header: React.FC<HeaderProps> = ({
  onOpenSettings,
  backendGeminiConfigured,
  setBackendGeminiConfigured,
  onAddToast
}) => {
  const { user, isAuthenticated, logout, openAuthModal } = useAuth();
  const [backendStatus, setBackendStatus] = useState<"connecting" | "connected" | "disconnected">("connecting");

  const checkHealth = async () => {
    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:8000";
      const res = await fetch(`${API_BASE}/api/health`, { credentials: "include" });
      if (res.ok) {
        const data = await res.json();
        setBackendStatus("connected");
        setBackendGeminiConfigured(data.gemini_configured || false);
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

  const hasApiKey = backendGeminiConfigured;

  const handleLogout = () => {
    logout();
    onAddToast("Operator session ended. Switched to anonymous context.", "info");
  };

  return (
    <header className="relative w-full z-40 mb-6">
      <div className="tactical-panel px-5 py-3.5 flex flex-wrap items-center justify-between gap-4 border border-white/10 shadow-lg">
        {/* Brand Identity */}
        <div className="flex items-center gap-3">
          <div className="flex items-center justify-center w-9 h-9 rounded bg-[#00F0FF]/10 border border-[#00F0FF]/30">
            <ShieldCheck className="w-5 h-5 text-[#00F0FF]" />
          </div>
          <div className="text-left">
            <div className="flex items-center gap-2">
              <span className="text-base font-extrabold tracking-wider text-white font-mono">
                SENTINEL<span className="text-[#00F0FF]">.AI</span>
              </span>
              <span className="text-[10px] bg-[#00F0FF]/10 text-[#00F0FF] border border-[#00F0FF]/30 px-1.5 py-0.5 rounded font-mono font-bold uppercase tracking-wider">
                SOC v2.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-medium">Enterprise Phishing Intelligence Gateway</p>
          </div>
        </div>

        {/* Telemetry Pills & Actions */}
        <div className="flex items-center flex-wrap gap-2.5">
          {/* API Connection Indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-[#090D16] border border-white/10 text-xs font-mono">
            {backendStatus === "connected" ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-[#00E699]" />
                <span className="text-slate-300">GATEWAY: <strong className="text-[#00E699]">ONLINE</strong></span>
              </>
            ) : backendStatus === "connecting" ? (
              <>
                <div className="w-2 h-2 rounded-full bg-[#FFB800] animate-ping" />
                <span className="text-slate-400">CONNECTING...</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-[#FF3366]" />
                <span className="text-[#FF3366] font-bold">GATEWAY: OFFLINE</span>
              </>
            )}
          </div>

          {/* Engine Mode Status */}
          <button
            onClick={onOpenSettings}
            className={`flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-mono font-medium transition cursor-pointer focus-visible:ring-2 focus-visible:ring-[#00F0FF] ${
              hasApiKey
                ? "bg-[#00F0FF]/10 border-[#00F0FF]/30 text-[#00F0FF] hover:bg-[#00F0FF]/20"
                : "bg-[#00E699]/10 border-[#00E699]/30 text-[#00E699] hover:bg-[#00E699]/20"
            }`}
            title={hasApiKey ? "Hybrid Mode: Local Heuristics + Gemini 3.6 Flash LLM" : "Autonomous Mode: 100% Local Private Rules"}
          >
            {hasApiKey ? (
              <>
                <Sparkles className="w-3.5 h-3.5 text-[#00F0FF]" />
                <span>Engine: <strong>Gemini 3.6 Flash</strong></span>
              </>
            ) : (
              <>
                <Cpu className="w-3.5 h-3.5 text-[#00E699]" />
                <span>Engine: <strong>Local Heuristics</strong></span>
              </>
            )}
          </button>

          {/* Auth Operator Profile */}
          {isAuthenticated && user ? (
            <div className="flex items-center gap-2 pl-2 border-l border-white/10">
              <div className="px-3 py-1 rounded bg-[#090D16] border border-white/10 flex items-center gap-2">
                <div className="w-2 h-2 rounded-full bg-[#00E699]" />
                <span className="text-xs font-mono text-slate-200 truncate max-w-[140px]">{user.email}</span>
                {user.role === "admin" && (
                  <span className="text-[9px] px-1 py-0.5 rounded bg-[#FFB800]/20 text-[#FFB800] border border-[#FFB800]/30 font-bold uppercase font-mono">
                    ADMIN
                  </span>
                )}
              </div>
              <button
                onClick={handleLogout}
                className="p-1.5 rounded bg-[#FF3366]/10 hover:bg-[#FF3366]/20 border border-[#FF3366]/30 text-[#FF3366] transition cursor-pointer"
                title="Logout Operator"
                aria-label="Logout Operator"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            </div>
          ) : (
            <button
              onClick={openAuthModal}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#00F0FF]/15 hover:bg-[#00F0FF]/25 border border-[#00F0FF]/30 text-[#00F0FF] text-xs font-mono font-bold uppercase tracking-wider transition cursor-pointer"
            >
              <UserIcon className="w-3.5 h-3.5" />
              Operator Login
            </button>
          )}

          {/* Settings Modal Button */}
          <button
            onClick={onOpenSettings}
            className="p-2 rounded bg-[#090D16] hover:bg-[#131C31] border border-white/10 text-slate-300 transition cursor-pointer"
            aria-label="Gateway Settings"
            title="Gateway Settings"
          >
            <Settings className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};
