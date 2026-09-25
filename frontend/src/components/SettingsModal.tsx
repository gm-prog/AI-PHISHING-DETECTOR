import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, Key, HelpCircle, Check, AlertTriangle, RefreshCw, Eye, EyeOff } from "lucide-react";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  userApiKey: string;
  onSave: (key: string) => void;
  onAddToast: (message: string, type: "success" | "error" | "info") => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  userApiKey,
  onSave,
  onAddToast
}) => {
  const [apiKey, setApiKey] = useState(userApiKey);
  const [showKey, setShowKey] = useState(false);
  const [isVerifying, setIsVerifying] = useState(false);
  const [verifyResult, setVerifyResult] = useState<{ status: "idle" | "success" | "failed"; message: string }>({
    status: "idle",
    message: ""
  });

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) {
        onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

  const handleTestConnection = async () => {
    if (!apiKey.trim()) {
      setVerifyResult({ status: "failed", message: "API Key cannot be empty." });
      return;
    }

    setIsVerifying(true);
    setVerifyResult({ status: "idle", message: "" });

    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";
      const response = await fetch(`${API_BASE}/api/verify-gemini-key`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ api_key: apiKey.trim() })
      });

      if (!response.ok) {
        throw new Error("HTTP connection error.");
      }

      const data = await response.json();
      if (data.valid) {
        setVerifyResult({ status: "success", message: "Gemini 3.6 Flash key verified successfully." });
        onAddToast("Gemini 3.6 Flash key verified successfully.", "success");
      } else {
        setVerifyResult({ status: "failed", message: data.error || "Invalid API key." });
        onAddToast("Gemini key verification failed.", "error");
      }
    } catch (e: any) {
      setVerifyResult({
        status: "failed",
        message: e.message || "Failed to communicate with authentication gateway."
      });
      onAddToast("Gateway verification route error.", "error");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSave = () => {
    onSave(apiKey.trim());
    onAddToast("Gateway settings updated.", "success");
    onClose();
  };

  const handleClear = () => {
    setApiKey("");
    onSave("");
    onAddToast("Gemini API key cleared.", "info");
    setVerifyResult({ status: "idle", message: "" });
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
          />

          <motion.div
            role="dialog"
            aria-modal="true"
            aria-labelledby="settings-modal-title"
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            className="w-full max-w-lg tactical-panel p-6 rounded shadow-2xl relative z-10 overflow-hidden border border-white/10"
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded bg-[#00F0FF]/10 border border-[#00F0FF]/30 flex items-center justify-center">
                  <Key className="w-4 h-4 text-[#00F0FF]" />
                </div>
                <h3 id="settings-modal-title" className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                  Gateway Engine Settings
                </h3>
              </div>
              <button
                onClick={onClose}
                className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white transition cursor-pointer"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Content Body */}
            <div className="space-y-4 text-left">
              <div>
                <label className="text-[11px] font-bold font-mono uppercase tracking-wider text-slate-300 block mb-1">
                  Google Gemini 3.6 Flash API Key
                </label>
                
                <div className="relative">
                  <input
                    type={showKey ? "text" : "password"}
                    placeholder="Enter Key (AIzaSy...)"
                    value={apiKey}
                    onChange={(e) => {
                      setApiKey(e.target.value);
                      if (verifyResult.status !== "idle") {
                        setVerifyResult({ status: "idle", message: "" });
                      }
                    }}
                    className="w-full pl-3 pr-10 py-2 text-xs rounded tactical-input font-mono"
                    id="settings_api_input"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                  >
                    {showKey ? <EyeOff className="w-3.5 h-3.5" /> : <Eye className="w-3.5 h-3.5" />}
                  </button>
                </div>
              </div>

              {/* Informative helper block */}
              <div className="p-3 rounded bg-[#090D16] border border-white/10 text-xs text-slate-400 leading-relaxed flex gap-2">
                <HelpCircle className="w-4 h-4 text-[#00F0FF] flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-slate-300 mb-0.5">Where do I get a key?</p>
                  <p>
                    Generate a developer key in{" "}
                    <a
                      href="https://aistudio.google.com/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-[#00F0FF] hover:underline font-semibold"
                    >
                      Google AI Studio
                    </a>.
                  </p>
                </div>
              </div>

              {/* Verification Feedback Banner */}
              {verifyResult.status !== "idle" && (
                <div
                  className={`p-3 rounded border text-xs font-mono flex gap-2 ${
                    verifyResult.status === "success"
                      ? "badge-safe"
                      : "badge-danger"
                  }`}
                >
                  {verifyResult.status === "success" ? (
                    <Check className="w-4 h-4 flex-shrink-0 mt-0.5 text-[#00E699]" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-[#FF3366]" />
                  )}
                  <div>
                    <p className="font-bold uppercase tracking-wider">
                      {verifyResult.status === "success" ? "Key Authorized" : "Verification Failed"}
                    </p>
                    <p className="text-slate-300 mt-0.5 leading-relaxed">{verifyResult.message}</p>
                  </div>
                </div>
              )}
            </div>

            {/* Footer Actions */}
            <div className="flex flex-wrap gap-2 justify-between items-center border-t border-white/10 pt-3 mt-5">
              {apiKey && (
                <button
                  onClick={handleClear}
                  className="px-3 py-2 rounded bg-[#FF3366]/10 hover:bg-[#FF3366]/20 border border-[#FF3366]/30 text-[#FF3366] text-xs font-bold font-mono uppercase tracking-wider transition cursor-pointer"
                >
                  Clear Key
                </button>
              )}
              
              <div className="flex gap-2 ml-auto">
                <button
                  onClick={handleTestConnection}
                  disabled={isVerifying || !apiKey.trim()}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded border text-xs font-bold font-mono uppercase tracking-wider transition cursor-pointer ${
                    isVerifying || !apiKey.trim()
                      ? "bg-slate-900 border-white/10 text-slate-600 cursor-not-allowed"
                      : "bg-[#090D16] hover:bg-[#131C31] border-white/10 text-slate-300"
                  }`}
                >
                  {isVerifying ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin text-slate-400" />
                      Testing...
                    </>
                  ) : (
                    "Test Connection"
                  )}
                </button>
                
                <button
                  onClick={handleSave}
                  className="px-4 py-2 rounded bg-[#00F0FF] hover:bg-[#33F3FF] text-[#080C14] text-xs font-extrabold font-mono uppercase tracking-wider transition cursor-pointer"
                >
                  Save Settings
                </button>
              </div>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
