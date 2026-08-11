import React, { useState } from "react";
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

  const handleTestConnection = async () => {
    if (!apiKey.trim()) {
      setVerifyResult({ status: "failed", message: "API Key cannot be empty." });
      return;
    }

    setIsVerifying(true);
    setVerifyResult({ status: "idle", message: "" });

    try {
      const API_BASE = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || "http://localhost:8000";
      const response = await fetch(`${API_BASE}/api/verify-key`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ api_key: apiKey.trim() })
      });

      if (!response.ok) {
        throw new Error("HTTP error connecting to verification gateway.");
      }

      const data = await response.json();
      if (data.valid) {
        setVerifyResult({ status: "success", message: "Gemini Key authorized successfully!" });
        onAddToast("Gemini key verified successfully.", "success");
      } else {
        setVerifyResult({ status: "failed", message: data.error || "Invalid API key." });
        onAddToast("Gemini key verification failed.", "error");
      }
    } catch (e: any) {
      setVerifyResult({
        status: "failed",
        message: e.message || "Failed to communicate with authentication gateway."
      });
      onAddToast("Failed to connect to verification route.", "error");
    } finally {
      setIsVerifying(false);
    }
  };

  const handleSave = () => {
    localStorage.setItem("gemini_api_key", apiKey.trim());
    onSave(apiKey.trim());
    onAddToast("Settings saved successfully.", "success");
    onClose();
  };

  const handleClear = () => {
    setApiKey("");
    localStorage.removeItem("gemini_api_key");
    onSave("");
    onAddToast("Gemini API key cleared.", "info");
    setVerifyResult({ status: "idle", message: "" });
  };

  return (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          {/* Backdrop Blur Overlay */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="absolute inset-0 bg-black/75 backdrop-blur-sm"
          />

          {/* Modal Card */}
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 15 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.9, y: 15 }}
            transition={{ type: "spring", damping: 25, stiffness: 350 }}
            className="w-full max-w-lg glass-panel p-6 rounded-2xl shadow-3xl relative z-10 overflow-hidden border-white/10"
            style={{ backdropFilter: "blur(20px)" }}
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-white/5 pb-3.5 mb-5">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-blue-600/10 border border-blue-500/20 flex items-center justify-center">
                  <Key className="w-4 h-4 text-blue-400" />
                </div>
                <h3 className="text-base font-bold text-white font-mono uppercase tracking-wider">
                  Settings & API Gateway
                </h3>
              </div>
              <button
                onClick={onClose}
                className="p-1 rounded-lg hover:bg-white/5 text-slate-400 hover:text-slate-200 transition"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Content Body */}
            <div className="space-y-4 text-left">
              <div>
                <label className="text-xs font-bold font-mono uppercase tracking-wider text-slate-300 block mb-2">
                  Google Gemini API Key
                </label>
                
                <div className="relative">
                  <input
                    type={showKey ? "text" : "password"}
                    placeholder="Enter API Key (AIzaSy...)"
                    value={apiKey}
                    onChange={(e) => {
                      setApiKey(e.target.value);
                      if (verifyResult.status !== "idle") {
                        setVerifyResult({ status: "idle", message: "" });
                      }
                    }}
                    className="w-full pl-4 pr-11 py-3 text-xs rounded-xl glass-input text-white font-mono"
                    id="settings_api_input"
                  />
                  <button
                    type="button"
                    onClick={() => setShowKey(!showKey)}
                    className="absolute right-3.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300 transition"
                  >
                    {showKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                  </button>
                </div>
              </div>

              {/* Informative helper block */}
              <div className="p-3 rounded-xl bg-slate-900/60 border border-white/5 text-xs text-slate-400 leading-relaxed flex gap-2.5">
                <HelpCircle className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-slate-300 mb-0.5">Where do I get a key?</p>
                  <p>
                    Create a free developer API key via the official{" "}
                    <a
                      href="https://aistudio.google.com/"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-blue-400 hover:text-blue-300 underline font-semibold transition"
                    >
                      Google AI Studio portal
                    </a>.
                  </p>
                </div>
              </div>

              {/* Verification Feedback Banner */}
              {verifyResult.status !== "idle" && (
                <motion.div
                  initial={{ opacity: 0, y: -10 }}
                  animate={{ opacity: 1, y: 0 }}
                  className={`p-3.5 rounded-xl border text-xs font-mono flex gap-2.5 ${
                    verifyResult.status === "success"
                      ? "bg-green-500/10 border-green-500/20 text-green-400"
                      : "bg-red-500/10 border-red-500/20 text-red-400"
                  }`}
                >
                  {verifyResult.status === "success" ? (
                    <Check className="w-4 h-4 flex-shrink-0 mt-0.5 text-green-400" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5 text-red-400" />
                  )}
                  <div>
                    <p className="font-bold uppercase tracking-wider">
                      {verifyResult.status === "success" ? "Verification OK" : "Verification Failed"}
                    </p>
                    <p className="text-slate-300 mt-1 leading-relaxed">{verifyResult.message}</p>
                  </div>
                </motion.div>
              )}
            </div>

            {/* Footer Actions */}
            <div className="flex flex-wrap gap-2.5 justify-between items-center border-t border-white/5 pt-4 mt-6">
              {apiKey && (
                <button
                  onClick={handleClear}
                  className="px-3.5 py-2.5 rounded-xl bg-red-950/20 hover:bg-red-950/40 border border-red-500/20 text-red-400 text-xs font-bold font-mono uppercase tracking-wider transition"
                >
                  Clear Key
                </button>
              )}
              
              <div className="flex gap-2 ml-auto">
                <button
                  onClick={handleTestConnection}
                  disabled={isVerifying || !apiKey.trim()}
                  className={`flex items-center gap-1.5 px-4 py-2.5 rounded-xl border text-xs font-bold font-mono uppercase tracking-wider transition ${
                    isVerifying || !apiKey.trim()
                      ? "bg-slate-900/20 border-white/5 text-slate-500 cursor-not-allowed"
                      : "bg-slate-800 hover:bg-slate-700/80 border-white/10 text-slate-300"
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
                  className="px-5 py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 border border-blue-400/20 text-white text-xs font-bold font-mono uppercase tracking-wider shadow-[0_0_15px_-3px_rgba(59,130,246,0.5)] transition"
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
