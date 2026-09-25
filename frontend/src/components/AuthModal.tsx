import React, { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Shield, Lock, Mail, UserPlus, LogIn, X, AlertTriangle, CheckCircle2 } from "lucide-react";
import { useAuth } from "../context/AuthContext";

interface AuthModalProps {
  onAddToast: (message: string, type: "success" | "error" | "info") => void;
}

export const AuthModal: React.FC<AuthModalProps> = ({ onAddToast }) => {
  const { isAuthModalOpen, closeAuthModal, login, register } = useAuth();
  const [tab, setTab] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [errorMsg, setErrorMsg] = useState("");

  const resetForm = () => {
    setEmail("");
    setPassword("");
    setErrorMsg("");
  };

  const handleClose = () => {
    resetForm();
    closeAuthModal();
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isAuthModalOpen) {
        handleClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isAuthModalOpen]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setErrorMsg("");

    if (!email || !password) {
      setErrorMsg("Please provide both email address and password.");
      return;
    }

    if (password.length < 8) {
      setErrorMsg("Password must be at least 8 characters long.");
      return;
    }

    setIsSubmitting(true);
    try {
      if (tab === "login") {
        const res = await login(email, password);
        if (res.success) {
          onAddToast("Operator authenticated successfully.", "success");
          resetForm();
        } else {
          setErrorMsg(res.error || "Authentication credentials rejected.");
        }
      } else {
        const res = await register(email, password);
        if (res.success) {
          onAddToast("Security account established successfully.", "success");
          resetForm();
        } else {
          setErrorMsg(res.error || "Account provisioning failed.");
        }
      }
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <AnimatePresence>
      {isAuthModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={handleClose}
            className="absolute inset-0 bg-black/80 backdrop-blur-sm"
          />

          <motion.div
            role="dialog"
            aria-modal="true"
            aria-labelledby="auth-modal-title"
            initial={{ opacity: 0, scale: 0.95, y: 10 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            className="w-full max-w-md tactical-panel p-6 rounded shadow-2xl relative z-10 overflow-hidden border border-white/10"
          >
            {/* Header */}
            <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-4">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded bg-[#00F0FF]/10 border border-[#00F0FF]/30 flex items-center justify-center">
                  <Shield className="w-4 h-4 text-[#00F0FF]" />
                </div>
                <div>
                  <h3 id="auth-modal-title" className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                    {tab === "login" ? "Operator Authentication" : "Register Security Account"}
                  </h3>
                  <p className="text-[10px] text-slate-400 font-mono">
                    {tab === "login" ? "Authenticate to access isolated vault" : "Provision a new tenant workspace"}
                  </p>
                </div>
              </div>
              <button
                onClick={handleClose}
                className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white transition cursor-pointer"
                aria-label="Close modal"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Tab Selector */}
            <div className="flex rounded bg-[#090D16] p-1 mb-4 border border-white/10" role="tablist">
              <button
                type="button"
                role="tab"
                aria-selected={tab === "login"}
                onClick={() => {
                  setTab("login");
                  setErrorMsg("");
                }}
                className={`flex-1 flex items-center justify-center gap-2 py-1.5 rounded text-xs font-mono font-bold uppercase tracking-wider transition cursor-pointer ${
                  tab === "login"
                    ? "bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/40 font-bold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <LogIn className="w-3.5 h-3.5" />
                Sign In
              </button>
              <button
                type="button"
                role="tab"
                aria-selected={tab === "register"}
                onClick={() => {
                  setTab("register");
                  setErrorMsg("");
                }}
                className={`flex-1 flex items-center justify-center gap-2 py-1.5 rounded text-xs font-mono font-bold uppercase tracking-wider transition cursor-pointer ${
                  tab === "register"
                    ? "bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/40 font-bold"
                    : "text-slate-400 hover:text-slate-200"
                }`}
              >
                <UserPlus className="w-3.5 h-3.5" />
                Register
              </button>
            </div>

            {/* Error Banner */}
            {errorMsg && (
              <div className="mb-4 p-2.5 rounded bg-[#FF3366]/10 border border-[#FF3366]/30 text-[#FF3366] text-xs flex items-start gap-2 font-mono">
                <AlertTriangle className="w-4 h-4 text-[#FF3366] flex-shrink-0 mt-0.5" />
                <span>{errorMsg}</span>
              </div>
            )}

            {/* Form */}
            <form onSubmit={handleSubmit} className="space-y-3 text-left">
              <div>
                <label className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider block mb-1">
                  Email Address
                </label>
                <div className="relative">
                  <Mail className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="email"
                    required
                    placeholder="operator@sentinel.security"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 rounded tactical-input text-xs font-mono"
                  />
                </div>
              </div>

              <div>
                <label className="text-[11px] font-mono font-bold text-slate-300 uppercase tracking-wider block mb-1">
                  Password
                </label>
                <div className="relative">
                  <Lock className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
                  <input
                    type="password"
                    required
                    placeholder="••••••••••••"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className="w-full pl-9 pr-3 py-2 rounded tactical-input text-xs font-mono"
                  />
                </div>
              </div>

              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full mt-4 py-2.5 rounded bg-[#00F0FF] hover:bg-[#33F3FF] disabled:opacity-50 text-[#080C14] font-mono font-extrabold text-xs uppercase tracking-wider transition flex items-center justify-center gap-2 cursor-pointer"
              >
                {isSubmitting ? (
                  <div className="w-4 h-4 border-2 border-slate-600 border-t-[#080C14] rounded-full animate-spin" />
                ) : tab === "login" ? (
                  <>
                    <LogIn className="w-4 h-4" />
                    Authorize Session
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="w-4 h-4" />
                    Establish Workspace
                  </>
                )}
              </button>
            </form>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
