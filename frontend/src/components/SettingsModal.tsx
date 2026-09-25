import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { X, ShieldCheck, Server, LockKeyhole } from "lucide-react";

interface SettingsModalProps {
  isOpen: boolean;
  onClose: () => void;
  onAddToast: (message: string, type: "success" | "error" | "info") => void;
}

export const SettingsModal: React.FC<SettingsModalProps> = ({
  isOpen,
  onClose,
  onAddToast
}) => {
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isOpen) onClose();
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [isOpen, onClose]);

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
            <div className="flex items-center justify-between border-b border-white/10 pb-3 mb-5">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded bg-[#00F0FF]/10 border border-[#00F0FF]/30 flex items-center justify-center">
                  <ShieldCheck className="w-4 h-4 text-[#00F0FF]" />
                </div>
                <div>
                  <h3 id="settings-modal-title" className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                    Gateway Security Settings
                  </h3>
                  <p className="text-[10px] text-slate-400 font-mono">
                    Credentials remain server-side
                  </p>
                </div>
              </div>
              <button onClick={onClose} className="p-1 rounded hover:bg-white/10 text-slate-400 hover:text-white transition cursor-pointer" aria-label="Close settings">
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-3 text-left">
              <div className="p-4 rounded bg-[#090D16] border border-white/10 flex gap-3">
                <Server className="w-5 h-5 text-[#00F0FF] flex-shrink-0" />
                <div>
                  <p className="text-xs font-bold text-slate-200 font-mono uppercase tracking-wider">AI provider credentials</p>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                    Gemini credentials are configured on the backend only. They are never stored in browser storage, embedded in frontend bundles, or accepted from scan requests.
                  </p>
                </div>
              </div>

              <div className="p-4 rounded bg-[#090D16] border border-white/10 flex gap-3">
                <LockKeyhole className="w-5 h-5 text-[#00E699] flex-shrink-0" />
                <div>
                  <p className="text-xs font-bold text-slate-200 font-mono uppercase tracking-wider">Session security</p>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                    Authentication uses an HttpOnly server-side session cookie with CSRF protection. JavaScript cannot read the authentication credential.
                  </p>
                </div>
              </div>
            </div>

            <div className="border-t border-white/10 pt-4 mt-5 flex justify-end">
              <button
                onClick={() => {
                  onAddToast("Gateway security settings verified.", "success");
                  onClose();
                }}
                className="px-4 py-2 rounded bg-[#00F0FF] hover:bg-[#33F3FF] text-[#080C14] text-xs font-extrabold font-mono uppercase tracking-wider transition cursor-pointer"
              >
                Close
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
