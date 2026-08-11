import React, { useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { CheckCircle, AlertCircle, Info, X } from "lucide-react";

export interface ToastItem {
  id: string;
  message: string;
  type: "success" | "error" | "info";
}

interface ToastProps {
  toasts: ToastItem[];
  onClose: (id: string) => void;
}

export const Toast: React.FC<ToastProps> = ({ toasts, onClose }) => {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col gap-3 w-full max-w-sm pointer-events-none">
      <AnimatePresence>
        {toasts.map((toast) => (
          <ToastCard key={toast.id} toast={toast} onClose={onClose} />
        ))}
      </AnimatePresence>
    </div>
  );
};

interface ToastCardProps {
  toast: ToastItem;
  onClose: (id: string) => void;
}

const ToastCard: React.FC<ToastCardProps> = ({ toast, onClose }) => {
  // Auto-dismiss after 3.5 seconds
  useEffect(() => {
    const timer = setTimeout(() => {
      onClose(toast.id);
    }, 3500);
    return () => clearTimeout(timer);
  }, [toast.id, onClose]);

  const config = {
    success: {
      icon: CheckCircle,
      color: "text-green-400",
      border: "border-green-500/20",
      bg: "bg-green-950/20",
      shadow: "shadow-green-950/20",
      title: "Success"
    },
    error: {
      icon: AlertCircle,
      color: "text-red-400",
      border: "border-red-500/20",
      bg: "bg-red-950/20",
      shadow: "shadow-red-950/20",
      title: "Security Gateway Error"
    },
    info: {
      icon: Info,
      color: "text-blue-400",
      border: "border-blue-500/20",
      bg: "bg-blue-950/20",
      shadow: "shadow-blue-950/20",
      title: "Information"
    }
  }[toast.type];

  const Icon = config.icon;

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 30, scale: 0.9, x: 50 }}
      animate={{ opacity: 1, y: 0, scale: 1, x: 0 }}
      exit={{ opacity: 0, scale: 0.9, x: 80, transition: { duration: 0.2 } }}
      className={`glass-panel p-4 rounded-xl flex gap-3 border shadow-xl pointer-events-auto ${config.border} ${config.bg} ${config.shadow}`}
      style={{ backdropFilter: "blur(12px)" }}
    >
      <div className="flex-shrink-0">
        <Icon className={`w-5 h-5 ${config.color}`} />
      </div>
      
      <div className="flex-1 text-left min-w-0">
        <h4 className="text-xs font-bold text-white font-mono uppercase tracking-wider">
          {config.title}
        </h4>
        <p className="text-[11px] text-slate-300 mt-1 font-medium leading-relaxed break-words">
          {toast.message}
        </p>
      </div>

      <button
        onClick={() => onClose(toast.id)}
        className="flex-shrink-0 self-start p-0.5 rounded-lg hover:bg-white/5 text-slate-500 hover:text-slate-300 transition"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </motion.div>
  );
};
