import React from "react";
import { History, Trash2, Globe, FileText, Code2, AlertTriangle } from "lucide-react";
import type { ScanHistoryItem } from "../types";

interface HistoryTrackerProps {
  history: ScanHistoryItem[];
  onSelect: (item: ScanHistoryItem) => void;
  onClear: () => void;
}

export const HistoryTracker: React.FC<HistoryTrackerProps> = ({ history, onSelect, onClear }) => {
  const getIcon = (type: "url" | "email_text" | "email_header") => {
    switch (type) {
      case "url":
        return Globe;
      case "email_text":
        return FileText;
      case "email_header":
        return Code2;
    }
  };

  const getStatusColor = (status: "safe" | "warning" | "danger") => {
    switch (status) {
      case "safe":
        return "text-green-400 border-green-500/30 bg-green-500/10";
      case "warning":
        return "text-amber-400 border-amber-500/30 bg-amber-500/10";
      case "danger":
        return "text-red-400 border-red-500/30 bg-red-500/10";
    }
  };

  const formatDate = (isoStr: string) => {
    try {
      const date = new Date(isoStr);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " - " + date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  };

  return (
    <div className="glass-panel p-6 rounded-2xl shadow-2xl h-full flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between border-b border-white/5 pb-3 mb-4">
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
          <History className="w-4 h-4 text-blue-400" /> Threat Scan History
        </h3>
        {history.length > 0 && (
          <button
            onClick={onClear}
            className="flex items-center gap-1 text-[10px] font-mono uppercase text-red-400 hover:text-red-300 transition"
          >
            <Trash2 className="w-3.5 h-3.5" /> Clear History
          </button>
        )}
      </div>

      {/* History List */}
      <div className="flex-1 overflow-y-auto max-h-[300px] pr-1">
        {history.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 py-12">
            <AlertTriangle className="w-6 h-6 mb-2 opacity-30" />
            <p className="text-xs font-mono">No threat records scanned yet.</p>
          </div>
        ) : (
          <div className="space-y-2">
            {history.map((item) => {
              const TypeIcon = getIcon(item.input_type);
              const statusColor = getStatusColor(item.status);

              return (
                <div
                  key={item.id}
                  onClick={() => onSelect(item)}
                  className="p-3 rounded-xl bg-slate-900/40 hover:bg-slate-900/80 border border-white/5 hover:border-white/10 flex items-center justify-between gap-4 transition-all duration-200 cursor-pointer text-left"
                >
                  <div className="flex items-center gap-3 overflow-hidden">
                    <div className="p-2 rounded-lg bg-slate-800 border border-white/5 text-slate-400 flex-shrink-0">
                      <TypeIcon className="w-4 h-4" />
                    </div>
                    <div className="overflow-hidden">
                      <p className="text-xs font-semibold text-slate-200 truncate pr-2">
                        {item.content}
                      </p>
                      <p className="text-[10px] text-slate-500 font-mono mt-0.5">
                        {formatDate(item.timestamp)}
                      </p>
                    </div>
                  </div>

                  <div className="flex-shrink-0 flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-400">
                      {item.risk_score}%
                    </span>
                    <span className={`text-[9px] px-2 py-0.5 rounded-full font-mono font-bold uppercase tracking-wider border ${statusColor}`}>
                      {item.status}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};
