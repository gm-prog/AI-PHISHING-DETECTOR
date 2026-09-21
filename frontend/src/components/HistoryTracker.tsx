import React, { useState } from "react";
import { History, Trash2, Globe, FileText, Code2, AlertTriangle, Search, X } from "lucide-react";
import type { ScanHistoryItem } from "../types";
import { useAuth } from "../context/AuthContext";

interface HistoryTrackerProps {
  history: ScanHistoryItem[];
  onSelect: (item: ScanHistoryItem) => void;
  onClear: () => void;
  onDeleteSingle?: (id: string) => void;
}

export const HistoryTracker: React.FC<HistoryTrackerProps> = ({
  history,
  onSelect,
  onClear,
  onDeleteSingle
}) => {
  const { isAuthenticated } = useAuth();
  const [searchTerm, setSearchTerm] = useState("");
  const [filterMode, setFilterMode] = useState<"all" | "threats" | "clean">("all");

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

  const getStatusBadge = (status: "safe" | "warning" | "danger") => {
    switch (status) {
      case "safe":
        return "badge-safe";
      case "warning":
        return "badge-warning";
      case "danger":
        return "badge-danger";
    }
  };

  const formatDate = (isoStr: string) => {
    try {
      const date = new Date(isoStr);
      return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) + " · " + date.toLocaleDateString([], { month: 'short', day: 'numeric' });
    } catch {
      return isoStr;
    }
  };

  const filteredHistory = history.filter((item) => {
    const matchesSearch = item.content.toLowerCase().includes(searchTerm.toLowerCase()) ||
                          item.input_type.toLowerCase().includes(searchTerm.toLowerCase());
    if (!matchesSearch) return false;

    if (filterMode === "threats") return item.status === "danger" || item.status === "warning";
    if (filterMode === "clean") return item.status === "safe";
    return true;
  });

  return (
    <div className="tactical-panel p-5 rounded border border-white/10 h-full flex flex-col text-left">
      {/* Tracker Header */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3 mb-3">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-[#00F0FF]" />
          <h3 className="text-xs sm:text-sm font-bold text-white font-mono uppercase tracking-wider">
            Threat Intelligence Vault
          </h3>
        </div>

        <div className="flex items-center gap-2">
          {/* User Scope Badge */}
          <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${
            isAuthenticated
              ? "bg-[#00F0FF]/10 border-[#00F0FF]/30 text-[#00F0FF]"
              : "bg-[#090D16] border-white/10 text-slate-400"
          }`}>
            {isAuthenticated ? "ISOLATED USER VAULT" : "ANONYMOUS VAULT"}
          </span>

          {history.length > 0 && (
            <button
              onClick={onClear}
              className="flex items-center gap-1 text-[10px] font-mono uppercase text-[#FF3366] hover:underline cursor-pointer focus-visible:ring-1 focus-visible:ring-[#FF3366]"
              title="Purge Vault History"
            >
              <Trash2 className="w-3 h-3" /> Purge
            </button>
          )}
        </div>
      </div>

      {/* Filter Controls & Search */}
      {history.length > 0 && (
        <div className="space-y-2 mb-3">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search keyword, domain, payload..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-8 pr-7 py-1.5 rounded tactical-input text-[11px] font-mono"
            />
            {searchTerm && (
              <button
                onClick={() => setSearchTerm("")}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-500 hover:text-slate-300"
              >
                <X className="w-3 h-3" />
              </button>
            )}
          </div>

          <div className="flex gap-1.5">
            <button
              onClick={() => setFilterMode("all")}
              className={`px-2.5 py-1 rounded text-[10px] font-mono transition cursor-pointer ${
                filterMode === "all"
                  ? "bg-[#00F0FF]/20 text-[#00F0FF] border border-[#00F0FF]/40 font-bold"
                  : "bg-[#090D16] text-slate-400 border border-white/10 hover:text-slate-200"
              }`}
            >
              ALL ({history.length})
            </button>
            <button
              onClick={() => setFilterMode("threats")}
              className={`px-2.5 py-1 rounded text-[10px] font-mono transition cursor-pointer ${
                filterMode === "threats"
                  ? "bg-[#FF3366]/20 text-[#FF3366] border border-[#FF3366]/40 font-bold"
                  : "bg-[#090D16] text-slate-400 border border-white/10 hover:text-slate-200"
              }`}
            >
              THREATS ({history.filter(h => h.status !== "safe").length})
            </button>
            <button
              onClick={() => setFilterMode("clean")}
              className={`px-2.5 py-1 rounded text-[10px] font-mono transition cursor-pointer ${
                filterMode === "clean"
                  ? "bg-[#00E699]/20 text-[#00E699] border border-[#00E699]/40 font-bold"
                  : "bg-[#090D16] text-slate-400 border border-white/10 hover:text-slate-200"
              }`}
            >
              CLEAN ({history.filter(h => h.status === "safe").length})
            </button>
          </div>
        </div>
      )}

      {/* History Telemetry Log */}
      <div className="flex-1 overflow-y-auto max-h-[320px] pr-1">
        {filteredHistory.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 py-10">
            <AlertTriangle className="w-6 h-6 mb-2 opacity-30 text-[#00F0FF]" />
            <p className="text-xs font-mono">
              {history.length === 0 ? "No scan history recorded." : "No matching vault records."}
            </p>
          </div>
        ) : (
          <div className="space-y-1.5">
            {filteredHistory.map((item) => {
              const TypeIcon = getIcon(item.input_type);
              const badgeClass = getStatusBadge(item.status);

              return (
                <div
                  key={item.id}
                  className="p-2.5 rounded bg-[#090D16] hover:bg-[#131C31] border border-white/10 flex items-center justify-between gap-3 transition cursor-pointer group focus-visible:ring-1 focus-visible:ring-[#00F0FF]"
                  onClick={() => onSelect(item)}
                  tabIndex={0}
                  role="button"
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      onSelect(item);
                    }
                  }}
                >
                  <div className="flex items-center gap-2.5 overflow-hidden flex-1 min-w-0">
                    <div className="p-1.5 rounded bg-[#101726] border border-white/10 text-slate-400 flex-shrink-0">
                      <TypeIcon className="w-3.5 h-3.5" />
                    </div>
                    <div className="overflow-hidden min-w-0">
                      <p className="text-xs font-semibold text-slate-200 truncate pr-2 font-mono">
                        {item.content}
                      </p>
                      <p className="text-[10px] text-slate-500 font-mono mt-0.5">
                        {formatDate(item.timestamp)}
                      </p>
                    </div>
                  </div>

                  <div className="flex-shrink-0 flex items-center gap-2">
                    <span className="text-xs font-mono font-bold text-slate-300">
                      {item.risk_score}%
                    </span>
                    <span className={`text-[9px] px-2 py-0.5 rounded font-mono font-bold uppercase ${badgeClass}`}>
                      {item.status}
                    </span>
                    {onDeleteSingle && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onDeleteSingle(item.id);
                        }}
                        className="opacity-0 group-hover:opacity-100 p-1 text-slate-500 hover:text-[#FF3366] transition cursor-pointer"
                        title="Delete log entry"
                        aria-label="Delete log entry"
                      >
                        <Trash2 className="w-3 h-3" />
                      </button>
                    )}
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
