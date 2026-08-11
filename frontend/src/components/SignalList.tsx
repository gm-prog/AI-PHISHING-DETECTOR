import React, { useState } from "react";
import { ShieldAlert, AlertTriangle, Info, ChevronDown, ChevronUp, CheckCircle, Search } from "lucide-react";
import type { PhishingSignal, AnalysisResponse } from "../types";

interface SignalListProps {
  signals: PhishingSignal[];
  analysisData?: AnalysisResponse;
}

export const SignalList: React.FC<SignalListProps> = ({ signals, analysisData }) => {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const toggleExpand = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  const hasVT = analysisData?.vt_status === "success";
  const hasUH = analysisData?.urlhaus_status === "success";

  if (!signals || signals.length === 0) {
    return (
      <div className="glass-panel p-6 rounded-2xl flex flex-col shadow-2xl h-full border-green-500/20 gap-4">
        <div className="flex flex-col items-center justify-center text-center flex-1">
          <div className="w-12 h-12 rounded-xl bg-green-500/10 border border-green-500/20 flex items-center justify-center mb-3">
            <CheckCircle className="w-6 h-6 text-green-400" />
          </div>
          <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider">No Suspicious Signals Found</h3>
          <p className="text-xs text-slate-400 mt-2 max-w-xs leading-relaxed">
            Our analysis did not trigger any heuristic indicators or language anomalies. The input seems safe.
          </p>
        </div>

        {/* Still show VT/URLhaus even when no heuristic signals */}
        {(hasVT || hasUH) && (
          <ExternalIntelPanel analysisData={analysisData} />
        )}
      </div>
    );
  }

  // Sort signals: High severity first, then Medium, then Low
  const severityOrder = { high: 0, medium: 1, low: 2 };
  const sortedSignals = [...signals].sort(
    (a, b) => severityOrder[a.severity] - severityOrder[b.severity]
  );

  const getSeverityStyle = (severity: "high" | "medium" | "low") => {
    switch (severity) {
      case "high":
        return {
          icon: ShieldAlert,
          color: "text-red-400",
          border: "border-red-500/20",
          bg: "bg-red-950/20 hover:bg-red-950/40",
          badge: "bg-red-500/10 text-red-400 border border-red-500/30"
        };
      case "medium":
        return {
          icon: AlertTriangle,
          color: "text-amber-400",
          border: "border-amber-500/20",
          bg: "bg-amber-950/15 hover:bg-amber-950/30",
          badge: "bg-amber-500/10 text-amber-400 border border-amber-500/30"
        };
      case "low":
        return {
          icon: Info,
          color: "text-blue-400",
          border: "border-blue-500/20",
          bg: "bg-blue-950/10 hover:bg-blue-950/20",
          badge: "bg-blue-500/10 text-blue-400 border border-blue-500/30"
        };
    }
  };

  return (
    <div className="glass-panel p-6 rounded-2xl shadow-2xl h-full flex flex-col">
      <div className="border-b border-white/5 pb-3 mb-4">
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
          <span>🛡</span> Flagged Warning Signs ({signals.length})
        </h3>
      </div>

      <div className="space-y-3 overflow-y-auto flex-1 max-h-[300px] pr-1">
        {sortedSignals.map((signal) => {
          const style = getSeverityStyle(signal.severity);
          const Icon = style.icon;
          const isExpanded = expandedId === signal.id;

          return (
            <div
              key={signal.id}
              className={`rounded-xl border ${style.border} ${style.bg} transition-all duration-200 cursor-pointer`}
              onClick={() => toggleExpand(signal.id)}
            >
              {/* Header block */}
              <div className="p-3.5 flex items-center justify-between gap-3 select-none">
                <div className="flex items-center gap-3">
                  <div className="flex-shrink-0">
                    <Icon className={`w-4 h-4 ${style.color}`} />
                  </div>
                  <div className="text-left">
                    <h4 className="text-xs font-semibold text-white tracking-wide">{signal.title}</h4>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className={`text-[9px] px-2 py-0.5 rounded-full font-mono font-bold uppercase tracking-wider ${style.badge}`}>
                    {signal.severity}
                  </span>
                  {isExpanded ? (
                    <ChevronUp className="w-3.5 h-3.5 text-slate-500" />
                  ) : (
                    <ChevronDown className="w-3.5 h-3.5 text-slate-500" />
                  )}
                </div>
              </div>

              {/* Collapsible Content */}
              {isExpanded && (
                <div className="px-3.5 pb-4 pt-1 text-left border-t border-white/5">
                  <p className="text-xs text-slate-300 leading-relaxed font-sans mt-2">
                    {signal.description}
                  </p>
                  <p className="text-[10px] font-mono text-slate-500 mt-3 uppercase tracking-wider">
                    Signal Trigger ID: <code className="text-slate-400">{signal.id}</code>
                  </p>
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* External Threat Intelligence */}
      {(hasVT || hasUH) && (
        <div className="mt-4 border-t border-white/5 pt-4">
          <ExternalIntelPanel analysisData={analysisData} />
        </div>
      )}
    </div>
  );
};

// Separate component for VT + URLhaus panels
const ExternalIntelPanel: React.FC<{ analysisData?: AnalysisResponse }> = ({ analysisData }) => {
  const hasVT = analysisData?.vt_status === "success";
  const hasUH = analysisData?.urlhaus_status === "success";

  return (
    <div className="space-y-3">
      {/* VirusTotal Panel */}
      {hasVT && (
        <div className="rounded-xl border border-amber-500/20 bg-amber-950/10 p-3.5">
          <div className="flex items-center gap-2 mb-2">
            <Search className="w-3.5 h-3.5 text-amber-400" />
            <span className="text-[10px] font-mono font-bold text-amber-300 uppercase tracking-widest">
              VirusTotal Analysis
            </span>
            <span className="ml-auto text-[9px] px-2 py-0.5 rounded-full font-mono font-bold border border-amber-500/30 bg-amber-500/10 text-amber-400">
              {(analysisData?.vt_malicious_vendors ?? 0) > 0 ? "THREATS FOUND" : "CLEAN"}
            </span>
          </div>

          {(analysisData?.vt_malicious_vendors ?? 0) > 0 ? (
            <div className="space-y-1.5">
              <p className="text-xs text-red-300 font-semibold">
                ⚠️ {analysisData?.vt_malicious_vendors} vendor(s) flagged this URL as malicious
              </p>
              {analysisData?.virustotal_findings?.vendors?.slice(0, 5).map((vendor, idx) => (
                <div key={idx} className="text-[10px] text-red-400 bg-red-500/10 px-2.5 py-1 rounded-lg font-mono">
                  • {vendor}
                </div>
              ))}
              <p className="text-[10px] text-slate-400 mt-1.5">
                Reputation Score: <span className="text-red-400 font-bold">{analysisData?.vt_reputation}/100</span>
              </p>
            </div>
          ) : (
            <p className="text-xs text-green-300">✅ No threats detected by VirusTotal vendors</p>
          )}
        </div>
      )}

      {/* URLhaus Panel */}
      {hasUH && (
        <div className={`rounded-xl border p-3.5 ${
          analysisData?.urlhaus_in_database
            ? "border-red-500/30 bg-red-950/20"
            : "border-blue-500/20 bg-blue-950/10"
        }`}>
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-[10px] font-mono font-bold text-blue-300 uppercase tracking-widest">
              URLhaus Threat Database
            </span>
            <span className={`ml-auto text-[9px] px-2 py-0.5 rounded-full font-mono font-bold border ${
              analysisData?.urlhaus_in_database
                ? "border-red-500/30 bg-red-500/10 text-red-400"
                : "border-green-500/30 bg-green-500/10 text-green-400"
            }`}>
              {analysisData?.urlhaus_in_database ? "MALICIOUS" : "NOT FOUND"}
            </span>
          </div>

          {analysisData?.urlhaus_in_database ? (
            <div className="space-y-1.5 text-left">
              <p className="text-xs text-red-300 font-semibold">
                ⛔ This URL is listed in URLhaus threat database!
              </p>
              <p className="text-[10px] text-amber-400 font-mono">
                Threat Type: <strong>{analysisData.urlhaus_threat_type?.toUpperCase() || "UNKNOWN"}</strong>
              </p>
              {analysisData.urlhaus_findings?.malware_families && analysisData.urlhaus_findings.malware_families.length > 0 && (
                <p className="text-[10px] text-red-400 font-mono">
                  Families / Tags: {analysisData.urlhaus_findings.malware_families.join(", ")}
                </p>
              )}
              {analysisData.urlhaus_findings?.date_added && (
                <p className="text-[10px] text-slate-400 font-mono">
                  Added: {new Date(analysisData.urlhaus_findings.date_added).toLocaleDateString()}
                </p>
              )}
            </div>
          ) : (
            <p className="text-xs text-green-300">✅ URL not found in URLhaus threat database</p>
          )}
        </div>
      )}
    </div>
  );
};
