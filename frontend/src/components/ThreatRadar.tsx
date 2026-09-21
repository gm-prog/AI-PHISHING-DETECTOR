import React from "react";
import { Shield, AlertTriangle, Fingerprint, Activity, Globe } from "lucide-react";
import type { AnalysisResponse } from "../types";

interface ThreatRadarProps {
  response: AnalysisResponse;
}

export const ThreatRadar: React.FC<ThreatRadarProps> = ({ response }) => {
  const { input_type, risk_score, phishing_signals, virustotal_findings, urlhaus_in_database } = response;

  // Calculate individual vector intensities
  const domainSpoofSignals = phishing_signals.filter(s =>
    s.id.includes("typo") || s.id.includes("domain") || s.id.includes("tld") || s.id.includes("ip")
  ).length;

  const socialEngineeringSignals = phishing_signals.filter(s =>
    s.id.includes("urgency") || s.id.includes("keyword") || s.id.includes("impersonat") || s.id.includes("pressure")
  ).length;

  const authHeaderSignals = phishing_signals.filter(s =>
    s.id.includes("spf") || s.id.includes("dkim") || s.id.includes("mismatch")
  ).length;

  const externalThreatHit = (virustotal_findings?.malicious_count ?? 0) > 0 || urlhaus_in_database;

  // Normalized vector scores (0 to 100)
  const lexicalScore = Math.min(100, domainSpoofSignals * 35 + (input_type === "url" && risk_score > 30 ? 20 : 0));
  const socialScore = Math.min(100, socialEngineeringSignals * 30 + (input_type === "email_text" && risk_score > 40 ? 30 : 0));
  const authScore = Math.min(100, authHeaderSignals * 45 + (response.details?.sender_mismatch ? 40 : 0));
  const intelScore = externalThreatHit ? 95 : (risk_score > 50 ? 35 : 10);

  const vectors = [
    {
      name: "Lexical & Spoofing",
      score: lexicalScore,
      icon: Globe,
      color: lexicalScore > 60 ? "text-red-400" : lexicalScore > 25 ? "text-amber-400" : "text-cyan-400",
      bg: lexicalScore > 60 ? "bg-red-500" : lexicalScore > 25 ? "bg-amber-500" : "bg-cyan-500",
    },
    {
      name: "Social Engineering",
      score: socialScore,
      icon: AlertTriangle,
      color: socialScore > 60 ? "text-red-400" : socialScore > 25 ? "text-amber-400" : "text-purple-400",
      bg: socialScore > 60 ? "bg-red-500" : socialScore > 25 ? "bg-amber-500" : "bg-purple-500",
    },
    {
      name: "Sender Identity/Auth",
      score: authScore,
      icon: Fingerprint,
      color: authScore > 60 ? "text-red-400" : authScore > 25 ? "text-amber-400" : "text-emerald-400",
      bg: authScore > 60 ? "bg-red-500" : authScore > 25 ? "bg-amber-500" : "bg-emerald-500",
    },
    {
      name: "External Threat Intel",
      score: intelScore,
      icon: Activity,
      color: intelScore > 60 ? "text-red-400" : intelScore > 25 ? "text-amber-400" : "text-blue-400",
      bg: intelScore > 60 ? "bg-red-500" : intelScore > 25 ? "bg-amber-500" : "bg-blue-500",
    },
  ];

  return (
    <div className="glass-panel p-5 rounded-2xl border border-white/5 space-y-4 text-left">
      <div className="flex items-center justify-between border-b border-white/5 pb-3">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-blue-400" />
          <h4 className="text-xs font-mono font-bold text-white uppercase tracking-wider">
            Threat Vector Telemetry
          </h4>
        </div>
        <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-blue-950/40 border border-blue-500/20 text-blue-300">
          Real-time Multi-Vector Breakdown
        </span>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
        {vectors.map((vec, idx) => {
          const Icon = vec.icon;
          return (
            <div key={idx} className="p-3 rounded-xl bg-slate-900/60 border border-white/5 space-y-2">
              <div className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <Icon className={`w-3.5 h-3.5 ${vec.color}`} />
                  <span className="text-[11px] font-mono font-medium text-slate-300">{vec.name}</span>
                </div>
                <span className={`font-mono font-bold text-xs ${vec.color}`}>{vec.score}%</span>
              </div>

              {/* Progress Bar */}
              <div className="w-full h-1.5 rounded-full bg-slate-800 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-700 ease-out ${vec.bg}`}
                  style={{ width: `${vec.score}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
