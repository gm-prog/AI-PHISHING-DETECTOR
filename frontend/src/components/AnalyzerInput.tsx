import React, { useState } from "react";
import { transitionExternalProcessingConsent } from "./consentLifecycle.mjs";
import { Globe, FileText, Code2, CornerDownRight, RotateCcw, Zap } from "lucide-react";
import { MOCK_SAMPLES } from "../mockData";

interface AnalyzerInputProps {
  onAnalyze: (type: "url" | "email_text" | "email_header", content: string, allowExternalProcessing: boolean) => void;
  isLoading: boolean;
}

export const AnalyzerInput: React.FC<AnalyzerInputProps> = ({ onAnalyze, isLoading }) => {
  const [activeTab, setActiveTab] = useState<"url" | "email_text" | "email_header">("url");
  const [content, setContent] = useState("");
  const [validationError, setValidationError] = useState("");
  const [allowExternalProcessing, setAllowExternalProcessing] = useState(false);

  const tabOptions = [
    { id: "url", name: "URL Vector", icon: Globe, placeholder: "https://secure-paypa1-update.xyz/login", max: 2048 },
    { id: "email_text", name: "Email Body", icon: FileText, placeholder: "Paste suspicious email body text to analyze social engineering urgency...", max: 50000 },
    { id: "email_header", name: "MIME Headers", icon: Code2, placeholder: "Paste raw RFC 822 email headers (SPF, DKIM, DMARC, Return-Path)...", max: 50000 }
  ] as const;

  const currentTabConfig = tabOptions.find(t => t.id === activeTab) || tabOptions[0];

  const handleTabChange = (tabId: "url" | "email_text" | "email_header") => {
    setActiveTab(tabId);
    setContent("");
    setValidationError("");
    setAllowExternalProcessing(
      transitionExternalProcessingConsent(allowExternalProcessing, "context-change").nextValue,
    );
  };

  const handleAutofill = (sampleContent: string) => {
    setContent(sampleContent);
    setValidationError("");
    setAllowExternalProcessing(
      transitionExternalProcessingConsent(allowExternalProcessing, "context-change").nextValue,
    );
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError("");

    const trimmedContent = content.trim();
    if (!trimmedContent) {
      setValidationError("Input vector payload cannot be empty.");
      return;
    }

    if (activeTab === "url") {
      const hasProtocol = /^(https?:\/\/)/i.test(trimmedContent);
      const isDomain = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}/i.test(trimmedContent);
      if (!hasProtocol && !isDomain) {
        setValidationError("Enter a valid URL or domain string (e.g. https://example.com).");
        return;
      }
    }

    // Consent is deliberately one-shot: the next scan must opt in independently.
    const consentTransition = transitionExternalProcessingConsent(
      allowExternalProcessing,
      "submit",
    );
    setAllowExternalProcessing(consentTransition.nextValue);
    onAnalyze(activeTab, trimmedContent, consentTransition.forCurrentScan);
  };

  const activeSamples = MOCK_SAMPLES.filter((s) => s.type === activeTab);

  return (
    <div className="tactical-panel p-5 rounded relative overflow-hidden shadow-lg border border-white/10 text-left mb-6">
      {/* Laser Scanning Indicator */}
      {isLoading && <div className="scan-line-tactical" />}

      {/* Vector Selection Tabs */}
      <div className="flex border-b border-white/10 pb-2.5 gap-2 overflow-x-auto" role="tablist">
        {tabOptions.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => handleTabChange(tab.id)}
              disabled={isLoading}
              className={`flex items-center gap-2 px-3.5 py-2 text-xs font-mono font-bold tracking-wider uppercase rounded border transition cursor-pointer focus-visible:ring-2 focus-visible:ring-[#00F0FF] ${
                isActive
                  ? "bg-[#00F0FF]/15 border-[#00F0FF]/50 text-[#00F0FF]"
                  : "bg-[#090D16] border-white/10 text-slate-400 hover:text-slate-200 hover:border-white/20"
              }`}
            >
              <Icon className="w-3.5 h-3.5 text-current" />
              {tab.name}
            </button>
          );
        })}
      </div>

      <form onSubmit={handleSubmit} className="mt-4 space-y-3.5" role="tabpanel">
        {/* Vector Input Area */}
        <div className="relative">
          {activeTab === "url" ? (
            <input
              type="text"
              placeholder={currentTabConfig.placeholder}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              disabled={isLoading}
              maxLength={currentTabConfig.max}
              className="w-full px-3.5 py-3 text-xs sm:text-sm tactical-input font-mono"
              id="url_input_field"
            />
          ) : (
            <textarea
              placeholder={currentTabConfig.placeholder}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              disabled={isLoading}
              maxLength={currentTabConfig.max}
              rows={6}
              className="w-full px-3.5 py-2.5 text-xs sm:text-sm tactical-input font-mono resize-y"
              id="textarea_input_field"
            />
          )}

          {/* Character Counter & Specs */}
          <div className="flex justify-between items-center mt-1.5 px-0.5 text-[10px] font-mono text-slate-500">
            <span>
              {content.length > 0 ? (
                <span className="text-slate-400">{content.length.toLocaleString()} / {currentTabConfig.max.toLocaleString()} bytes</span>
              ) : (
                <span>Max Payload: {currentTabConfig.max.toLocaleString()} bytes</span>
              )}
            </span>
            <span className="text-slate-500 uppercase tracking-wider">Zero-Trust Analysis Pipeline</span>
          </div>

          {validationError && (
            <p className="mt-2 text-xs text-[#FF3366] font-mono font-medium flex items-center gap-1.5">
              <span>⚠</span> {validationError}
            </p>
          )}
        </div>

        {/* Curated Threat Scenarios Pre-fill */}
        {!isLoading && activeSamples.length > 0 && (
          <div className="space-y-1.5 pt-2 border-t border-white/5">
            <p className="text-[10px] uppercase tracking-wider text-slate-400 font-bold font-mono flex items-center gap-1.5">
              <CornerDownRight className="w-3.5 h-3.5 text-[#00F0FF]" /> Load Threat Vector Payload:
            </p>
            <div className="flex flex-wrap gap-1.5">
              {activeSamples.map((sample) => {
                const isMalicious = sample.id.includes("phish") || sample.id.includes("typo") || sample.id.includes("urgency");
                return (
                  <button
                    key={sample.id}
                    type="button"
                    onClick={() => handleAutofill(sample.content)}
                    className={`px-2.5 py-1 rounded border text-[11px] font-mono transition cursor-pointer focus-visible:ring-1 focus-visible:ring-[#00F0FF] ${
                      isMalicious
                        ? "bg-[#FF3366]/10 hover:bg-[#FF3366]/20 border-[#FF3366]/30 text-[#FF3366]"
                        : "bg-[#090D16] hover:bg-[#131C31] border-white/10 text-slate-300"
                    }`}
                  >
                    {sample.name}
                  </button>
                );
              })}
            </div>
          </div>
        )}

        {/* Explicit per-scan privacy consent; unchecked is local-only */}
        <div className="rounded border border-white/10 bg-[#090D16] p-3 text-left">
          <label className="flex items-start gap-2.5 cursor-pointer">
            <input
              type="checkbox"
              checked={allowExternalProcessing}
              onChange={(e) => setAllowExternalProcessing(e.target.checked)}
              disabled={isLoading}
              className="mt-0.5 accent-[#00F0FF]"
              id="external_processing_consent"
            />
            <span className="text-xs text-slate-200 font-mono">
              Allow external threat intelligence and AI for this scan (optional)
              <span className="block mt-1 text-[11px] leading-relaxed text-slate-400 font-sans">
                Off by default: local heuristics and locally stored threat feeds only. If enabled, relevant URL indicators or submitted content may be sent to configured third-party providers such as VirusTotal, URLhaus, Google Web Risk, or Gemini, under their own data-handling policies. This choice applies only to this scan.
              </span>
            </span>
          </label>
          <p className="mt-2 text-[10px] font-mono uppercase tracking-wider text-emerald-400">
            {allowExternalProcessing ? "External processing enabled for this scan" : "Local-only mode selected"}
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex justify-between items-center pt-2.5 border-t border-white/10">
          {content && !isLoading ? (
            <button
              type="button"
              onClick={() => {
                setContent("");
                setAllowExternalProcessing(
                  transitionExternalProcessingConsent(allowExternalProcessing, "context-change").nextValue,
                );
              }}
              className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 font-mono transition cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Reset Input
            </button>
          ) : <div />}

          <div className="ml-auto">
            <button
              type="submit"
              disabled={isLoading}
              className={`flex items-center gap-2 px-5 py-2.5 rounded font-mono font-bold tracking-wider text-xs uppercase transition cursor-pointer focus-visible:ring-2 focus-visible:ring-[#00F0FF] ${
                isLoading
                  ? "bg-slate-800 border border-white/10 text-slate-500 cursor-not-allowed"
                  : "bg-[#00F0FF] hover:bg-[#33F3FF] text-[#080C14] border border-[#00F0FF] font-extrabold"
              }`}
              id="analyze_submit_btn"
            >
              {isLoading ? (
                <>
                  <div className="w-3.5 h-3.5 rounded-full border-2 border-slate-600 border-t-[#080C14] animate-spin" />
                  <span>ANALYZING VECTOR...</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5 fill-current text-[#080C14]" />
                  EXECUTE THREAT SCAN
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};
