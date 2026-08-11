import React, { useState } from "react";
import { Globe, FileText, Code2, Play, CornerDownRight, RotateCcw } from "lucide-react";
import { MOCK_SAMPLES } from "../mockData";

interface AnalyzerInputProps {
  onAnalyze: (type: "url" | "email_text" | "email_header", content: string) => void;
  isLoading: boolean;
}

export const AnalyzerInput: React.FC<AnalyzerInputProps> = ({ onAnalyze, isLoading }) => {
  const [activeTab, setActiveTab] = useState<"url" | "email_text" | "email_header">("url");
  const [content, setContent] = useState("");
  const [validationError, setValidationError] = useState("");

  const tabOptions = [
    { id: "url", name: "Inspect URL", icon: Globe, placeholder: "https://secure-login-update-paypal.xyz/signin" },
    { id: "email_text", name: "Inspect Email Text", icon: FileText, placeholder: "Paste suspicious email body copy here..." },
    { id: "email_header", name: "Inspect Headers", icon: Code2, placeholder: "Paste raw email headers from your mail client..." }
  ] as const;

  const handleTabChange = (tabId: "url" | "email_text" | "email_header") => {
    setActiveTab(tabId);
    setContent("");
    setValidationError("");
  };

  const handleAutofill = (sampleContent: string) => {
    setContent(sampleContent);
    setValidationError("");
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setValidationError("");

    const trimmedContent = content.trim();
    if (!trimmedContent) {
      setValidationError("Please enter content to inspect.");
      return;
    }

    if (activeTab === "url") {
      // Basic URL verification
      const hasProtocol = /^(https?:\/\/)/i.test(trimmedContent);
      const isDomain = /^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}/i.test(trimmedContent);
      if (!hasProtocol && !isDomain) {
        setValidationError("Please enter a valid website address or domain name.");
        return;
      }
    }

    onAnalyze(activeTab, trimmedContent);
  };

  // Get samples filtered by active tab
  const activeSamples = MOCK_SAMPLES.filter((s) => s.type === activeTab);

  // Loading animation phase text rotation
  const getLoadingText = () => {
    return "Running Cyber Threats Engine...";
  };

  return (
    <div className="glass-panel p-6 rounded-2xl relative overflow-hidden shadow-2xl mb-8">
      {/* Laser Scanning Indicator Effect */}
      {isLoading && <div className="scan-line" />}

      {/* Tabs */}
      <div className="flex border-b border-white/5 pb-3 gap-2 overflow-x-auto">
        {tabOptions.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => handleTabChange(tab.id)}
              disabled={isLoading}
              className={`flex items-center gap-2.5 px-4 py-2.5 text-xs font-mono font-bold tracking-wider uppercase rounded-xl border transition-all duration-300 ${
                isActive
                  ? "bg-blue-600/25 border-blue-500/40 text-blue-400 font-bold shadow-[0_0_15px_-3px_rgba(59,130,246,0.3)]"
                  : "bg-slate-900/40 border-white/5 text-slate-400 hover:text-slate-200 hover:border-white/10"
              }`}
            >
              <Icon className="w-4 h-4" />
              {tab.name}
            </button>
          );
        })}
      </div>

      <form onSubmit={handleSubmit} className="mt-5 space-y-4">
        {/* Form Input */}
        <div>
          {activeTab === "url" ? (
            <input
              type="text"
              placeholder={tabOptions[0].placeholder}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              disabled={isLoading}
              className="w-full px-4 py-3.5 text-sm rounded-xl glass-input text-white placeholder-slate-500 font-mono"
              id="url_input_field"
            />
          ) : (
            <textarea
              placeholder={activeTab === "email_text" ? tabOptions[1].placeholder : tabOptions[2].placeholder}
              value={content}
              onChange={(e) => setContent(e.target.value)}
              disabled={isLoading}
              rows={6}
              className="w-full px-4 py-3 text-sm rounded-xl glass-input text-white placeholder-slate-500 font-mono resize-y"
              id="textarea_input_field"
            />
          )}

          {validationError && (
            <p className="mt-2 text-xs text-red-400 font-medium flex items-center gap-1 font-mono">
              <span>⚠</span> {validationError}
            </p>
          )}
        </div>

        {/* Quick Test Samples */}
        {!isLoading && (
          <div className="space-y-2">
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold font-mono flex items-center gap-1">
              <CornerDownRight className="w-3.5 h-3.5" /> Quick Test Samples
            </p>
            <div className="flex flex-wrap gap-2">
              {activeSamples.map((sample) => (
                <button
                  key={sample.id}
                  type="button"
                  onClick={() => handleAutofill(sample.content)}
                  className="px-2.5 py-1.5 rounded-lg bg-slate-900/80 hover:bg-slate-800/80 border border-white/5 hover:border-white/10 text-xs text-slate-400 hover:text-slate-200 transition-all font-mono"
                >
                  {sample.name}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Submit CTA */}
        <div className="flex justify-between items-center pt-2">
          {content && !isLoading && (
            <button
              type="button"
              onClick={() => setContent("")}
              className="flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 font-mono transition"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Clear
            </button>
          )}
          <div className="ml-auto">
            <button
              type="submit"
              disabled={isLoading}
              className={`flex items-center gap-2 px-6 py-3 rounded-xl font-bold font-mono tracking-wider text-xs uppercase transition-all duration-300 ${
                isLoading
                  ? "bg-slate-800 border border-white/5 text-slate-500 cursor-not-allowed"
                  : "bg-blue-600 hover:bg-blue-500 hover:scale-[1.02] border border-blue-400/20 text-white shadow-[0_0_20px_-5px_rgba(59,130,246,0.5)] cursor-pointer"
              }`}
              id="analyze_submit_btn"
            >
              {isLoading ? (
                <>
                  <div className="w-3.5 h-3.5 rounded-full border-2 border-slate-500 border-t-blue-400 animate-spin" />
                  {getLoadingText()}
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5 fill-current" />
                  Analyze Input
                </>
              )}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
};
