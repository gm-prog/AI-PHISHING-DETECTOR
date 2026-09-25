import React, { useState } from "react";
import { Sparkles, Copy, Check, FileText, Download, Printer, Code, Eye } from "lucide-react";

interface LlmReportProps {
  explanation: string;
  onAddToast?: (msg: string, type: "success" | "error" | "info") => void;
}

export const LlmReport: React.FC<LlmReportProps> = ({ explanation, onAddToast }) => {
  const [copied, setCopied] = useState(false);
  const [viewMode, setViewMode] = useState<"formatted" | "raw">("formatted");

  const handleCopy = () => {
    navigator.clipboard.writeText(explanation);
    setCopied(true);
    if (onAddToast) onAddToast("Threat briefing copied to clipboard.", "success");
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([explanation], { type: "text/markdown;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `sentinel-threat-briefing-${Date.now()}.md`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
    if (onAddToast) onAddToast("Threat assessment exported to Markdown file.", "info");
  };

  const handlePrint = () => {
    const printWindow = window.open("", "_blank");
    if (printWindow) {
      const doc = printWindow.document;
      doc.title = "SENTINEL AI — Threat Intelligence Briefing";

      const style = doc.createElement("style");
      style.textContent = `
        body { font-family: 'Plus Jakarta Sans', sans-serif; padding: 30px; line-height: 1.6; color: #0f172a; background: #ffffff; }
        h2, h3, h4 { color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; }
        table { border-collapse: collapse; width: 100%; margin: 15px 0; }
        th, td { border: 1px solid #94a3b8; padding: 8px 12px; text-align: left; }
        th { background: #e2e8f0; }
        blockquote { border-left: 4px solid #00f0ff; margin: 12px 0; padding: 6px 16px; background: #f8fafc; }
      `;
      doc.head.appendChild(style);

      const heading = doc.createElement("h1");
      heading.textContent = "SENTINEL AI — THREAT BRIEFING";
      doc.body.appendChild(heading);

      const report = doc.createElement("pre");
      report.style.whiteSpace = "pre-wrap";
      report.style.fontFamily = "inherit";
      report.textContent = explanation;
      doc.body.appendChild(report);
      printWindow.print();
    }
  };

  const renderInlineFormatting = (text: string): React.ReactNode[] => {
    const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
    return parts.map((part, i) => {
      if (part.startsWith("**") && part.endsWith("**")) {
        return (
          <strong key={i} className="font-semibold text-white">
            {part.slice(2, -2)}
          </strong>
        );
      }
      if (part.startsWith("`") && part.endsWith("`")) {
        return (
          <code key={i} className="px-1.5 py-0.5 rounded bg-[#090D16] text-[#00F0FF] font-mono text-[10px] border border-white/10">
            {part.slice(1, -1)}
          </code>
        );
      }
      return part;
    });
  };

  const parseTable = (lines: string[]): React.ReactNode | null => {
    const tableLines = lines.filter(l => l.trim().startsWith("|"));
    if (tableLines.length < 2) return null;

    const parseCells = (row: string) =>
      row
        .split("|")
        .map((c) => c.trim())
        .filter((_, i, a) => i > 0 && i < a.length - 1);

    const headerCells = parseCells(tableLines[0]);
    const dataRows = tableLines.slice(2).map(parseCells);

    return (
      <div className="overflow-x-auto my-3 border border-white/10 rounded">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#090D16] text-slate-300 border-b border-white/10">
            <tr>
              {headerCells.map((h, i) => (
                <th key={i} className="px-3 py-2 font-bold uppercase tracking-wider">{renderInlineFormatting(h)}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-white/5 bg-[#0F172A]">
            {dataRows.map((row, ri) => (
              <tr key={ri} className="hover:bg-[#131C31]">
                {row.map((cell, ci) => (
                  <td key={ci} className="px-3 py-2 text-slate-300">{renderInlineFormatting(cell)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  const parseMarkdown = (md: string): React.ReactNode => {
    if (!md) return null;

    const lines = md.split("\n");
    const elements: React.ReactNode[] = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];
      const trimmed = line.trim();

      if (trimmed.startsWith("|")) {
        const tableBlock: string[] = [];
        while (i < lines.length && lines[i].trim().startsWith("|")) {
          tableBlock.push(lines[i]);
          i++;
        }
        const tableEl = parseTable(tableBlock);
        if (tableEl) {
          elements.push(<div key={`table-${i}`}>{tableEl}</div>);
        }
        continue;
      }

      if (trimmed.startsWith("## ")) {
        elements.push(
          <h2 key={i} className="text-sm sm:text-base font-extrabold tracking-tight text-white mt-5 mb-2.5 border-b border-white/10 pb-1.5 flex items-center gap-2">
            {renderInlineFormatting(trimmed.replace(/^##\s+/, ""))}
          </h2>
        );
        i++;
        continue;
      }

      if (trimmed.startsWith("### ")) {
        elements.push(
          <h3 key={i} className="text-xs sm:text-sm font-bold font-mono tracking-wider uppercase text-[#00F0FF] mt-4 mb-2 pb-1 border-b border-white/5 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#00F0FF] flex-shrink-0" />
            {renderInlineFormatting(trimmed.replace(/^###\s+/, ""))}
          </h3>
        );
        i++;
        continue;
      }

      if (trimmed.startsWith("#### ")) {
        elements.push(
          <h4 key={i} className="text-xs font-bold font-mono tracking-wide uppercase text-slate-200 mt-3 mb-1">
            {renderInlineFormatting(trimmed.replace(/^####\s+/, ""))}
          </h4>
        );
        i++;
        continue;
      }

      if (trimmed.startsWith("> ")) {
        elements.push(
          <div key={i} className="my-2 p-2.5 rounded bg-[#090D16] border-l-2 border-[#00F0FF] text-xs text-slate-300">
            {renderInlineFormatting(trimmed.replace(/^>\s+/, ""))}
          </div>
        );
        i++;
        continue;
      }

      if (trimmed === "---" || trimmed === "***" || trimmed === "___") {
        elements.push(<hr key={i} className="my-3 border-t border-white/10" />);
        i++;
        continue;
      }

      if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
        const itemContent = trimmed.replace(/^[-*]\s+/, "");
        elements.push(
          <ul key={i} className="list-none pl-4 my-1">
            <li className="text-xs text-slate-300 leading-relaxed relative before:content-['■'] before:text-[6px] before:text-[#00F0FF] before:absolute before:-left-3.5 before:top-1.5">
              {renderInlineFormatting(itemContent)}
            </li>
          </ul>
        );
        i++;
        continue;
      }

      if (trimmed === "") {
        elements.push(<div key={i} className="h-1" />);
        i++;
        continue;
      }

      elements.push(
        <p key={i} className="text-xs text-slate-300 leading-relaxed my-1 text-left">
          {renderInlineFormatting(line)}
        </p>
      );
      i++;
    }

    return <>{elements}</>;
  };

  return (
    <div className="tactical-panel p-5 rounded border border-white/10 flex flex-col h-full text-left">
      {/* Inspector Header & Action Bar */}
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3 mb-3">
        <div className="flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-[#00F0FF]" />
          <h3 className="text-xs sm:text-sm font-bold text-white font-mono uppercase tracking-wider">
            Threat Intelligence Briefing
          </h3>
        </div>

        <div className="flex items-center gap-2">
          {/* View Mode Toggle */}
          <div className="flex rounded bg-[#090D16] p-0.5 border border-white/10">
            <button
              onClick={() => setViewMode("formatted")}
              className={`px-2 py-1 rounded text-[10px] font-mono transition cursor-pointer flex items-center gap-1 ${
                viewMode === "formatted" ? "bg-[#00F0FF]/20 text-[#00F0FF] font-bold" : "text-slate-400 hover:text-slate-200"
              }`}
              title="Formatted View"
            >
              <Eye className="w-3 h-3" />
              Report
            </button>
            <button
              onClick={() => setViewMode("raw")}
              className={`px-2 py-1 rounded text-[10px] font-mono transition cursor-pointer flex items-center gap-1 ${
                viewMode === "raw" ? "bg-[#00F0FF]/20 text-[#00F0FF] font-bold" : "text-slate-400 hover:text-slate-200"
              }`}
              title="Raw Markdown Source"
            >
              <Code className="w-3 h-3" />
              Raw
            </button>
          </div>

          {/* Action Buttons */}
          <button
            onClick={handleCopy}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#090D16] hover:bg-[#131C31] border border-white/10 text-slate-300 hover:text-white transition text-[10px] font-mono cursor-pointer"
            title="Copy Report to Clipboard"
          >
            {copied ? (
              <>
                <Check className="w-3 h-3 text-[#00E699]" />
                <span className="text-[#00E699] font-bold">Copied</span>
              </>
            ) : (
              <>
                <Copy className="w-3 h-3" />
                <span>Copy</span>
              </>
            )}
          </button>

          <button
            onClick={handleDownload}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#090D16] hover:bg-[#131C31] border border-white/10 text-slate-300 hover:text-white transition text-[10px] font-mono cursor-pointer"
            title="Download Markdown File"
          >
            <Download className="w-3 h-3" />
            <span>Export</span>
          </button>

          <button
            onClick={handlePrint}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-[#090D16] hover:bg-[#131C31] border border-white/10 text-slate-300 hover:text-white transition text-[10px] font-mono cursor-pointer"
            title="Print Threat Briefing"
          >
            <Printer className="w-3 h-3" />
            <span>Print</span>
          </button>
        </div>
      </div>

      {/* Main Narrative Area */}
      <div className="flex-1 overflow-y-auto max-h-[440px] pr-1">
        {explanation ? (
          viewMode === "formatted" ? (
            <div className="space-y-1 font-sans">
              {parseMarkdown(explanation)}
            </div>
          ) : (
            <pre className="p-3 rounded bg-[#090D16] border border-white/10 font-mono text-[11px] text-slate-300 whitespace-pre-wrap leading-relaxed">
              {explanation}
            </pre>
          )
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 py-16">
            <FileText className="w-8 h-8 mb-2 opacity-30 text-[#00F0FF]" />
            <p className="text-xs font-mono">Awaiting threat vector submission...</p>
          </div>
        )}
      </div>
    </div>
  );
};
