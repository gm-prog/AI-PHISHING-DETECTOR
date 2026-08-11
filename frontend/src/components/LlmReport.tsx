import React, { useState } from "react";
import { Sparkles, Copy, Check, FileText } from "lucide-react";
import "../App.css";

interface LlmReportProps {
  explanation: string;
}

export const LlmReport: React.FC<LlmReportProps> = ({ explanation }) => {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(explanation);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Inline bold+code parser: handles **bold** and `inline-code`
  const renderInlineFormatting = (text: string): React.ReactNode[] => {
    // Split on **bold** and `code` patterns
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
          <code key={i} className="px-1.5 py-0.5 rounded bg-slate-950/60 text-cyan-300 font-mono text-[10px]">
            {part.slice(1, -1)}
          </code>
        );
      }
      return part;
    });
  };

  // Parse a block of lines that form a markdown table. Returns a table element or null.
  const parseTable = (lines: string[]): React.ReactNode | null => {
    // Detect table: rows starting with |
    const tableLines = lines.filter(l => l.trim().startsWith("|"));
    if (tableLines.length < 2) return null;

    const parseCells = (row: string) =>
      row
        .split("|")
        .map((c) => c.trim())
        .filter((_, i, a) => i > 0 && i < a.length - 1); // remove empty first/last

    const headerCells = parseCells(tableLines[0]);
    // Skip separator row (e.g. |---|---|)
    const dataRows = tableLines.slice(2).map(parseCells);

    return (
      <div className="markdown-table-wrapper">
        <table className="markdown-table">
          <thead>
            <tr>
              {headerCells.map((h, i) => (
                <th key={i}>{renderInlineFormatting(h)}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {dataRows.map((row, ri) => (
              <tr key={ri}>
                {row.map((cell, ci) => (
                  <td key={ci}>{renderInlineFormatting(cell)}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  // Main markdown-to-JSX parser (line-by-line with table detection)
  const parseMarkdown = (md: string): React.ReactNode => {
    if (!md) return null;

    const lines = md.split("\n");
    const elements: React.ReactNode[] = [];
    let i = 0;

    while (i < lines.length) {
      const line = lines[i];
      const trimmed = line.trim();

      // --- Detect table blocks ---
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

      // H2
      if (trimmed.startsWith("## ")) {
        elements.push(
          <h2 key={i} className="text-base font-extrabold tracking-tight text-white mt-8 mb-4 border-b border-white/10 pb-2">
            {renderInlineFormatting(trimmed.replace(/^##\s+/, ""))}
          </h2>
        );
        i++;
        continue;
      }

      // H3
      if (trimmed.startsWith("### ")) {
        elements.push(
          <h3 key={i} className="text-sm font-bold font-mono tracking-widest uppercase text-white mt-6 mb-3 pb-1 border-b border-white/5 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-cyan-400 flex-shrink-0" />
            {renderInlineFormatting(trimmed.replace(/^###\s+/, ""))}
          </h3>
        );
        i++;
        continue;
      }

      // H4
      if (trimmed.startsWith("#### ")) {
        elements.push(
          <h4 key={i} className="text-xs font-bold font-mono tracking-wider uppercase text-blue-300 mt-4 mb-2">
            {renderInlineFormatting(trimmed.replace(/^####\s+/, ""))}
          </h4>
        );
        i++;
        continue;
      }

      // Blockquote lines (e.g., `> Some detail`)
      if (trimmed.startsWith("> ")) {
        elements.push(
          <div key={i} className="markdown-blockquote">
            {renderInlineFormatting(trimmed.replace(/^>\s+/, ""))}
          </div>
        );
        i++;
        continue;
      }

      // Horizontal rule
      if (trimmed === "---" || trimmed === "***" || trimmed === "___") {
        elements.push(<hr key={i} className="markdown-hr" />);
        i++;
        continue;
      }

      // Unordered list items
      if (trimmed.startsWith("- ") || trimmed.startsWith("* ")) {
        const itemContent = trimmed.replace(/^[-*]\s+/, "");
        elements.push(
          <ul key={i} className="list-none pl-5 my-1.5">
            <li className="text-xs text-slate-300 leading-relaxed relative before:content-['■'] before:text-[6px] before:text-cyan-500 before:absolute before:-left-3.5 before:top-1.5">
              {renderInlineFormatting(itemContent)}
            </li>
          </ul>
        );
        i++;
        continue;
      }

      // Empty line = spacer
      if (trimmed === "") {
        elements.push(<div key={i} className="h-2" />);
        i++;
        continue;
      }

      // Normal paragraph
      elements.push(
        <p key={i} className="text-xs text-slate-300 leading-relaxed my-2 text-left">
          {renderInlineFormatting(line)}
        </p>
      );
      i++;
    }

    return <>{elements}</>;
  };

  return (
    <div className="glass-panel p-6 rounded-2xl relative shadow-2xl h-full flex flex-col">
      {/* Header bar */}
      <div className="flex items-center justify-between border-b border-white/5 pb-3 mb-4">
        <h3 className="text-sm font-bold text-white font-mono uppercase tracking-wider flex items-center gap-2">
          <Sparkles className="w-4 h-4 text-cyan-400" /> AI Threat Assessment Report
        </h3>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-800/40 hover:bg-slate-800/80 border border-white/5 hover:border-white/10 text-xs text-slate-400 hover:text-slate-200 transition"
          title="Copy full report"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-green-400" />
              <span className="text-green-400 font-mono text-[10px]">Copied</span>
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              <span className="font-mono text-[10px]">Copy Report</span>
            </>
          )}
        </button>
      </div>

      {/* Main Narrative Area */}
      <div className="flex-1 overflow-y-auto max-h-[380px] pr-1 scroll-smooth">
        {explanation ? (
          <div className="space-y-1 font-sans">
            {parseMarkdown(explanation)}
          </div>
        ) : (
          <div className="h-full flex flex-col items-center justify-center text-slate-500 py-16">
            <FileText className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs font-mono">Awaiting threat inspection content...</p>
          </div>
        )}
      </div>
    </div>
  );
};
