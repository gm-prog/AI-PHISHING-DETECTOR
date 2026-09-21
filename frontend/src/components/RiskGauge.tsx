import React, { useEffect, useState } from "react";

interface RiskGaugeProps {
  score: number;
  status: "safe" | "warning" | "danger";
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, status }) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  useEffect(() => {
    let start = 0;
    const end = score;
    if (start === end) {
      setAnimatedScore(end);
      return;
    }

    const duration = 600;
    const increment = end > start ? 1 : -1;
    const stepTime = Math.abs(Math.floor(duration / (end - start)));
    
    const timer = setInterval(() => {
      start += increment;
      setAnimatedScore(start);
      if (start === end) {
        clearInterval(timer);
      }
    }, Math.max(stepTime, 6));

    return () => clearInterval(timer);
  }, [score]);

  const getStatusTokens = () => {
    switch (status) {
      case "safe":
        return {
          color: "#00E699",
          badgeClass: "badge-safe",
          label: "CLEAN / LOW RISK"
        };
      case "warning":
        return {
          color: "#FFB800",
          badgeClass: "badge-warning",
          label: "SUSPICIOUS / WARNING"
        };
      case "danger":
        return {
          color: "#FF3366",
          badgeClass: "badge-danger",
          label: "CRITICAL / THREAT CONFIRMED"
        };
      default:
        return {
          color: "#00F0FF",
          badgeClass: "badge-cyan",
          label: "INSPECTING..."
        };
    }
  };

  const tokens = getStatusTokens();

  const radius = 75;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="tactical-panel p-5 rounded border border-white/10 flex flex-col items-center justify-center text-center h-full">
      <div className="relative w-44 h-44 flex items-center justify-center">
        {/* Outer Grid Tick Ring */}
        <div className="absolute inset-0 rounded-full border border-dashed border-white/10" />
        
        {/* SVG Radial Gauge */}
        <svg className="w-full h-full transform -rotate-90 relative z-10" viewBox="0 0 190 190">
          <circle
            cx="95"
            cy="95"
            r={radius}
            fill="transparent"
            stroke="rgba(255, 255, 255, 0.05)"
            strokeWidth={strokeWidth}
          />
          <circle
            cx="95"
            cy="95"
            r={radius}
            fill="transparent"
            stroke={tokens.color}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="butt"
            style={{ transition: "stroke-dashoffset 0.4s ease-out, stroke 0.4s ease" }}
          />
        </svg>

        {/* Center Telemetry Display */}
        <div className="absolute flex flex-col items-center justify-center z-20">
          <span className="text-[10px] font-mono tracking-widest text-slate-400 uppercase font-bold">Threat Index</span>
          <span className="text-4xl font-extrabold font-mono tracking-tighter" style={{ color: tokens.color }}>
            {animatedScore}
          </span>
          <span className="text-[10px] font-mono text-slate-500 font-bold">/ 100 SCORE</span>
        </div>
      </div>

      {/* Threat Status Badge */}
      <div className={`mt-4 px-4 py-1.5 rounded text-center font-mono font-bold tracking-wider uppercase text-xs ${tokens.badgeClass}`}>
        {tokens.label}
      </div>
    </div>
  );
};
