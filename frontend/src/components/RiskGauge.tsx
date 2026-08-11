import React, { useEffect, useState } from "react";

interface RiskGaugeProps {
  score: number;
  status: "safe" | "warning" | "danger";
}

export const RiskGauge: React.FC<RiskGaugeProps> = ({ score, status }) => {
  const [animatedScore, setAnimatedScore] = useState(0);

  // Animate the score counter on change
  useEffect(() => {
    let start = 0;
    const end = score;
    if (start === end) {
      setAnimatedScore(end);
      return;
    }

    const duration = 800; // ms
    const increment = end > start ? 1 : -1;
    const stepTime = Math.abs(Math.floor(duration / (end - start)));
    
    const timer = setInterval(() => {
      start += increment;
      setAnimatedScore(start);
      if (start === end) {
        clearInterval(timer);
      }
    }, Math.max(stepTime, 8)); // Cap minimum duration step at 8ms

    return () => clearInterval(timer);
  }, [score]);

  // Color config based on status
  const getColorScheme = () => {
    switch (status) {
      case "safe":
        return {
          stroke: "#22c55e",
          glow: "rgba(34,197,94,0.35)",
          text: "text-green-400",
          bg: "bg-green-500/10 border-green-500/20"
        };
      case "warning":
        return {
          stroke: "#f59e0b",
          glow: "rgba(245,158,11,0.35)",
          text: "text-amber-400",
          bg: "bg-amber-500/10 border-amber-500/20"
        };
      case "danger":
        return {
          stroke: "#ef4444",
          glow: "rgba(239,68,68,0.35)",
          text: "text-red-400",
          bg: "bg-red-500/10 border-red-500/20"
        };
      default:
        return {
          stroke: "#3b82f6",
          glow: "rgba(59,130,246,0.35)",
          text: "text-blue-400",
          bg: "bg-blue-500/10 border-blue-500/20"
        };
    }
  };

  const scheme = getColorScheme();

  // SVG Gauge calculations
  const radius = 80;
  const strokeWidth = 10;
  const circumference = 2 * Math.PI * radius;
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference;

  return (
    <div className="flex flex-col items-center justify-center p-6 glass-panel rounded-2xl relative overflow-hidden h-full shadow-2xl">
      <div className="relative w-48 h-48 flex items-center justify-center">
        {/* Animated Cyber Target Outer Ring */}
        <div className="absolute inset-0 rounded-full border border-dashed border-white/10 animate-[spin_40s_linear_infinite]" />
        <div 
          className="absolute inset-2 rounded-full border border-double border-white/5" 
          style={{ boxShadow: `inset 0 0 15px ${scheme.glow}` }}
        />
        
        {/* SVG Radial Progress */}
        <svg className="w-full h-full transform -rotate-90 relative z-10" viewBox="0 0 200 200">
          <defs>
            <filter id="glow-effect" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="6" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>
          
          {/* Base track */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke="rgba(255, 255, 255, 0.03)"
            strokeWidth={strokeWidth}
          />
          
          {/* Active progress track */}
          <circle
            cx="100"
            cy="100"
            r={radius}
            fill="transparent"
            stroke={scheme.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            filter="url(#glow-effect)"
            style={{ transition: "stroke-dashoffset 0.5s ease-out, stroke 0.5s ease" }}
          />
        </svg>

        {/* Center Text (Score Display) */}
        <div className="absolute flex flex-col items-center justify-center text-center z-20">
          <span className="text-[10px] font-mono tracking-widest text-slate-400 font-bold uppercase">Risk Score</span>
          <span className={`text-4xl font-extrabold tracking-tighter font-mono ${scheme.text}`}>
            {animatedScore}
          </span>
          <span className="text-[10px] font-mono text-slate-500 font-bold">/ 100</span>
        </div>
      </div>

      {/* Status Alert Badge */}
      <div className={`mt-6 px-5 py-2 rounded-xl border text-center font-mono font-bold tracking-widest uppercase text-xs transition-slow ${scheme.bg} ${scheme.text}`}>
        Threat: {status}
      </div>
    </div>
  );
};
