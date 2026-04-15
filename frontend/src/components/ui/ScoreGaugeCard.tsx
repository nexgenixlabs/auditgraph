import React from 'react';
import { scoreToColor, scoreToGrade } from '../../constants/design';

interface ScoreGaugeCardProps {
  label: string;
  score: number;
  maxScore?: number;
  /** Show letter grade (A-F) instead of percentage */
  showGrade?: boolean;
  subtitle?: string;
  className?: string;
}

/**
 * Score Gauge Card — circular progress indicator for posture scores.
 *
 * Uses scoreToColor/scoreToGrade from design tokens.
 * JetBrains Mono for the score value.
 */
export default function ScoreGaugeCard({
  label,
  score,
  maxScore = 100,
  showGrade,
  subtitle,
  className = '',
}: ScoreGaugeCardProps) {
  const pct = Math.min(Math.max((score / maxScore) * 100, 0), 100);
  const color = scoreToColor(100 - pct); // Invert: high score = green
  const grade = scoreToGrade(100 - pct);

  // SVG arc
  const r = 38;
  const circumference = 2 * Math.PI * r;
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div
      className={`kpi-card flex flex-col items-center ${className}`}
    >
      {/* Gauge circle */}
      <div className="relative w-24 h-24 mb-3">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 88 88">
          {/* Track */}
          <circle
            cx="44" cy="44" r={r}
            fill="none"
            stroke="var(--border-subtle)"
            strokeWidth="6"
          />
          {/* Progress */}
          <circle
            cx="44" cy="44" r={r}
            fill="none"
            stroke={color}
            strokeWidth="6"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            style={{ transition: 'stroke-dashoffset 0.6s ease-out' }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-xl font-semibold" style={{ color }}>
            {showGrade ? grade : `${Math.round(pct)}%`}
          </span>
        </div>
      </div>

      {/* Label */}
      <span className="text-xs font-medium text-center" style={{ color: 'var(--text-secondary)' }}>
        {label}
      </span>

      {/* Subtitle */}
      {subtitle && (
        <span className="text-[10px] mt-0.5 text-center" style={{ color: 'var(--text-muted)' }}>
          {subtitle}
        </span>
      )}
    </div>
  );
}
