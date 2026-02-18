import React from 'react';
import { scoreToColor } from '../../constants/design';

interface ArcGaugeProps {
  score: number | null;
  grade: string | null;
  size?: number;
}

export default function ArcGauge({ score, grade, size = 170 }: ArcGaugeProps) {
  const cx = size / 2;
  const cy = size / 2;
  const r = size * 0.382; // ~65 at 170
  const startAngle = 135;
  const endAngle = 405;
  const arcLen = endAngle - startAngle; // 270 degrees

  const pct = score != null ? Math.min(score, 100) / 100 : 0;
  const color = score != null ? scoreToColor(score) : '#475569';
  const gradeLabel = grade ?? '—';

  function angleToXY(angle: number) {
    const rad = (angle * Math.PI) / 180;
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
  }

  function arcPath(start: number, sweep: number) {
    const s = angleToXY(start);
    const e = angleToXY(start + sweep);
    const largeArc = sweep > 180 ? 1 : 0;
    return `M ${s.x} ${s.y} A ${r} ${r} 0 ${largeArc} 1 ${e.x} ${e.y}`;
  }

  const bgPath = arcPath(startAngle, arcLen);
  const fgPath = arcPath(startAngle, arcLen * pct);
  const fontSize = Math.round(size * 0.212);
  const gradeFontSize = Math.round(size * 0.082);

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <path d={bgPath} stroke="#334155" strokeWidth="12" fill="none" strokeLinecap="round" />
      {score != null && pct > 0 && (
        <path d={fgPath} stroke={color} strokeWidth="12" fill="none" strokeLinecap="round"
          style={{ transition: 'all 1s ease-in-out' }} />
      )}
      <text x={cx} y={cy - 6} textAnchor="middle" fill={score != null ? color : '#94A3B8'} fontSize={fontSize} fontWeight="800">
        {score != null ? Math.round(score) : '—'}
      </text>
      <text x={cx} y={cy + 18} textAnchor="middle" fill="#94A3B8" fontSize={gradeFontSize} fontWeight="600">
        {score != null ? `Grade ${gradeLabel}` : 'No Data'}
      </text>
      <text x={cx - r * 0.89} y={cy + r * 0.8} textAnchor="middle" fill="#475569" fontSize="9">0</text>
      <text x={cx + r * 0.89} y={cy + r * 0.8} textAnchor="middle" fill="#475569" fontSize="9">100</text>
    </svg>
  );
}
