import React from 'react';
import { RISK_LEVELS, RISK_HEX } from '../../constants/metrics';

interface RiskCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

interface RiskDonutChartProps {
  counts: RiskCounts;
  onSegmentClick?: (level: string) => void;
  cloudSources?: string[];
}

const riskConfig = RISK_LEVELS.map(key => ({
  key,
  label: key.charAt(0).toUpperCase() + key.slice(1),
  color: RISK_HEX[key].color,
  hoverColor: RISK_HEX[key].hoverColor,
}));

export default function RiskDonutChart({ counts, onSegmentClick, cloudSources }: RiskDonutChartProps) {
  const total = counts.total || 1;
  const size = 200;
  const strokeWidth = 35;
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;

  // Calculate segment data
  let cumulativePercent = 0;
  const segments = riskConfig.map(config => {
    const count = counts[config.key as keyof RiskCounts] as number;
    const percent = (count / total) * 100;
    const dashLength = (percent / 100) * circumference;
    const dashOffset = circumference - (cumulativePercent / 100) * circumference;

    const segment = {
      ...config,
      count,
      percent,
      dashLength,
      dashOffset,
      rotation: (cumulativePercent / 100) * 360 - 90,
    };

    cumulativePercent += percent;
    return segment;
  }).filter(s => s.count > 0);

  const [hoveredSegment, setHoveredSegment] = React.useState<string | null>(null);

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <div className="text-sm font-semibold text-gray-900">Risk Distribution</div>
        {cloudSources && cloudSources.length > 0 && (
          <div className="flex items-center gap-1">
            {cloudSources.map(c => (
              <span key={c} className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase bg-gray-100 text-gray-600">
                {c}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="flex items-center justify-center gap-8">
        {/* SVG Donut */}
        <div className="relative">
          <svg width={size} height={size} className="transform -rotate-90">
            {/* Background circle */}
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke="#f3f4f6"
              strokeWidth={strokeWidth}
            />

            {/* Risk segments */}
            {segments.map((segment, idx) => (
              <circle
                key={segment.key}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="none"
                stroke={hoveredSegment === segment.key ? segment.hoverColor : segment.color}
                strokeWidth={strokeWidth}
                strokeDasharray={`${segment.dashLength} ${circumference - segment.dashLength}`}
                strokeDashoffset={segment.dashOffset}
                className="transition-all duration-200 cursor-pointer"
                onMouseEnter={() => setHoveredSegment(segment.key)}
                onMouseLeave={() => setHoveredSegment(null)}
                onClick={() => onSegmentClick?.(segment.key)}
                style={{ transformOrigin: 'center' }}
              />
            ))}
          </svg>

          {/* Center text */}
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <div className="text-3xl font-bold text-gray-900">{counts.total}</div>
            <div className="text-xs text-gray-500">Total</div>
          </div>
        </div>

        {/* Legend */}
        <div className="space-y-2">
          {riskConfig.map(config => {
            const count = counts[config.key as keyof RiskCounts] as number;
            const percent = ((count / total) * 100).toFixed(1);

            return (
              <button
                key={config.key}
                onClick={() => onSegmentClick?.(config.key)}
                onMouseEnter={() => setHoveredSegment(config.key)}
                onMouseLeave={() => setHoveredSegment(null)}
                className={`
                  flex items-center gap-2 w-full px-2 py-1 rounded-lg text-left transition
                  ${hoveredSegment === config.key ? 'bg-gray-100' : 'hover:bg-gray-50'}
                `}
              >
                <div
                  className="w-3 h-3 rounded-full flex-shrink-0"
                  style={{ backgroundColor: config.color }}
                />
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-gray-900">{config.label}</div>
                </div>
                <div className="text-sm font-bold text-gray-900">{count}</div>
                <div className="text-xs text-gray-500 w-12 text-right">{percent}%</div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
