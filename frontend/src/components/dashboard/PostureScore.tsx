import React from 'react';

interface PostureScoreProps {
  score: number;
  previousRun?: {
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
  currentRun?: {
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
}

function getGrade(score: number): { label: string; color: string } {
  if (score >= 90) return { label: 'A', color: 'text-green-600' };
  if (score >= 75) return { label: 'B', color: 'text-green-500' };
  if (score >= 60) return { label: 'C', color: 'text-yellow-600' };
  if (score >= 40) return { label: 'D', color: 'text-orange-600' };
  return { label: 'F', color: 'text-red-600' };
}

function getArcColor(score: number): string {
  if (score >= 90) return '#16a34a';
  if (score >= 75) return '#22c55e';
  if (score >= 60) return '#eab308';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

function TrendArrow({ current, previous, label, inverse = false }: {
  current: number;
  previous: number;
  label: string;
  inverse?: boolean;
}) {
  const diff = current - previous;
  if (diff === 0) return null;

  const isGood = inverse ? diff < 0 : diff > 0;
  const arrow = diff > 0 ? '+' : '';

  return (
    <div className="flex items-center gap-1 text-xs">
      <span className="text-gray-500">{label}:</span>
      <span className={isGood ? 'text-green-600 font-medium' : 'text-red-600 font-medium'}>
        {arrow}{diff}
      </span>
    </div>
  );
}

export default function PostureScore({ score, previousRun, currentRun }: PostureScoreProps) {
  const grade = getGrade(score);
  const arcColor = getArcColor(score);

  const size = 140;
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = Math.PI * radius; // Half circle
  const dashLength = (score / 100) * circumference;

  const hasTrend = previousRun && currentRun;

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="text-sm font-semibold text-gray-900 mb-3">Security Posture</div>

      <div className="flex items-center gap-6">
        {/* Arc gauge */}
        <div className="relative flex-shrink-0" style={{ width: size, height: size / 2 + 20 }}>
          <svg width={size} height={size / 2 + 10} viewBox={`0 0 ${size} ${size / 2 + 10}`}>
            {/* Background arc */}
            <path
              d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
              fill="none"
              stroke="#f3f4f6"
              strokeWidth={strokeWidth}
              strokeLinecap="round"
            />
            {/* Score arc */}
            <path
              d={`M ${strokeWidth / 2} ${size / 2} A ${radius} ${radius} 0 0 1 ${size - strokeWidth / 2} ${size / 2}`}
              fill="none"
              stroke={arcColor}
              strokeWidth={strokeWidth}
              strokeLinecap="round"
              strokeDasharray={`${dashLength} ${circumference}`}
              className="transition-all duration-700"
            />
          </svg>
          <div className="absolute inset-x-0 bottom-0 text-center">
            <div className={`text-2xl font-bold ${grade.color}`}>{score}%</div>
            <div className="text-xs text-gray-500">Grade: <span className={`font-bold ${grade.color}`}>{grade.label}</span></div>
          </div>
        </div>

        {/* Trend comparison */}
        <div className="flex-1 min-w-0">
          {hasTrend ? (
            <div className="space-y-1.5">
              <div className="text-xs font-medium text-gray-700 mb-2">vs Previous Run</div>
              <TrendArrow
                current={currentRun!.critical_count}
                previous={previousRun!.critical_count}
                label="Critical"
                inverse
              />
              <TrendArrow
                current={currentRun!.high_count}
                previous={previousRun!.high_count}
                label="High"
                inverse
              />
              <TrendArrow
                current={currentRun!.medium_count}
                previous={previousRun!.medium_count}
                label="Medium"
                inverse
              />
              <TrendArrow
                current={currentRun!.total_identities}
                previous={previousRun!.total_identities}
                label="Total"
              />
            </div>
          ) : (
            <div className="text-xs text-gray-400 italic">
              Trend data available after 2+ runs
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
