import React from 'react';
import { useNavigate } from 'react-router-dom';

interface PostureScoreProps {
  score: number;
  previousScore?: number | null;
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

export default function PostureScore({ score, previousScore }: PostureScoreProps) {
  const navigate = useNavigate();
  const grade = getGrade(score);
  const arcColor = getArcColor(score);

  const size = 140;
  const strokeWidth = 12;
  const radius = (size - strokeWidth) / 2;
  const circumference = Math.PI * radius; // Half circle
  const dashLength = (score / 100) * circumference;

  const scoreDelta = previousScore != null ? Math.round((score - previousScore) * 10) / 10 : null;
  const isImproved = scoreDelta !== null && scoreDelta > 0;

  return (
    <div
      className="bg-white border rounded-xl p-5 cursor-pointer hover:shadow-md transition"
      onClick={() => navigate('/identities?risk_level=critical')}
      title="View critical risk identities"
    >
      <div className="flex items-center justify-between mb-3">
        <div className="text-sm font-semibold text-gray-900">Security Posture</div>
        <span className="text-[10px] text-gray-400">Click to drill down</span>
      </div>

      <div className="flex flex-col items-center">
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

        {/* Delta vs previous run */}
        {scoreDelta !== null && scoreDelta !== 0 ? (
          <div className={`mt-3 flex items-center gap-1.5 px-3 py-1.5 rounded-lg ${isImproved ? 'bg-green-50' : 'bg-red-50'}`}>
            <svg className={`w-4 h-4 ${isImproved ? 'text-green-600' : 'text-red-600'}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={isImproved ? 'M5 10l7-7m0 0l7 7m-7-7v18' : 'M19 14l-7 7m0 0l-7-7m7 7V3'} />
            </svg>
            <span className={`text-sm font-semibold ${isImproved ? 'text-green-700' : 'text-red-700'}`}>
              {Math.abs(scoreDelta)}%
            </span>
            <span className="text-xs text-gray-500">vs previous run</span>
          </div>
        ) : scoreDelta === 0 ? (
          <div className="mt-3 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-gray-50">
            <span className="text-xs text-gray-500">No change vs previous run</span>
          </div>
        ) : (
          <div className="mt-3 text-xs text-gray-400 italic">
            Trend data available after 2+ runs
          </div>
        )}
      </div>
    </div>
  );
}
