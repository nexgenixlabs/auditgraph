import React from 'react';

interface Control {
  id: string;
  name: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
}

interface Framework {
  name: string;
  score: number;
  pass_count: number;
  total_controls: number;
  controls: Control[];
}

interface ComplianceScorecardProps {
  data: Record<string, Framework> | null;
  loading?: boolean;
}

const statusConfig: Record<string, { label: string; color: string; bg: string; icon: string }> = {
  pass: {
    label: 'Pass',
    color: 'text-green-700',
    bg: 'bg-green-100',
    icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z',
  },
  warn: {
    label: 'Warn',
    color: 'text-yellow-700',
    bg: 'bg-yellow-100',
    icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z',
  },
  fail: {
    label: 'Fail',
    color: 'text-red-700',
    bg: 'bg-red-100',
    icon: 'M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z',
  },
};

function ScoreRing({ score, size = 48 }: { score: number; size?: number }) {
  const r = (size - 6) / 2;
  const circ = 2 * Math.PI * r;
  const offset = circ - (score / 100) * circ;
  const color = score >= 75 ? '#16a34a' : score >= 50 ? '#d97706' : '#dc2626';

  return (
    <svg width={size} height={size} className="flex-shrink-0">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#e5e7eb" strokeWidth={4} />
      <circle
        cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={4}
        strokeDasharray={circ} strokeDashoffset={offset}
        strokeLinecap="round" transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x={size / 2} y={size / 2} textAnchor="middle" dominantBaseline="central"
        className="text-xs font-bold" fill={color}>
        {score}%
      </text>
    </svg>
  );
}

export default function ComplianceScorecard({ data, loading }: ComplianceScorecardProps) {
  if (loading || !data) {
    return (
      <div className="bg-white border rounded-2xl p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-5 bg-gray-200 rounded w-48" />
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-48 bg-gray-100 rounded-xl" />)}
          </div>
        </div>
      </div>
    );
  }

  const frameworks = Object.values(data);
  const overallScore = frameworks.length > 0
    ? Math.round(frameworks.reduce((s, fw) => s + fw.score, 0) / frameworks.length)
    : 0;

  return (
    <div className="bg-white border rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b bg-gray-50 flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-gray-900">GRC Compliance Scorecard</h3>
          <p className="text-xs text-gray-500 mt-0.5">Automated assessment based on current identity posture</p>
        </div>
        <div className="flex items-center gap-3">
          <ScoreRing score={overallScore} size={52} />
          <div className="text-right">
            <div className="text-xs text-gray-500">Overall</div>
            <div className={`text-sm font-bold ${overallScore >= 75 ? 'text-green-700' : overallScore >= 50 ? 'text-yellow-700' : 'text-red-700'}`}>
              {overallScore >= 75 ? 'Healthy' : overallScore >= 50 ? 'Needs Work' : 'At Risk'}
            </div>
          </div>
        </div>
      </div>

      {/* Framework cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 divide-y md:divide-y-0 md:divide-x">
        {frameworks.map(fw => {
          const fails = fw.controls.filter(c => c.status === 'fail').length;
          const warns = fw.controls.filter(c => c.status === 'warn').length;

          return (
            <div key={fw.name} className="p-5">
              {/* Framework header */}
              <div className="flex items-center justify-between mb-4">
                <div>
                  <div className="font-semibold text-gray-900 text-sm">{fw.name}</div>
                  <div className="text-[10px] text-gray-500 mt-0.5">
                    {fw.pass_count}/{fw.total_controls} controls passing
                  </div>
                </div>
                <ScoreRing score={fw.score} size={40} />
              </div>

              {/* Controls */}
              <div className="space-y-2.5">
                {fw.controls.map(ctrl => {
                  const cfg = statusConfig[ctrl.status];
                  return (
                    <div key={ctrl.id} className="group">
                      <div className="flex items-center gap-2">
                        <svg className={`w-4 h-4 flex-shrink-0 ${cfg.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={cfg.icon} />
                        </svg>
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span className="text-[10px] font-mono text-gray-400">{ctrl.id}</span>
                          <span className="text-xs font-medium text-gray-800 truncate">{ctrl.name}</span>
                        </div>
                        <span className={`ml-auto px-1.5 py-0.5 rounded text-[9px] font-bold uppercase flex-shrink-0 ${cfg.bg} ${cfg.color}`}>
                          {cfg.label}
                        </span>
                      </div>
                      <div className="text-[10px] text-gray-500 ml-6 mt-0.5">{ctrl.detail}</div>
                    </div>
                  );
                })}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
