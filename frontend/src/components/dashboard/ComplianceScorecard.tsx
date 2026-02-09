import React from 'react';
import { useNavigate } from 'react-router-dom';

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

// Control ID → drilldown URL mapping
const controlDrillDown: Record<string, string> = {
  // SOC 2
  'CC6.1': '/identities?privilege_tier=0',
  'CC6.2': '/identities?activity_status=dormant&privilege_tier=0,1',
  'CC6.3': '/identities?owner_status=unowned&identity_category=service_principal',
  'CC7.2': '/identities?credential_status=expired',
  // HIPAA
  '§164.312(a)': '/identities?privilege_tier=0',
  '§164.312(d)': '/identities?credential_status=expired',
  '§164.308(a)(3)': '/identities?activity_status=dormant&privilege_tier=0,1',
  '§164.312(b)': '/identities?risk_level=high',
  // PCI-DSS
  'Req 7.1': '/identities?privilege_tier=0',
  'Req 8.1': '/identities?credential_status=expired',
  'Req 8.6': '/identities?owner_status=unowned&identity_category=service_principal',
  // NIST 800-53
  'AC-2': '/identities?activity_status=dormant&privilege_tier=0,1',
  'AC-6': '/identities?privilege_tier=0',
  'IA-5': '/identities?credential_status=expired',
  'CM-8': '/identities?owner_status=unowned',
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
        fontSize={11} fontWeight={700} fill={color}>
        {score}%
      </text>
    </svg>
  );
}

export default function ComplianceScorecard({ data, loading }: ComplianceScorecardProps) {
  const navigate = useNavigate();

  if (loading || !data) {
    return (
      <div className="bg-white border rounded-2xl p-6">
        <div className="animate-pulse space-y-4">
          <div className="h-5 bg-gray-200 rounded w-48" />
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
      <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-gray-200">
        {frameworks.map(fw => {
          return (
            <div key={fw.name} className="p-5 bg-white">
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
                  const drillUrl = controlDrillDown[ctrl.id];
                  return (
                    <button
                      key={ctrl.id}
                      className="group w-full text-left rounded-lg px-1.5 py-1 -mx-1.5 hover:bg-gray-50 transition"
                      onClick={() => drillUrl && navigate(drillUrl)}
                    >
                      <div className="flex items-center gap-2">
                        <svg className={`w-4 h-4 flex-shrink-0 ${cfg.color}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={cfg.icon} />
                        </svg>
                        <div className="flex items-center gap-1.5 min-w-0">
                          <span className="text-[10px] font-mono text-gray-400">{ctrl.id}</span>
                          <span className="text-xs font-medium text-gray-800 truncate group-hover:text-blue-600 transition">{ctrl.name}</span>
                        </div>
                        <span className={`ml-auto px-1.5 py-0.5 rounded text-[9px] font-bold uppercase flex-shrink-0 ${cfg.bg} ${cfg.color}`}>
                          {cfg.label}
                        </span>
                      </div>
                      <div className="text-[10px] text-gray-500 ml-6 mt-0.5 truncate">{ctrl.detail}</div>
                    </button>
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
