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
  tier?: string;
  category?: string;
  short_name?: string;
  identity_controls_count?: number;
  total_framework_controls?: number;
  scope_label?: string;
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
  'CC6.2': '/identities?credential_status=expired',
  'CC6.3': '/identities?owner_status=unowned&identity_category=service_principal',
  'CC6.6': '/identities?mfa_enforced=false',
  'CC7.1': '/identities?activity_status=stale',
  'CC7.2': '/identities?activity_status=dormant&privilege_tier=0,1',
  'CC8.1': '/identities?excessive_permissions=true',
  'CC8.2': '/identities?credential_rotation=overdue',
  // HIPAA
  '§164.312(a)': '/identities?privilege_tier=0',
  '§164.312(d)': '/identities?credential_status=expired',
  '§164.308(a)(1)': '/identities?privilege_tier=0',
  '§164.308(a)(3)': '/identities?activity_status=dormant&privilege_tier=0,1',
  '§164.308(a)(4)': '/identities?activity_status=stale&has_roles=true',
  '§164.308(a)(5)': '/identities?mfa_enforced=false',
  '§164.308(a)(8)': '/identities?activity_status=stale',
  '§164.312(b)': '/identities?risk_level=high',
  '§164.312(c)': '/identities?excessive_permissions=true',
  '§164.312(e)': '/identities?credential_rotation=overdue',
  // PCI-DSS
  '7.1': '/identities?privilege_tier=0',
  '7.2.1': '/identities?credential_status=expired',
  '7.2.2': '/identities?excessive_permissions=true',
  '8.2.1': '/identities?shared_account=true',
  '8.3': '/identities?credential_status=expired',
  '8.3.6': '/identities?mfa_enforced=false',
  '8.5': '/identities?shared_account=true',
  '8.6': '/identities?owner_status=unowned&identity_category=service_principal',
  '10.1': '/identities?activity_status=stale',
  '10.2': '/identities?activity_status=stale&has_roles=true',
  // NIST 800-53
  'AC-2': '/identities?activity_status=stale',
  'AC-3': '/identities?excessive_permissions=true',
  'AC-5': '/identities?shared_account=true',
  'AC-6': '/identities?privilege_tier=0',
  'AC-17': '/identities?mfa_enforced=false',
  'AU-6': '/identities?activity_status=stale&has_roles=true',
  'IA-2': '/identities?mfa_enforced=false',
  'IA-4': '/identities?activity_status=stale',
  'IA-5': '/identities?credential_status=expired',
  'IA-8': '/identities?identity_category=guest&mfa_enforced=false',
  'SI-4': '/identities?activity_status=stale&has_roles=true',
  'PM-10': '/identities?identity_category=service_principal&has_owner=false',
  // CIS Azure
  '1.1': '/identities?privilege_tier=0',
  '1.2': '/identities?activity_status=stale',
  '1.3': '/identities?mfa_enforced=false',
  '1.4': '/identities?identity_category=guest',
  '1.5': '/identities?identity_category=service_principal&has_owner=false',
  // ISO 27001
  'A.5.15': '/identities?privilege_tier=0',
  'A.5.16': '/identities?activity_status=stale',
  'A.5.17': '/identities?credential_status=expired',
  'A.8.2': '/identities?excessive_permissions=true',
  'A.8.5': '/identities?mfa_enforced=false',
};

const TIER_ORDER = ['core', 'industry', 'privacy', 'benchmark'];
const TIER_LABELS: Record<string, string> = {
  core: 'Core Governance',
  industry: 'Industry Specific',
  privacy: 'Privacy & Data Protection',
  benchmark: 'Technical Benchmarks',
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

  const frameworks = Object.entries(data);
  const allValues = Object.values(data);
  const overallScore = allValues.length > 0
    ? Math.round(allValues.reduce((s, fw) => s + fw.score, 0) / allValues.length)
    : 0;

  // Group by tier
  const tierGroups: Record<string, [string, Framework][]> = {};
  for (const entry of frameworks) {
    const tier = entry[1].tier || 'core';
    if (!tierGroups[tier]) tierGroups[tier] = [];
    tierGroups[tier].push(entry);
  }
  const orderedTiers = TIER_ORDER.filter(t => tierGroups[t]?.length);
  // If no tier data, fall back to flat display
  const hasTierData = orderedTiers.length > 0;

  // Count total identity controls
  const totalIdentityControls = allValues.reduce((s, fw) => s + (fw.total_controls || 0), 0);
  const totalFrameworkControls = allValues.reduce((s, fw) => s + (fw.total_framework_controls || 0), 0);

  return (
    <div className="bg-white border rounded-2xl overflow-hidden">
      {/* Header */}
      <div className="px-6 py-4 border-b bg-gray-50 flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold text-gray-900">GRC Compliance Scorecard</h3>
            <span className="px-2 py-0.5 rounded-full text-[9px] font-medium bg-violet-50 text-violet-600">
              Identity Controls
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-0.5">
            Assessing identity, access, and privilege controls only
            {totalFrameworkControls > 0 && (
              <span className="ml-1 text-gray-400">
                ({totalIdentityControls} of {totalFrameworkControls} total controls across {allValues.length} frameworks)
              </span>
            )}
          </p>
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

      {/* Framework cards grouped by tier */}
      {hasTierData ? (
        <div>
          {orderedTiers.map(tier => (
            <div key={tier}>
              {/* Tier header */}
              <div className="px-6 py-2 bg-gray-50 border-b border-t">
                <span className="text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                  {TIER_LABELS[tier] || tier}
                </span>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-gray-200">
                {tierGroups[tier].map(([, fw]) => (
                  <FrameworkCard key={fw.name} fw={fw} navigate={navigate} />
                ))}
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-px bg-gray-200">
          {frameworks.map(([, fw]) => (
            <FrameworkCard key={fw.name} fw={fw} navigate={navigate} />
          ))}
        </div>
      )}
    </div>
  );
}

function FrameworkCard({ fw, navigate }: { fw: Framework; navigate: (path: string) => void }) {
  return (
    <div className="p-5 bg-white">
      {/* Framework header */}
      <div className="flex items-center justify-between mb-4">
        <div>
          <div className="font-semibold text-gray-900 text-sm flex items-center gap-2">
            {fw.short_name || fw.name}
            {!!fw.identity_controls_count && !!fw.total_framework_controls && fw.total_framework_controls > 0 && (
              <span className="px-1.5 py-0.5 bg-gray-100 text-gray-400 text-[9px] font-medium rounded">
                {fw.identity_controls_count} of {fw.total_framework_controls}
              </span>
            )}
          </div>
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
}
