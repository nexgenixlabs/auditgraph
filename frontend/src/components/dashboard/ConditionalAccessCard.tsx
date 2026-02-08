import React from 'react';
import { useNavigate } from 'react-router-dom';

interface WeakPolicyFlag {
  flag: string;
  count: number;
  severity: 'critical' | 'high' | 'medium';
}

interface CaData {
  total_policies: number;
  enabled_policies: number;
  disabled_policies?: number;
  mfa_policies?: number;
  coverage: {
    covered: number;
    partial?: number;
    excluded: number;
    no_coverage: number;
    coverage_pct: number;
  };
  weak_policy_flags: WeakPolicyFlag[];
}

interface ConditionalAccessCardProps {
  data: CaData | null;
  loading?: boolean;
}

const flagLabels: Record<string, string> = {
  no_mfa_for_all_users: 'No MFA for All-User policies',
  no_mfa_for_admins: 'No MFA for admin roles',
  ca_policy_disabled: 'Disabled CA policies',
  legacy_auth_enabled: 'Legacy auth allowed',
};

const severityConfig: Record<string, { bg: string; text: string }> = {
  critical: { bg: 'bg-red-100', text: 'text-red-700' },
  high: { bg: 'bg-orange-100', text: 'text-orange-700' },
  medium: { bg: 'bg-yellow-100', text: 'text-yellow-700' },
};

export default function ConditionalAccessCard({ data, loading }: ConditionalAccessCardProps) {
  const navigate = useNavigate();
  if (loading) {
    return (
      <div className="bg-white border rounded-2xl p-6 animate-pulse">
        <div className="h-5 bg-gray-100 rounded w-48 mb-4" />
        <div className="h-16 bg-gray-100 rounded mb-4" />
        <div className="h-20 bg-gray-100 rounded" />
      </div>
    );
  }

  if (!data || data.total_policies === 0) {
    return (
      <div className="bg-white border rounded-2xl p-6">
        <div className="text-sm font-semibold text-gray-900 mb-3">Conditional Access</div>
        <div className="text-center py-4">
          <svg className="w-10 h-10 text-gray-300 mx-auto mb-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
          </svg>
          <div className="text-xs text-gray-500">No CA policies found. Requires Policy.Read.All permission.</div>
        </div>
      </div>
    );
  }

  const pct = data.coverage.coverage_pct;
  const pctColor = pct >= 80 ? 'text-green-600' : pct >= 50 ? 'text-yellow-600' : 'text-red-600';

  return (
    <div className="bg-white border rounded-2xl p-6">
      <div className="text-sm font-semibold text-gray-900 mb-4 flex items-center gap-2">
        <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
        </svg>
        Conditional Access
      </div>

      {/* Coverage % */}
      <div className="flex items-baseline gap-2 mb-4">
        <span className={`text-3xl font-bold ${pctColor}`}>{pct}%</span>
        <span className="text-sm text-gray-500">coverage</span>
      </div>

      {/* Stats grid */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="bg-gray-50 rounded-lg p-3">
          <div className="text-xs text-gray-500">Policies</div>
          <div className="text-lg font-bold text-gray-900">{data.enabled_policies}<span className="text-sm font-normal text-gray-400">/{data.total_policies}</span></div>
        </div>
        <div className="bg-gray-50 rounded-lg p-3">
          <div className="text-xs text-gray-500">MFA Enforcing</div>
          <div className="text-lg font-bold text-blue-700">{data.mfa_policies ?? 0}</div>
        </div>
        <button
          onClick={() => navigate('/identities?ca_coverage=covered')}
          className="bg-gray-50 rounded-lg p-3 text-left hover:bg-green-50 transition"
        >
          <div className="text-xs text-gray-500">Covered</div>
          <div className="text-lg font-bold text-green-700">{data.coverage.covered}</div>
        </button>
        <button
          onClick={() => navigate('/identities?ca_coverage=not_covered')}
          className="bg-gray-50 rounded-lg p-3 text-left hover:bg-red-50 transition"
        >
          <div className="text-xs text-gray-500">Not Covered</div>
          <div className="text-lg font-bold text-red-700">{data.coverage.no_coverage + data.coverage.excluded}</div>
        </button>
      </div>

      {/* Weak policy flags */}
      {data.weak_policy_flags.length > 0 && (
        <div>
          <div className="text-xs font-semibold text-gray-700 mb-2">Policy Risks</div>
          <div className="space-y-1.5">
            {data.weak_policy_flags.map((flag, idx) => {
              const cfg = severityConfig[flag.severity] || severityConfig.medium;
              return (
                <div key={idx} className="flex items-center justify-between">
                  <span className="text-xs text-gray-700">{flagLabels[flag.flag] || flag.flag}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${cfg.bg} ${cfg.text}`}>
                    {flag.count} {flag.severity.toUpperCase()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
