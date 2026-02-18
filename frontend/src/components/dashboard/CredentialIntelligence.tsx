import React, { useEffect, useState } from 'react';
import { COLORS, RISK_COLORS } from '../../constants/design';
import { useConnection } from '../../contexts/ConnectionContext';

interface CredentialIntelData {
  secret_age_distribution: Record<string, number>;
  auth_method_breakdown: Record<string, number>;
  rotation_compliance: {
    overdue: number;
    due_soon: number;
    compliant: number;
    total_with_creds: number;
    stale_passwords: number;
    multi_active_secrets: number;
  };
}

const AGE_COLORS: Record<string, string> = {
  '<30d': '#22C55E',
  '30-90d': '#3B82F6',
  '90-180d': '#F59E0B',
  '180-365d': '#F97316',
  '>365d': '#EF4444',
};

const METHOD_COLORS: Record<string, string> = {
  password: '#8B5CF6',
  certificate: '#3B82F6',
  key: '#F59E0B',
  federated: '#10B981',
  unknown: '#94A3B8',
};

export default function CredentialIntelligence() {
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<CredentialIntelData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(withConnection('/api/dashboard/credential-intelligence'))
      .then(r => r.ok ? r.json() : null)
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [selectedConnectionId]);

  if (loading) {
    return (
      <div className="bg-white rounded-xl p-5 animate-pulse" style={{ border: `1px solid ${COLORS.border}` }}>
        <div className="h-5 rounded w-48 mb-4" style={{ backgroundColor: COLORS.borderLight }} />
        <div className="h-32 rounded" style={{ backgroundColor: COLORS.borderLight }} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
        <div className="text-sm font-bold mb-2" style={{ color: COLORS.textPrimary }}>Credential Intelligence</div>
        <p className="text-sm" style={{ color: COLORS.textMuted }}>No credential data available</p>
      </div>
    );
  }

  const { secret_age_distribution: age, auth_method_breakdown: methods, rotation_compliance: rot } = data;
  const ageTotal = Object.values(age).reduce((s, v) => s + v, 0) || 1;
  const methodTotal = Object.values(methods).reduce((s, v) => s + v, 0) || 1;
  const rotTotal = Math.max(rot.total_with_creds, 1);
  const compliancePct = Math.round((rot.compliant / rotTotal) * 100);

  return (
    <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
      <div className="text-[14px] font-bold mb-4" style={{ color: COLORS.textPrimary }}>Credential Intelligence</div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
        {/* Secret Age Distribution */}
        <div>
          <div className="text-[11px] uppercase tracking-wider mb-2" style={{ color: COLORS.textMuted }}>Secret Age Distribution</div>
          <div className="space-y-1.5">
            {Object.entries(age).map(([bucket, count]) => (
              <div key={bucket} className="flex items-center gap-2">
                <span className="text-[11px] w-14 text-right font-medium" style={{ color: COLORS.textSecondary }}>{bucket}</span>
                <div className="flex-1 h-3 rounded-full overflow-hidden" style={{ backgroundColor: COLORS.borderLight }}>
                  <div className="h-full rounded-full transition-all duration-500" style={{
                    width: `${Math.max((count / ageTotal) * 100, 2)}%`,
                    backgroundColor: AGE_COLORS[bucket] || COLORS.textMuted,
                  }} />
                </div>
                <span className="text-[11px] w-7 font-bold" style={{ color: COLORS.textPrimary }}>{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Auth Method Breakdown */}
        <div>
          <div className="text-[11px] uppercase tracking-wider mb-2" style={{ color: COLORS.textMuted }}>Auth Method Breakdown</div>
          <div className="space-y-1.5">
            {Object.entries(methods).map(([method, count]) => (
              <div key={method} className="flex items-center gap-2">
                <span className="text-[11px] w-14 text-right font-medium capitalize" style={{ color: COLORS.textSecondary }}>{method}</span>
                <div className="flex-1 h-3 rounded-full overflow-hidden" style={{ backgroundColor: COLORS.borderLight }}>
                  <div className="h-full rounded-full transition-all duration-500" style={{
                    width: `${Math.max((count / methodTotal) * 100, 2)}%`,
                    backgroundColor: METHOD_COLORS[method] || COLORS.textMuted,
                  }} />
                </div>
                <span className="text-[11px] w-7 font-bold" style={{ color: COLORS.textPrimary }}>{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Rotation Compliance */}
        <div>
          <div className="text-[11px] uppercase tracking-wider mb-2" style={{ color: COLORS.textMuted }}>Rotation Compliance</div>
          <div className="flex items-center gap-3 mb-3">
            <div className="text-3xl font-extrabold" style={{
              color: compliancePct >= 80 ? RISK_COLORS.low.color
                : compliancePct >= 50 ? RISK_COLORS.medium.color
                : RISK_COLORS.critical.color
            }}>
              {compliancePct}%
            </div>
            <div className="text-[11px]" style={{ color: COLORS.textSecondary }}>
              {rot.compliant} of {rot.total_with_creds}<br />identities compliant
            </div>
          </div>
          <div className="space-y-1">
            <Stat label="Rotation Overdue" value={rot.overdue} color={rot.overdue > 0 ? RISK_COLORS.critical.color : COLORS.textMuted} />
            <Stat label="Due Within 30d" value={rot.due_soon} color={rot.due_soon > 0 ? RISK_COLORS.high.color : COLORS.textMuted} />
            <Stat label="Stale Passwords" value={rot.stale_passwords} color={rot.stale_passwords > 0 ? RISK_COLORS.high.color : COLORS.textMuted} />
            <Stat label="Multi-Active Secrets" value={rot.multi_active_secrets} color={rot.multi_active_secrets > 0 ? RISK_COLORS.medium.color : COLORS.textMuted} />
          </div>
        </div>
      </div>
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="flex items-center justify-between">
      <span className="text-[11px]" style={{ color: COLORS.textSecondary }}>{label}</span>
      <span className="text-[12px] font-bold" style={{ color }}>{value}</span>
    </div>
  );
}
