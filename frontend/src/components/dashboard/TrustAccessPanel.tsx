import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS, RISK_COLORS } from '../../constants/design';
import { useConnection } from '../../contexts/ConnectionContext';

interface ExternalSummary {
  total_identities: number;
  guests: number;
  federated: number;
  guests_with_roles: number;
  guest_admins: number;
  multi_tenant_apps: number;
  cross_tenant: number;
}

interface OrgEntry {
  org_id: string;
  identity_count: number;
  high_risk_count: number;
}

interface GuestEntry {
  identity_id: string;
  display_name: string;
  risk_level: string;
  risk_score: number;
  activity_status: string;
  org_id: string | null;
}

interface TrustData {
  external_summary: ExternalSummary;
  top_organizations: OrgEntry[];
  top_risk_guests: GuestEntry[];
}

const RISK_BADGE: Record<string, { bg: string; text: string }> = {
  critical: { bg: RISK_COLORS.critical.bg, text: RISK_COLORS.critical.color },
  high: { bg: RISK_COLORS.high.bg, text: RISK_COLORS.high.color },
  medium: { bg: RISK_COLORS.medium.bg, text: RISK_COLORS.medium.color },
  low: { bg: RISK_COLORS.low.bg, text: RISK_COLORS.low.color },
};

export default function TrustAccessPanel() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<TrustData | null>(null);
  const [resourceStats, setResourceStats] = useState<{ storage_accounts?: number; key_vaults?: number; total_high_risk?: number } | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.all([
      fetch(withConnection('/api/dashboard/trust')).then(r => r.ok ? r.json() : null),
      fetch(withConnection('/api/resources/stats')).then(r => r.ok ? r.json() : null),
    ]).then(([trustData, resData]) => {
      setData(trustData);
      setResourceStats(resData);
      setLoading(false);
    }).catch(() => setLoading(false));
  }, [selectedConnectionId]);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-4 gap-4">
          {[1, 2, 3, 4].map(i => <div key={i} className="h-20 rounded-xl animate-pulse" style={{ backgroundColor: COLORS.borderLight }} />)}
        </div>
        <div className="h-48 rounded-xl animate-pulse" style={{ backgroundColor: COLORS.borderLight }} />
      </div>
    );
  }

  if (!data) {
    return (
      <div className="bg-white rounded-xl p-8 text-center" style={{ border: `1px solid ${COLORS.border}` }}>
        <p className="text-sm" style={{ color: COLORS.textMuted }}>No trust data available. Run a discovery scan first.</p>
      </div>
    );
  }

  const { external_summary: ext, top_organizations: orgs, top_risk_guests: guests } = data;

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <SummaryCard label="Guest Identities" value={ext.guests}
          color={ext.guests > 0 ? RISK_COLORS.medium.color : COLORS.textMuted}
          onClick={() => navigate('/identities?identity_category=guest')} />
        <SummaryCard label="Guests with Roles" value={ext.guests_with_roles}
          color={ext.guests_with_roles > 0 ? RISK_COLORS.high.color : COLORS.textMuted}
          sub={ext.guests > 0 ? `${Math.round((ext.guests_with_roles / ext.guests) * 100)}% of guests` : undefined} />
        <SummaryCard label="Guest Admins" value={ext.guest_admins}
          color={ext.guest_admins > 0 ? RISK_COLORS.critical.color : RISK_COLORS.low.color}
          sub="Entra admin roles" />
        <SummaryCard label="Multi-Tenant Apps" value={ext.multi_tenant_apps}
          color={ext.multi_tenant_apps > 0 ? RISK_COLORS.medium.color : COLORS.textMuted}
          sub="External publisher" />
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* External Organizations */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>External Organizations</div>
          {orgs.length === 0 ? (
            <p className="text-[12px]" style={{ color: COLORS.textMuted }}>No cross-tenant identities detected</p>
          ) : (
            <div className="space-y-2">
              {orgs.map(o => (
                <div key={o.org_id} className="flex items-center justify-between py-1.5 border-b" style={{ borderColor: COLORS.borderLight }}>
                  <div>
                    <div className="text-[12px] font-medium" style={{ color: COLORS.textPrimary }}>
                      {o.org_id.length > 24 ? `${o.org_id.slice(0, 8)}...${o.org_id.slice(-8)}` : o.org_id}
                    </div>
                    <div className="text-[10px]" style={{ color: COLORS.textMuted }}>{o.identity_count} identities</div>
                  </div>
                  {o.high_risk_count > 0 && (
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold" style={{
                      color: RISK_COLORS.critical.color, backgroundColor: RISK_COLORS.critical.bg
                    }}>{o.high_risk_count} high risk</span>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Top Risk Guests */}
        <div className="bg-white rounded-xl p-5" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[14px] font-bold mb-3" style={{ color: COLORS.textPrimary }}>Highest Risk Guest Identities</div>
          {guests.length === 0 ? (
            <p className="text-[12px]" style={{ color: COLORS.textMuted }}>No guest identities found</p>
          ) : (
            <div className="space-y-2">
              {guests.slice(0, 6).map(g => {
                const badge = RISK_BADGE[g.risk_level] || RISK_BADGE.low;
                return (
                  <div key={g.identity_id}
                    className="flex items-center justify-between py-1.5 border-b cursor-pointer hover:bg-gray-50 -mx-2 px-2 rounded transition"
                    style={{ borderColor: COLORS.borderLight }}
                    onClick={() => navigate(`/identities/${encodeURIComponent(g.identity_id)}`)}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="text-[12px] font-medium truncate" style={{ color: COLORS.textPrimary }}>{g.display_name}</div>
                      <div className="text-[10px]" style={{ color: COLORS.textMuted }}>
                        {g.activity_status}{g.org_id ? ` · ${g.org_id.slice(0, 8)}...` : ''}
                      </div>
                    </div>
                    <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase ml-2" style={{
                      color: badge.text, backgroundColor: badge.bg
                    }}>{g.risk_level}</span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      {/* Additional metrics row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-white rounded-xl p-4" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Federated Identities</div>
          <div className="text-2xl font-extrabold" style={{ color: ext.federated > 0 ? RISK_COLORS.medium.color : COLORS.textMuted }}>{ext.federated}</div>
          <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>External IdP trust</div>
        </div>
        <div className="bg-white rounded-xl p-4" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Cross-Tenant</div>
          <div className="text-2xl font-extrabold" style={{ color: ext.cross_tenant > 0 ? RISK_COLORS.medium.color : COLORS.textMuted }}>{ext.cross_tenant}</div>
          <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>Identities from external orgs</div>
        </div>
        <div className="bg-white rounded-xl p-4" style={{ border: `1px solid ${COLORS.border}` }}>
          <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>External Exposure</div>
          <div className="text-2xl font-extrabold" style={{
            color: (ext.guest_admins + ext.multi_tenant_apps) > 0 ? RISK_COLORS.high.color : RISK_COLORS.low.color
          }}>{ext.guest_admins + ext.multi_tenant_apps}</div>
          <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>Guest admins + multi-tenant apps</div>
        </div>
        <div className="bg-white rounded-xl p-4 cursor-pointer hover:shadow-md transition" style={{ border: `1px solid ${COLORS.border}` }}
          onClick={() => navigate('/resources')}>
          <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>Monitored Resources</div>
          <div className="text-2xl font-extrabold" style={{ color: COLORS.brandLight }}>
            {(resourceStats?.storage_accounts ?? 0) + (resourceStats?.key_vaults ?? 0)}
          </div>
          <div className="text-[10px]" style={{ color: COLORS.textSecondary }}>
            {resourceStats?.storage_accounts ?? 0} storage · {resourceStats?.key_vaults ?? 0} key vaults
          </div>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({ label, value, color, sub, onClick }: {
  label: string; value: number; color: string; sub?: string; onClick?: () => void;
}) {
  return (
    <div
      className={`bg-white rounded-xl p-4 ${onClick ? 'cursor-pointer hover:shadow-md' : ''} transition`}
      style={{ border: `1px solid ${COLORS.border}` }}
      onClick={onClick}
    >
      <div className="text-[11px] uppercase tracking-wider mb-1" style={{ color: COLORS.textMuted }}>{label}</div>
      <div className="text-2xl font-extrabold" style={{ color }}>{value}</div>
      {sub && <div className="text-[10px] mt-0.5" style={{ color: COLORS.textSecondary }}>{sub}</div>}
    </div>
  );
}
