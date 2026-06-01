/**
 * ConnectedAppRiskCard — Executive Posture intel-row tile for OAuth consent grants.
 *
 * Peer to AIIdentityRiskCard. Surfaces the Vercel-breach narrative on the
 * CISO dashboard: "Who said yes to what, when, and is it still necessary?"
 *
 * Primary Risk surfaces critical-severity grants by default. Falls back
 * to "X grants over 180 days old" (the dormant-consent pattern) when
 * critical/high are zero. Click deep-links to /identities (App Registration
 * filter) — the canonical surface for connected-app investigation.
 *
 * Data: live from /api/dashboard/connected-app-risk. No hardcoded values.
 * Loading / error / no-data states all render a valid card; never crashes
 * the dashboard.
 */
import React, { useEffect, useState } from 'react';
import { DN } from '../dashboard/ciso-shared';

interface ConnectedAppRiskSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  admin_consents: number;
  user_consents: number;
  application_grants: number;
  delegated_grants: number;
  avg_age_days: number;
  over_180_days: number;
  unique_apps: number;
}

interface TopRiskyApp {
  client_app_id: string;
  display_name: string | null;
  max_risk_score: number;
  has_critical?: string | null;
  has_high?: string | null;
  grant_count: number;
  top_risky_scopes?: string[];
  oldest_grant_at?: string | null;
}

interface Resp {
  summary: ConnectedAppRiskSummary;
  top_risky_apps: TopRiskyApp[];
}

export function ConnectedAppRiskCard() {
  const [data, setData] = useState<Resp | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/dashboard/connected-app-risk')
      .then(r => {
        if (!r.ok) throw new Error('fetch_failed');
        return r.json();
      })
      .then((d: Resp) => { if (!cancelled) setData(d); })
      .catch(() => { if (!cancelled) setError(true); });
    return () => { cancelled = true; };
  }, []);

  // Shell — same container classes as the other intel-row peer cards so the
  // five tiles read as one visual system.
  const Shell = ({ children }: { children: React.ReactNode }) => (
    <DN navigateTo="/identities?identity_type=service_principal">
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition cursor-pointer">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">
          Connected App Risk
        </span>
        {children}
      </div>
    </DN>
  );

  if (!data && !error) {
    return (
      <Shell>
        <div className="space-y-1 flex-1">
          <div className="h-3 w-3/4 bg-white/[0.04] rounded animate-pulse" />
          <div className="h-3 w-2/3 bg-white/[0.04] rounded animate-pulse" />
        </div>
      </Shell>
    );
  }

  if (error || !data) {
    return (
      <Shell>
        <p className="text-xs text-gray-500 mt-auto">Data unavailable</p>
      </Shell>
    );
  }

  const s = data.summary;
  const total = s.total || 0;

  if (total === 0) {
    return (
      <Shell>
        <p className="text-xs text-gray-400">No OAuth consents discovered</p>
        <p className="text-xs text-gray-500 mt-auto">Open Identities →</p>
      </Shell>
    );
  }

  // Pick primary risk by priority: critical scopes → admin-consented → dormant
  const rows = [
    { label: 'Grants with critical scopes', count: s.critical, key: 'critical' },
    { label: 'Admin-consented grants', count: s.admin_consents, key: 'admin' },
    { label: 'Dormant — >180 days old', count: s.over_180_days, key: 'dormant' },
  ].filter(r => r.count > 0).sort((a, b) => b.count - a.count);

  if (rows.length === 0) {
    return (
      <Shell>
        <p className="text-xs font-semibold text-emerald-400">No OAuth risk</p>
        <p className="text-xs text-gray-500 mt-auto">
          {total.toLocaleString()} grant{total !== 1 ? 's' : ''} ·{' '}
          {s.unique_apps.toLocaleString()} app{s.unique_apps !== 1 ? 's' : ''}
        </p>
      </Shell>
    );
  }

  // Tone color from the highest-severity bucket present
  const toneColor =
    s.critical > 0 ? '#ef4444' :
    s.high > 0     ? '#f97316' :
    s.medium > 0   ? '#f59e0b' :
                     '#10b981';

  return (
    <Shell>
      <div className="space-y-0.5 flex-1">
        {rows.map((r, i) => (
          <div
            key={r.key}
            className={`flex items-center justify-between text-xs rounded px-1 -mx-1 ${i === 0 ? 'font-medium text-gray-200' : 'text-gray-400'}`}
          >
            <span className="truncate mr-2">
              {i === 0 && (
                <span className="text-[9px] font-semibold uppercase tracking-wider mr-1"
                      style={{ color: toneColor }}>
                  Primary Risk:
                </span>
              )}
              <span className={i === 0 ? 'text-[11px]' : ''}>{r.label}</span>
            </span>
            <span className="font-mono text-gray-300 flex-shrink-0">
              {r.count.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
      <p className="text-xs text-gray-500 mt-auto truncate">
        {s.unique_apps.toLocaleString()} app{s.unique_apps !== 1 ? 's' : ''}
        {' '}· avg age{' '}
        <span className="text-gray-400 font-medium">{s.avg_age_days}d</span>
      </p>
    </Shell>
  );
}

export default ConnectedAppRiskCard;
