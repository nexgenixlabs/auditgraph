/**
 * AIIdentityRiskCard — Executive Posture intel-row tile for AI identity risk.
 *
 * Peer to IdentityRiskCardV31 (Blast Radius / Attack Path / Identity Risk trio).
 * Surfaces the AI Security pillar at the CISO level: the differentiator metric
 * (AI agents with no human owner) is "Primary Risk" when present, with
 * critical/high-risk AI agents and AI-privileged humans as supporting context.
 *
 * Data: live from /api/ai-security/stats (single source of truth — same endpoint
 * the AI Inventory pillar uses). No hardcoded values. Loading / error / no-data
 * / no-risk states all render a valid card, never crash the dashboard.
 *
 * Click: deep-link to /ai-inventory/agents (the canonical AI Agents view).
 */
import React, { useEffect, useState } from 'react';
import { DN } from '../dashboard/ciso-shared';

interface AISecurityStats {
  total_ai_agents: number;
  total_ai_privileged_humans: number;
  risk_distribution: Record<string, number>;
  avg_risk_score: number;
  avg_risk_severity: string;
  ai_agents_no_owner: number;
}

const SEV_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#10b981',
  info: '#3b82f6',
};

export function AIIdentityRiskCard() {
  const [stats, setStats] = useState<AISecurityStats | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/ai-security/stats')
      .then(r => {
        if (!r.ok) throw new Error('fetch_failed');
        return r.json();
      })
      .then((d: AISecurityStats) => { if (!cancelled) setStats(d); })
      .catch(() => { if (!cancelled) setError(true); });
    return () => { cancelled = true; };
  }, []);

  // Shell uses identical container classes to IdentityRiskCardV31 so the four
  // intel-row tiles read as one visual system.
  const Shell = ({ children }: { children: React.ReactNode }) => (
    <DN navigateTo="/ai-inventory/agents">
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition cursor-pointer">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">AI Identity Risk</span>
        {children}
      </div>
    </DN>
  );

  // Loading — subtle skeleton, no spinner (the rest of the row finishes fast)
  if (!stats && !error) {
    return (
      <Shell>
        <div className="space-y-1 flex-1">
          <div className="h-3 w-3/4 bg-white/[0.04] rounded animate-pulse" />
          <div className="h-3 w-2/3 bg-white/[0.04] rounded animate-pulse" />
        </div>
      </Shell>
    );
  }

  // Endpoint error / feature-flagged off / network — don't break the dashboard
  if (error || !stats) {
    return (
      <Shell>
        <p className="text-xs text-gray-500 mt-auto">Data unavailable</p>
      </Shell>
    );
  }

  const total = stats.total_ai_agents || 0;
  const critHigh = (stats.risk_distribution?.critical || 0) + (stats.risk_distribution?.high || 0);
  const noOwner = stats.ai_agents_no_owner || 0;
  const privHumans = stats.total_ai_privileged_humans || 0;

  // No AI agents discovered yet — guide rather than dead-end
  if (total === 0 && privHumans === 0) {
    return (
      <Shell>
        <p className="text-xs text-gray-400">No AI agents discovered</p>
        <p className="text-xs text-gray-500 mt-auto">Open AI Inventory →</p>
      </Shell>
    );
  }

  const rows = [
    { label: 'AI agents with no human owner', count: noOwner, key: 'no_owner' },
    { label: 'AI agents at critical/high risk', count: critHigh, key: 'risk' },
    { label: 'Humans with AI-privileged access', count: privHumans, key: 'priv_humans' },
  ].filter(r => r.count > 0).sort((a, b) => b.count - a.count);

  // Inventory present, no surfaced risk — emerald clean state, mirrors IdentityRiskCardV31
  if (rows.length === 0) {
    return (
      <Shell>
        <p className="text-xs font-semibold text-emerald-400">No AI identity risk</p>
        <p className="text-xs text-gray-500 mt-auto">
          {total.toLocaleString()} AI agent{total !== 1 ? 's' : ''} monitored
        </p>
      </Shell>
    );
  }

  const sevLabel = stats.avg_risk_severity || 'info';
  const sevColor = SEV_COLOR[sevLabel] || '#6b7280';

  return (
    <Shell>
      <div className="space-y-0.5 flex-1">
        {rows.map((r, i) => (
          <div
            key={r.key}
            className={`flex items-center justify-between text-xs rounded px-1 -mx-1 ${i === 0 ? 'font-medium text-gray-200' : 'text-gray-400'}`}
          >
            <span className="truncate mr-2">
              {i === 0 && <span className="text-[9px] font-semibold uppercase tracking-wider text-[#f59e0b] mr-1">Primary Risk:</span>}
              <span className={i === 0 ? 'text-[11px]' : ''}>{r.label}</span>
            </span>
            <span className="font-mono text-gray-300 flex-shrink-0">{r.count.toLocaleString()}</span>
          </div>
        ))}
      </div>
      <p className="text-xs text-gray-500 mt-auto">
        {total.toLocaleString()} AI agent{total !== 1 ? 's' : ''}
        {total > 0 && (
          <>
            {' '}· avg risk{' '}
            <span style={{ color: sevColor }} className="font-medium">{sevLabel}</span>
          </>
        )}
      </p>
    </Shell>
  );
}

export default AIIdentityRiskCard;
