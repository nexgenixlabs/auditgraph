/**
 * AG-IA-P1 (2026-06-10) — NHI Access page.
 *
 * Dedicated surface for the Non-Human bucket. Answers the Astrix-killer
 * question: "What does each service principal, managed identity, and CI/CD
 * identity touch — and which of them are credential time-bombs?"
 *
 * Pulls /api/spns/stats which already aggregates NHI exposure intel
 * (credential posture, blast radius, exposure score). Visual language
 * matches AIAccess + HumanAccess so the three buckets feel like peers.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import LoadingState from '../components/LoadingState';
import { NoDataInScopeState } from '../components/EmptyState';

interface SpnStats {
  total: number;
  custom: number;
  microsoft: number;
  critical: number;
  high_risk: number;
  expired_credentials: number;
  expiring_soon: number;
  by_category: Record<string, number>;
  by_risk: Record<string, number>;
  by_activity: Record<string, number>;
  by_blast_radius: Record<string, number>;
  exposure_critical: number;
  can_escalate_count: number;
  orphaned_privileged: number;
  blind_count?: number;
  cross_sub_count?: number;
  avg_exposure_score?: number;
}

const TONE_STYLE = {
  healthy:    { bg: 'rgba(34, 197, 94, 0.10)',  border: 'rgba(34, 197, 94, 0.35)',  text: '#4ade80', label: 'Healthy' },
  borderline: { bg: 'rgba(245, 158, 11, 0.10)', border: 'rgba(245, 158, 11, 0.35)', text: '#fbbf24', label: 'Borderline' },
  concerning: { bg: 'rgba(239, 68, 68, 0.10)',  border: 'rgba(239, 68, 68, 0.35)',  text: '#f87171', label: 'Concerning' },
  unknown:    { bg: 'rgba(107, 114, 128, 0.10)',border: 'rgba(107, 114, 128, 0.30)',text: '#9ca3af', label: 'Unknown' },
} as const;

type Tone = keyof typeof TONE_STYLE;

function pctTone(value: number, total: number, healthyMax: number, borderlineMax: number): Tone {
  if (total === 0) return 'unknown';
  const pct = (value / total) * 100;
  if (pct <= healthyMax) return 'healthy';
  if (pct <= borderlineMax) return 'borderline';
  return 'concerning';
}

export default function NHIAccess() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [stats, setStats] = useState<SpnStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    fetch(withConnection('/api/spns/stats'))
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (cancelled) return;
        if (!d) { setError('fetch_error'); return; }
        setStats(d);
      })
      .catch(() => { if (!cancelled) setError('fetch_error'); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const cards = useMemo(() => {
    if (!stats) return [];
    const total = stats.custom || 0;
    return [
      {
        key: 'expired_creds',
        label: 'Expired Secrets',
        count: stats.expired_credentials || 0,
        tone: pctTone(stats.expired_credentials || 0, total, 0, 5) as Tone,
        prompt: 'Expired client secrets on active service principals → either rotate or revoke. Either way, leaving them is a posture finding.',
        navigateTo: '/spns?credential_filter=expired',
      },
      {
        key: 'expiring_soon',
        label: 'Expiring < 30d',
        count: stats.expiring_soon || 0,
        tone: pctTone(stats.expiring_soon || 0, total, 5, 15) as Tone,
        prompt: 'Rotate before expiry to prevent downtime — set up Key Vault rotation triggers.',
        navigateTo: '/spns?credential_filter=expiring_soon',
      },
      {
        key: 'high_blast',
        label: 'High Blast Radius',
        count: (stats.by_blast_radius?.['high'] || 0) + (stats.by_blast_radius?.['critical'] || 0),
        tone: pctTone((stats.by_blast_radius?.['high'] || 0) + (stats.by_blast_radius?.['critical'] || 0), total, 5, 15) as Tone,
        prompt: 'NHIs with high or critical blast radius — single compromised credential cascades wide.',
        navigateTo: '/spns?blast_radius=high,critical',
      },
      {
        key: 'critical_risk',
        label: 'Critical Risk',
        count: stats.critical || 0,
        tone: stats.critical > 0 ? 'concerning' as const : 'healthy' as const,
        prompt: stats.critical > 0 ? 'Triage critical NHIs before next audit cycle — each one is a graphless attack path waiting to be drawn.' : 'No NHIs at critical risk today.',
        navigateTo: '/spns?risk_level=critical',
      },
      {
        key: 'can_escalate',
        label: 'Can Escalate',
        count: stats.can_escalate_count || 0,
        tone: pctTone(stats.can_escalate_count || 0, total, 0, 10) as Tone,
        prompt: 'NHIs holding role-assignment-write permissions — they can grant themselves more access.',
        navigateTo: '/attack-paths?source_type=nhi',
      },
      {
        key: 'orphaned',
        label: 'Orphaned · Privileged',
        count: stats.orphaned_privileged || 0,
        tone: stats.orphaned_privileged > 0 ? 'concerning' as const : 'healthy' as const,
        prompt: stats.orphaned_privileged > 0 ? 'No owner, privileged access — the #1 breach precursor in the NHI category.' : 'Every privileged NHI has a tracked owner.',
        navigateTo: '/ownership?type=nhi',
      },
    ];
  }, [stats]);

  if (loading) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <LoadingState message="Loading non-human identity access posture..." />
      </div>
    );
  }

  if (error || !stats || stats.custom === 0) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto space-y-4">
        <div className="px-1">
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Non-Human Identity Access</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            Role assignments, secrets posture, blast radius for every service principal,
            managed identity, and CI/CD identity in your tenant.
          </p>
        </div>
        <NoDataInScopeState
          title="No non-human identities in scope"
          subjects="non-human identities"
        />
      </div>
    );
  }

  const total = stats.custom || 0;
  const spnCount = stats.by_category?.['service_principal'] || 0;
  const miSysCount = stats.by_category?.['managed_identity_system'] || 0;
  const miUserCount = stats.by_category?.['managed_identity_user'] || 0;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: '#fb923c' }}>Identity</span>
          <span>·</span>
          <span>Non-Human</span>
          <span>·</span>
          <span>Access</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>Non-Human Identity Access</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Role assignments, secrets posture, and blast radius for{' '}
          <strong style={{ color: 'var(--text-primary)' }}>{total}</strong>{' '}
          non-human {total === 1 ? 'identity' : 'identities'}
          {' '}({spnCount} service principals, {miSysCount} system MIs, {miUserCount} user MIs).
        </p>
      </div>

      {/* Findings */}
      <div className="rounded-xl border p-5"
        style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-raised)' }}>
        <h2 className="text-xs font-semibold uppercase tracking-wider mb-3"
          style={{ color: 'var(--text-tertiary)' }}>
          Findings
        </h2>
        <ul className="space-y-2">
          <li className="flex gap-2.5 text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
            <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2" style={{ backgroundColor: '#24A2A1' }} />
            <span>AuditGraph discovered <strong>{total}</strong> non-human identities in your tenant — {spnCount} SPN{spnCount === 1 ? '' : 's'}, {miSysCount + miUserCount} managed {miSysCount + miUserCount === 1 ? 'identity' : 'identities'}.</span>
          </li>
          {stats.expired_credentials > 0 && (
            <li className="flex gap-2.5 text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
              <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2" style={{ backgroundColor: '#f87171' }} />
              <span><strong>{stats.expired_credentials}</strong> NHIs hold expired client secrets — they are credential time-bombs. Rotate or revoke.</span>
            </li>
          )}
          {stats.can_escalate_count > 0 && (
            <li className="flex gap-2.5 text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
              <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2" style={{ backgroundColor: '#fbbf24' }} />
              <span><strong>{stats.can_escalate_count}</strong> NHIs can grant themselves additional access (role-assignment-write). Open Attack Paths to see chains.</span>
            </li>
          )}
          {stats.orphaned_privileged > 0 && (
            <li className="flex gap-2.5 text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
              <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2" style={{ backgroundColor: '#f87171' }} />
              <span><strong>{stats.orphaned_privileged}</strong> privileged NHIs have no human owner — when an incident happens, there is nobody to call.</span>
            </li>
          )}
        </ul>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {cards.map(card => {
          const style = TONE_STYLE[card.tone];
          const pct = total > 0 ? Math.round((card.count / total) * 100) : 0;
          const clickable = card.count > 0;
          return (
            <button
              key={card.key}
              onClick={() => clickable && navigate(card.navigateTo)}
              disabled={!clickable}
              className={`rounded-xl border p-4 flex flex-col justify-between min-h-[148px] text-left transition ${clickable ? 'hover:scale-[1.02] cursor-pointer' : 'cursor-default opacity-80'}`}
              style={{ backgroundColor: style.bg, borderColor: style.border }}
            >
              <div>
                <div className="flex items-start justify-between gap-1.5">
                  <p className="text-[10px] uppercase tracking-wider font-semibold"
                    style={{ color: 'var(--text-tertiary)' }}>{card.label}</p>
                  <span
                    className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded"
                    style={{ backgroundColor: style.bg, color: style.text, border: `1px solid ${style.border}` }}
                  >
                    {style.label}
                  </span>
                </div>
                <p className="text-3xl font-bold font-mono mt-2" style={{ color: style.text }}>{card.count}</p>
                <p className="text-[10px] mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                  {pct}% of NHIs{clickable ? ' · click to view' : ''}
                </p>
              </div>
              <p className="text-[10px] mt-3 leading-snug" style={{ color: 'var(--text-secondary)' }}>
                {card.prompt}
              </p>
            </button>
          );
        })}
      </div>

      {/* Risk distribution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="rounded-xl border"
          style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Risk Distribution</h3>
            <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
              Non-human identities by risk level · click to drill in
            </p>
          </div>
          <div className="p-4 space-y-1">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map(level => {
              const count = stats.by_risk?.[level] || 0;
              const max = Math.max(...Object.values(stats.by_risk || {}), 1);
              const color = level === 'critical' ? '#f87171' : level === 'high' ? '#fb923c' : level === 'medium' ? '#fbbf24' : '#4ade80';
              if (count === 0) return null;
              return (
                <button
                  key={level}
                  onClick={() => navigate(`/spns?risk_level=${level}`)}
                  className="w-full flex items-center justify-between text-xs rounded px-2 py-1.5 hover:bg-slate-800/40 transition-colors text-left group"
                >
                  <span className="uppercase font-semibold" style={{ color }}>{level}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-32 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full" style={{ backgroundColor: color, opacity: 0.6, width: `${(count / max) * 100}%` }} />
                    </div>
                    <span className="font-mono w-6 text-right" style={{ color: 'var(--text-secondary)' }}>{count}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        <div className="rounded-xl border"
          style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
          <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
            <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Activity Status</h3>
            <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
              Non-human identities by activity classification — stale + never-used are dead weight
            </p>
          </div>
          <div className="p-4 space-y-1">
            {Object.entries(stats.by_activity || {}).map(([status, count]) => {
              const max = Math.max(...Object.values(stats.by_activity || {}), 1);
              const color = status === 'active' ? '#4ade80' : status === 'inactive' ? '#fbbf24' : status === 'stale' ? '#fb923c' : status === 'never_used' ? '#f87171' : '#9ca3af';
              return (
                <button
                  key={status}
                  onClick={() => navigate(`/spns?activity=${status}`)}
                  className="w-full flex items-center justify-between text-xs rounded px-2 py-1.5 hover:bg-slate-800/40 transition-colors text-left group"
                >
                  <span className="capitalize font-medium" style={{ color }}>{status.replace('_', ' ')}</span>
                  <div className="flex items-center gap-2">
                    <div className="w-32 h-1.5 rounded-full bg-slate-800 overflow-hidden">
                      <div className="h-full rounded-full" style={{ backgroundColor: color, opacity: 0.6, width: `${(count / max) * 100}%` }} />
                    </div>
                    <span className="font-mono w-6 text-right" style={{ color: 'var(--text-secondary)' }}>{count}</span>
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
