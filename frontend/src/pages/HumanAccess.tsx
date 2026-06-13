/**
 * AG-IA-P1 (2026-06-10) — Human Access page.
 *
 * Dedicated surface for the Human bucket. Answers the SailPoint-killer
 * question: "Who has what, who can sign in, who is over-privileged?"
 *
 * Pulls only `human_user` + `guest` identities and renders KPI cards
 * for MFA coverage, privileged count, stale, guests, ungoverned.
 *
 * Visual language deliberately mirrors AIAccess so the three Identity
 * buckets feel like peer surfaces, not a tier ladder.
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import LoadingState from '../components/LoadingState';
import { NoDataInScopeState } from '../components/EmptyState';

interface HumanRow {
  id: number;
  display_name: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  status: string;
  cloud_provider: string;
  mfa_status?: string | null;
  last_seen_at?: string | null;
}

interface HumanAccessData {
  total: number;
  members: number;
  guests: number;
  privileged: number;
  noMfa: number;
  unknownMfa: number;
  stale: number;
  critical: number;
  high: number;
  topRoles: Array<{ role_name: string; count: number }>;
  topPrivileged: HumanRow[];
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

function riskColor(score: number): string {
  if (score >= 75) return 'text-red-400';
  if (score >= 50) return 'text-orange-400';
  if (score >= 25) return 'text-yellow-400';
  return 'text-green-400';
}

export default function HumanAccess() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [data, setData] = useState<HumanAccessData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      fetch(withConnection('/api/identities?identity_category=human_user,guest&limit=500'))
        .then(r => r.ok ? r.json() : null),
    ])
      .then(([list]) => {
        if (cancelled) return;
        if (!list || !Array.isArray(list.identities)) {
          setError('no_data');
          return;
        }
        const rows: HumanRow[] = list.identities;
        const total = rows.length;
        const members = rows.filter(r => r.identity_category === 'human_user').length;
        const guests = rows.filter(r => r.identity_category === 'guest').length;
        const privileged = rows.filter(r => (r.risk_score || 0) >= 70).length;
        const critical = rows.filter(r => r.risk_level === 'critical').length;
        const high = rows.filter(r => r.risk_level === 'high').length;
        const noMfa = rows.filter(r => (r.mfa_status || '').toLowerCase() === 'disabled').length;
        const unknownMfa = rows.filter(r => !r.mfa_status || r.mfa_status === 'unknown').length;
        const now = Date.now();
        const stale = rows.filter(r => {
          if (!r.last_seen_at) return false;
          const t = new Date(r.last_seen_at).getTime();
          return Number.isFinite(t) && (now - t) > 90 * 24 * 60 * 60 * 1000;
        }).length;

        const topPrivileged = [...rows]
          .sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
          .slice(0, 8);

        setData({
          total,
          members,
          guests,
          privileged,
          noMfa,
          unknownMfa,
          stale,
          critical,
          high,
          topRoles: [],
          topPrivileged,
        });
      })
      .catch(() => { if (!cancelled) setError('fetch_error'); })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const cards = useMemo(() => {
    if (!data) return [];
    return [
      {
        key: 'mfa_disabled',
        label: 'MFA Disabled',
        count: data.noMfa,
        tone: pctTone(data.noMfa, data.total, 0, 5),
        prompt: data.noMfa > 0 ? 'Force MFA on every human account — the #1 prevention against credential phishing.' : 'Every human has MFA — keep it that way.',
        navigateTo: '/identity-explorer/humans?mfa=disabled',
      },
      {
        key: 'mfa_unknown',
        label: 'Unknown MFA',
        count: data.unknownMfa,
        tone: pctTone(data.unknownMfa, data.total, 20, 60),
        prompt: 'Entra P2 licence required to see MFA state. Without it, we cannot prove coverage.',
        navigateTo: '/identity-explorer/humans?mfa=unknown',
      },
      {
        key: 'privileged',
        label: 'Highly Privileged',
        count: data.privileged,
        tone: pctTone(data.privileged, data.total, 5, 15),
        prompt: 'Each human with risk ≥70 should be PIM-eligible, not standing access.',
        navigateTo: '/identity-explorer/humans?risk_level=critical,high',
      },
      {
        key: 'stale',
        label: 'Stale > 90 days',
        count: data.stale,
        tone: pctTone(data.stale, data.total, 5, 20),
        prompt: 'Humans without sign-in for 90+ days should be disabled or re-certified.',
        navigateTo: '/identity-explorer/humans?status=stale',
      },
      {
        key: 'guests',
        label: 'Guest Accounts',
        count: data.guests,
        tone: pctTone(data.guests, data.total, 10, 25),
        prompt: 'Guests should have time-bound access and quarterly re-cert.',
        navigateTo: '/identity-explorer/humans?identity_category=guest',
      },
      {
        key: 'critical',
        label: 'Critical Risk',
        count: data.critical,
        tone: data.critical > 0 ? 'concerning' as const : 'healthy' as const,
        prompt: data.critical > 0 ? 'Open the Critical filter and triage before next audit cycle.' : 'No human at critical risk today.',
        navigateTo: '/identity-explorer/humans?risk_level=critical',
      },
    ];
  }, [data]);

  if (loading) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <LoadingState message="Loading human identity access posture..." />
      </div>
    );
  }

  if (error || !data || data.total === 0) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto space-y-4">
        <div className="px-1">
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>Human Access</h1>
          <p className="text-xs mt-0.5" style={{ color: 'var(--text-secondary)' }}>
            Sign-in, MFA, privilege, and lifecycle posture for every human in your tenant.
          </p>
        </div>
        <NoDataInScopeState
          title="No human identities in scope"
          subjects="human identities"
        />
      </div>
    );
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: 'var(--accent-primary)' }}>Identity</span>
          <span>·</span>
          <span>Human</span>
          <span>·</span>
          <span>Access</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>Human Access</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Sign-in, MFA, privilege, and lifecycle posture for{' '}
          <strong style={{ color: 'var(--text-primary)' }}>{data.total}</strong>{' '}
          human {data.total === 1 ? 'identity' : 'identities'} in your tenant
          {' '}({data.members} member{data.members === 1 ? '' : 's'}, {data.guests} guest{data.guests === 1 ? '' : 's'}).
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
            <span>AuditGraph discovered <strong>{data.total}</strong> human {data.total === 1 ? 'identity' : 'identities'} ({data.members} member{data.members === 1 ? '' : 's'}, {data.guests} guest{data.guests === 1 ? '' : 's'}) with direct or PIM-eligible Azure access.</span>
          </li>
          {data.privileged > 0 && (
            <li className="flex gap-2.5 text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
              <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2" style={{ backgroundColor: '#fbbf24' }} />
              <span><strong>{data.privileged}</strong> highly privileged humans (risk ≥70) — Entra Conditional Access + PIM-eligible access is the industry guidance.</span>
            </li>
          )}
          {data.unknownMfa > 0 && (
            <li className="flex gap-2.5 text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
              <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2" style={{ backgroundColor: '#fbbf24' }} />
              <span>MFA state is <strong>unknown</strong> for {data.unknownMfa} of {data.total} humans — typically because Entra P2 isn't licensed. AuditGraph cannot prove MFA coverage without it.</span>
            </li>
          )}
          {data.stale > 0 && (
            <li className="flex gap-2.5 text-sm leading-relaxed" style={{ color: 'var(--text-primary)' }}>
              <span className="flex-shrink-0 w-1 h-1 rounded-full mt-2" style={{ backgroundColor: '#f87171' }} />
              <span><strong>{data.stale}</strong> humans haven't signed in for 90+ days — candidates for offboarding or re-certification.</span>
            </li>
          )}
        </ul>
      </div>

      {/* KPI cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {cards.map(card => {
          const style = TONE_STYLE[card.tone];
          const pct = data.total > 0 ? Math.round((card.count / data.total) * 100) : 0;
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
                  {pct}% of humans{clickable ? ' · click to view' : ''}
                </p>
              </div>
              <p className="text-[10px] mt-3 leading-snug" style={{ color: 'var(--text-secondary)' }}>
                {card.prompt}
              </p>
            </button>
          );
        })}
      </div>

      {/* Top privileged */}
      <div className="rounded-xl border"
        style={{ backgroundColor: 'var(--bg-raised)', borderColor: 'var(--border-default)' }}>
        <div className="px-4 py-3 border-b" style={{ borderColor: 'var(--border-subtle)' }}>
          <h3 className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Top Privileged Humans</h3>
          <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
            Highest risk score · click to investigate · industry guidance: every human ≥70 should be PIM-eligible
          </p>
        </div>
        <div className="p-4 space-y-1">
          {data.topPrivileged.map((u, i) => (
            <button
              key={i}
              onClick={() => navigate(`/identities/${u.id}`)}
              className="w-full flex items-center justify-between text-xs rounded-lg px-3 py-2 hover:bg-slate-800/40 transition-colors text-left"
            >
              <div className="flex items-center gap-2 min-w-0">
                <span className="text-[9px] font-bold uppercase px-1.5 py-0.5 rounded flex-shrink-0"
                  style={{
                    backgroundColor: u.identity_category === 'guest' ? 'rgba(245, 158, 11, 0.10)' : 'rgba(99, 102, 241, 0.10)',
                    color: u.identity_category === 'guest' ? '#fbbf24' : '#a5b4fc',
                    border: `1px solid ${u.identity_category === 'guest' ? 'rgba(245, 158, 11, 0.35)' : 'rgba(99, 102, 241, 0.35)'}`,
                  }}
                >
                  {u.identity_category === 'guest' ? 'GUEST' : 'MEMBER'}
                </span>
                <span className="truncate" style={{ color: 'var(--text-secondary)' }}>{u.display_name}</span>
              </div>
              <span className={`font-mono font-bold ${riskColor(u.risk_score || 0)}`}>{u.risk_score || 0}</span>
            </button>
          ))}
          {data.topPrivileged.length === 0 && (
            <p className="text-xs py-4 text-center" style={{ color: 'var(--accent-success, #10b981)' }}>
              ✓ No privileged humans flagged
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
