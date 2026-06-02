/**
 * JmlSnapshotCard — Executive Posture intel-row tile for Joiner/Mover/Leaver.
 *
 * AG-JML Day 2: Org-level lifecycle observability on the CISO dashboard.
 * Composes existing signals (no new detection) into the joiner/mover/leaver
 * framing every auditor recognizes:
 *
 *   - Joiners: created in last 30d with critical/high risk
 *   - Movers:  open mover_stale_access anomalies
 *   - Leavers: open ghost_identity anomalies
 *
 * Positioning: CIEM-style observability, NOT IGA-style automation.
 * Tagline: "CIEM detects what your IGA misses." Click deep-links to
 * /identities filtered by created_in_last_30d / has anomaly.
 *
 * Data: live from /api/dashboard/jml-snapshot. No hardcoded values.
 * Loading / error / no-data states all render a valid card.
 */
import React, { useEffect, useState } from 'react';
import { DN } from '../dashboard/ciso-shared';

interface JmlBucket {
  count: number;
  top: Array<{
    identity_id: string;
    display_name: string | null;
    risk_level?: string;
    severity?: string;
    title?: string;
    created_at?: string | null;
    detected_at?: string | null;
  }>;
}

interface JmlResp {
  joiners: JmlBucket;
  movers: JmlBucket;
  leavers: JmlBucket;
  reason?: string;
}

export function JmlSnapshotCard() {
  const [data, setData] = useState<JmlResp | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetch('/api/dashboard/jml-snapshot')
      .then(r => {
        if (!r.ok) throw new Error('fetch_failed');
        return r.json();
      })
      .then((d: JmlResp) => { if (!cancelled) setData(d); })
      .catch(() => { if (!cancelled) setError(true); });
    return () => { cancelled = true; };
  }, []);

  const Shell = ({ children }: { children: React.ReactNode }) => (
    <DN navigateTo="/identities?lifecycle=any">
      <div className="bg-[#111827] border border-white/5 rounded-lg p-3 h-full flex flex-col overflow-hidden hover:border-white/10 hover:scale-[1.01] transition cursor-pointer">
        <span className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">
          Lifecycle (JML)
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

  const j = data.joiners?.count || 0;
  const m = data.movers?.count || 0;
  const l = data.leavers?.count || 0;
  const total = j + m + l;

  if (data.reason === 'no_completed_run') {
    return (
      <Shell>
        <p className="text-xs text-gray-400">No snapshot yet</p>
        <p className="text-xs text-gray-500 mt-auto">Run discovery →</p>
      </Shell>
    );
  }

  if (total === 0) {
    return (
      <Shell>
        <p className="text-xs font-semibold text-emerald-400">No lifecycle risk</p>
        <p className="text-xs text-gray-500 mt-auto">All joiners / movers / leavers clean</p>
      </Shell>
    );
  }

  // Rank buckets by count — most pressing surfaces first as Primary Risk.
  const rows = [
    { label: 'Joiners with privileged access', count: j, key: 'joiners', tone: '#f59e0b' },
    { label: 'Movers with stale access',       count: m, key: 'movers',  tone: '#f97316' },
    { label: 'Leavers — disabled + privileged', count: l, key: 'leavers', tone: '#ef4444' },
  ].filter(r => r.count > 0).sort((a, b) => b.count - a.count);

  const primaryTone = rows[0]?.tone || '#10b981';

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
                      style={{ color: primaryTone }}>
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
        <span className="text-gray-400 font-medium">{j}</span>J ·{' '}
        <span className="text-gray-400 font-medium">{m}</span>M ·{' '}
        <span className="text-gray-400 font-medium">{l}</span>L lifecycle events
      </p>
    </Shell>
  );
}

export default JmlSnapshotCard;
