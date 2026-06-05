/**
 * Lifecycle (JML) — Joiner / Mover / Leaver narrative page.
 *
 * AG-173: dedicated drill-down for the CISO dashboard's "Lifecycle" tile.
 * Previously the tile linked to /identities?lifecycle=any which was a
 * generic table dump. This page tells the actual story:
 *
 *   Joiners — created in the last 30 days with critical/high risk on day 1.
 *             ("Onboarding a new contractor as Subscription Owner is the
 *              joiner-day-one accident every CIEM should catch.")
 *
 *   Movers  — department or title changed AND prior privileged roles still
 *             attached. ("Transferred from Sales to Finance but still has
 *             Owner on the Sales subscription.")
 *
 *   Leavers — disabled in the directory but role assignments still active.
 *             ("Ghost identity — left the company three months ago, still
 *              holds Contributor on prod.")
 *
 * Positioning: CIEM observability of lifecycle. We FLAG these patterns
 * from existing signals; we do NOT write to your directory (that's IGA).
 */
import React, { useEffect, useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';

interface JmlSample {
  identity_id: string;
  display_name: string | null;
  risk_level?: string;
  severity?: string;
  title?: string;
  created_at?: string | null;
  detected_at?: string | null;
}

interface JmlBucket {
  count: number;
  top: JmlSample[];
}

interface JmlResp {
  joiners: JmlBucket;
  movers: JmlBucket;
  leavers: JmlBucket;
  reason?: string;
}

type Bucket = 'joiners' | 'movers' | 'leavers';

const BUCKET_META: Record<Bucket, {
  label: string;
  tone: string;
  pillBg: string;
  pillText: string;
  story: string;
  what: string;
  signal: string;
  why: string;
}> = {
  joiners: {
    label: 'Joiners',
    tone: '#f59e0b',
    pillBg: 'bg-amber-50',
    pillText: 'text-amber-700',
    story: 'Onboarded in the last 30 days with critical/high risk on day one.',
    what: 'New identities (humans or non-humans) created within the last 30 days that already hold roles classified as critical or high risk by the AuditGraph scoring engine.',
    signal: 'identities.created_datetime ≤ 30d ago AND risk_level ∈ {critical, high}',
    why: 'Joiner-day-one over-permissioning is one of the most common audit findings — and one of the easiest to roll back when caught early. A contractor who lands as Subscription Owner instead of Reader is a 30-day fix window, not a Q4 audit fire.',
  },
  movers: {
    label: 'Movers',
    tone: '#f97316',
    pillBg: 'bg-orange-50',
    pillText: 'text-orange-700',
    story: 'Changed role or department in HR — but kept their old privileged access.',
    what: 'Open mover_stale_access anomalies — identities whose department or job_title changed since the prior snapshot while their prior critical/high privileged roles remain attached.',
    signal: 'anomalies.anomaly_type = mover_stale_access AND resolved = false',
    why: '"Permission creep" is the #1 driver of standing-privilege risk. The mover scenario is exactly how engineers end up with Contributor on every subscription they ever touched — IGA tools assign roles, almost none of them clean up.',
  },
  leavers: {
    label: 'Leavers',
    tone: '#ef4444',
    pillBg: 'bg-red-50',
    pillText: 'text-red-700',
    story: 'Disabled in the directory — but the role assignments are still live.',
    what: 'Open ghost_identity anomalies — identities that are disabled (enabled=false) yet still have one or more active role assignments. SailPoint-style deprovisioning often disables the user object without unwinding the roles.',
    signal: 'anomalies.anomaly_type = ghost_identity AND resolved = false',
    why: 'Disabled-but-privileged is the canonical breach precursor — a disabled account whose credentials leaked still resolves into a session if the role assignments outlive the directory state. This is the bucket auditors look at first.',
  },
};

export default function LifecycleJml() {
  const navigate = useNavigate();
  const [data, setData] = useState<JmlResp | null>(null);
  const [error, setError] = useState(false);
  const [active, setActive] = useState<Bucket>('leavers');

  useEffect(() => {
    fetch('/api/dashboard/jml-snapshot')
      .then(r => r.ok ? r.json() : Promise.reject(new Error('fetch_failed')))
      .then((d: JmlResp) => setData(d))
      .catch(() => setError(true));
  }, []);

  const totals = useMemo(() => {
    if (!data) return { j: 0, m: 0, l: 0, total: 0 };
    const j = data.joiners?.count || 0;
    const m = data.movers?.count || 0;
    const l = data.leavers?.count || 0;
    return { j, m, l, total: j + m + l };
  }, [data]);

  // Pick the leading bucket once data lands — leavers > movers > joiners
  // is the severity ordering for the executive read.
  useEffect(() => {
    if (!data) return;
    if (totals.l > 0) setActive('leavers');
    else if (totals.m > 0) setActive('movers');
    else if (totals.j > 0) setActive('joiners');
  }, [data, totals]);

  if (error) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-semibold text-gray-900 mb-2">Lifecycle Risk</h1>
        <p className="text-sm text-red-700">Unable to load lifecycle snapshot. Run a discovery and retry.</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-6 space-y-3 animate-pulse">
        <div className="h-8 w-1/3 bg-gray-100 rounded" />
        <div className="h-32 w-full bg-gray-100 rounded-xl" />
        <div className="h-64 w-full bg-gray-100 rounded-xl" />
      </div>
    );
  }

  if (data.reason === 'no_completed_run') {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-semibold text-gray-900 mb-2">Lifecycle Risk</h1>
        <p className="text-sm text-gray-600">No completed discovery run yet. Trigger a snapshot first.</p>
      </div>
    );
  }

  const activeBucket = data[active] || { count: 0, top: [] };
  const meta = BUCKET_META[active];

  return (
    <div className="p-6 space-y-6 max-w-7xl">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-medium text-gray-500 uppercase tracking-wider">
          CIEM Observability
          <span className="text-gray-300">·</span>
          <span>Lifecycle</span>
        </div>
        <h1 className="text-2xl font-semibold text-gray-900 mt-1">Joiners · Movers · Leavers</h1>
        <p className="text-sm text-gray-600 mt-2 max-w-3xl">
          AuditGraph flags the three lifecycle patterns auditors care about most — without touching your
          IGA. We <span className="font-medium">observe</span> what your directory + role assignments + HR
          fields say, then surface the identities where the lifecycle state has drifted from policy.
        </p>
      </div>

      {/* Three bucket cards */}
      <div className="grid grid-cols-3 gap-4">
        {(['joiners', 'movers', 'leavers'] as Bucket[]).map(b => {
          const bm = BUCKET_META[b];
          const count = data[b]?.count || 0;
          const isActive = active === b;
          return (
            <button
              key={b}
              onClick={() => setActive(b)}
              className={`text-left rounded-xl p-4 transition border-2 ${
                isActive
                  ? `border-current ${bm.pillBg} shadow-sm`
                  : 'border-gray-200 bg-white hover:border-gray-300'
              }`}
              style={isActive ? { color: bm.tone } : {}}
            >
              <div className="flex items-baseline justify-between">
                <span
                  className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider text-white"
                  style={{ backgroundColor: bm.tone }}
                >
                  {bm.label}
                </span>
                <span className="text-3xl font-bold text-gray-900">{count.toLocaleString()}</span>
              </div>
              <p className={`text-xs mt-3 ${isActive ? bm.pillText : 'text-gray-600'}`}>
                {bm.story}
              </p>
            </button>
          );
        })}
      </div>

      {/* Detail panel for active bucket */}
      <div className="bg-white rounded-xl border border-gray-200 overflow-hidden">
        <div className={`px-5 py-4 ${meta.pillBg} border-b border-gray-200`}>
          <div className="flex items-center gap-2">
            <span
              className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider text-white"
              style={{ backgroundColor: meta.tone }}
            >
              {meta.label}
            </span>
            <span className={`text-sm font-semibold ${meta.pillText}`}>{activeBucket.count.toLocaleString()} identities flagged</span>
          </div>
        </div>

        {/* What / Signal / Why */}
        <div className="p-5 grid grid-cols-3 gap-6 border-b border-gray-100">
          <div>
            <div className="text-xs uppercase tracking-wider font-medium text-gray-500 mb-2">What we count</div>
            <p className="text-sm text-gray-700">{meta.what}</p>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider font-medium text-gray-500 mb-2">Signal</div>
            <code className="text-xs text-gray-700 font-mono bg-gray-50 px-2 py-1 rounded block whitespace-pre-wrap">
              {meta.signal}
            </code>
          </div>
          <div>
            <div className="text-xs uppercase tracking-wider font-medium text-gray-500 mb-2">Why it matters</div>
            <p className="text-sm text-gray-700">{meta.why}</p>
          </div>
        </div>

        {/* Top identities table */}
        <div className="p-5">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-gray-900">
              Top {Math.min(activeBucket.top.length, 5)} of {activeBucket.count.toLocaleString()}
            </h3>
            {activeBucket.count > activeBucket.top.length && (
              <button
                onClick={() => navigate(
                  active === 'joiners'
                    ? '/identities?lifecycle=joiner'
                    : active === 'movers'
                      ? '/anomalies?type=mover_stale_access&resolved=false'
                      : '/anomalies?type=ghost_identity&resolved=false'
                )}
                className="text-xs font-medium text-blue-600 hover:text-blue-800"
              >
                View all {activeBucket.count.toLocaleString()} →
              </button>
            )}
          </div>

          {activeBucket.top.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-sm text-emerald-700 font-medium">No {meta.label.toLowerCase()} flagged.</p>
              <p className="text-xs text-gray-500 mt-1">Either the bucket is genuinely clean, or the upstream signal hasn't been collected yet.</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs text-gray-500 uppercase tracking-wider border-b border-gray-200">
                  <tr>
                    <th className="text-left py-2 pr-4">Identity</th>
                    <th className="text-left py-2 pr-4">Signal</th>
                    <th className="text-left py-2 pr-4">When</th>
                    <th className="py-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {activeBucket.top.map(item => (
                    <tr key={item.identity_id} className="hover:bg-gray-50">
                      <td className="py-3 pr-4">
                        <button
                          onClick={() => navigate(`/identities/${encodeURIComponent(item.identity_id)}`)}
                          className="font-medium text-gray-900 hover:text-blue-700 text-left"
                        >
                          {item.display_name || item.identity_id}
                        </button>
                      </td>
                      <td className="py-3 pr-4 text-gray-600">
                        {item.title || (item.risk_level
                          ? <span className="inline-block px-1.5 py-0.5 rounded text-xs font-medium bg-red-50 text-red-700">
                              {item.risk_level} on day 1
                            </span>
                          : '—')}
                      </td>
                      <td className="py-3 pr-4 text-gray-500 text-xs">
                        {item.detected_at || item.created_at
                          ? new Date(item.detected_at || item.created_at!).toLocaleString()
                          : '—'}
                      </td>
                      <td className="py-3 text-right">
                        <button
                          onClick={() => navigate(`/identities/${encodeURIComponent(item.identity_id)}`)}
                          className="text-xs font-medium text-blue-600 hover:text-blue-800"
                        >
                          Investigate →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>

      {/* Positioning footer */}
      <div className="rounded-xl border border-blue-200 bg-blue-50 p-4 flex items-start gap-3">
        <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider bg-blue-600 text-white flex-shrink-0">
          CIEM, not IGA
        </span>
        <p className="text-xs text-blue-900">
          AuditGraph flags lifecycle drift from observed state — we don't write to your directory.
          Pair us with SailPoint, Saviynt, or your in-house IGA: they handle provisioning, we tell you
          when their state is wrong.
        </p>
      </div>
    </div>
  );
}
