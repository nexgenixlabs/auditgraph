import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';

/**
 * AG-86: Shadow Apps page.
 * Lists every identity flagged as outside the approved registry, with the
 * per-identity reasons surfaced inline. Admin can one-click approve.
 */
interface ShadowApp {
  identity_id: string;
  display_name: string;
  publisher_name: string | null;
  verified_publisher: boolean | null;
  created_datetime: string | null;
  risk_level: string;
  risk_score: number;
  reasons: string[];
  ai_platform: string | null;
}

interface ShadowResp {
  shadow_apps: ShadowApp[];
  total: number;
}

interface ApprovedApp {
  id: number;
  app_id: string | null;
  display_name: string | null;
  publisher_name: string | null;
  app_category: string;
  match_kind: string;
  notes: string | null;
  is_seeded: boolean;
  added_by_user_id: number | null;
  created_at: string | null;
}

interface ApprovedResp {
  approved_apps: ApprovedApp[];
  total: number;
}

export default function ShadowApps() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<'shadow' | 'approved'>('shadow');
  const [shadow, setShadow] = useState<ShadowResp | null>(null);
  const [approved, setApproved] = useState<ApprovedResp | null>(null);
  const [loading, setLoading] = useState(true);
  const [busyId, setBusyId] = useState<string | null>(null);

  const reload = () => {
    setLoading(true);
    Promise.all([
      fetch('/api/shadow-apps').then(r => r.ok ? r.json() : null),
      fetch('/api/approved-apps').then(r => r.ok ? r.json() : null),
    ]).then(([s, a]) => {
      setShadow(s);
      setApproved(a);
    }).finally(() => setLoading(false));
  };

  useEffect(reload, []);

  const handleApprove = async (identityId: string) => {
    setBusyId(identityId);
    try {
      const resp = await fetch(`/api/shadow-apps/${encodeURIComponent(identityId)}/approve`, {
        method: 'POST',
      });
      if (resp.ok) reload();
    } finally {
      setBusyId(null);
    }
  };

  const handleRemoveApproved = async (id: number) => {
    if (!window.confirm('Remove this app from the approved registry? It may flag as Shadow again on the next discovery.')) return;
    const resp = await fetch(`/api/approved-apps/${id}`, { method: 'DELETE' });
    if (resp.ok) reload();
  };

  return (
    <div className="p-6 max-w-7xl mx-auto">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900">Shadow App Detection</h1>
        <p className="text-sm text-gray-600 mt-1">
          Apps in your tenant that aren't in the approved registry and match risk signatures
          (unverified publisher, AI/automation pattern, high-scope grants, recent intake).
        </p>
      </div>

      <div className="flex gap-2 border-b border-gray-200 mb-4">
        <button
          onClick={() => setTab('shadow')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
            tab === 'shadow'
              ? 'border-red-600 text-red-700'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          Shadow ({shadow?.total ?? 0})
        </button>
        <button
          onClick={() => setTab('approved')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px ${
            tab === 'approved'
              ? 'border-emerald-600 text-emerald-700'
              : 'border-transparent text-gray-500 hover:text-gray-700'
          }`}
        >
          Approved Registry ({approved?.total ?? 0})
        </button>
      </div>

      {loading && (
        <div className="bg-white rounded-xl p-6 text-sm text-gray-500">Loading…</div>
      )}

      {!loading && tab === 'shadow' && shadow && (
        <>
          {shadow.shadow_apps.length === 0 ? (
            <div className="bg-emerald-50 border border-emerald-200 rounded-xl p-6">
              <p className="text-sm text-emerald-900 font-medium">
                Nothing flagged as Shadow. Either your tenant is clean or no discovery has run yet.
              </p>
              <p className="text-xs text-emerald-700 mt-2">
                Detection signals: unverified publisher, AI/automation name pattern, high-risk Graph scopes
                (Mail/Files/Directory), creation in last 30 days. Re-run discovery to refresh.
              </p>
            </div>
          ) : (
            <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b border-gray-200">
                  <tr className="text-left text-xs uppercase tracking-wider text-gray-500">
                    <th className="px-4 py-3">App</th>
                    <th className="px-4 py-3">Publisher</th>
                    <th className="px-4 py-3">Why flagged</th>
                    <th className="px-4 py-3">Created</th>
                    <th className="px-4 py-3">Risk</th>
                    <th className="px-4 py-3 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {shadow.shadow_apps.map(a => (
                    <tr key={a.identity_id} className="hover:bg-gray-50">
                      <td className="px-4 py-3">
                        <div className="font-medium text-gray-900">{a.display_name || '—'}</div>
                        <div className="text-[10px] font-mono text-gray-400">
                          {a.identity_id.slice(0, 16)}…
                        </div>
                        {a.ai_platform && (
                          <span className="inline-flex mt-1 px-1.5 py-0.5 rounded text-[9px] font-semibold bg-violet-100 text-violet-700">
                            AI · {a.ai_platform}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <div className="text-sm text-gray-700">{a.publisher_name || <span className="text-gray-400">—</span>}</div>
                        {a.verified_publisher === true ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[9px] font-semibold bg-emerald-100 text-emerald-700 mt-1">
                            Verified
                          </span>
                        ) : a.verified_publisher === false ? (
                          <span className="inline-flex px-1.5 py-0.5 rounded text-[9px] font-semibold bg-red-100 text-red-700 mt-1">
                            Unverified
                          </span>
                        ) : null}
                      </td>
                      <td className="px-4 py-3 max-w-md">
                        <ul className="space-y-0.5">
                          {a.reasons.slice(0, 3).map((r, i) => (
                            <li key={i} className="text-[11px] text-gray-700 flex items-start gap-1">
                              <span className="text-red-500 mt-0.5">•</span>
                              <span>{r}</span>
                            </li>
                          ))}
                        </ul>
                      </td>
                      <td className="px-4 py-3 text-xs text-gray-600">
                        {a.created_datetime ? new Date(a.created_datetime).toLocaleDateString() : '—'}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          a.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                          a.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                          a.risk_level === 'medium' ? 'bg-amber-100 text-amber-700' :
                          'bg-gray-100 text-gray-700'
                        }`}>
                          {a.risk_level || 'low'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <div className="flex gap-2 justify-end">
                          <button
                            onClick={() => navigate(`/identities/${encodeURIComponent(a.identity_id)}`)}
                            className="text-xs font-medium text-blue-600 hover:text-blue-800"
                          >
                            Inspect
                          </button>
                          <button
                            onClick={() => handleApprove(a.identity_id)}
                            disabled={busyId === a.identity_id}
                            className="px-2 py-1 text-xs font-medium rounded bg-emerald-600 text-white hover:bg-emerald-700 disabled:opacity-50"
                          >
                            {busyId === a.identity_id ? '…' : 'Approve'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}

      {!loading && tab === 'approved' && approved && (
        <div className="bg-white border border-gray-200 rounded-xl overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-gray-50 border-b border-gray-200">
              <tr className="text-left text-xs uppercase tracking-wider text-gray-500">
                <th className="px-4 py-3">App</th>
                <th className="px-4 py-3">Publisher</th>
                <th className="px-4 py-3">Match Kind</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Source</th>
                <th className="px-4 py-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {approved.approved_apps.map(r => (
                <tr key={r.id} className="hover:bg-gray-50">
                  <td className="px-4 py-3">
                    <div className="font-medium text-gray-900">{r.display_name || '—'}</div>
                    {r.app_id && (
                      <div className="text-[10px] font-mono text-gray-400">{r.app_id.slice(0, 24)}…</div>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-gray-700">{r.publisher_name || '—'}</td>
                  <td className="px-4 py-3 text-xs text-gray-600">{r.match_kind}</td>
                  <td className="px-4 py-3">
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-gray-100 text-gray-700 uppercase">
                      {r.app_category}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-xs">
                    {r.is_seeded ? (
                      <span className="text-gray-500 italic">seeded</span>
                    ) : (
                      <span className="text-gray-700">admin</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-right">
                    {!r.is_seeded && (
                      <button
                        onClick={() => handleRemoveApproved(r.id)}
                        className="text-xs font-medium text-red-600 hover:text-red-800"
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {approved.approved_apps.length === 0 && (
            <div className="p-6 text-sm text-gray-500">
              No approved apps configured yet. The default Microsoft built-ins are seeded automatically when
              discovery first runs.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
