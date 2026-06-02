/**
 * Connected Apps — OAuth Consent Grant story page.
 *
 * AG-85 follow-on: dedicated drill-down for the CISO dashboard's
 * "Connected App Risk" tile. Previously the tile linked to
 * /identities?identity_type=service_principal — a generic SP dump.
 *
 * This page tells the Vercel / Context.ai breach story:
 *   "Who said yes to what, when, and is it still necessary?"
 *
 * Surfaces:
 *   - Trust posture (verified publisher / unverified / Microsoft / unknown)
 *   - Top risky apps with publisher chip + critical scopes
 *   - Dormant grants (>180 days old, no recent activity)
 *   - Admin-consent split (single-user vs tenant-wide)
 *   - Vercel scenario callout — the playbook auditors recognize
 */
import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

interface Summary {
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
  verified_publisher_grants?: number;
  unverified_publisher_grants?: number;
  unverified_high_risk_grants?: number;
  publisher_unknown_grants?: number;
}

interface TopApp {
  client_app_id: string;
  display_name: string | null;
  max_risk_score: number;
  has_critical?: string | null;
  has_high?: string | null;
  grant_count: number;
  top_risky_scopes?: string[];
  oldest_grant_at?: string | null;
  publisher_name?: string | null;
  verified_publisher?: boolean | null;
  publisher_domain?: string | null;
}

interface Resp {
  summary: Summary;
  top_risky_apps: TopApp[];
}

function PublisherChip({ name, verified }: { name?: string | null; verified?: boolean | null }) {
  const isMs = (name || '').toLowerCase().startsWith('microsoft');
  if (isMs) {
    return (
      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-blue-100 text-blue-800">
        Microsoft
      </span>
    );
  }
  if (verified === true) {
    return (
      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-emerald-100 text-emerald-800">
        Verified · {name}
      </span>
    );
  }
  if (verified === false) {
    return (
      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-red-100 text-red-800">
        Unverified{name ? ` · ${name}` : ''}
      </span>
    );
  }
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide bg-gray-100 text-gray-700">
      Publisher unknown
    </span>
  );
}

function SevPill({ level }: { level: string }) {
  const cls =
    level === 'critical' ? 'bg-red-100 text-red-700' :
    level === 'high' ? 'bg-orange-100 text-orange-700' :
    level === 'medium' ? 'bg-amber-100 text-amber-700' :
    'bg-emerald-100 text-emerald-700';
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      {level}
    </span>
  );
}

export default function ConnectedApps() {
  const navigate = useNavigate();
  const [data, setData] = useState<Resp | null>(null);
  const [error, setError] = useState(false);

  useEffect(() => {
    fetch('/api/dashboard/connected-app-risk')
      .then(r => r.ok ? r.json() : Promise.reject(new Error('fetch_failed')))
      .then((d: Resp) => setData(d))
      .catch(() => setError(true));
  }, []);

  if (error) {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-semibold text-gray-900 mb-2">Connected Apps</h1>
        <p className="text-sm text-red-700">Unable to load connected-app risk. Run a discovery first.</p>
      </div>
    );
  }

  if (!data) {
    return (
      <div className="p-6 space-y-3 animate-pulse">
        <div className="h-8 w-1/3 bg-gray-100 rounded" />
        <div className="h-24 w-full bg-gray-100 rounded-xl" />
        <div className="h-64 w-full bg-gray-100 rounded-xl" />
      </div>
    );
  }

  const s = data.summary;
  const total = s.total || 0;

  if (total === 0) {
    return (
      <div className="p-6 max-w-5xl space-y-4">
        <h1 className="text-2xl font-semibold text-gray-900">Connected Apps</h1>
        <div className="rounded-xl border border-gray-200 bg-white p-6 text-center">
          <p className="text-sm text-gray-600">No OAuth consent grants discovered yet.</p>
          <p className="text-xs text-gray-500 mt-2">
            Run a discovery with <code className="font-mono">Directory.Read.All</code> +{' '}
            <code className="font-mono">Application.Read.All</code> to populate the connected-apps inventory.
          </p>
        </div>
      </div>
    );
  }

  // Primary risk pick — same priority as the dashboard tile so the story
  // matches what the user just clicked through from.
  const primaryRows = [
    { label: 'Grants with critical scopes', count: s.critical, key: 'critical', tone: 'red' },
    { label: 'Unverified publisher + high-risk scope', count: s.unverified_high_risk_grants || 0, key: 'unverified', tone: 'red' },
    { label: 'Admin-consented grants', count: s.admin_consents, key: 'admin', tone: 'orange' },
    { label: 'Dormant — >180 days old', count: s.over_180_days, key: 'dormant', tone: 'amber' },
  ].filter(r => r.count > 0).sort((a, b) => b.count - a.count);

  return (
    <div className="p-6 space-y-6 max-w-7xl">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-xs font-medium text-gray-500 uppercase tracking-wider">
          OAuth Consent Inventory
          <span className="text-gray-300">·</span>
          <span>Connected Apps</span>
        </div>
        <h1 className="text-2xl font-semibold text-gray-900 mt-1">Who said yes to what?</h1>
        <p className="text-sm text-gray-600 mt-2 max-w-3xl">
          Every OAuth consent grant is a long-lived authorization for a third-party app to read tenant
          data — most of them survive the user who consented. AuditGraph inventories them, scores them
          by scope and publisher trust, and flags the patterns that match real-world breach playbooks
          (Vercel, Context.ai, MOVEit).
        </p>
      </div>

      {/* Summary tiles */}
      <div className="grid grid-cols-4 gap-3">
        <div className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="text-xs uppercase tracking-wider font-medium text-gray-500">Apps</div>
          <div className="text-2xl font-bold text-gray-900 mt-1">{s.unique_apps.toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">{s.total.toLocaleString()} grants</div>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="text-xs uppercase tracking-wider font-medium text-gray-500">Critical / High</div>
          <div className="text-2xl font-bold text-red-700 mt-1">{(s.critical + s.high).toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">
            {s.critical.toLocaleString()} critical · {s.high.toLocaleString()} high
          </div>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="text-xs uppercase tracking-wider font-medium text-gray-500">Tenant-wide (admin)</div>
          <div className="text-2xl font-bold text-orange-700 mt-1">{s.admin_consents.toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">
            {s.user_consents.toLocaleString()} single-user
          </div>
        </div>
        <div className="rounded-xl border border-gray-200 bg-white p-4">
          <div className="text-xs uppercase tracking-wider font-medium text-gray-500">Dormant (&gt;180d)</div>
          <div className="text-2xl font-bold text-amber-700 mt-1">{s.over_180_days.toLocaleString()}</div>
          <div className="text-xs text-gray-500 mt-1">avg {s.avg_age_days}d old</div>
        </div>
      </div>

      {/* Publisher trust breakdown */}
      <div className="rounded-xl border border-gray-200 bg-white p-5">
        <h3 className="text-sm font-semibold text-gray-900 mb-3">Publisher trust posture</h3>
        <div className="grid grid-cols-4 gap-3 text-xs">
          <div className="flex items-center gap-2">
            <PublisherChip name="Microsoft" verified={true} />
            <span className="text-gray-700 font-medium">
              {(s.total - (s.verified_publisher_grants || 0) - (s.unverified_publisher_grants || 0) - (s.publisher_unknown_grants || 0)).toLocaleString()}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <PublisherChip name="Verified" verified={true} />
            <span className="text-gray-700 font-medium">{(s.verified_publisher_grants || 0).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2">
            <PublisherChip verified={false} />
            <span className="text-gray-700 font-medium">{(s.unverified_publisher_grants || 0).toLocaleString()}</span>
          </div>
          <div className="flex items-center gap-2">
            <PublisherChip />
            <span className="text-gray-700 font-medium">{(s.publisher_unknown_grants || 0).toLocaleString()}</span>
          </div>
        </div>
        {(s.unverified_high_risk_grants || 0) > 0 && (
          <p className="text-xs text-red-700 mt-3 font-medium">
            ⚠ {(s.unverified_high_risk_grants || 0).toLocaleString()} grants combine an unverified publisher with a high-risk scope —
            the consent-phishing signature the Vercel breach playbook used.
          </p>
        )}
      </div>

      {/* Primary risk rows */}
      {primaryRows.length > 0 && (
        <div className="rounded-xl border border-gray-200 bg-white">
          <div className="px-5 py-3 border-b border-gray-100">
            <h3 className="text-sm font-semibold text-gray-900">Where the risk lives</h3>
          </div>
          <ul className="divide-y divide-gray-100">
            {primaryRows.map(r => (
              <li key={r.key} className="px-5 py-3 flex items-center justify-between">
                <span className="text-sm text-gray-700">{r.label}</span>
                <span className="font-mono text-sm font-semibold text-gray-900">{r.count.toLocaleString()}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Top risky apps */}
      <div className="rounded-xl border border-gray-200 bg-white overflow-hidden">
        <div className="px-5 py-3 border-b border-gray-100">
          <h3 className="text-sm font-semibold text-gray-900">Top {data.top_risky_apps.length} risky connected apps</h3>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-xs text-gray-500 uppercase tracking-wider border-b border-gray-200">
              <tr>
                <th className="text-left py-2.5 px-5">App</th>
                <th className="text-left py-2.5 px-5">Publisher</th>
                <th className="text-left py-2.5 px-5">Risk</th>
                <th className="text-left py-2.5 px-5">Top scopes</th>
                <th className="text-right py-2.5 px-5">Grants</th>
                <th className="text-right py-2.5 px-5">Oldest</th>
                <th className="py-2.5 px-5"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.top_risky_apps.map(app => {
                const lvl = app.has_critical ? 'critical' : app.has_high ? 'high' : 'medium';
                return (
                  <tr key={app.client_app_id} className="hover:bg-gray-50">
                    <td className="py-3 px-5">
                      <div className="font-medium text-gray-900">{app.display_name || 'Unknown'}</div>
                      <div className="text-[10px] font-mono text-gray-400">{app.client_app_id}</div>
                    </td>
                    <td className="py-3 px-5">
                      <PublisherChip name={app.publisher_name} verified={app.verified_publisher ?? null} />
                    </td>
                    <td className="py-3 px-5">
                      <SevPill level={lvl} />
                      <div className="text-[10px] text-gray-400 mt-0.5">score {app.max_risk_score}/100</div>
                    </td>
                    <td className="py-3 px-5">
                      <div className="flex flex-wrap gap-1 max-w-[280px]">
                        {(app.top_risky_scopes || []).slice(0, 4).map(s => (
                          <span key={s} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-50 text-red-700 border border-red-200">
                            {s}
                          </span>
                        ))}
                        {(app.top_risky_scopes || []).length > 4 && (
                          <span className="text-[10px] text-gray-500">+{(app.top_risky_scopes || []).length - 4} more</span>
                        )}
                      </div>
                    </td>
                    <td className="py-3 px-5 text-right font-mono text-gray-700">{app.grant_count}</td>
                    <td className="py-3 px-5 text-right text-xs text-gray-500">
                      {app.oldest_grant_at ? new Date(app.oldest_grant_at).toLocaleDateString() : '—'}
                    </td>
                    <td className="py-3 px-5 text-right">
                      <button
                        onClick={() => navigate(`/identities/${encodeURIComponent(app.client_app_id)}`)}
                        className="text-xs font-medium text-blue-600 hover:text-blue-800"
                      >
                        Investigate →
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Vercel scenario interactive detector — AG-84 */}
      <VercelScenarioPanel />
    </div>
  );
}

interface VercelMatch {
  id: number;
  client_app_id: string;
  client_display_name: string | null;
  resource_display_name: string | null;
  publisher_name: string | null;
  verified_publisher: boolean | null;
  consent_type: string | null;
  risk_level: string;
  risk_score: number;
  age_days: number | null;
  high_risk_scopes: string[];
  has_offline_access: boolean;
  created_datetime: string | null;
  reasons: string[];
}

interface VercelResp {
  matched: VercelMatch[];
  matched_count: number;
  with_offline_access: number;
  scenario: {
    name: string;
    signature: string[];
    why_it_matters: string;
  };
}

function VercelScenarioPanel() {
  const [data, setData] = React.useState<VercelResp | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState(false);
  const [expanded, setExpanded] = React.useState(false);

  const runScenario = () => {
    setLoading(true);
    setError(false);
    fetch('/api/connected-apps/vercel-scenario')
      .then(r => r.ok ? r.json() : Promise.reject(new Error('fetch_failed')))
      .then((d: VercelResp) => { setData(d); setExpanded(true); })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  };

  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 p-5 space-y-4">
      <div className="flex items-start gap-3">
        <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider bg-amber-600 text-white flex-shrink-0">
          Scenario
        </span>
        <div className="text-xs text-amber-900 space-y-2 flex-1">
          <p className="font-medium">Vercel / Context.ai (2024-2025): The OAuth consent breach playbook.</p>
          <p>
            Attacker registers a "productivity" OAuth app under an unverified publisher, prompts a single
            admin to grant tenant-wide consent for Mail.Read + Files.Read.All + offline_access. That single
            click hands them a refresh token that survives password rotations, MFA upgrades, and the
            original user's departure.
          </p>
          <p>
            Signature: <strong>unverified publisher + admin consent + high-risk scope + offline_access</strong>.
          </p>
        </div>
        <button
          onClick={runScenario}
          disabled={loading}
          className="px-3 py-1.5 rounded-md text-xs font-semibold bg-amber-600 text-white hover:bg-amber-700 transition disabled:opacity-50 flex-shrink-0"
        >
          {loading ? 'Scanning…' : data ? 'Re-run scenario' : 'Run Vercel scenario →'}
        </button>
      </div>

      {error && (
        <p className="text-xs text-red-700">Couldn't run scenario. Re-run discovery first.</p>
      )}

      {data && (
        <div className="rounded-lg bg-white border border-amber-200 p-4 space-y-3">
          <div className="flex items-baseline justify-between">
            <h3 className="text-sm font-semibold text-gray-900">Matched grants</h3>
            <div className="text-right">
              <div className="text-2xl font-bold text-red-700">{data.matched_count}</div>
              <div className="text-[10px] text-gray-500">{data.with_offline_access} with offline_access</div>
            </div>
          </div>

          {data.matched_count === 0 ? (
            <p className="text-sm text-emerald-700 font-medium">
              No grants match the Vercel signature. Your OAuth surface is clean against this specific playbook.
            </p>
          ) : (
            <>
              <p className="text-xs text-gray-600">
                Each row matches all four signature preconditions. Investigate immediately and revoke
                any grant that wasn't explicitly approved by your change-control process.
              </p>
              {!expanded && (
                <button
                  onClick={() => setExpanded(true)}
                  className="text-xs font-medium text-amber-700 hover:text-amber-900"
                >
                  Show matched grants →
                </button>
              )}
              {expanded && (
                <div className="overflow-x-auto -mx-4 px-4">
                  <table className="w-full text-xs">
                    <thead className="text-[10px] text-gray-500 uppercase tracking-wider border-b border-gray-200">
                      <tr>
                        <th className="text-left py-2 pr-3">App</th>
                        <th className="text-left py-2 pr-3">Resource</th>
                        <th className="text-left py-2 pr-3">Why it matched</th>
                        <th className="text-right py-2 pr-3">Age</th>
                        <th className="text-right py-2">Risk</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-100">
                      {data.matched.slice(0, 20).map(m => (
                        <tr key={m.id} className="hover:bg-amber-50/50">
                          <td className="py-2 pr-3">
                            <div className="font-medium text-gray-900">{m.client_display_name || '—'}</div>
                            <div className="text-[10px] font-mono text-gray-400">{m.client_app_id.slice(0, 16)}…</div>
                          </td>
                          <td className="py-2 pr-3 text-gray-700">{m.resource_display_name || '—'}</td>
                          <td className="py-2 pr-3">
                            <ul className="space-y-0.5">
                              {m.reasons.map((r, i) => (
                                <li key={i} className="text-[10px] text-gray-700">
                                  <span className="text-red-500 mr-1">●</span>{r}
                                </li>
                              ))}
                            </ul>
                          </td>
                          <td className="py-2 pr-3 text-right text-gray-600">
                            {typeof m.age_days === 'number' ? `${m.age_days}d` : '—'}
                          </td>
                          <td className="py-2 text-right">
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                              m.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                              m.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                              'bg-amber-100 text-amber-700'
                            }`}>
                              {m.risk_level}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {data.matched_count > 20 && (
                    <p className="text-[10px] text-gray-500 mt-2">
                      Showing top 20 of {data.matched_count} matches. Use the Connected Apps table above
                      and filter by publisher trust to see the rest.
                    </p>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
