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

      {/* Multi-scenario consent risk detector — Vercel/MOVEit/Storm-0558/
          NOBELIUM/Shadow-IT. CISO chooses which playbook to surface. */}
      <ScenarioMenuPanel />
    </div>
  );
}

interface ScenarioMatch {
  id: number;
  client_app_id: string;
  client_display_name: string | null;
  resource_display_name: string | null;
  publisher_name: string | null;
  verified_publisher: boolean | null;
  risk_level: string;
  risk_score: number;
  age_days: number | null;
  high_risk_scopes: string[];
  has_offline_access: boolean;
  consent_type: string | null;
}

interface ConsentScenario {
  key: string;
  name: string;
  tagline: string;
  signature: string[];
  why_it_matters: string;
  count: number;
  top: ScenarioMatch[];
  frameworks?: { nist?: string[]; cis?: string[]; mitre?: string[] };
}

interface ScenariosResp {
  scenarios: ConsentScenario[];
  totals: { scenarios: number; matched_grants: number };
}

const SCENARIO_TONE: Record<string, { tone: string; bg: string; ring: string; text: string }> = {
  vercel:              { tone: '#ef4444', bg: 'bg-red-50',     ring: 'ring-red-300',     text: 'text-red-900' },
  moveit:              { tone: '#f97316', bg: 'bg-orange-50',  ring: 'ring-orange-300',  text: 'text-orange-900' },
  storm0558:           { tone: '#a855f7', bg: 'bg-purple-50',  ring: 'ring-purple-300',  text: 'text-purple-900' },
  nobelium_dormant:    { tone: '#f59e0b', bg: 'bg-amber-50',   ring: 'ring-amber-300',   text: 'text-amber-900' },
  shadow_productivity: { tone: '#3b82f6', bg: 'bg-blue-50',    ring: 'ring-blue-300',    text: 'text-blue-900' },
};

function ScenarioMenuPanel() {
  const navigate = useNavigate();
  const [data, setData] = React.useState<ScenariosResp | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState(false);
  const [activeKey, setActiveKey] = React.useState<string | null>(null);

  React.useEffect(() => {
    fetch('/api/connected-apps/scenarios')
      .then(r => r.ok ? r.json() : Promise.reject(new Error('fetch_failed')))
      .then((d: ScenariosResp) => {
        setData(d);
        // Auto-select the highest-count scenario so the page lands
        // on something useful even before the user clicks.
        const top = [...(d.scenarios || [])].sort((a, b) => b.count - a.count)[0];
        if (top && top.count > 0) setActiveKey(top.key);
      })
      .catch(() => setError(true))
      .finally(() => setLoading(false));
  }, []);

  if (error) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-4">
        <p className="text-xs text-red-700">Couldn't load consent scenarios. Run a discovery first.</p>
      </div>
    );
  }

  if (loading || !data) {
    return (
      <div className="rounded-xl border border-gray-200 bg-white p-5 animate-pulse">
        <div className="h-4 w-1/3 bg-gray-100 rounded mb-3" />
        <div className="grid grid-cols-5 gap-2">
          {[1, 2, 3, 4, 5].map(i => <div key={i} className="h-16 bg-gray-100 rounded" />)}
        </div>
      </div>
    );
  }

  const active = data.scenarios.find(s => s.key === activeKey) || null;
  const meta = active ? (SCENARIO_TONE[active.key] || SCENARIO_TONE.vercel) : SCENARIO_TONE.vercel;

  return (
    <div className="rounded-xl border border-amber-200 bg-amber-50 p-5 space-y-4">
      <div className="flex items-start gap-3">
        <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-bold uppercase tracking-wider bg-amber-600 text-white flex-shrink-0">
          Scenarios
        </span>
        <div className="text-xs text-amber-900 space-y-1 flex-1">
          <p className="font-medium">
            Consent risk has four axes: publisher trust, scope minimization, dormancy, and intake hygiene.
          </p>
          <p>
            Verified ≠ safe (MOVEit). Microsoft ≠ safe (Storm-0558). Recent ≠ safe (Shadow IT). Old ≠ safe (NOBELIUM).
            Each tile below filters your own grants against one of the canonical breach playbooks.
          </p>
        </div>
      </div>

      {/* Scenario tile picker */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
        {data.scenarios.map(s => {
          const tone = SCENARIO_TONE[s.key] || SCENARIO_TONE.vercel;
          const isActive = activeKey === s.key;
          return (
            <button
              key={s.key}
              onClick={() => setActiveKey(s.key)}
              className={`text-left rounded-lg p-3 transition border-2 ${
                isActive
                  ? `${tone.bg} ${tone.text} border-current shadow-sm`
                  : 'bg-white border-gray-200 hover:border-gray-300 text-gray-700'
              }`}
              style={isActive ? { color: tone.tone } : {}}
            >
              <div className="flex items-baseline justify-between">
                <span className="text-[10px] font-bold uppercase tracking-wider">{s.name.split(' (')[0]}</span>
                <span className={`text-xl font-bold ${isActive ? '' : 'text-gray-900'}`}>{s.count}</span>
              </div>
              <p className={`text-[10px] mt-1 leading-tight ${isActive ? tone.text : 'text-gray-500'}`}>
                {s.tagline}
              </p>
            </button>
          );
        })}
      </div>

      {/* Active scenario detail panel */}
      {active && (
        <div className={`rounded-lg bg-white border-2 ${meta.ring.replace('ring-', 'border-')} p-4 space-y-3`}>
          <div className="flex items-baseline justify-between">
            <div>
              <h3 className="text-sm font-semibold text-gray-900">{active.name}</h3>
              <p className="text-xs text-gray-600 mt-0.5">{active.tagline}</p>
            </div>
            <div className="text-right">
              <div className={`text-3xl font-bold`} style={{ color: meta.tone }}>{active.count}</div>
              <div className="text-[10px] text-gray-500">matched grants</div>
            </div>
          </div>

          <div className="grid md:grid-cols-2 gap-4 pt-2 border-t border-gray-100">
            <div>
              <div className="text-[10px] uppercase tracking-wider font-medium text-gray-500 mb-1">Signature</div>
              <ul className="space-y-0.5">
                {active.signature.map((sig, i) => (
                  <li key={i} className="text-xs text-gray-700 flex items-start gap-1">
                    <span style={{ color: meta.tone }}>●</span> {sig}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <div className="text-[10px] uppercase tracking-wider font-medium text-gray-500 mb-1">Why it matters</div>
              <p className="text-xs text-gray-700">{active.why_it_matters}</p>
              {active.frameworks && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {(active.frameworks.mitre || []).map(t => (
                    <span key={t} className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-gray-100 text-gray-600">
                      MITRE {t}
                    </span>
                  ))}
                  {(active.frameworks.cis || []).slice(0, 2).map(t => (
                    <span key={t} className="px-1.5 py-0.5 rounded text-[9px] font-mono bg-gray-100 text-gray-600">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

          {active.count === 0 ? (
            <p className="text-sm text-emerald-700 font-medium pt-2 border-t border-gray-100">
              No grants match this signature. Your inventory is clean against this specific playbook.
            </p>
          ) : (
            <div className="overflow-x-auto -mx-4 px-4 pt-2 border-t border-gray-100">
              <table className="w-full text-xs">
                <thead className="text-[10px] text-gray-500 uppercase tracking-wider border-b border-gray-100">
                  <tr>
                    <th className="text-left py-2 pr-3">App</th>
                    <th className="text-left py-2 pr-3">Publisher</th>
                    <th className="text-left py-2 pr-3">Resource</th>
                    <th className="text-right py-2 pr-3">Age</th>
                    <th className="text-right py-2">Risk</th>
                    <th className="py-2"></th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {active.top.map(m => (
                    <tr key={m.id} className="hover:bg-gray-50">
                      <td className="py-2 pr-3">
                        <div className="font-medium text-gray-900">{m.client_display_name || '—'}</div>
                        <div className="text-[10px] font-mono text-gray-400">{m.client_app_id.slice(0, 16)}…</div>
                      </td>
                      <td className="py-2 pr-3">
                        {(m.publisher_name || '').toLowerCase().startsWith('microsoft')
                          ? <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-800">Microsoft</span>
                          : m.verified_publisher === true
                            ? <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-100 text-emerald-800">Verified</span>
                            : m.verified_publisher === false
                              ? <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-800">Unverified</span>
                              : <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-gray-100 text-gray-700">Unknown</span>
                        }
                      </td>
                      <td className="py-2 pr-3 text-gray-700">{m.resource_display_name || '—'}</td>
                      <td className="py-2 pr-3 text-right text-gray-600">
                        {typeof m.age_days === 'number' ? `${m.age_days}d` : '—'}
                      </td>
                      <td className="py-2 pr-3 text-right">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${
                          m.risk_level === 'critical' ? 'bg-red-100 text-red-700' :
                          m.risk_level === 'high' ? 'bg-orange-100 text-orange-700' :
                          'bg-amber-100 text-amber-700'
                        }`}>{m.risk_level}</span>
                      </td>
                      <td className="py-2 text-right">
                        <button
                          onClick={() => navigate(`/identities/${encodeURIComponent(m.client_app_id)}`)}
                          className="text-[11px] font-medium text-blue-600 hover:text-blue-800"
                        >
                          →
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {active.count > active.top.length && (
                <p className="text-[10px] text-gray-500 mt-2">
                  Showing top {active.top.length} of {active.count}. Use the Top risky apps table above to drill further.
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

