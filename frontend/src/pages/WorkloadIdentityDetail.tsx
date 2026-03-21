import React, { useState, useEffect } from 'react';
import { useParams, useSearchParams, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { AccessGraphTab } from '../components/graph';
import {
  WORKLOAD_TYPE_CONFIG,
  LIFECYCLE_STATE_CONFIG,
  OWNER_STATUS_CONFIG,
  SCOPE_FLAG_CONFIG,
} from '../constants/metrics';

// ── Types ────────────────────────────────────────────────────────────

interface Permission {
  permission_name: string;
  permission_description?: string;
  resource_name?: string;
  risk_level?: string;
}

interface SignInEvent {
  sign_in_id?: string;
  created_datetime: string;
  status: string;
  resource_display_name?: string;
  ip_address?: string;
  location_city?: string;
  location_country?: string;
  risk_level?: string;
  conditional_access_status?: string;
}

interface Finding {
  finding_type: string;
  severity: string;
  title: string;
  description: string;
  remediation: string;
  component: string;
  score_impact: number;
}

interface Anomaly {
  id: number;
  anomaly_type: string;
  severity: string;
  title: string;
  created_at: string;
  resolved: boolean;
}

interface WorkloadDetailData {
  identity_type: string;
  display_name: string;
  exposure: {
    total: number;
    privilege: number;
    credential_risk: number;
    exposure: number;
    lifecycle: number;
    visibility: number;
    can_escalate: boolean;
    effective_scope_flag: string;
    lifecycle_state: string;
    owner_status: string;
    federated_trust: boolean;
    cross_subscription: boolean;
    credential_age_days: number;
    critical_overrides: Array<{ type: string; description: string }>;
  };
  findings: Finding[];
  activity_inference: { confidence: number; classification: string };
  recommendations: Array<{ priority: string; action: string }>;
  detail: Record<string, any>;
  roles?: Array<{ role_name: string; scope_type?: string; scope?: string; created_on?: string }>;
  entra_roles?: Array<{ role_name: string; risk_level?: string }>;
  credentials?: Array<{ credential_type: string; start_datetime?: string; end_datetime?: string; display_name?: string; key_id?: string }>;
  owners?: Array<{ owner_display_name?: string; owner_upn?: string; owner_object_id?: string }>;
  permissions?: Permission[];
  blast_radius?: string;
  critical_roles?: string[];
  linked_spn?: any;
  activity_stats?: {
    total_sign_ins: number;
    successful_sign_ins: number;
    failed_sign_ins: number;
    unique_resources: number;
    unique_ips: number;
    off_hours_pct: number;
    peak_hour: number;
    avg_daily_sign_ins: number;
    risk_sign_ins: number;
    ca_failures: number;
  };
  anomalies?: Anomaly[];
  recent_signins?: SignInEvent[];
  signals?: Record<string, string[]>;
  p2_enabled?: boolean;
}

// ── Helpers ──────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: 'bg-red-600',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-400',
};

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300',
  high: 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  medium: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/40 dark:text-yellow-300',
  low: 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300',
};

function exposureColor(score: number): string {
  if (score >= 80) return 'text-red-600 dark:text-red-400';
  if (score >= 60) return 'text-orange-500 dark:text-orange-400';
  if (score >= 35) return 'text-yellow-500 dark:text-yellow-400';
  return 'text-green-500 dark:text-green-400';
}

function exposureRingColor(score: number): string {
  if (score >= 80) return '#dc2626';
  if (score >= 60) return '#f97316';
  if (score >= 35) return '#eab308';
  return '#22c55e';
}

function ExposureRing({ score, size = 64 }: { score: number; size?: number }) {
  const r = (size - 4) / 2;
  const c = 2 * Math.PI * r;
  const pct = Math.min(score, 100) / 100;
  return (
    <svg width={size} height={size} className="transform -rotate-90">
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="currentColor" strokeWidth={3} className="text-gray-200 dark:text-slate-700" />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={exposureRingColor(score)} strokeWidth={3}
        strokeDasharray={`${c * pct} ${c * (1 - pct)}`} strokeLinecap="round" />
      <text x={size / 2} y={size / 2} textAnchor="middle" dominantBaseline="central"
        className="font-bold fill-current" style={{ fontSize: size > 48 ? 14 : 10, fill: exposureRingColor(score) }}
        transform={`rotate(90 ${size / 2} ${size / 2})`}>{score}</text>
    </svg>
  );
}

function ComponentBar({ label, score, max, signals }: { label: string; score: number; max: number; signals?: string[] }) {
  const pct = max > 0 ? Math.min((score / max) * 100, 100) : 0;
  const color = pct >= 80 ? 'bg-red-500' : pct >= 50 ? 'bg-orange-400' : pct >= 25 ? 'bg-yellow-400' : 'bg-green-400';
  return (
    <div>
      <div className="flex items-center gap-2 text-xs">
        <span className="w-24 text-gray-500 dark:text-slate-400 text-right">{label}</span>
        <div className="flex-1 h-2.5 bg-gray-100 dark:bg-slate-700 rounded-full overflow-hidden">
          <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
        </div>
        <span className="w-12 text-gray-600 dark:text-slate-300 text-right font-medium">{score}/{max}</span>
      </div>
      {!!signals && signals.length > 0 && (
        <div className="ml-28 mt-0.5 space-y-0.5">
          {signals.map((s, i) => (
            <p key={i} className="text-[10px] text-gray-400 dark:text-slate-500 leading-tight">
              <span className="text-gray-300 dark:text-slate-600 mr-1">&#x2022;</span>{s}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}

function TypeBadge({ type }: { type: string }) {
  const cfg = WORKLOAD_TYPE_CONFIG[type] || WORKLOAD_TYPE_CONFIG.spn;
  return <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${cfg.badgeClass}`}>{cfg.shortLabel}</span>;
}

function CopyField({ label, value }: { label: string; value?: string }) {
  const [copied, setCopied] = useState(false);
  if (!value) return null;
  const doCopy = () => {
    navigator.clipboard.writeText(value).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  };
  return (
    <div className="flex items-center gap-1 min-w-0">
      <span className="text-gray-400 dark:text-slate-500 text-xs">{label}:</span>
      <code className="text-xs font-mono text-gray-600 dark:text-slate-300 truncate max-w-[200px]" title={value}>{value}</code>
      <button onClick={doCopy} className="ml-0.5 text-gray-300 dark:text-slate-600 hover:text-blue-500 dark:hover:text-blue-400 flex-shrink-0" title="Copy">
        {copied ? (
          <svg className="w-3.5 h-3.5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" /></svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" /></svg>
        )}
      </button>
    </div>
  );
}

function formatDate(v?: string | null): string {
  if (!v) return '—';
  try {
    return new Date(v).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
  } catch { return v; }
}

function formatDateTime(v?: string | null): string {
  if (!v) return '—';
  try {
    return new Date(v).toLocaleString('en-US', { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  } catch { return v; }
}

function daysUntil(dateStr?: string | null): number | null {
  if (!dateStr) return null;
  try {
    const d = new Date(dateStr);
    return Math.ceil((d.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  } catch { return null; }
}

// ── Tabs ─────────────────────────────────────────────────────────────

const TABS = [
  { key: 'roles', label: 'Roles & Permissions' },
  { key: 'credentials', label: 'Credentials' },
  { key: 'access_graph', label: 'Access Graph' },
  { key: 'anomalies', label: 'Anomalies' },
  { key: 'activity', label: 'Activity' },
  { key: 'findings', label: 'Findings' },
  { key: 'owners', label: 'Ownership' },
  { key: 'properties', label: 'Properties' },
] as const;

type TabKey = typeof TABS[number]['key'];

// ── Tab: Roles & Permissions ─────────────────────────────────────────

function RolesTab({ data }: { data: WorkloadDetailData }) {
  const roles = data.roles || [];
  const entraRoles = data.entra_roles || [];
  const perms = data.permissions || [];

  return (
    <div className="space-y-6">
      {/* RBAC Roles */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-2">RBAC Role Assignments ({roles.length})</h3>
        {roles.length === 0 ? (
          <p className="text-xs text-gray-400 dark:text-slate-500 italic">No RBAC roles assigned</p>
        ) : (
          <div className="overflow-x-auto border border-gray-200 dark:border-slate-700 rounded-lg">
            <table className="w-full text-xs">
              <thead className="bg-gray-50 dark:bg-slate-800 text-gray-500 dark:text-slate-400">
                <tr>
                  <th className="text-left px-3 py-2 font-medium">Role</th>
                  <th className="text-left px-3 py-2 font-medium">Scope</th>
                  <th className="text-left px-3 py-2 font-medium">Type</th>
                  <th className="text-left px-3 py-2 font-medium">Assigned</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
                {roles.map((r, i) => (
                  <tr key={i} className="hover:bg-gray-50 dark:hover:bg-slate-800/50">
                    <td className="px-3 py-2 font-medium text-gray-800 dark:text-slate-200">{r.role_name}</td>
                    <td className="px-3 py-2 text-gray-500 dark:text-slate-400 max-w-[300px] truncate" title={r.scope}>{r.scope || '—'}</td>
                    <td className="px-3 py-2">
                      {r.scope_type && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                          SCOPE_FLAG_CONFIG[r.scope_type]?.badgeClass || 'bg-gray-100 text-gray-500'
                        }`}>{r.scope_type}</span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-gray-400 dark:text-slate-500">{formatDate(r.created_on)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Entra Directory Roles */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-2">Entra Directory Roles ({entraRoles.length})</h3>
        {entraRoles.length === 0 ? (
          <p className="text-xs text-gray-400 dark:text-slate-500 italic">No Entra directory roles assigned</p>
        ) : (
          <div className="overflow-x-auto border border-gray-200 dark:border-slate-700 rounded-lg">
            <table className="w-full text-xs">
              <thead className="bg-gray-50 dark:bg-slate-800 text-gray-500 dark:text-slate-400">
                <tr>
                  <th className="text-left px-3 py-2 font-medium">Role</th>
                  <th className="text-left px-3 py-2 font-medium">Risk Level</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
                {entraRoles.map((r, i) => (
                  <tr key={i} className="hover:bg-gray-50 dark:hover:bg-slate-800/50">
                    <td className="px-3 py-2 font-medium text-gray-800 dark:text-slate-200">{r.role_name}</td>
                    <td className="px-3 py-2">
                      {r.risk_level && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${SEV_BADGE[r.risk_level] || 'bg-gray-100 text-gray-500'}`}>
                          {r.risk_level.toUpperCase()}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Graph API Permissions */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-2">Graph API Permissions ({perms.length})</h3>
        {perms.length === 0 ? (
          <p className="text-xs text-gray-400 dark:text-slate-500 italic">No Graph API permissions</p>
        ) : (
          <div className="overflow-x-auto border border-gray-200 dark:border-slate-700 rounded-lg">
            <table className="w-full text-xs">
              <thead className="bg-gray-50 dark:bg-slate-800 text-gray-500 dark:text-slate-400">
                <tr>
                  <th className="text-left px-3 py-2 font-medium">Permission</th>
                  <th className="text-left px-3 py-2 font-medium">Risk</th>
                  <th className="text-left px-3 py-2 font-medium">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
                {perms.map((p, i) => (
                  <tr key={i} className="hover:bg-gray-50 dark:hover:bg-slate-800/50">
                    <td className="px-3 py-2 font-mono text-gray-800 dark:text-slate-200">{p.permission_name}</td>
                    <td className="px-3 py-2">
                      {p.risk_level && (
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${SEV_BADGE[p.risk_level] || 'bg-gray-100 text-gray-500'}`}>
                          {p.risk_level.toUpperCase()}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-gray-500 dark:text-slate-400 max-w-[300px] truncate" title={p.permission_description}>
                      {p.permission_description || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Tab: Credentials ─────────────────────────────────────────────────

function CredentialsTab({ data }: { data: WorkloadDetailData }) {
  const creds = data.credentials || [];
  const isManagedIdentity = data.identity_type === 'managed_identity';

  if (isManagedIdentity) {
    return (
      <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4">
        <div className="flex items-center gap-2">
          <svg className="w-5 h-5 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <div>
            <p className="text-sm font-medium text-blue-800 dark:text-blue-300">Credentials Managed by Azure</p>
            <p className="text-xs text-blue-600 dark:text-blue-400 mt-0.5">
              Managed identities use Azure-managed certificates that are automatically rotated. No manual credential management is required.
            </p>
          </div>
        </div>
      </div>
    );
  }

  const activeSecrets = creds.filter(c => c.credential_type === 'secret' && (!c.end_datetime || new Date(c.end_datetime) > new Date())).length;
  const activeCerts = creds.filter(c => c.credential_type === 'certificate' && (!c.end_datetime || new Date(c.end_datetime) > new Date())).length;
  const oldestDays = data.exposure?.credential_age_days || 0;

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="flex items-center gap-4 text-xs">
        <span className="px-2 py-1 rounded bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-300 font-medium">
          {activeSecrets} active secret{activeSecrets !== 1 ? 's' : ''}
        </span>
        <span className="px-2 py-1 rounded bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-300 font-medium">
          {activeCerts} certificate{activeCerts !== 1 ? 's' : ''}
        </span>
        {oldestDays > 0 && (
          <span className={`px-2 py-1 rounded font-medium ${
            oldestDays > 365 ? 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300' :
            oldestDays > 180 ? 'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300' :
            'bg-gray-100 text-gray-600 dark:bg-slate-800 dark:text-slate-300'
          }`}>
            Oldest: {oldestDays}d
          </span>
        )}
      </div>

      {creds.length === 0 ? (
        <p className="text-xs text-gray-400 dark:text-slate-500 italic">No credentials found</p>
      ) : (
        <div className="overflow-x-auto border border-gray-200 dark:border-slate-700 rounded-lg">
          <table className="w-full text-xs">
            <thead className="bg-gray-50 dark:bg-slate-800 text-gray-500 dark:text-slate-400">
              <tr>
                <th className="text-left px-3 py-2 font-medium">Type</th>
                <th className="text-left px-3 py-2 font-medium">Name</th>
                <th className="text-left px-3 py-2 font-medium">Key ID</th>
                <th className="text-left px-3 py-2 font-medium">Created</th>
                <th className="text-left px-3 py-2 font-medium">Expires</th>
                <th className="text-left px-3 py-2 font-medium">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
              {creds.map((c, i) => {
                const days = daysUntil(c.end_datetime);
                const expired = days !== null && days < 0;
                const expiringSoon = days !== null && days >= 0 && days <= 30;
                return (
                  <tr key={i} className="hover:bg-gray-50 dark:hover:bg-slate-800/50">
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
                        c.credential_type === 'certificate' ? 'bg-purple-100 text-purple-700 dark:bg-purple-900/40 dark:text-purple-300' : 'bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300'
                      }`}>{c.credential_type === 'certificate' ? 'CERT' : 'SECRET'}</span>
                    </td>
                    <td className="px-3 py-2 text-gray-800 dark:text-slate-200">{c.display_name || '—'}</td>
                    <td className="px-3 py-2">
                      {c.key_id ? <CopyField label="" value={c.key_id} /> : <span className="text-gray-400">—</span>}
                    </td>
                    <td className="px-3 py-2 text-gray-500 dark:text-slate-400">{formatDate(c.start_datetime)}</td>
                    <td className={`px-3 py-2 font-medium ${
                      expired ? 'text-red-600 dark:text-red-400' :
                      expiringSoon ? 'text-amber-600 dark:text-amber-400' :
                      'text-gray-500 dark:text-slate-400'
                    }`}>
                      {c.end_datetime ? formatDate(c.end_datetime) : 'Never'}
                      {days !== null && !expired && days <= 30 && ` (${days}d)`}
                    </td>
                    <td className="px-3 py-2">
                      {expired ? (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">EXPIRED</span>
                      ) : expiringSoon ? (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300">EXPIRING</span>
                      ) : (
                        <span className="px-1.5 py-0.5 rounded text-[10px] font-bold bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300">ACTIVE</span>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── Tab: Activity ────────────────────────────────────────────────────

function ActivityTab({ data }: { data: WorkloadDetailData }) {
  const p2 = data.p2_enabled;
  const stats = data.activity_stats;
  const signins = data.recent_signins || [];

  return (
    <div className="space-y-6">
      {/* Activity Inference (always shown) */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-2">Activity Classification</h3>
        <div className="flex items-center gap-3">
          <div className="flex-1 h-3 bg-gray-100 dark:bg-slate-700 rounded-full overflow-hidden">
            <div className="h-full bg-blue-500 rounded-full" style={{ width: `${data.activity_inference.confidence}%` }} />
          </div>
          <span className="text-xs text-gray-600 dark:text-slate-300 font-medium whitespace-nowrap">
            {data.activity_inference.confidence}% confidence
          </span>
        </div>
        <p className="text-xs text-gray-500 dark:text-slate-400 mt-1">
          Classification: <span className={`font-medium ${
            LIFECYCLE_STATE_CONFIG[data.activity_inference.classification]?.badgeClass ? '' : ''
          }`}>
            <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-semibold ${
              LIFECYCLE_STATE_CONFIG[data.activity_inference.classification]?.badgeClass || 'bg-gray-100 text-gray-500'
            }`}>{LIFECYCLE_STATE_CONFIG[data.activity_inference.classification]?.label || data.activity_inference.classification.replace(/_/g, ' ')}</span>
          </span>
        </p>
      </div>

      {/* P2 Sign-In Stats */}
      {p2 && !!stats ? (
        <div>
          <h3 className="text-sm font-semibold text-emerald-700 dark:text-emerald-400 mb-2 flex items-center gap-1">
            <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" /></svg>
            Sign-In Activity (P2 Telemetry)
          </h3>

          {/* Stats grid */}
          <div className="grid grid-cols-3 gap-3 mb-4">
            {[
              { label: 'Total (30d)', value: stats.total_sign_ins.toLocaleString() },
              { label: 'Avg/Day', value: String(stats.avg_daily_sign_ins) },
              { label: 'Success', value: String(stats.successful_sign_ins) },
              { label: 'Failed', value: String(stats.failed_sign_ins), warn: stats.failed_sign_ins > 0 },
              { label: 'Unique Resources', value: String(stats.unique_resources) },
              { label: 'Unique IPs', value: String(stats.unique_ips) },
            ].map((s, i) => (
              <div key={i} className="bg-gray-50 dark:bg-slate-800 rounded-lg p-2.5">
                <p className="text-[10px] text-gray-400 dark:text-slate-500 uppercase">{s.label}</p>
                <p className={`text-lg font-bold ${s.warn ? 'text-red-600 dark:text-red-400' : 'text-gray-800 dark:text-slate-200'}`}>{s.value}</p>
              </div>
            ))}
          </div>

          {/* Success/Failure bar */}
          {stats.total_sign_ins > 0 && (
            <div className="mb-4">
              <div className="flex items-center justify-between text-[10px] text-gray-500 dark:text-slate-400 mb-1">
                <span>Success: {stats.successful_sign_ins}</span>
                <span>Failed: {stats.failed_sign_ins}</span>
              </div>
              <div className="h-3 bg-gray-100 dark:bg-slate-700 rounded-full overflow-hidden flex">
                <div className="h-full bg-green-500 rounded-l-full" style={{ width: `${(stats.successful_sign_ins / stats.total_sign_ins) * 100}%` }} />
                <div className="h-full bg-red-400 rounded-r-full" style={{ width: `${(stats.failed_sign_ins / stats.total_sign_ins) * 100}%` }} />
              </div>
            </div>
          )}

          {/* Additional metrics row */}
          <div className="flex items-center gap-4 text-xs mb-4">
            <span className={`${stats.off_hours_pct > 50 ? 'text-orange-600 dark:text-orange-400' : 'text-gray-500 dark:text-slate-400'}`}>
              Off-Hours: {stats.off_hours_pct}%
            </span>
            <span className="text-gray-500 dark:text-slate-400">
              Peak Hour: {stats.peak_hour != null ? `${stats.peak_hour}:00 UTC` : '—'}
            </span>
            {stats.risk_sign_ins > 0 && (
              <span className="text-red-600 dark:text-red-400 font-medium">
                Risky Sign-Ins: {stats.risk_sign_ins}
              </span>
            )}
            {stats.ca_failures > 0 && (
              <span className="text-orange-600 dark:text-orange-400 font-medium">
                CA Failures: {stats.ca_failures}
              </span>
            )}
          </div>

          {/* Recent sign-ins table */}
          {signins.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-gray-600 dark:text-slate-400 mb-2">Recent Sign-Ins ({signins.length})</h4>
              <div className="overflow-x-auto border border-gray-200 dark:border-slate-700 rounded-lg max-h-[300px] overflow-y-auto">
                <table className="w-full text-xs">
                  <thead className="bg-gray-50 dark:bg-slate-800 text-gray-500 dark:text-slate-400 sticky top-0">
                    <tr>
                      <th className="text-left px-3 py-2 font-medium">Time</th>
                      <th className="text-left px-3 py-2 font-medium">Status</th>
                      <th className="text-left px-3 py-2 font-medium">Resource</th>
                      <th className="text-left px-3 py-2 font-medium">IP</th>
                      <th className="text-left px-3 py-2 font-medium">Location</th>
                      <th className="text-left px-3 py-2 font-medium">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-100 dark:divide-slate-800">
                    {signins.map((si, i) => (
                      <tr key={i} className="hover:bg-gray-50 dark:hover:bg-slate-800/50">
                        <td className="px-3 py-1.5 text-gray-500 dark:text-slate-400 whitespace-nowrap">{formatDateTime(si.created_datetime)}</td>
                        <td className="px-3 py-1.5">
                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                            si.status === 'success' ? 'bg-green-100 text-green-700 dark:bg-green-900/40 dark:text-green-300' : 'bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300'
                          }`}>{si.status === 'success' ? 'OK' : 'FAIL'}</span>
                        </td>
                        <td className="px-3 py-1.5 text-gray-700 dark:text-slate-300 max-w-[200px] truncate" title={si.resource_display_name}>
                          {si.resource_display_name || '—'}
                        </td>
                        <td className="px-3 py-1.5 font-mono text-gray-500 dark:text-slate-400">{si.ip_address || '—'}</td>
                        <td className="px-3 py-1.5 text-gray-500 dark:text-slate-400">
                          {[si.location_city, si.location_country].filter(Boolean).join(', ') || '—'}
                        </td>
                        <td className="px-3 py-1.5">
                          {si.risk_level && si.risk_level !== 'none' && (
                            <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${SEV_BADGE[si.risk_level] || 'bg-gray-100 text-gray-500'}`}>
                              {si.risk_level.toUpperCase()}
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="bg-gray-50 dark:bg-slate-800 border border-gray-200 dark:border-slate-700 rounded-lg p-4">
          <p className="text-xs text-gray-500 dark:text-slate-400">
            {!p2
              ? 'Enable Entra ID P2 telemetry in Settings to get detailed sign-in activity for workload identities.'
              : 'No sign-in data available for this identity yet.'}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Tab: Findings ────────────────────────────────────────────────────

function FindingsTab({ data }: { data: WorkloadDetailData }) {
  const findings = data.findings || [];
  const anomalies = data.anomalies || [];

  return (
    <div className="space-y-6">
      {/* Exposure Findings */}
      <div>
        <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-2">Exposure Findings ({findings.length})</h3>
        {findings.length === 0 ? (
          <p className="text-xs text-gray-400 dark:text-slate-500 italic">No exposure findings detected</p>
        ) : (
          <div className="space-y-2">
            {findings.map((f, i) => (
              <div key={i} className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-3">
                <div className="flex items-start gap-2">
                  <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold ${SEV_BADGE[f.severity] || 'bg-gray-100 text-gray-500'}`}>
                    {f.severity.toUpperCase()}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium text-gray-800 dark:text-slate-200">{f.title}</p>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-100 dark:bg-slate-800 text-gray-500 dark:text-slate-400">{f.component}</span>
                      {f.score_impact > 0 && (
                        <span className="text-[10px] text-red-500 font-medium">+{f.score_impact}</span>
                      )}
                    </div>
                    <p className="text-xs text-gray-500 dark:text-slate-400 mt-0.5">{f.description}</p>
                    {f.remediation && (
                      <p className="text-xs text-blue-600 dark:text-blue-400 mt-1">{f.remediation}</p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Behavioral Anomalies (P2) */}
      {anomalies.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-violet-700 dark:text-violet-400 mb-2">
            Behavioral Anomalies ({anomalies.filter(a => !a.resolved).length} unresolved)
          </h3>
          <div className="space-y-2">
            {anomalies.map(a => (
              <div key={a.id} className={`flex items-start gap-2 bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-lg p-3 ${a.resolved ? 'opacity-60' : ''}`}>
                <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold ${SEV_BADGE[a.severity] || 'bg-gray-100 text-gray-500'}`}>
                  {a.severity.toUpperCase()}
                </span>
                <div className="flex-1">
                  <p className="text-sm font-medium text-gray-800 dark:text-slate-200">{a.title}</p>
                  <p className="text-xs text-gray-400 dark:text-slate-500 mt-0.5">
                    {a.anomaly_type.replace(/_/g, ' ')} &middot; {formatDate(a.created_at)}
                    {a.resolved && <span className="ml-1 text-green-600 dark:text-green-400">(resolved)</span>}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Tab: Properties ──────────────────────────────────────────────────

function PropertiesTab({ data }: { data: WorkloadDetailData }) {
  const d = data.detail || {};
  const owners = data.owners || [];
  const recommendations = data.recommendations || [];

  const props: Array<{ label: string; value: string | React.ReactNode }> = [
    { label: 'Display Name', value: d.display_name || '—' },
    { label: 'Identity Type', value: data.identity_type },
    { label: 'Category', value: (d.identity_category || '').replace(/_/g, ' ') || '—' },
    { label: 'App ID', value: d.app_id ? <CopyField label="" value={d.app_id} /> : '—' },
    { label: 'Object ID', value: (d.object_id || d.app_object_id) ? <CopyField label="" value={d.object_id || d.app_object_id} /> : '—' },
    { label: 'Created', value: formatDate(d.created_datetime) },
    { label: 'Enabled', value: d.account_enabled != null ? (d.account_enabled ? 'Yes' : 'No') : '—' },
    { label: 'Activity Status', value: d.activity_status || '—' },
    { label: 'Last Sign-In', value: formatDate(d.last_sign_in || d.spn_last_sign_in) },
    { label: 'Cloud', value: d.cloud || 'azure' },
    { label: 'Blast Radius', value: data.blast_radius || '—' },
    { label: 'SPN Type', value: d.service_principal_type || d.sp_type || '—' },
  ];

  return (
    <div className="space-y-6">
      {/* Key-value grid */}
      <div className="grid grid-cols-2 gap-x-8 gap-y-2">
        {props.map((p, i) => (
          <div key={i} className="flex items-center justify-between py-1.5 border-b border-gray-100 dark:border-slate-800">
            <span className="text-xs text-gray-500 dark:text-slate-400">{p.label}</span>
            <span className="text-xs text-gray-800 dark:text-slate-200 font-medium text-right">{p.value}</span>
          </div>
        ))}
      </div>

      {/* Owners */}
      {owners.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-2">Owners ({owners.length})</h3>
          <div className="space-y-1.5">
            {owners.map((o, i) => (
              <div key={i} className="flex items-center gap-2 text-xs bg-gray-50 dark:bg-slate-800 rounded-lg px-3 py-2">
                <svg className="w-4 h-4 text-gray-400 dark:text-slate-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                </svg>
                <span className="font-medium text-gray-700 dark:text-slate-300">{o.owner_display_name || 'Unknown'}</span>
                {o.owner_upn && <span className="text-gray-400 dark:text-slate-500">({o.owner_upn})</span>}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {recommendations.length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-2">Recommendations</h3>
          <div className="space-y-1.5">
            {recommendations.map((rec, i) => (
              <div key={i} className="flex items-start gap-2 text-xs">
                <span className={`mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-bold ${SEV_BADGE[rec.priority] || 'bg-gray-100 text-gray-500'}`}>
                  {rec.priority.toUpperCase()}
                </span>
                <span className="text-gray-600 dark:text-slate-400">{rec.action}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Tab: Anomalies (inline) ──────────────────────────────────────────

function AnomaliesInlineTab({ anomalies }: { anomalies: Anomaly[] }) {
  if (anomalies.length === 0) {
    return <p className="text-xs text-gray-400 dark:text-slate-500 italic py-4">No anomalies detected</p>;
  }
  return (
    <div className="space-y-2">
      {anomalies.map(a => (
        <div key={a.id} className="flex items-start gap-3 p-3 rounded-lg border border-gray-100 dark:border-slate-700 bg-gray-50/50 dark:bg-slate-800/30">
          <span className={`mt-0.5 w-2 h-2 rounded-full flex-shrink-0 ${
            a.severity === 'critical' ? 'bg-red-500' :
            a.severity === 'high' ? 'bg-orange-500' :
            a.severity === 'medium' ? 'bg-yellow-500' : 'bg-blue-400'
          }`} />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <span className="text-xs font-medium text-gray-800 dark:text-slate-200">{a.title}</span>
              <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${SEV_BADGE[a.severity] || ''}`}>
                {a.severity.toUpperCase()}
              </span>
              {a.resolved && (
                <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400">RESOLVED</span>
              )}
            </div>
            <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-0.5">
              {a.anomaly_type.replace(/_/g, ' ')} — {formatDate(a.created_at)}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Tab: Ownership (inline) ─────────────────────────────────────────

function OwnersInlineTab({ owners }: { owners: Array<{ owner_display_name?: string; owner_upn?: string; owner_object_id?: string }> }) {
  if (owners.length === 0) {
    return (
      <div className="text-center py-6">
        <p className="text-xs text-gray-400 dark:text-slate-500 italic">No owners assigned</p>
        <p className="text-[10px] text-gray-400 dark:text-slate-500 mt-1">This identity has no assigned owner — governance gap</p>
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {owners.map((o, i) => (
        <div key={i} className="flex items-center gap-3 p-3 rounded-lg border border-gray-100 dark:border-slate-700 bg-gray-50/50 dark:bg-slate-800/30">
          <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-900/30 flex items-center justify-center text-blue-600 dark:text-blue-400 text-xs font-bold flex-shrink-0">
            {(o.owner_display_name || '?')[0].toUpperCase()}
          </div>
          <div className="flex-1 min-w-0">
            <p className="text-xs font-medium text-gray-800 dark:text-slate-200 truncate">{o.owner_display_name || 'Unknown'}</p>
            {o.owner_upn && <p className="text-[10px] text-gray-400 dark:text-slate-500 truncate">{o.owner_upn}</p>}
          </div>
          {o.owner_object_id && (
            <code className="text-[9px] text-gray-400 dark:text-slate-600 font-mono truncate max-w-[120px]" title={o.owner_object_id}>
              {o.owner_object_id.slice(0, 8)}...
            </code>
          )}
        </div>
      ))}
    </div>
  );
}

// ── Main Page Component ──────────────────────────────────────────────

const WorkloadIdentityDetail: React.FC = () => {
  const { id } = useParams<{ id: string }>();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const { withConnection } = useConnection();

  const type = searchParams.get('type') || 'spn';
  const [data, setData] = useState<WorkloadDetailData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>('roles');

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    setError(null);
    fetch(withConnection(`/api/workload-identities/${id}?type=${type}`))
      .then(r => {
        if (!r.ok) throw new Error(r.status === 404 ? 'Identity not found' : 'Failed to load identity');
        return r.json();
      })
      .then(setData)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [id, type]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="max-w-2xl mx-auto mt-12 text-center">
        <p className="text-gray-500 dark:text-slate-400 mb-4">{error || 'Identity not found'}</p>
        <button onClick={() => navigate('/workload-identities')}
          className="text-sm text-blue-600 dark:text-blue-400 hover:underline">
          Back to Workload Identities
        </button>
      </div>
    );
  }

  const exp = data.exposure;

  return (
    <div className="max-w-5xl mx-auto space-y-4">
      {/* Breadcrumb */}
      <button onClick={() => navigate('/workload-identities')}
        className="flex items-center gap-1 text-xs text-gray-500 dark:text-slate-400 hover:text-blue-600 dark:hover:text-blue-400 transition-colors">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" /></svg>
        <span>Workload Identities</span>
        <span className="text-gray-300 dark:text-slate-600 mx-1">/</span>
        <span className="text-gray-700 dark:text-slate-300 font-medium truncate max-w-[300px]">{data.display_name}</span>
      </button>

      {/* Header Card */}
      <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-xl p-5">
        {/* Top row: name + score */}
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 mb-1">
              <TypeBadge type={data.identity_type} />
              <h1 className="text-lg font-bold text-gray-900 dark:text-white truncate">{data.display_name}</h1>
            </div>
            <div className="flex flex-wrap items-center gap-3 mt-1">
              <CopyField label="App ID" value={data.detail?.app_id || data.detail?.app_id_external} />
              <CopyField label="Object ID" value={data.detail?.object_id || data.detail?.app_object_id} />
            </div>
          </div>
          <div className="flex items-center gap-3 flex-shrink-0">
            <ExposureRing score={exp.total} size={64} />
            <div className="text-right">
              <p className="text-xs text-gray-400 dark:text-slate-500">Exposure</p>
              <p className={`text-xl font-bold ${exposureColor(exp.total)}`}>{exp.total}/100</p>
              {exp.critical_overrides.length > 0 && (
                <span className="text-[9px] font-bold text-red-600 dark:text-red-400">OVERRIDE</span>
              )}
            </div>
          </div>
        </div>

        {/* Status badges */}
        <div className="flex flex-wrap gap-1.5 mt-3 pt-3 border-t border-gray-100 dark:border-slate-800">
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
            LIFECYCLE_STATE_CONFIG[exp.lifecycle_state]?.badgeClass || 'bg-gray-100 text-gray-500'
          }`}>{LIFECYCLE_STATE_CONFIG[exp.lifecycle_state]?.label || exp.lifecycle_state}</span>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
            OWNER_STATUS_CONFIG[exp.owner_status]?.badgeClass || 'bg-gray-100 text-gray-500'
          }`}>{OWNER_STATUS_CONFIG[exp.owner_status]?.label || exp.owner_status}</span>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${
            SCOPE_FLAG_CONFIG[exp.effective_scope_flag]?.badgeClass || 'bg-gray-100 text-gray-500'
          }`}>{SCOPE_FLAG_CONFIG[exp.effective_scope_flag]?.label || exp.effective_scope_flag}</span>
          {exp.can_escalate && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-100 text-red-700 dark:bg-red-900/40 dark:text-red-300">Can Escalate</span>
          )}
          {exp.cross_subscription && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300">Cross-Sub</span>
          )}
          {exp.federated_trust && (
            <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-blue-100 text-blue-700 dark:bg-blue-900/40 dark:text-blue-300">Federated</span>
          )}
        </div>

        {/* Metadata line */}
        <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-[11px] text-gray-400 dark:text-slate-500">
          <span>Created: {formatDate(data.detail?.created_datetime)}</span>
          <span>Last Sign-In: {formatDate(data.detail?.last_sign_in || data.detail?.spn_last_sign_in)}</span>
          {(data.owners || []).length > 0 && (
            <span>Owner: {data.owners![0].owner_display_name || 'Unknown'}{(data.owners || []).length > 1 ? ` +${(data.owners || []).length - 1}` : ''}</span>
          )}
          {data.blast_radius && <span>Blast Radius: {data.blast_radius}</span>}
        </div>
      </div>

      {/* Risk Breakdown Panel */}
      <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-700 dark:text-slate-300 mb-3">Risk Breakdown</h2>
        <div className="space-y-2">
          <ComponentBar label="Privilege" score={exp.privilege} max={40} signals={data.signals?.privilege} />
          <ComponentBar label="Cred Risk" score={exp.credential_risk} max={25} signals={data.signals?.credential} />
          <ComponentBar label="Exposure" score={exp.exposure} max={20} signals={data.signals?.exposure} />
          <ComponentBar label="Lifecycle" score={exp.lifecycle} max={10} signals={data.signals?.lifecycle} />
          <ComponentBar label="Visibility" score={exp.visibility} max={5} signals={data.signals?.visibility} />
        </div>

        {/* Critical overrides */}
        {exp.critical_overrides.length > 0 && (
          <div className="mt-3 pt-3 border-t border-gray-100 dark:border-slate-800 bg-red-50 dark:bg-red-900/10 rounded-lg p-3">
            <h4 className="text-xs font-semibold text-red-700 dark:text-red-300 mb-1">Critical Overrides (Score Forced to 100)</h4>
            {exp.critical_overrides.map((ov, i) => (
              <p key={i} className="text-xs text-red-600 dark:text-red-400">{ov.description}</p>
            ))}
          </div>
        )}
      </div>

      {/* Tab Bar */}
      <div className="bg-white dark:bg-slate-900 border border-gray-200 dark:border-slate-700 rounded-xl overflow-hidden">
        <div className="flex border-b border-gray-200 dark:border-slate-700 overflow-x-auto">
          {TABS.map(tab => (
            <button key={tab.key} onClick={() => setActiveTab(tab.key)}
              className={`px-4 py-2.5 text-xs font-medium whitespace-nowrap transition-colors ${
                activeTab === tab.key
                  ? 'text-blue-600 dark:text-blue-400 border-b-2 border-blue-600 dark:border-blue-400 bg-blue-50/50 dark:bg-blue-900/10'
                  : 'text-gray-500 dark:text-slate-400 hover:text-gray-700 dark:hover:text-slate-300'
              }`}>
              {tab.label}
              {tab.key === 'findings' && data.findings.length > 0 && (
                <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-[10px] bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-400">
                  {data.findings.length}
                </span>
              )}
              {tab.key === 'anomalies' && (data.anomalies?.length || 0) > 0 && (
                <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-[10px] bg-orange-100 dark:bg-orange-900/30 text-orange-600 dark:text-orange-400">
                  {data.anomalies!.length}
                </span>
              )}
              {tab.key === 'owners' && (data.owners?.length || 0) > 0 && (
                <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-[10px] bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-400">
                  {data.owners!.length}
                </span>
              )}
              {tab.key === 'roles' && ((data.roles?.length || 0) + (data.entra_roles?.length || 0)) > 0 && (
                <span className="ml-1.5 px-1.5 py-0.5 rounded-full text-[10px] bg-gray-100 dark:bg-slate-800 text-gray-600 dark:text-slate-400">
                  {(data.roles?.length || 0) + (data.entra_roles?.length || 0)}
                </span>
              )}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        <div className={activeTab === 'access_graph' ? '' : 'p-5'}>
          {activeTab === 'roles' && <RolesTab data={data} />}
          {activeTab === 'credentials' && <CredentialsTab data={data} />}
          {activeTab === 'access_graph' && (
            <AccessGraphTab identityId={data.detail?.identity_id || data.detail?.app_object_id || data.detail?.app_id || data.detail?.object_id || id || ''} />
          )}
          {activeTab === 'anomalies' && <AnomaliesInlineTab anomalies={data.anomalies || []} />}
          {activeTab === 'activity' && <ActivityTab data={data} />}
          {activeTab === 'findings' && <FindingsTab data={data} />}
          {activeTab === 'owners' && <OwnersInlineTab owners={data.owners || []} />}
          {activeTab === 'properties' && <PropertiesTab data={data} />}
        </div>
      </div>

      {/* Link to full identity detail (for SPN/MI) */}
      {data.identity_type !== 'app_registration' && !!data.detail?.identity_id && (
        <div className="text-center">
          <a href={`/identities/${encodeURIComponent(data.detail.identity_id)}`}
            className="text-xs text-blue-600 dark:text-blue-400 hover:underline">
            Open Full Identity Detail (Legacy View) →
          </a>
        </div>
      )}
    </div>
  );
};

export default WorkloadIdentityDetail;
