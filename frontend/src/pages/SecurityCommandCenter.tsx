import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCopilot } from '../contexts/CopilotContext';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import AudienceBadge from '../components/AudienceBadge';

// ─── Types ────────────────────────────────────────────────────────

/** Shape from GET /api/security/overview */
interface SecurityOverview {
  posture_score: number;
  risk_score: number;
  identities: {
    total: number;
    users: number;
    service_principals: number;
    managed_identities: number;
    guests: number;
  };
  findings: { critical: number; high: number; medium: number; low: number };
  nhi: {
    secrets_without_expiry: number;
    secrets_older_than_180_days: number;
    unused_service_principals: number;
  };
  attack_paths: { identities_with_paths: number };
  credentials: { total: number; expired: number; expiring_soon: number };
  cloud_providers: { cloud: string; identities: number; attack_paths: number; findings: number; subscriptions: number }[];
  discovery_metadata: { run_ids: number[]; data_as_of: string | null };
}

interface RiskyIdentity {
  identity_id: number;
  display_name: string;
  identity_category: string;
  risk_score: number;
  risk_level: string;
  activity_status: string;
  attack_path_count: number;
  rbac_role_count: number;
  entra_role_count: number;
}

interface FixRecommendation {
  id: number;
  fix_category: string;
  severity?: string;
  priority_score: number;
  title: string;
  description: string;
  entity_name: string | null;
  effort: string | null;
  status: string;
}

// SSOT: GET /api/remediation/generated — same source as Remediation Center page,
// so the Command Center headline never disagrees with the page it links to.
// (The separate /api/remediation-queue/summary endpoint covers the manual
// workflow board, which is a different concept and almost always empty.)
interface RemediationQueueSummary {
  open: number;
  critical: number;
  in_progress: number;
  completed_this_week: number;
}

interface ActivityEntry {
  id: number;
  action_type: string;
  description: string;
  user_display_name: string | null;
  user_username: string | null;
  created_at: string;
}

// ─── Badge Maps ───────────────────────────────────────────────────

// Cap the inline Top Risky Identities + Remediation Priority lists at the top
// items so the page stays above-the-fold; "View All" still routes to the full
// page (Identities / Remediation Center). Fetch limits are intentionally left
// higher so the cap is purely a render concern.
const ROW_CAP = 5;

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
};

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-emerald-500/20 text-emerald-400',
};

const CATEGORY_LABEL: Record<string, string> = {
  human_user: 'User',
  service_principal: 'SPN',
  managed_identity_system: 'Sys MI',
  managed_identity_user: 'User MI',
  guest: 'Guest',
};

const EFFORT_BADGE: Record<string, string> = {
  low: 'text-emerald-400',
  medium: 'text-yellow-400',
  high: 'text-orange-400',
};

// ─── Helpers ──────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

// ─── Main Component ───────────────────────────────────────────────

export default function SecurityCommandCenter() {
  const navigate = useNavigate();
  const { openCopilot } = useCopilot();
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  // Canonical Posture Score — the SAME number the CISO board renders
  // (/api/dashboard/posture), so the Command Center can't disagree with the
  // exec view. Previously this gauge read overview.posture_score which used a
  // different formula (privileged %) and disagreed with the CISO's 100-(crit+high)%
  // posture metric, causing the 93-vs-69 conflict. Kept on this page as a small
  // header chip (Command Center is the OPS view; the headline is queue health).
  const [cisoPostureScore, setCisoPostureScore] = useState<number | null>(null);
  // Remediation Queue Health — Command Center's real headline metric as an
  // OPS console: "what's in flight, what's stuck, what closed." SSOT:
  // /api/remediation-queue/summary.
  const [queueSummary, setQueueSummary] = useState<RemediationQueueSummary | null>(null);
  const [riskyIdentities, setRiskyIdentities] = useState<RiskyIdentity[]>([]);
  const [recommendations, setRecommendations] = useState<FixRecommendation[]>([]);
  const [activities, setActivities] = useState<ActivityEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [copilotSummary, setCopilotSummary] = useState<string | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      // Single primary call + lazy-loaded lists + canonical posture score + queue summary in parallel
      const [overviewRes, postureRes, queueRes, riskyRes, recsRes, activityRes] = await Promise.all([
        fetch(withConnection('/api/security/overview')),
        fetch(withConnection('/api/dashboard/posture')),
        fetch(withConnection('/api/remediation/generated')),
        fetch(withConnection('/api/identities?risk_level=critical&limit=10')),
        fetch(withConnection('/api/fix-recommendations?limit=10&status=open')),
        fetch(withConnection('/api/activity?limit=15')),
      ]);

      if (overviewRes.ok) setOverview(await overviewRes.json());

      // Canonical posture score (SSOT — same field the CISO board uses).
      // Fail-open: if this endpoint blips, gauge falls back to 0 (handled below)
      // rather than disagreeing with the CISO board with a stale/divergent value.
      if (postureRes.ok) {
        try {
          const p = await postureRes.json();
          const s = typeof p?.posture_score === 'number' ? p.posture_score : null;
          if (s !== null) setCisoPostureScore(s);
        } catch { /* ignore */ }
      }

      // Remediation queue summary (SSOT — /api/remediation/generated.stats).
      // Same source the Remediation Center page renders, so the two never
      // disagree. Empty/error → card renders empty-state cleanly.
      if (queueRes.ok) {
        try {
          const q = await queueRes.json();
          const s = q && typeof q === 'object' ? q.stats : null;
          if (s && typeof s === 'object') setQueueSummary(s as RemediationQueueSummary);
        } catch { /* ignore */ }
      }

      if (riskyRes.ok) {
        const d = await riskyRes.json();
        let identities = d.identities || [];
        // If fewer than 10 critical, backfill with high-risk
        if (identities.length < 10) {
          try {
            const highRes = await fetch(withConnection(`/api/identities?risk_level=high&limit=${10 - identities.length}`));
            if (highRes.ok) {
              const hd = await highRes.json();
              const existingIds = new Set(identities.map((i: RiskyIdentity) => i.identity_id));
              const highIdentities = (hd.identities || []).filter((i: RiskyIdentity) => !existingIds.has(i.identity_id));
              identities = [...identities, ...highIdentities];
            }
          } catch { /* ignore */ }
        }
        setRiskyIdentities(identities);
      }

      if (recsRes.ok) {
        const d = await recsRes.json();
        let recs = d.recommendations || [];
        // If no fix-recommendations, fall back to generated remediations
        if (recs.length === 0) {
          try {
            const genRes = await fetch(withConnection('/api/remediation/generated?limit=10'));
            if (genRes.ok) {
              const gd = await genRes.json();
              const generated = (gd.actions || gd.items || []).slice(0, 10);
              recs = generated.map((g: Record<string, unknown>) => ({
                id: g.id,
                title: g.title || g.action_title || 'Remediation Action',
                description: g.description || '',
                fix_category: g.condition_key || g.action_type || 'auto-generated',
                entity_name: g.identity_name || g.identity_display_name || null,
                effort: g.priority || g.severity || 'medium',
                priority_score: g.risk_reduction || g.confidence || 0,
              }));
            }
          } catch { /* ignore */ }
        }
        setRecommendations(recs);
      }

      if (activityRes.ok) {
        const d = await activityRes.json();
        setActivities(d.entries || []);
      }
    } catch (err) {
      console.error('Failed to fetch command center data:', err);
    } finally {
      setLoading(false);
    }
  }, [withConnection, selectedConnectionId, activeOrgId]);

  useEffect(() => { fetchAll(); }, [fetchAll]);

  const fetchSummary = useCallback(async () => {
    setSummaryLoading(true);
    try {
      const res = await fetch('/api/copilot/security-summary');
      if (res.ok) {
        const data = await res.json();
        setCopilotSummary(data.summary);
      }
    } catch { /* ignore */ }
    finally { setSummaryLoading(false); }
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading Security Command Center...</div>
      </div>
    );
  }

  // Derived metrics from overview
  // SSOT: prefer the canonical CISO posture score; fall back to 0 if not yet
  // loaded (gauge component handles 0 cleanly). Do NOT fall back to
  // overview.posture_score — that's a different metric (privileged %) and
  // mixing the two is what caused the 93-vs-69 inconsistency.
  const postureScore = cisoPostureScore !== null ? Math.round(cisoPostureScore) : 0;
  const find = overview?.findings || { critical: 0, high: 0, medium: 0, low: 0 };
  const attackPathCount = overview?.attack_paths?.identities_with_paths ?? 0;
  const cred = overview?.credentials || { total: 0, expired: 0, expiring_soon: 0 };
  const nhi = overview?.nhi || { secrets_without_expiry: 0, secrets_older_than_180_days: 0, unused_service_principals: 0 };
  const ident = overview?.identities || { total: 0, users: 0, service_principals: 0, managed_identities: 0, guests: 0 };

  // High-risk identities = critical + high from the risky list
  const highRiskCount = riskyIdentities.length;
  // Stale credentials = secrets older than 180 days
  const staleCredentials = nhi.secrets_older_than_180_days;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold text-white">Security Command Center</h1>
            <AudienceBadge label="OPS CONSOLE" variant="blue" />
          </div>
          <p className="text-sm text-slate-400 mt-1">
            Active risks and remediation queue — what needs action now
            {overview?.discovery_metadata?.data_as_of && (
              <span className="ml-3 text-slate-500">
                Data as of: {new Date(overview.discovery_metadata.data_as_of).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
              </span>
            )}
            <span className="ml-3 text-[11px] text-slate-500 hidden lg:inline">
              Related:{' '}
              <a href="/" className="text-blue-400 hover:text-blue-300 transition-colors">↗ Executive Posture</a>
              <span className="mx-1 text-slate-600">·</span>
              <a href="/dashboard" className="text-blue-400 hover:text-blue-300 transition-colors">↗ Risk Monitoring</a>
            </span>
          </p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={fetchSummary}
            disabled={summaryLoading}
            className="px-3 py-2 bg-indigo-600/20 hover:bg-indigo-600/30 text-indigo-400 border border-indigo-500/30 text-sm rounded-lg transition-colors disabled:opacity-50 flex items-center gap-1.5"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
            </svg>
            {summaryLoading ? 'Generating...' : 'AI Summary'}
          </button>
          <button
            onClick={() => openCopilot({ contextType: 'posture' })}
            className="px-3 py-2 text-sm rounded-lg transition-colors flex items-center gap-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z" />
            </svg>
            Ask Copilot
          </button>
        </div>
      </div>

      {/* Fallback: no data */}
      {!overview && (
        <div className="bg-slate-800/60 border border-amber-500/30 rounded-xl p-4 flex items-center gap-3">
          <svg className="w-5 h-5 text-amber-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-sm text-amber-300">
            No security data available yet. Run a discovery scan to populate the dashboard.
          </span>
        </div>
      )}

      {/* Row 1: Remediation Queue Health (ops headline) + Summary Cards.
          Was the Posture Score gauge — that's the CISO board's headline. Command
          Center's role is "what are we doing about it?" so the headline is queue
          health. Posture is still surfaced as a small header chip + cross-link. */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        <div className="lg:col-span-4 bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 flex flex-col items-center justify-center">
          <RemediationQueueCard summary={queueSummary} posture={postureScore} />
        </div>

        {/* Summary Cards */}
        <div className="lg:col-span-8 grid grid-cols-2 md:grid-cols-3 gap-3">
          <MetricCard
            label="Critical Findings"
            value={find.critical}
            color="text-red-400"
            bgColor="bg-red-500/10 border-red-500/20"
            onClick={() => navigate('/security-findings?severity=critical')}
          />
          <MetricCard
            label="High Findings"
            value={find.high}
            color="text-orange-400"
            bgColor="bg-orange-500/10 border-orange-500/20"
            onClick={() => navigate('/security-findings?severity=high')}
          />
          <MetricCard
            label="Attack Paths"
            value={attackPathCount}
            color="text-purple-400"
            bgColor="bg-purple-500/10 border-purple-500/20"
            onClick={() => navigate('/attack-paths')}
          />
          <MetricCard
            label="High Risk Identities"
            value={highRiskCount}
            color="text-amber-400"
            bgColor="bg-amber-500/10 border-amber-500/20"
            onClick={() => navigate('/identities?risk_level=high')}
          />
          <MetricCard
            label="Total Identities"
            value={ident.total}
            color="text-blue-400"
            bgColor="bg-blue-500/10 border-blue-500/20"
            onClick={() => navigate('/identities')}
          />
          <MetricCard
            label="Stale Credentials"
            value={staleCredentials}
            color="text-slate-400"
            bgColor="bg-slate-500/10 border-slate-500/20"
            onClick={() => navigate('/workload-identities')}
          />
        </div>
      </div>

      {/* Row 2: Risky Identities + Remediation Priority */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Top Risky Identities */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Top Risky Identities</h2>
            <button
              onClick={() => navigate('/identities?risk_level=high')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              View All
            </button>
          </div>
          <div className="divide-y divide-slate-700/30">
            {riskyIdentities.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">No risky identities found</div>
            ) : riskyIdentities.slice(0, ROW_CAP).map((identity) => (
              <button
                key={identity.identity_id}
                onClick={() => navigate(`/identities/${identity.identity_id}`)}
                className="w-full px-4 py-2.5 flex items-center gap-3 hover:bg-slate-700/30 transition-colors text-left"
              >
                <RiskBar score={identity.risk_score} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white truncate">{identity.display_name || `ID-${identity.identity_id}`}</div>
                  <div className="text-xs text-slate-500">
                    {CATEGORY_LABEL[identity.identity_category] || identity.identity_category}
                    {identity.attack_path_count > 0 && <span className="ml-2 text-red-400">{identity.attack_path_count} attack paths</span>}
                    {(identity.rbac_role_count + identity.entra_role_count) > 0 && (
                      <span className="ml-2 text-amber-400">{identity.rbac_role_count + identity.entra_role_count} roles</span>
                    )}
                  </div>
                </div>
                <span className={`px-2 py-0.5 text-xs rounded ${RISK_BADGE[identity.risk_level] || 'bg-slate-600 text-slate-300'}`}>
                  {identity.risk_level || 'unknown'}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Remediation Priority */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Remediation Priority</h2>
            <button
              onClick={() => navigate('/remediation')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              View All
            </button>
          </div>
          <div className="divide-y divide-slate-700/30">
            {recommendations.length === 0 ? (
              <div className="px-4 py-6 text-center">
                <div className="text-sm text-slate-500">No remediation actions generated yet.</div>
                <button onClick={() => navigate('/remediation')} className="text-xs text-blue-400 hover:text-blue-300 mt-1">Generate plan from findings →</button>
              </div>
            ) : recommendations.slice(0, ROW_CAP).map((rec) => (
              <div key={rec.id} className="px-4 py-2.5 flex items-start gap-3">
                <span className={`mt-0.5 px-2 py-0.5 text-[10px] font-medium rounded whitespace-nowrap ${SEVERITY_BADGE[rec.effort || 'medium'] || 'bg-slate-600 text-slate-300'}`}>
                  {(rec.effort || 'medium').toUpperCase()}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white truncate">{rec.title}</div>
                  <div className="text-xs text-slate-500 mt-0.5">
                    {rec.fix_category}
                    {rec.entity_name && <span className="ml-1">— {rec.entity_name}</span>}
                  </div>
                  {rec.description && (
                    <div className="text-xs text-emerald-400/80 mt-1 truncate">{rec.description}</div>
                  )}
                </div>
                <span className={`text-xs whitespace-nowrap ${EFFORT_BADGE[rec.effort || 'medium'] || 'text-slate-500'}`}>
                  Priority {rec.priority_score}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: NHI Security + Activity Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* NHI Security Overview */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl">
          <div className="px-4 py-3 border-b border-slate-700/50">
            <h2 className="text-sm font-semibold text-white">Credential & NHI Security</h2>
          </div>
          <div className="divide-y divide-slate-700/30">
            <div className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-700/30 transition-colors" onClick={() => navigate('/workload-identities')}>
              <span className="text-sm text-slate-300">Total credentials tracked</span>
              <span className="text-lg font-bold text-slate-300">{cred.total}</span>
            </div>
            <div className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-700/30 transition-colors" onClick={() => navigate('/workload-identities?credential_filter=expired')}>
              <span className="text-sm text-slate-300">Expired credentials</span>
              <span className={`text-lg font-bold ${cred.expired > 0 ? 'text-red-400' : 'text-slate-300'}`}>{cred.expired}</span>
            </div>
            <div className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-700/30 transition-colors" onClick={() => navigate('/workload-identities?credential_filter=expiring')}>
              <span className="text-sm text-slate-300">Expiring within 30 days</span>
              <span className={`text-lg font-bold ${cred.expiring_soon > 0 ? 'text-orange-400' : 'text-slate-300'}`}>{cred.expiring_soon}</span>
            </div>
            <div className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-700/30 transition-colors" onClick={() => navigate('/workload-identities?credential_filter=no_expiry')}>
              <span className="text-sm text-slate-300">Secrets without expiry</span>
              <span className={`text-lg font-bold ${nhi.secrets_without_expiry > 0 ? 'text-red-400' : 'text-slate-300'}`}>{nhi.secrets_without_expiry}</span>
            </div>
            <div className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-700/30 transition-colors" onClick={() => navigate('/workload-identities?credential_filter=old')}>
              <span className="text-sm text-slate-300">Secrets older than 180 days</span>
              <span className={`text-lg font-bold ${nhi.secrets_older_than_180_days > 0 ? 'text-orange-400' : 'text-slate-300'}`}>{nhi.secrets_older_than_180_days}</span>
            </div>
            <div className="px-4 py-3 flex items-center justify-between cursor-pointer hover:bg-slate-700/30 transition-colors" onClick={() => navigate('/identities?activity_status=never_used&identity_category=service_principal')}>
              <span className="text-sm text-slate-300">Unused service principals</span>
              <span className={`text-lg font-bold ${nhi.unused_service_principals > 0 ? 'text-yellow-400' : 'text-slate-300'}`}>{nhi.unused_service_principals}</span>
            </div>
          </div>
        </div>

        {/* Activity Timeline */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl">
          <div className="px-4 py-3 border-b border-slate-700/50 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Activity Timeline</h2>
            <button
              onClick={() => navigate('/activity')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              View All
            </button>
          </div>
          <div className="divide-y divide-slate-700/30 max-h-[400px] overflow-y-auto">
            {activities.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">No activity yet</div>
            ) : activities.map((entry) => (
              <div key={entry.id} className="px-4 py-2.5 flex items-start gap-3">
                <div className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${
                  entry.action_type.includes('delete') || entry.action_type.includes('fail') ? 'bg-red-400' :
                  entry.action_type.includes('create') || entry.action_type.includes('discover') ? 'bg-emerald-400' :
                  'bg-blue-400'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white">{entry.description || entry.action_type}</div>
                  {entry.user_display_name && (
                    <div className="text-xs text-blue-400 mt-0.5">{entry.user_display_name}</div>
                  )}
                </div>
                <span className="text-[10px] text-slate-600 whitespace-nowrap">{timeAgo(entry.created_at)}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* AI Security Summary */}
      {copilotSummary && (
        <div className="bg-indigo-500/5 border border-indigo-500/20 rounded-xl p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              <svg className="w-4 h-4 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
              <h2 className="text-sm font-semibold text-indigo-400">AI Security Summary</h2>
            </div>
            <button onClick={() => setCopilotSummary(null)} className="text-slate-500 hover:text-slate-400 text-xs">
              Dismiss
            </button>
          </div>
          <div className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed copilot-markdown">
            {copilotSummary}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────


/**
 * Remediation Queue Health — Command Center's headline metric as the ops view.
 * Active = open + in_progress (in-flight items). Sub-stats break out the queue
 * by status. A small posture chip + cross-link to Executive Posture preserves
 * the SSOT score on this page without it being the headline. Empty queue gets
 * a CTA so the page never dead-ends.
 */
function RemediationQueueCard({ summary, posture }: { summary: RemediationQueueSummary | null; posture: number }) {
  const navigate = useNavigate();

  if (!summary) {
    return (
      <div className="flex flex-col items-center w-full text-slate-500 text-xs">
        <div className="h-20 w-20 rounded-full bg-slate-700/30 animate-pulse mb-2" />
        Loading queue…
      </div>
    );
  }

  // /api/remediation/generated.stats shape: {open, critical, in_progress, completed_this_week}.
  // "open" here already excludes in-progress/completed — it's the new+planned bucket.
  const open = summary.open || 0;
  const inProg = summary.in_progress || 0;
  const completed = summary.completed_this_week || 0;
  const crit = summary.critical || 0;
  const active = open + inProg;

  // Big-number color reflects urgency: red if any critical, amber if any active, emerald if clear
  const headlineColor = crit > 0 ? '#ef4444' : active > 0 ? '#f59e0b' : '#22c55e';
  const statusLabel = active === 0 && completed === 0 ? 'Nothing to remediate'
                    : active === 0 ? 'All resolved this week'
                    : crit > 0 ? 'Critical items waiting'
                    : 'Items waiting';

  return (
    <div className="flex flex-col items-center w-full">
      <div className="text-xs text-slate-400 uppercase tracking-wider font-medium mb-2">Remediation Queue</div>
      <div className="text-5xl font-bold leading-none" style={{ color: headlineColor }}>{active}</div>
      <div className="text-xs mt-1" style={{ color: headlineColor }}>{statusLabel}</div>

      {(active > 0 || completed > 0) ? (
        <div className="text-[11px] text-slate-500 mt-3 flex items-center gap-3">
          <span>open <span className="text-amber-400 font-mono">{open}</span></span>
          <span className="text-slate-700">·</span>
          <span>in progress <span className="text-blue-400 font-mono">{inProg}</span></span>
          <span className="text-slate-700">·</span>
          <span>done this wk <span className="text-emerald-400 font-mono">{completed}</span></span>
        </div>
      ) : (
        <div className="text-[11px] text-slate-500 mt-3">No items — risk graph is clean</div>
      )}

      {crit > 0 && (
        <div className="text-[10px] text-red-400 mt-1">
          {crit} critical {crit === 1 ? 'item' : 'items'} need immediate action
        </div>
      )}

      <button
        onClick={() => navigate('/remediation')}
        className="text-[11px] text-blue-400 hover:text-blue-300 mt-3 transition-colors"
      >
        → Open Remediation Center
      </button>

      {/* Posture cross-reference — SSOT value preserved, but clearly framed as
          "see Executive Posture for the board view" rather than competing for
          headline space on the ops console. */}
      <div className="mt-3 pt-3 border-t border-slate-700/40 w-full flex items-center justify-center gap-2 text-[10px] text-slate-500">
        <span>Posture</span>
        <span className="font-mono font-semibold" style={{ color: scoreColor(posture) }}>{posture}</span>
        <span className="text-slate-700">·</span>
        <a href="/" className="text-blue-400 hover:text-blue-300 transition-colors">↗ Executive Posture</a>
      </div>
    </div>
  );
}

function MetricCard({ label, value, color, bgColor, onClick }: {
  label: string; value: number; color: string; bgColor: string; onClick?: () => void;
}) {
  return (
    <div
      className={`rounded-xl p-4 border ${bgColor} ${onClick ? 'cursor-pointer hover:brightness-125 transition-all' : ''}`}
      onClick={onClick}
    >
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
    </div>
  );
}

function RiskBar({ score }: { score: number }) {
  const width = Math.max(5, score);
  const color = score >= 80 ? '#ef4444' : score >= 60 ? '#f97316' : score >= 40 ? '#f59e0b' : '#3b82f6';
  return (
    <div className="flex items-center gap-2 w-16 flex-shrink-0">
      <div className="flex-1 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className="h-full rounded-full" style={{ width: `${width}%`, backgroundColor: color }} />
      </div>
      <span className="text-[10px] font-mono text-slate-400 w-6 text-right">{score}</span>
    </div>
  );
}
