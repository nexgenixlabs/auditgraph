import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useCopilot } from '../contexts/CopilotContext';

// ─── Types ────────────────────────────────────────────────────────

interface PostureScore {
  posture_score: number;
  previous_score: number | null;
  trend: number | null;
  critical_findings: number;
  high_findings: number;
  attack_paths_count: number;
  privileged_identities: number;
  stale_credentials: number;
  high_risk_identities: number;
}

interface RiskyIdentity {
  identity_id: number;
  identity_name: string;
  identity_type: string;
  risk_score: number;
  risk_level: string;
  identity_category: string;
  activity_status: string;
  attack_paths: number;
  privileged_roles: number;
  factors: Record<string, number>;
}

interface RemediationItem {
  id: number;
  finding_type: string;
  severity: string;
  risk_score: number;
  title: string;
  remediation: string;
  identity_name: string | null;
  identity_category: string | null;
}

interface PrivilegedIdentity {
  identity_id: number;
  display_name: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  activity_status: string;
  privileged_roles: string[];
  role_count: number;
}

interface SecurityEvent {
  id: number;
  event_type: string;
  severity: string;
  title: string;
  description: string | null;
  identity_name: string | null;
  created_at: string;
}

// ─── Badge Maps ───────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  warning: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  info: 'bg-slate-500/20 text-slate-400 border border-slate-500/30',
};

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400',
  high: 'bg-orange-500/20 text-orange-400',
  medium: 'bg-yellow-500/20 text-yellow-400',
  low: 'bg-emerald-500/20 text-emerald-400',
};

const TYPE_LABEL: Record<string, string> = {
  PRIVILEGE_ESCALATION: 'Priv Escalation',
  KEYVAULT_SECRET_ACCESS: 'KeyVault Access',
  SPN_SECRET_EXPOSURE: 'SPN Exposure',
  ROLE_CHAINING: 'Role Chaining',
};

const CATEGORY_LABEL: Record<string, string> = {
  human_user: 'User',
  service_principal: 'SPN',
  managed_identity_system: 'Sys MI',
  managed_identity_user: 'User MI',
  guest: 'Guest',
};

// ─── Helpers ──────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return '#10b981';
  if (score >= 60) return '#f59e0b';
  if (score >= 40) return '#f97316';
  return '#ef4444';
}

function scoreLabel(score: number): string {
  if (score >= 80) return 'Good';
  if (score >= 60) return 'Fair';
  if (score >= 40) return 'Poor';
  return 'Critical';
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
  const [posture, setPosture] = useState<PostureScore | null>(null);
  const [riskyIdentities, setRiskyIdentities] = useState<RiskyIdentity[]>([]);
  const [remediation, setRemediation] = useState<RemediationItem[]>([]);
  const [privileged, setPrivileged] = useState<PrivilegedIdentity[]>([]);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [copilotSummary, setCopilotSummary] = useState<string | null>(null);
  const [summaryLoading, setSummaryLoading] = useState(false);

  const fetchAll = useCallback(async () => {
    setLoading(true);
    try {
      const [postureRes, riskyRes, remRes, privRes, eventsRes] = await Promise.all([
        fetch('/api/posture-score'),
        fetch('/api/risky-identities?limit=10'),
        fetch('/api/remediation-priority?limit=10'),
        fetch('/api/privileged-identities?limit=10'),
        fetch('/api/security-events?limit=15'),
      ]);
      if (postureRes.ok) setPosture(await postureRes.json());
      if (riskyRes.ok) { const d = await riskyRes.json(); setRiskyIdentities(d.identities || []); }
      if (remRes.ok) { const d = await remRes.json(); setRemediation(d.items || []); }
      if (privRes.ok) { const d = await privRes.json(); setPrivileged(d.identities || []); }
      if (eventsRes.ok) { const d = await eventsRes.json(); setEvents(d.events || []); }
    } catch (err) {
      console.error('Failed to fetch command center data:', err);
    } finally {
      setLoading(false);
    }
  }, []);

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

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Command Center</h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time security posture, risk analysis, and remediation priorities
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

      {/* Row 1: Posture Score Gauge + Summary Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Posture Score Gauge */}
        <div className="lg:col-span-4 bg-slate-800/60 border border-slate-700/50 rounded-xl p-6 flex flex-col items-center justify-center">
          <PostureGauge score={posture?.posture_score ?? 0} trend={posture?.trend ?? null} />
        </div>

        {/* Summary Cards */}
        <div className="lg:col-span-8 grid grid-cols-2 md:grid-cols-3 gap-3">
          <MetricCard
            label="Critical Findings"
            value={posture?.critical_findings ?? 0}
            color="text-red-400"
            bgColor="bg-red-500/10 border-red-500/20"
          />
          <MetricCard
            label="High Findings"
            value={posture?.high_findings ?? 0}
            color="text-orange-400"
            bgColor="bg-orange-500/10 border-orange-500/20"
          />
          <MetricCard
            label="Attack Paths"
            value={posture?.attack_paths_count ?? 0}
            color="text-purple-400"
            bgColor="bg-purple-500/10 border-purple-500/20"
          />
          <MetricCard
            label="High Risk Identities"
            value={posture?.high_risk_identities ?? 0}
            color="text-amber-400"
            bgColor="bg-amber-500/10 border-amber-500/20"
          />
          <MetricCard
            label="Privileged Identities"
            value={posture?.privileged_identities ?? 0}
            color="text-blue-400"
            bgColor="bg-blue-500/10 border-blue-500/20"
          />
          <MetricCard
            label="Stale Credentials"
            value={posture?.stale_credentials ?? 0}
            color="text-slate-400"
            bgColor="bg-slate-500/10 border-slate-500/20"
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
              onClick={() => navigate('/identities')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              View All
            </button>
          </div>
          <div className="divide-y divide-slate-700/30">
            {riskyIdentities.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">No risky identities found</div>
            ) : riskyIdentities.map((identity) => (
              <button
                key={identity.identity_id}
                onClick={() => navigate(`/identities/${identity.identity_id}`)}
                className="w-full px-4 py-2.5 flex items-center gap-3 hover:bg-slate-700/30 transition-colors text-left"
              >
                <RiskBar score={identity.risk_score} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white truncate">{identity.identity_name || `ID-${identity.identity_id}`}</div>
                  <div className="text-xs text-slate-500">
                    {CATEGORY_LABEL[identity.identity_category] || identity.identity_category}
                    {identity.attack_paths > 0 && <span className="ml-2 text-red-400">{identity.attack_paths} attack paths</span>}
                    {identity.privileged_roles > 0 && <span className="ml-2 text-amber-400">{identity.privileged_roles} priv roles</span>}
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
              onClick={() => navigate('/graph-findings')}
              className="text-xs text-blue-400 hover:text-blue-300"
            >
              View All
            </button>
          </div>
          <div className="divide-y divide-slate-700/30">
            {remediation.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">No open findings</div>
            ) : remediation.map((item) => (
              <div key={item.id} className="px-4 py-2.5 flex items-start gap-3">
                <span className={`mt-0.5 px-2 py-0.5 text-[10px] font-medium rounded whitespace-nowrap ${SEVERITY_BADGE[item.severity] || 'bg-slate-600 text-slate-300'}`}>
                  {item.severity.toUpperCase()}
                </span>
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white truncate">{item.title}</div>
                  <div className="text-xs text-slate-500 mt-0.5">
                    {TYPE_LABEL[item.finding_type] || item.finding_type}
                    {item.identity_name && <span className="ml-1">— {item.identity_name}</span>}
                  </div>
                  {item.remediation && (
                    <div className="text-xs text-emerald-400/80 mt-1 truncate">{item.remediation}</div>
                  )}
                </div>
                <span className="text-xs text-slate-500 whitespace-nowrap">Risk {item.risk_score}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Row 3: Privileged Identities + Security Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Privileged Identities */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl">
          <div className="px-4 py-3 border-b border-slate-700/50">
            <h2 className="text-sm font-semibold text-white">Privileged Identities</h2>
          </div>
          <div className="divide-y divide-slate-700/30">
            {privileged.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">No privileged identities found</div>
            ) : privileged.map((p) => (
              <button
                key={p.identity_id}
                onClick={() => navigate(`/identities/${p.identity_id}`)}
                className="w-full px-4 py-2.5 flex items-center gap-3 hover:bg-slate-700/30 transition-colors text-left"
              >
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white truncate">{p.display_name}</div>
                  <div className="text-xs text-slate-500 flex flex-wrap gap-1 mt-0.5">
                    {(p.privileged_roles || []).slice(0, 3).map((role) => (
                      <span key={role} className="px-1.5 py-0.5 bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded text-[10px]">
                        {role}
                      </span>
                    ))}
                    {(p.privileged_roles || []).length > 3 && (
                      <span className="text-[10px] text-slate-500">+{p.privileged_roles.length - 3} more</span>
                    )}
                  </div>
                </div>
                <span className={`px-2 py-0.5 text-xs rounded ${RISK_BADGE[p.risk_level] || 'bg-slate-600 text-slate-300'}`}>
                  {p.risk_level || 'unknown'}
                </span>
              </button>
            ))}
          </div>
        </div>

        {/* Security Timeline */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl">
          <div className="px-4 py-3 border-b border-slate-700/50">
            <h2 className="text-sm font-semibold text-white">Security Timeline</h2>
          </div>
          <div className="divide-y divide-slate-700/30 max-h-[400px] overflow-y-auto">
            {events.length === 0 ? (
              <div className="px-4 py-6 text-center text-sm text-slate-500">No security events yet</div>
            ) : events.map((evt) => (
              <div key={evt.id} className="px-4 py-2.5 flex items-start gap-3">
                <div className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${
                  evt.severity === 'critical' ? 'bg-red-400' :
                  evt.severity === 'high' || evt.severity === 'warning' ? 'bg-orange-400' :
                  'bg-blue-400'
                }`} />
                <div className="flex-1 min-w-0">
                  <div className="text-sm text-white">{evt.title}</div>
                  {evt.description && <div className="text-xs text-slate-500 mt-0.5 truncate">{evt.description}</div>}
                  {evt.identity_name && <div className="text-xs text-blue-400 mt-0.5">{evt.identity_name}</div>}
                </div>
                <span className="text-[10px] text-slate-600 whitespace-nowrap">{timeAgo(evt.created_at)}</span>
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

      {/* Copilot is now in global CopilotPanel — opened via useCopilot() hook */}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────

function PostureGauge({ score, trend }: { score: number; trend: number | null }) {
  const color = scoreColor(score);
  const label = scoreLabel(score);
  // SVG arc for gauge
  const radius = 60;
  const circumference = Math.PI * radius; // semi-circle
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="flex flex-col items-center">
      <svg width="160" height="100" viewBox="0 0 160 100">
        {/* Background arc */}
        <path
          d="M 10 90 A 60 60 0 0 1 150 90"
          fill="none"
          stroke="#334155"
          strokeWidth="12"
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 10 90 A 60 60 0 0 1 150 90"
          fill="none"
          stroke={color}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={`${circumference}`}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 1s ease-out' }}
        />
        {/* Score text */}
        <text x="80" y="78" textAnchor="middle" fill="white" fontSize="28" fontWeight="bold">
          {score}
        </text>
        <text x="80" y="95" textAnchor="middle" fill={color} fontSize="12" fontWeight="500">
          {label}
        </text>
      </svg>
      <div className="text-xs text-slate-500 mt-1">Security Posture Score</div>
      {trend !== null && (
        <div className={`text-xs mt-1 ${trend > 0 ? 'text-emerald-400' : trend < 0 ? 'text-red-400' : 'text-slate-500'}`}>
          {trend > 0 ? '+' : ''}{trend} from previous scan
        </div>
      )}
    </div>
  );
}

function MetricCard({ label, value, color, bgColor }: { label: string; value: number; color: string; bgColor: string }) {
  return (
    <div className={`rounded-xl p-4 border ${bgColor}`}>
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
