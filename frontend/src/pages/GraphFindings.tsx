import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';

// ─── Types ────────────────────────────────────────────────────────

interface AttackPathNode { id: string; type: string; name: string; cloud?: string; }
interface AttackPathEdge { source: string; target: string; type: string; label?: string; }

interface GraphFinding {
  id: number;
  organization_id: number;
  identity_id: number | null;
  identity_name: string | null;
  identity_category: string | null;
  identity_risk_level: string | null;
  finding_type: string;
  severity: string;
  risk_score: number;
  title: string;
  description: string | null;
  attack_path: { nodes?: AttackPathNode[]; edges?: AttackPathEdge[]; depth?: number };
  remediation: string | null;
  discovery_run_id: number | null;
  fingerprint: string;
  status: string;
  assigned_to: string | null;
  ticket_id: string | null;
  suppressed_until: string | null;
  sla_deadline: string | null;
  sla_breached: boolean;
  created_at: string;
}

interface FindingStats {
  total: number; critical: number; high: number; medium: number;
  low: number; open: number; affected_identities: number; finding_types: number;
}

interface FindingComment {
  id: number; finding_id: number; username: string;
  comment: string; created_at: string;
}

interface RemediationMetrics {
  total: number; open_findings: number; open: number;
  acknowledged: number; in_progress: number;
  resolved_findings: number; ignored: number;
  mean_time_to_remediate_hours: number | null;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
}

// ─── Badge Maps ───────────────────────────────────────────────────

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
};

const STATUS_BADGE: Record<string, string> = {
  open: 'bg-red-500/20 text-red-400 border border-red-500/30',
  acknowledged: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30',
  in_progress: 'bg-blue-500/20 text-blue-400 border border-blue-500/30',
  resolved: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30',
  ignored: 'bg-slate-500/20 text-slate-400 border border-slate-500/30',
};

const STATUS_LABEL: Record<string, string> = {
  open: 'Open', acknowledged: 'Acknowledged', in_progress: 'In Progress',
  resolved: 'Resolved', ignored: 'Ignored',
};

const NEXT_STATUS: Record<string, string> = {
  open: 'acknowledged', acknowledged: 'in_progress',
  in_progress: 'resolved',
};

const TYPE_LABEL: Record<string, string> = {
  PRIVILEGE_ESCALATION: 'Privilege Escalation',
  KEYVAULT_SECRET_ACCESS: 'KeyVault Secret Access',
  SPN_SECRET_EXPOSURE: 'SPN Secret Exposure',
  ROLE_CHAINING: 'Role Chaining',
  CROSS_CLOUD_ESCALATION: 'Cross-Cloud Escalation',
  AWS_TRUST_ABUSE: 'AWS Trust Abuse',
  GCP_SA_IMPERSONATION: 'GCP SA Impersonation',
};

const TYPE_BADGE: Record<string, string> = {
  PRIVILEGE_ESCALATION: 'bg-red-500/15 text-red-400 border border-red-500/25',
  KEYVAULT_SECRET_ACCESS: 'bg-purple-500/15 text-purple-400 border border-purple-500/25',
  SPN_SECRET_EXPOSURE: 'bg-orange-500/15 text-orange-400 border border-orange-500/25',
  ROLE_CHAINING: 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/25',
  CROSS_CLOUD_ESCALATION: 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/25',
  AWS_TRUST_ABUSE: 'bg-amber-500/15 text-amber-400 border border-amber-500/25',
  GCP_SA_IMPERSONATION: 'bg-rose-500/15 text-rose-400 border border-rose-500/25',
};

const NODE_COLOR: Record<string, string> = {
  User: '#3b82f6', ServicePrincipal: '#8b5cf6', ManagedIdentity: '#06b6d4',
  Role: '#f59e0b', Resource: '#10b981', Subscription: '#6366f1', KeyVault: '#ec4899',
  AWSAccount: '#d97706', AWSPolicy: '#f59e0b', GCPProject: '#dc2626',
};

const selectCls = 'bg-slate-800 border border-slate-700 text-white text-sm rounded-lg px-3 py-2 focus:ring-blue-500 focus:border-blue-500';

// ─── Main Component ───────────────────────────────────────────────

export default function GraphFindings() {
  const navigate = useNavigate();
  const [findings, setFindings] = useState<GraphFinding[]>([]);
  const [stats, setStats] = useState<FindingStats | null>(null);
  const [metrics, setMetrics] = useState<RemediationMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [severityFilter, setSeverityFilter] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const fetchFindings = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (severityFilter) params.set('severity', severityFilter);
      if (typeFilter) params.set('type', typeFilter);
      if (statusFilter) params.set('status', statusFilter);
      params.set('limit', '100');
      const [findingsRes, metricsRes] = await Promise.all([
        fetch(`/api/graph-findings?${params.toString()}`),
        fetch('/api/remediation-metrics'),
      ]);
      if (findingsRes.ok) {
        const data = await findingsRes.json();
        setFindings(data.findings || []);
        setStats(data.stats || null);
      }
      if (metricsRes.ok) setMetrics(await metricsRes.json());
    } catch (err) {
      console.error('Failed to fetch graph findings:', err);
    } finally {
      setLoading(false);
    }
  }, [severityFilter, typeFilter, statusFilter]);

  useEffect(() => { fetchFindings(); }, [fetchFindings]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Attack Path Findings</h1>
          <p className="text-sm text-slate-400 mt-1">
            BFS-discovered privilege escalation paths with remediation workflow
          </p>
        </div>
        <div className="flex gap-2">
          <ExportDropdown />
          <button onClick={fetchFindings} className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm rounded-lg transition-colors">
            Refresh
          </button>
        </div>
      </div>

      {/* Metrics Bar */}
      {metrics && (
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <MetricCard label="Open" value={metrics.open_findings} color="text-red-400" bg="bg-red-500/10 border-red-500/20" />
          <MetricCard label="In Progress" value={metrics.in_progress} color="text-blue-400" bg="bg-blue-500/10 border-blue-500/20" />
          <MetricCard label="Resolved" value={metrics.resolved_findings} color="text-emerald-400" bg="bg-emerald-500/10 border-emerald-500/20" />
          <MetricCard label="Ignored" value={metrics.ignored} color="text-slate-400" bg="bg-slate-500/10 border-slate-500/20" />
          <MetricCard
            label="MTTR"
            value={metrics.mean_time_to_remediate_hours != null ? `${metrics.mean_time_to_remediate_hours}h` : '—'}
            color="text-amber-400" bg="bg-amber-500/10 border-amber-500/20"
          />
        </div>
      )}

      {/* Stats Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <MetricCard label="Total Findings" value={stats.total} color="text-white" bg="bg-slate-700/30 border-slate-600/30" />
          <MetricCard label="Critical" value={stats.critical} color="text-red-400" bg="bg-red-500/10 border-red-500/20" />
          <MetricCard label="High" value={stats.high} color="text-orange-400" bg="bg-orange-500/10 border-orange-500/20" />
          <MetricCard label="Affected Identities" value={stats.affected_identities} color="text-blue-400" bg="bg-blue-500/10 border-blue-500/20" />
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-3 flex-wrap">
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className={selectCls}>
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} className={selectCls}>
          <option value="">All Types</option>
          <option value="PRIVILEGE_ESCALATION">Privilege Escalation</option>
          <option value="KEYVAULT_SECRET_ACCESS">KeyVault Secret Access</option>
          <option value="SPN_SECRET_EXPOSURE">SPN Secret Exposure</option>
          <option value="ROLE_CHAINING">Role Chaining</option>
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={selectCls}>
          <option value="">Open (default)</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="in_progress">In Progress</option>
          <option value="resolved">Resolved</option>
          <option value="ignored">Ignored</option>
        </select>
      </div>

      {/* Findings List */}
      {loading ? (
        <div className="text-center text-slate-400 py-12">Loading findings...</div>
      ) : findings.length === 0 ? (
        <div className="text-center text-slate-500 py-12 bg-slate-800/50 rounded-xl border border-slate-700/50">
          <p className="text-lg font-medium">No attack path findings</p>
          <p className="text-sm mt-1">Run graph attack analysis to discover escalation paths</p>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((f) => (
            <FindingCard
              key={f.id}
              finding={f}
              expanded={expandedId === f.id}
              onToggle={() => setExpandedId(expandedId === f.id ? null : f.id)}
              onIdentityClick={(id) => navigate(`/identities/${id}`)}
              onRefresh={fetchFindings}
            />
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Sub-components ───────────────────────────────────────────────

function MetricCard({ label, value, color, bg }: { label: string; value: string | number; color: string; bg: string }) {
  return (
    <div className={`rounded-xl p-4 border ${bg}`}>
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-400 mt-1">{label}</div>
    </div>
  );
}

function FindingCard({
  finding, expanded, onToggle, onIdentityClick, onRefresh,
}: {
  finding: GraphFinding; expanded: boolean;
  onToggle: () => void; onIdentityClick: (id: number) => void;
  onRefresh: () => void;
}) {
  const nodes = finding.attack_path?.nodes || [];
  const edges = finding.attack_path?.edges || [];
  const [comments, setComments] = useState<FindingComment[]>([]);
  const [newComment, setNewComment] = useState('');
  const [assignEmail, setAssignEmail] = useState(finding.assigned_to || '');
  const [ticketId, setTicketId] = useState(finding.ticket_id || '');
  const [showAssign, setShowAssign] = useState(false);
  const [showTicket, setShowTicket] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);
  const [copilotAnswer, setCopilotAnswer] = useState<string | null>(null);
  const [copilotLoading, setCopilotLoading] = useState(false);

  const fetchComments = useCallback(async () => {
    try {
      const res = await fetch(`/api/findings/${finding.id}/comments`);
      if (res.ok) { const d = await res.json(); setComments(d.comments || []); }
    } catch { /* ignore */ }
  }, [finding.id]);

  useEffect(() => { if (expanded) fetchComments(); }, [expanded, fetchComments]);

  const updateStatus = async (status: string) => {
    setActionLoading(true);
    try {
      const body: Record<string, string> = { status };
      if (status === 'ignored') {
        const until = new Date(Date.now() + 30 * 86400000).toISOString();
        body.suppressed_until = until;
      }
      if (ticketId && status === 'in_progress') body.ticket_id = ticketId;
      const res = await fetch(`/api/findings/${finding.id}/status`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) onRefresh();
      else { const d = await res.json(); alert(d.error || 'Failed to update status'); }
    } catch { alert('Failed to update status'); }
    finally { setActionLoading(false); }
  };

  const assignFinding = async () => {
    if (!assignEmail.trim()) return;
    setActionLoading(true);
    try {
      const res = await fetch(`/api/findings/${finding.id}/assign`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ assigned_to: assignEmail.trim() }),
      });
      if (res.ok) { setShowAssign(false); onRefresh(); }
    } catch { alert('Failed to assign'); }
    finally { setActionLoading(false); }
  };

  const addComment = async () => {
    if (!newComment.trim()) return;
    setActionLoading(true);
    try {
      const res = await fetch(`/api/findings/${finding.id}/comments`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ comment: newComment.trim() }),
      });
      if (res.ok) { setNewComment(''); fetchComments(); }
    } catch { alert('Failed to add comment'); }
    finally { setActionLoading(false); }
  };

  const linkTicket = async () => {
    if (!ticketId.trim()) return;
    setActionLoading(true);
    try {
      // Use status update to attach ticket_id
      const res = await fetch(`/api/findings/${finding.id}/status`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: finding.status === 'open' ? 'acknowledged' : finding.status, ticket_id: ticketId.trim() }),
      });
      if (res.ok) { setShowTicket(false); onRefresh(); }
      else { const d = await res.json(); alert(d.error || 'Failed to link ticket'); }
    } catch { alert('Failed to link ticket'); }
    finally { setActionLoading(false); }
  };

  const askCopilot = async (question: string) => {
    setCopilotLoading(true);
    setCopilotAnswer(null);
    try {
      const res = await fetch('/api/copilot/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ question, context_type: 'finding', context_id: finding.id }),
      });
      if (res.ok) {
        const data = await res.json();
        setCopilotAnswer(data.answer);
      } else {
        const err = await res.json().catch(() => ({ error: 'Copilot unavailable' }));
        setCopilotAnswer(`Error: ${err.error}`);
      }
    } catch {
      setCopilotAnswer('Failed to reach copilot.');
    } finally {
      setCopilotLoading(false);
    }
  };

  const createJiraTicket = async () => {
    setActionLoading(true);
    try {
      const res = await fetch(`/api/findings/${finding.id}/jira`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      if (res.ok) onRefresh();
      else { const d = await res.json(); alert(d.error || 'Failed to create Jira ticket'); }
    } catch { alert('Failed to create Jira ticket'); }
    finally { setActionLoading(false); }
  };

  const nextStatus = NEXT_STATUS[finding.status];

  return (
    <div className="bg-slate-800/60 border border-slate-700/50 rounded-xl overflow-hidden">
      {/* Header row */}
      <button onClick={onToggle} className="w-full px-4 py-3 flex items-center gap-2 hover:bg-slate-700/30 transition-colors text-left">
        <span className={`px-2 py-0.5 text-xs font-medium rounded ${SEVERITY_BADGE[finding.severity] || 'bg-slate-600 text-slate-300'}`}>
          {finding.severity.toUpperCase()}
        </span>
        <span className={`px-2 py-0.5 text-xs font-medium rounded ${STATUS_BADGE[finding.status] || 'bg-slate-600 text-slate-300'}`}>
          {STATUS_LABEL[finding.status] || finding.status}
        </span>
        <span className={`px-2 py-0.5 text-xs font-medium rounded ${TYPE_BADGE[finding.finding_type] || 'bg-slate-600 text-slate-300'}`}>
          {TYPE_LABEL[finding.finding_type] || finding.finding_type}
        </span>
        <span className="text-sm text-white font-medium flex-1 truncate">{finding.title}</span>
        {finding.assigned_to && (
          <span className="text-[10px] text-slate-500 truncate max-w-[120px]" title={finding.assigned_to}>
            @ {finding.assigned_to}
          </span>
        )}
        {finding.ticket_id && (
          <span className="px-1.5 py-0.5 text-[10px] bg-indigo-500/15 text-indigo-400 border border-indigo-500/25 rounded">
            {finding.ticket_id}
          </span>
        )}
        <SlaBadge deadline={finding.sla_deadline} breached={finding.sla_breached} />
        <span className="text-xs text-slate-500">Risk {finding.risk_score}</span>
        <svg className={`w-4 h-4 text-slate-500 transition-transform ${expanded ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded detail */}
      {expanded && (
        <div className="px-4 pb-4 border-t border-slate-700/50 space-y-4">
          {/* Action buttons */}
          <div className="flex gap-2 flex-wrap mt-3">
            {nextStatus && (
              <button onClick={() => updateStatus(nextStatus)} disabled={actionLoading}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded-lg transition-colors disabled:opacity-50">
                {nextStatus === 'acknowledged' ? 'Acknowledge' : nextStatus === 'in_progress' ? 'Start Work' : 'Resolve'}
              </button>
            )}
            {finding.status === 'open' && (
              <button onClick={() => updateStatus('ignored')} disabled={actionLoading}
                className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs rounded-lg transition-colors disabled:opacity-50">
                Suppress (30d)
              </button>
            )}
            {(finding.status === 'resolved' || finding.status === 'ignored') && (
              <button onClick={() => updateStatus('open')} disabled={actionLoading}
                className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs rounded-lg transition-colors disabled:opacity-50">
                Reopen
              </button>
            )}
            <button onClick={() => setShowAssign(!showAssign)}
              className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs rounded-lg transition-colors">
              {finding.assigned_to ? 'Reassign' : 'Assign'}
            </button>
            <button onClick={() => setShowTicket(!showTicket)}
              className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs rounded-lg transition-colors">
              {finding.ticket_id ? 'Update Ticket' : 'Link Ticket'}
            </button>
            {!finding.ticket_id && (
              <button onClick={createJiraTicket} disabled={actionLoading}
                className="px-3 py-1.5 bg-blue-500/15 hover:bg-blue-500/25 text-blue-400 border border-blue-500/25 text-xs rounded-lg transition-colors disabled:opacity-50">
                Create Jira Ticket
              </button>
            )}
            <button onClick={() => askCopilot('Explain this attack path')} disabled={copilotLoading}
              className="px-3 py-1.5 bg-indigo-500/15 hover:bg-indigo-500/25 text-indigo-400 border border-indigo-500/25 text-xs rounded-lg transition-colors disabled:opacity-50 flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
              </svg>
              Explain
            </button>
            <button onClick={() => askCopilot('How do I remediate this finding?')} disabled={copilotLoading}
              className="px-3 py-1.5 bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-400 border border-emerald-500/25 text-xs rounded-lg transition-colors disabled:opacity-50 flex items-center gap-1">
              <svg className="w-3 h-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Remediate
            </button>
          </div>

          {/* Assign input */}
          {showAssign && (
            <div className="flex gap-2 items-center">
              <input type="email" value={assignEmail} onChange={(e) => setAssignEmail(e.target.value)}
                placeholder="user@company.com"
                className="flex-1 bg-slate-900 border border-slate-700 text-white text-sm rounded-lg px-3 py-1.5" />
              <button onClick={assignFinding} disabled={actionLoading}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded-lg disabled:opacity-50">
                Save
              </button>
            </div>
          )}

          {/* Ticket input */}
          {showTicket && (
            <div className="flex gap-2 items-center">
              <input type="text" value={ticketId} onChange={(e) => setTicketId(e.target.value)}
                placeholder="JIRA-1234 or ticket URL"
                className="flex-1 bg-slate-900 border border-slate-700 text-white text-sm rounded-lg px-3 py-1.5" />
              <button onClick={linkTicket} disabled={actionLoading}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded-lg disabled:opacity-50">
                Link
              </button>
            </div>
          )}

          {/* Description */}
          {finding.description && (
            <div>
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Description</div>
              <p className="text-sm text-slate-300">{finding.description}</p>
            </div>
          )}

          {/* Identity link */}
          {finding.identity_id && (
            <div>
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Affected Identity</div>
              <button onClick={() => onIdentityClick(finding.identity_id!)}
                className="text-sm text-blue-400 hover:text-blue-300 hover:underline">
                {finding.identity_name || `Identity #${finding.identity_id}`}
                {finding.identity_category && <span className="ml-2 text-xs text-slate-500">({finding.identity_category})</span>}
              </button>
            </div>
          )}

          {/* Attack Path Visualization */}
          {nodes.length > 0 && (
            <div>
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">Attack Path ({nodes.length} steps)</div>
              <div className="bg-slate-900/60 rounded-lg p-4 overflow-x-auto">
                <div className="flex items-center gap-2 min-w-max">
                  {nodes.map((node, idx) => (
                    <React.Fragment key={node.id}>
                      <div className="flex flex-col items-center gap-1 px-3 py-2 rounded-lg border"
                        style={{ borderColor: NODE_COLOR[node.type] || '#64748b', backgroundColor: `${NODE_COLOR[node.type] || '#64748b'}15` }}>
                        <div className="flex items-center gap-1">
                          {node.cloud && (
                            <span className={`px-1 py-px rounded text-[7px] font-bold uppercase ${
                              node.cloud === 'aws' ? 'bg-amber-900/40 text-amber-300' :
                              node.cloud === 'gcp' ? 'bg-red-900/40 text-red-300' :
                              'bg-blue-900/40 text-blue-300'
                            }`}>{node.cloud}</span>
                          )}
                          <span className="text-[10px] font-mono uppercase tracking-wider" style={{ color: NODE_COLOR[node.type] || '#94a3b8' }}>
                            {node.type}
                          </span>
                        </div>
                        <span className="text-xs text-white font-medium max-w-[140px] truncate" title={node.name}>{node.name}</span>
                      </div>
                      {idx < nodes.length - 1 && (
                        <div className="flex flex-col items-center">
                          <span className="text-[9px] text-slate-500 mb-0.5">{edges[idx]?.type?.replace(/_/g, ' ') || ''}</span>
                          <svg className="w-5 h-3 text-slate-600" fill="none" stroke="currentColor" viewBox="0 0 20 12">
                            <path d="M0 6h16m0 0l-4-4m4 4l-4 4" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" />
                          </svg>
                        </div>
                      )}
                    </React.Fragment>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <div>
              <div className="text-xs text-slate-500 uppercase tracking-wider mb-1">Remediation</div>
              <p className="text-sm text-emerald-400/90 bg-emerald-500/10 rounded-lg px-3 py-2 border border-emerald-500/20">
                {finding.remediation}
              </p>
            </div>
          )}

          {/* Copilot Answer */}
          {(copilotLoading || copilotAnswer) && (
            <div className="bg-indigo-500/5 border border-indigo-500/20 rounded-lg p-3">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5">
                  <svg className="w-3.5 h-3.5 text-indigo-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                  </svg>
                  <span className="text-xs font-medium text-indigo-400">AI Copilot</span>
                </div>
                {copilotAnswer && (
                  <button onClick={() => setCopilotAnswer(null)} className="text-[10px] text-slate-500 hover:text-slate-400">
                    Dismiss
                  </button>
                )}
              </div>
              {copilotLoading ? (
                <div className="text-sm text-slate-400 flex items-center gap-1">
                  Analyzing
                  <span className="inline-flex gap-0.5">
                    <span className="animate-bounce" style={{ animationDelay: '0ms' }}>.</span>
                    <span className="animate-bounce" style={{ animationDelay: '150ms' }}>.</span>
                    <span className="animate-bounce" style={{ animationDelay: '300ms' }}>.</span>
                  </span>
                </div>
              ) : (
                <div className="text-sm text-slate-300 whitespace-pre-wrap leading-relaxed">{copilotAnswer}</div>
              )}
            </div>
          )}

          {/* Comments */}
          <div>
            <div className="text-xs text-slate-500 uppercase tracking-wider mb-2">
              Comments ({comments.length})
            </div>
            {comments.length > 0 && (
              <div className="space-y-2 mb-3 max-h-[200px] overflow-y-auto">
                {comments.map((c) => (
                  <div key={c.id} className="bg-slate-900/60 rounded-lg px-3 py-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs text-blue-400 font-medium">{c.username}</span>
                      <span className="text-[10px] text-slate-600">
                        {new Date(c.created_at).toLocaleString()}
                      </span>
                    </div>
                    <p className="text-sm text-slate-300 mt-1">{c.comment}</p>
                  </div>
                ))}
              </div>
            )}
            <div className="flex gap-2">
              <input type="text" value={newComment} onChange={(e) => setNewComment(e.target.value)}
                placeholder="Add a comment..."
                onKeyDown={(e) => e.key === 'Enter' && addComment()}
                className="flex-1 bg-slate-900 border border-slate-700 text-white text-sm rounded-lg px-3 py-1.5" />
              <button onClick={addComment} disabled={actionLoading || !newComment.trim()}
                className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white text-xs rounded-lg disabled:opacity-50">
                Post
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

function SlaBadge({ deadline, breached }: { deadline: string | null; breached: boolean }) {
  if (!deadline) return null;
  const dt = new Date(deadline);
  const now = new Date();
  const hoursLeft = Math.round((dt.getTime() - now.getTime()) / 3600000);

  if (breached) {
    return (
      <span className="px-1.5 py-0.5 text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 rounded font-medium animate-pulse">
        SLA BREACHED
      </span>
    );
  }
  if (hoursLeft <= 8) {
    return (
      <span className="px-1.5 py-0.5 text-[10px] bg-orange-500/20 text-orange-400 border border-orange-500/30 rounded">
        SLA {hoursLeft}h left
      </span>
    );
  }
  return (
    <span className="px-1.5 py-0.5 text-[10px] bg-slate-500/15 text-slate-400 border border-slate-500/25 rounded">
      SLA {hoursLeft > 24 ? `${Math.round(hoursLeft / 24)}d` : `${hoursLeft}h`}
    </span>
  );
}

function ExportDropdown() {
  const [open, setOpen] = useState(false);

  const exportData = async (format: 'csv' | 'json', type: 'findings' | 'posture' | 'remediation') => {
    setOpen(false);
    try {
      const res = await fetch(`/api/reports/${type}?format=${format}`);
      if (!res.ok) { alert('Export failed'); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${type}_report.${format}`;
      a.click();
      URL.revokeObjectURL(url);
    } catch { alert('Export failed'); }
  };

  return (
    <div className="relative">
      <button onClick={() => setOpen(!open)}
        className="px-3 py-2 bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm rounded-lg transition-colors flex items-center gap-1.5">
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
        </svg>
        Export
      </button>
      {open && (
        <>
          <div className="fixed inset-0 z-40" onClick={() => setOpen(false)} />
          <div className="absolute right-0 mt-1 w-48 bg-slate-800 border border-slate-700 rounded-lg shadow-xl z-50 py-1">
            <div className="px-3 py-1.5 text-[10px] text-slate-500 uppercase tracking-wider">Findings</div>
            <button onClick={() => exportData('csv', 'findings')} className="w-full px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700 text-left">CSV</button>
            <button onClick={() => exportData('json', 'findings')} className="w-full px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700 text-left">JSON</button>
            <div className="border-t border-slate-700 my-1" />
            <div className="px-3 py-1.5 text-[10px] text-slate-500 uppercase tracking-wider">Posture</div>
            <button onClick={() => exportData('csv', 'posture')} className="w-full px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700 text-left">CSV</button>
            <button onClick={() => exportData('json', 'posture')} className="w-full px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700 text-left">JSON</button>
            <div className="border-t border-slate-700 my-1" />
            <div className="px-3 py-1.5 text-[10px] text-slate-500 uppercase tracking-wider">Remediation</div>
            <button onClick={() => exportData('csv', 'remediation')} className="w-full px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700 text-left">CSV</button>
            <button onClick={() => exportData('json', 'remediation')} className="w-full px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700 text-left">JSON</button>
          </div>
        </>
      )}
    </div>
  );
}
