/**
 * Identity Detail — Enterprise v1
 *
 * Four-tab layout wired to the Phase 3 identity engine:
 *   Tab 1: Overview — metadata, state summary, risk breakdown, owners
 *   Tab 2: Blast Radius — ReactFlow graph of BFS traversal result
 *   Tab 3: Activity & Timeline — chronological activity signals
 *   Tab 4: Simulations — past what-if runs + new simulation panel
 *
 * Each tab implements 4 states: loading, partial, error, empty.
 * Per-tab error boundaries prevent cascading failures.
 */

import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import {
  getIdentityState,
  getIdentitySimulations,
  runSimulation,
  exportSimulation,
  listIdentities,
  type IdentityState,
  type IdentityListRow,
  type WhatIfSimulationItem,
  type WhatIfSimulationListResponse,
  type WhatIfResult,
  type SimulationType,
  type SimulationFindingArtifact,
  type BlastRadiusResult,
  type RiskFactor,
  type DataContextDTO,
  type BuilderDataSource,
  type RoleAssignment,
  type PrivilegeLevel,
} from '../services/identityEngineApi';
import {
  ReactFlow,
  Controls,
  Background,
  type Node,
  type Edge,
  Position,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';

// ── Theme constants ──────────────────────────────────────────────────

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#fbbf24',
  low: '#22c55e',
  info: '#3b82f6',
};

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-900/30 text-red-400 border-red-700/40',
  high: 'bg-orange-900/30 text-orange-400 border-orange-700/40',
  medium: 'bg-yellow-900/30 text-yellow-400 border-yellow-700/40',
  low: 'bg-green-900/30 text-green-400 border-green-700/40',
  info: 'bg-blue-900/30 text-blue-400 border-blue-700/40',
};

const LIFECYCLE_COLORS: Record<string, string> = {
  active: 'text-green-400', dormant: 'text-amber-400',
  provisioned: 'text-blue-400', disabled: 'text-gray-500', expired: 'text-red-400',
};

const GOVERNANCE_BADGE: Record<string, { label: string; cls: string }> = {
  governed: { label: 'Governed', cls: 'bg-green-900/30 text-green-400 border-green-700/40' },
  ungoverned: { label: 'Ungoverned', cls: 'bg-amber-900/30 text-amber-400 border-amber-700/40' },
  orphaned: { label: 'Orphaned', cls: 'bg-red-900/30 text-red-400 border-red-700/40' },
  policy_violation: { label: 'Violation', cls: 'bg-red-900/30 text-red-400 border-red-700/40' },
};

const PRIVILEGE_BADGE: Record<string, { label: string; cls: string }> = {
  highly_privileged: { label: 'Highly Privileged', cls: 'bg-red-900/30 text-red-400 border-red-700/40' },
  privileged: { label: 'Privileged', cls: 'bg-orange-900/30 text-orange-400 border-orange-700/40' },
  standard: { label: 'Standard', cls: 'bg-slate-800/40 text-slate-400 border-slate-700/40' },
};

const NODE_COLORS: Record<string, string> = {
  identity: '#3b82f6',
  role: '#a855f7',
  resource: '#f97316',
  permission: '#6366f1',
  default: '#64748b',
};

// ── Helpers ──────────────────────────────────────────────────────────

function formatDate(iso: string | null | undefined): string {
  if (!iso) return '\u2014';
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

function formatRelativeTime(iso: string | null | undefined): string {
  if (!iso) return 'Unknown';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return 'Just now';
  const mins = Math.floor(ms / 60_000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo ago`;
  return `${Math.floor(months / 12)}y ago`;
}

function capitalize(s: string): string {
  return s.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function dataSourceLabel(ds: BuilderDataSource): string {
  const map: Record<string, string> = {
    full: 'Full data', partial: 'Partial data', stale: 'Stale data', none: 'No data',
  };
  return map[ds] || ds;
}

// ── Skeleton loaders ─────────────────────────────────────────────────

function SkeletonBlock({ lines = 3, className = '' }: { lines?: number; className?: string }) {
  return (
    <div className={`space-y-3 ${className}`}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} className="h-4 rounded bg-slate-700/50 animate-pulse" style={{ width: `${70 + (i * 8) % 30}%` }} />
      ))}
    </div>
  );
}

function SkeletonCard() {
  return (
    <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-5">
      <SkeletonBlock lines={4} />
    </div>
  );
}

// ── Error boundary wrapper ───────────────────────────────────────────

class TabErrorBoundary extends React.Component<
  { tab: string; children: React.ReactNode },
  { error: Error | null }
> {
  state = { error: null as Error | null };
  static getDerivedStateFromError(error: Error) { return { error }; }
  render() {
    if (this.state.error) {
      return (
        <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-6 text-center">
          <p className="text-red-400 font-medium mb-2">Error loading {this.props.tab} tab</p>
          <p className="text-sm text-red-300/70 mb-4">{this.state.error.message}</p>
          <button
            onClick={() => this.setState({ error: null })}
            className="px-4 py-2 bg-red-800/40 hover:bg-red-700/40 rounded text-red-300 text-sm transition-colors"
          >
            Retry
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ── Tab 1: Overview ──────────────────────────────────────────────────

function OverviewTab({ state }: { state: IdentityState }) {
  const { profile, activity, governance, privilege, risk, ownership } = state;
  const riskBadge = RISK_BADGE[risk.label] || RISK_BADGE.info;
  const lifecycleColor = LIFECYCLE_COLORS[activity.lifecycle_state] || 'text-gray-400';
  const govBadge = GOVERNANCE_BADGE[governance.classification] || GOVERNANCE_BADGE.ungoverned;
  const privBadge = PRIVILEGE_BADGE[privilege.privilege_level] || PRIVILEGE_BADGE.standard;

  return (
    <div className="space-y-6">
      {/* Identity metadata */}
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-5">
        <h3 className="text-lg font-semibold mb-4">Identity Profile</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
          <Field label="Display Name" value={profile.display_name} />
          <Field label="Type" value={capitalize(profile.identity_type)} />
          <Field label="Cloud" value={profile.cloud_id.toUpperCase()} />
          <Field label="Status" value={capitalize(profile.status)} />
          <Field label="UPN" value={profile.user_principal_name || '\u2014'} />
          <Field label="Source" value={capitalize(profile.source)} />
          <Field label="Created" value={formatDate(profile.created_at)} />
          <Field label="Last Modified" value={formatDate(profile.last_modified_at)} />
          <Field label="Discovered" value={formatDate(profile.discovered_at)} />
        </div>
      </div>

      {/* State summary card */}
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-5">
        <h3 className="text-lg font-semibold mb-4">Current State</h3>
        <div className="grid grid-cols-3 gap-6">
          <div>
            <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-wider">Lifecycle</span>
            <p className={`text-lg font-semibold mt-1 ${lifecycleColor}`}>
              {capitalize(activity.lifecycle_state)}
            </p>
            {activity.data_source !== 'full' && (
              <p className="text-xs text-[var(--text-tertiary)] mt-1" title={`Missing: ${activity.missing_signals.join(', ') || 'none'}`}>
                {dataSourceLabel(activity.data_source)}
              </p>
            )}
          </div>
          <div>
            <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-wider">Governance</span>
            <p className="mt-1">
              <span className={`inline-block px-2 py-0.5 text-sm rounded-full border ${govBadge.cls}`}>
                {govBadge.label}
              </span>
            </p>
          </div>
          <div>
            <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-wider">Privilege</span>
            <p className="mt-1">
              <span className={`inline-block px-2 py-0.5 text-sm rounded-full border ${privBadge.cls}`}>
                {privBadge.label}
              </span>
            </p>
            <p className="text-xs text-[var(--text-tertiary)] mt-1">
              {privilege.total_role_count} roles ({privilege.highly_privileged_role_count} critical)
            </p>
          </div>
        </div>
      </div>

      {/* Risk score */}
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold">Risk Score</h3>
          <span className={`inline-block px-3 py-1 text-sm rounded-full border font-bold ${riskBadge}`}>
            {risk.score.toFixed(1)} \u2014 {risk.label.toUpperCase()}
          </span>
        </div>
        {risk.factors.length > 0 ? (
          <div className="space-y-3">
            {risk.factors.map((f, i) => (
              <RiskFactorBar key={i} factor={f} maxScore={risk.score || 100} />
            ))}
          </div>
        ) : (
          <p className="text-sm text-[var(--text-tertiary)]">No risk factors computed for this identity.</p>
        )}
      </div>

      {/* Owner information */}
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-5">
        <h3 className="text-lg font-semibold mb-4">Ownership</h3>
        {ownership.owners.length === 0 ? (
          <div className="bg-amber-900/20 border border-amber-700/40 rounded-lg p-4">
            <p className="text-amber-400 font-medium">No owner assigned</p>
            <p className="text-sm text-amber-300/70 mt-1">
              This identity has no assigned owner. Assign an owner to improve governance posture.
            </p>
          </div>
        ) : (
          <div className="space-y-2">
            {ownership.owners.map((o) => (
              <div key={o.id} className="flex items-center justify-between py-2 border-b border-[var(--border-subtle)] last:border-0">
                <div>
                  <span className="font-medium">{o.name}</span>
                  <span className="text-xs text-[var(--text-tertiary)] ml-2">{o.type}</span>
                </div>
                <div className="text-sm text-[var(--text-secondary)]">
                  {o.last_active_days != null ? `Active ${o.last_active_days}d ago` : '\u2014'}
                  {o.has_reviewed && <span className="ml-2 text-green-400 text-xs">Reviewed</span>}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-wider">{label}</span>
      <p className="text-[var(--text-primary)] mt-0.5">{value || '\u2014'}</p>
    </div>
  );
}

function RiskFactorBar({ factor, maxScore }: { factor: RiskFactor; maxScore: number }) {
  const pct = maxScore > 0 ? Math.min((factor.contribution / maxScore) * 100, 100) : 0;
  const color = RISK_COLORS[factor.severity] || RISK_COLORS.info;
  return (
    <div>
      <div className="flex items-center justify-between text-sm mb-1">
        <span className="text-[var(--text-secondary)]">{factor.label || capitalize(factor.dimension)}</span>
        <span style={{ color }}>{factor.contribution.toFixed(1)}</span>
      </div>
      <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>
    </div>
  );
}

// ── Tab 2: Blast Radius ──────────────────────────────────────────────

function BlastRadiusTab({ blastRadius, identityName }: { blastRadius: BlastRadiusResult | null; identityName: string }) {
  if (!blastRadius || blastRadius.total_reachable === 0) {
    return (
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-8 text-center">
        <p className="text-[var(--text-secondary)] text-lg mb-2">No reachable resources found</p>
        <p className="text-sm text-[var(--text-tertiary)]">
          Graph data may not yet be populated for this identity. Run a discovery scan to populate blast radius data.
        </p>
      </div>
    );
  }

  const { nodes, edges } = buildBlastRadiusGraph(blastRadius, identityName);

  return (
    <div className="space-y-4">
      {/* Summary stats */}
      <div className="grid grid-cols-4 gap-4">
        <StatCard label="Total Reachable" value={blastRadius.total_reachable} />
        <StatCard label="Traversal Depth" value={blastRadius.traversal_depth} />
        <StatCard label="Critical Resources" value={blastRadius.critical_resources.length} color="text-red-400" />
        <StatCard label="High Resources" value={blastRadius.high_resources.length} color="text-orange-400" />
      </div>

      {/* Path type breakdown */}
      {Object.keys(blastRadius.reachable_by_path_type).length > 0 && (
        <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-4">
          <h4 className="text-sm font-medium text-[var(--text-secondary)] mb-2">Reachable by Path Type</h4>
          <div className="flex flex-wrap gap-3">
            {Object.entries(blastRadius.reachable_by_path_type).map(([type, count]) => (
              <span key={type} className="px-3 py-1 bg-slate-800/60 rounded-full text-sm">
                <span className="text-[var(--text-tertiary)]">{type}:</span>{' '}
                <span className="font-medium">{count}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Graph visualization */}
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg overflow-hidden" style={{ height: 500 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          fitView
          nodesDraggable
          nodesConnectable={false}
          proOptions={{ hideAttribution: true }}
          defaultEdgeOptions={{ style: { stroke: '#475569', strokeWidth: 1.5 } }}
        >
          <Controls className="!bg-slate-800 !border-slate-700" />
          <Background color="#1e293b" gap={20} />
        </ReactFlow>
      </div>

      {blastRadius.truncated && (
        <p className="text-xs text-amber-400">
          Traversal was truncated at max depth/paths. The full blast radius may be larger.
        </p>
      )}
    </div>
  );
}

function StatCard({ label, value, color = 'text-[var(--text-primary)]' }: { label: string; value: number; color?: string }) {
  return (
    <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-4 text-center">
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      <p className="text-xs text-[var(--text-tertiary)] mt-1">{label}</p>
    </div>
  );
}

function buildBlastRadiusGraph(br: BlastRadiusResult, identityName: string) {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // Center identity node
  nodes.push({
    id: 'identity',
    type: 'default',
    position: { x: 400, y: 50 },
    sourcePosition: Position.Bottom,
    data: { label: identityName },
    style: {
      background: NODE_COLORS.identity,
      color: '#fff',
      border: `2px solid ${NODE_COLORS.identity}`,
      borderRadius: 8,
      padding: '8px 16px',
      fontSize: 12,
      fontWeight: 600,
    },
  });

  let nodeIndex = 0;
  const addResourceNodes = (resources: { id: string; name: string; type: string; sensitivity: string }[], yOffset: number) => {
    resources.forEach((r, i) => {
      const nodeId = `resource-${nodeIndex++}`;
      const xSpread = resources.length > 1 ? 200 : 0;
      const xOffset = (i - (resources.length - 1) / 2) * xSpread;
      nodes.push({
        id: nodeId,
        type: 'default',
        position: { x: 400 + xOffset, y: yOffset },
        targetPosition: Position.Top,
        data: { label: `${r.name}\n(${r.type})` },
        style: {
          background: '#1e293b',
          color: '#f8fafc',
          border: `2px solid ${NODE_COLORS.resource}`,
          borderRadius: 8,
          padding: '8px 12px',
          fontSize: 11,
          whiteSpace: 'pre-line' as const,
          textAlign: 'center' as const,
        },
      });
      edges.push({
        id: `e-identity-${nodeId}`,
        source: 'identity',
        target: nodeId,
        label: r.sensitivity,
        labelStyle: { fontSize: 10, fill: '#94a3b8' },
        style: { stroke: NODE_COLORS.resource, strokeWidth: 1.5 },
      });
    });
  };

  // Critical resources
  if (br.critical_resources.length > 0) addResourceNodes(br.critical_resources, 200);
  // High resources
  if (br.high_resources.length > 0) addResourceNodes(br.high_resources, 350);
  // Medium resources
  if (br.medium_resources.length > 0) addResourceNodes(br.medium_resources, 500);

  // If no individual resources listed but total_reachable > 0, show a summary node
  if (br.critical_resources.length === 0 && br.high_resources.length === 0 && br.medium_resources.length === 0 && br.total_reachable > 0) {
    nodes.push({
      id: 'summary',
      type: 'default',
      position: { x: 400, y: 200 },
      targetPosition: Position.Top,
      data: { label: `${br.total_reachable} reachable resources` },
      style: {
        background: '#1e293b',
        color: '#f8fafc',
        border: `2px solid ${NODE_COLORS.resource}`,
        borderRadius: 8,
        padding: '8px 16px',
        fontSize: 12,
      },
    });
    edges.push({
      id: 'e-identity-summary',
      source: 'identity',
      target: 'summary',
      style: { stroke: NODE_COLORS.resource, strokeWidth: 1.5 },
    });
  }

  return { nodes, edges };
}

// ── Tab 3: Activity & Timeline ───────────────────────────────────────

function ActivityTab({ activity }: { activity: IdentityState['activity'] }) {
  if (activity.data_source === 'none') {
    return (
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-8 text-center">
        <p className="text-[var(--text-secondary)] text-lg mb-2">No activity signals available</p>
        <p className="text-sm text-[var(--text-tertiary)]">
          AuditGraph delivers full Tier 1 analysis without activity logs. Connect Azure AD P2 telemetry for enhanced activity tracking.
        </p>
      </div>
    );
  }

  const events: { date: string; type: string; detail: string; confidence: string }[] = [];

  if (activity.last_sign_in_at) {
    events.push({
      date: activity.last_sign_in_at,
      type: 'Sign-In',
      detail: 'Last sign-in recorded',
      confidence: activity.activity_confidence,
    });
  }
  if (activity.last_activity_at) {
    events.push({
      date: activity.last_activity_at,
      type: 'Activity',
      detail: 'Last activity recorded',
      confidence: activity.activity_confidence,
    });
  }

  // Sort newest first
  events.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());

  return (
    <div className="space-y-4">
      {/* Activity summary */}
      <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-5">
        <h3 className="text-lg font-semibold mb-4">Activity Summary</h3>
        <div className="grid grid-cols-4 gap-4 text-sm">
          <Field label="Lifecycle State" value={capitalize(activity.lifecycle_state)} />
          <Field label="Last Sign-In" value={formatRelativeTime(activity.last_sign_in_at)} />
          <Field label="Days Inactive" value={activity.days_since_last_activity != null ? String(activity.days_since_last_activity) : '\u2014'} />
          <Field label="Confidence" value={capitalize(activity.activity_confidence)} />
        </div>
        <div className="mt-3 flex items-center gap-2 text-xs">
          <span className={`px-2 py-0.5 rounded-full ${activity.has_p2_telemetry ? 'bg-green-900/30 text-green-400' : 'bg-slate-800 text-slate-500'}`}>
            {activity.has_p2_telemetry ? 'P2 Telemetry Active' : 'No P2 Telemetry'}
          </span>
          <span className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400">
            {dataSourceLabel(activity.data_source)}
          </span>
        </div>
      </div>

      {/* Timeline */}
      {events.length === 0 ? (
        <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-6 text-center">
          <p className="text-[var(--text-secondary)]">No timestamped events available</p>
          <p className="text-xs text-[var(--text-tertiary)] mt-1">
            Activity data is inferred from metadata. Connect Azure AD sign-in logs for detailed timeline.
          </p>
        </div>
      ) : (
        <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-5">
          <h3 className="text-lg font-semibold mb-4">Timeline</h3>
          <div className="space-y-4">
            {events.map((ev, i) => (
              <div key={i} className="flex items-start gap-4">
                <div className="flex flex-col items-center">
                  <div className="w-3 h-3 rounded-full bg-blue-500 border-2 border-blue-300/30" />
                  {i < events.length - 1 && <div className="w-px h-8 bg-slate-700" />}
                </div>
                <div className="flex-1 pb-4">
                  <div className="flex items-center justify-between">
                    <span className="font-medium text-sm">{ev.type}</span>
                    <span className="text-xs text-[var(--text-tertiary)]">{formatDate(ev.date)}</span>
                  </div>
                  <p className="text-sm text-[var(--text-secondary)] mt-0.5">{ev.detail}</p>
                  <span className="text-xs text-[var(--text-tertiary)]">Confidence: {ev.confidence}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Missing signals */}
      {activity.missing_signals.length > 0 && (
        <div className="bg-slate-800/40 border border-slate-700/40 rounded-lg p-4 text-sm">
          <p className="text-[var(--text-tertiary)]">
            Missing signals: {activity.missing_signals.join(', ')}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Tab 4: Simulations ───────────────────────────────────────────────

function SimulationsTab({ identityId, identityState }: { identityId: string; identityState: IdentityState }) {
  const [simulations, setSimulations] = useState<WhatIfSimulationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showNewPanel, setShowNewPanel] = useState(false);
  const [exportingId, setExportingId] = useState<string | null>(null);

  const fetchSimulations = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const resp = await getIdentitySimulations(identityId);
      setSimulations(resp.items);
    } catch (err: any) {
      setError(err?.message || 'Failed to load simulations');
    } finally {
      setLoading(false);
    }
  }, [identityId]);

  useEffect(() => { fetchSimulations(); }, [fetchSimulations]);

  const handleExport = useCallback(async (simId: string) => {
    setExportingId(simId);
    try {
      const artifact = await exportSimulation(identityId, simId);
      const blob = new Blob([JSON.stringify(artifact, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `simulation-${simId.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      // Silently fail export — non-critical
    } finally {
      setExportingId(null);
    }
  }, [identityId]);

  if (loading) return <SkeletonBlock lines={5} />;

  if (error) {
    return (
      <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-6 text-center">
        <p className="text-red-400 mb-2">{error}</p>
        <button onClick={fetchSimulations} className="px-4 py-2 bg-red-800/40 rounded text-red-300 text-sm">Retry</button>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-lg font-semibold">What-If Simulations</h3>
        <button
          onClick={() => setShowNewPanel(!showNewPanel)}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg transition-colors"
        >
          {showNewPanel ? 'Cancel' : 'Run New Simulation'}
        </button>
      </div>

      {showNewPanel && (
        <NewSimulationPanel
          identityId={identityId}
          identityState={identityState}
          onComplete={() => {
            setShowNewPanel(false);
            fetchSimulations();
          }}
        />
      )}

      {simulations.length === 0 ? (
        <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg p-8 text-center">
          <p className="text-[var(--text-secondary)] text-lg mb-2">No simulations yet</p>
          <p className="text-sm text-[var(--text-tertiary)]">
            Run a what-if simulation to see the impact of changes before applying them.
            Simulations calculate the blast radius delta of hypothetical remediation actions.
          </p>
        </div>
      ) : (
        <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-[var(--bg-surface)] border-b border-[var(--border-default)]">
                <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Type</th>
                <th className="text-right px-4 py-3 font-medium text-[var(--text-secondary)]">Before</th>
                <th className="text-center px-4 py-3 font-medium text-[var(--text-secondary)]" />
                <th className="text-right px-4 py-3 font-medium text-[var(--text-secondary)]">After</th>
                <th className="text-right px-4 py-3 font-medium text-[var(--text-secondary)]">Score Delta</th>
                <th className="text-right px-4 py-3 font-medium text-[var(--text-secondary)]">Date</th>
                <th className="text-center px-4 py-3 font-medium text-[var(--text-secondary)]">Export</th>
              </tr>
            </thead>
            <tbody>
              {simulations.map((sim) => {
                const delta = sim.score_delta;
                const deltaColor = delta < 0 ? 'text-green-400' : delta > 0 ? 'text-red-400' : 'text-gray-400';
                return (
                  <tr key={sim.id} className="border-b border-[var(--border-subtle)] hover:bg-[var(--bg-surface)]">
                    <td className="px-4 py-3 font-medium">{capitalize(sim.simulation_type)}</td>
                    <td className="px-4 py-3 text-right">{sim.blast_radius_before}</td>
                    <td className="px-4 py-3 text-center text-[var(--text-tertiary)]">\u2192</td>
                    <td className="px-4 py-3 text-right">{sim.blast_radius_after}</td>
                    <td className={`px-4 py-3 text-right font-mono ${deltaColor}`}>
                      {delta > 0 ? '+' : ''}{delta.toFixed(1)}
                    </td>
                    <td className="px-4 py-3 text-right text-[var(--text-tertiary)]">
                      {formatRelativeTime(sim.simulated_at)}
                    </td>
                    <td className="px-4 py-3 text-center">
                      <button
                        onClick={() => handleExport(sim.id)}
                        disabled={exportingId === sim.id}
                        className="text-blue-400 hover:text-blue-300 text-xs disabled:opacity-50"
                      >
                        {exportingId === sim.id ? '...' : 'Export'}
                      </button>
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

// ── Privilege level ordering for one-step-down constraint ──
const PRIVILEGE_ORDER: PrivilegeLevel[] = ['highly_privileged', 'privileged', 'standard'];

function NewSimulationPanel({
  identityId,
  identityState,
  onComplete,
}: {
  identityId: string;
  identityState: IdentityState;
  onComplete: (result: WhatIfResult) => void;
}) {
  const [simType, setSimType] = useState<SimulationType>('ROLE_REMOVAL');
  const [selectedRole, setSelectedRole] = useState('');
  const [targetPrivilege, setTargetPrivilege] = useState('');
  const [ownerSearch, setOwnerSearch] = useState('');
  const [ownerResults, setOwnerResults] = useState<IdentityListRow[]>([]);
  const [selectedOwner, setSelectedOwner] = useState('');
  const [ownerSearching, setOwnerSearching] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<WhatIfResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const roles: RoleAssignment[] = identityState?.roles?.roles || [];
  const currentPrivilege = identityState?.privilege?.privilege_level || 'standard';
  const currentPrivIdx = PRIVILEGE_ORDER.indexOf(currentPrivilege as PrivilegeLevel);
  const validTargets = currentPrivIdx >= 0 && currentPrivIdx < PRIVILEGE_ORDER.length - 1
    ? [PRIVILEGE_ORDER[currentPrivIdx + 1]] : [];

  useEffect(() => {
    setSelectedRole('');
    setTargetPrivilege(validTargets[0] || '');
    setSelectedOwner('');
    setOwnerSearch('');
    setOwnerResults([]);
    setResult(null);
    setError(null);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [simType]);

  useEffect(() => {
    if (simType !== 'OWNERSHIP_ASSIGNMENT' || ownerSearch.length < 2) {
      setOwnerResults([]); return;
    }
    const timer = setTimeout(async () => {
      setOwnerSearching(true);
      try {
        const resp = await listIdentities({ limit: 20, identity_type: 'human_user' });
        setOwnerResults(resp.items.filter(i =>
          i.display_name.toLowerCase().includes(ownerSearch.toLowerCase())
        ).slice(0, 10));
      } catch { setOwnerResults([]); }
      finally { setOwnerSearching(false); }
    }, 300);
    return () => clearTimeout(timer);
  }, [ownerSearch, simType]);

  const isValid = useMemo(() => {
    if (simType === 'ROLE_REMOVAL') return !!selectedRole;
    if (simType === 'PRIVILEGE_REDUCTION') return !!targetPrivilege && validTargets.length > 0;
    if (simType === 'OWNERSHIP_ASSIGNMENT') return !!selectedOwner;
    return false;
  }, [simType, selectedRole, targetPrivilege, selectedOwner, validTargets]);

  const buildPayload = (): Record<string, any> => {
    if (simType === 'ROLE_REMOVAL') return { role: selectedRole };
    if (simType === 'PRIVILEGE_REDUCTION') return { target_level: targetPrivilege };
    if (simType === 'OWNERSHIP_ASSIGNMENT') return { owner: selectedOwner };
    return {};
  };

  const handleSubmit = async () => {
    if (!isValid) return;
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const res = await runSimulation(identityId, simType, buildPayload());
      setResult(res);
    } catch (err: any) {
      setError(err?.message || 'Simulation failed');
    } finally {
      setSubmitting(false);
    }
  };

  const confidence = result ? (
    roles.length > 0 && result.before?.governance ? 'HIGH' :
    result.before?.risk_score > 0 ? 'MEDIUM' : 'LOW'
  ) : null;

  return (
    <div className="bg-[var(--bg-raised)] border border-blue-700/40 rounded-lg p-5 space-y-4">
      <h4 className="font-semibold">New Simulation</h4>

      {/* Type selector */}
      <div>
        <label className="block text-xs text-[var(--text-tertiary)] mb-1">Simulation Type</label>
        <select
          value={simType}
          onChange={(e) => setSimType(e.target.value as SimulationType)}
          className="w-full bg-[var(--bg-surface)] border border-[var(--border-default)] rounded px-3 py-2 text-sm"
        >
          <option value="ROLE_REMOVAL">Role Removal</option>
          <option value="PRIVILEGE_REDUCTION">Privilege Reduction</option>
          <option value="OWNERSHIP_ASSIGNMENT">Ownership Assignment</option>
        </select>
      </div>

      {/* ROLE_REMOVAL: dropdown of current roles */}
      {simType === 'ROLE_REMOVAL' && (
        <div>
          <label className="block text-xs text-[var(--text-tertiary)] mb-1">
            Role to Remove ({roles.length} assigned)
          </label>
          {roles.length === 0 ? (
            <p className="text-sm text-[var(--text-tertiary)]">No role assignments found.</p>
          ) : (
            <select
              value={selectedRole}
              onChange={(e) => setSelectedRole(e.target.value)}
              className="w-full bg-[var(--bg-surface)] border border-[var(--border-default)] rounded px-3 py-2 text-sm"
            >
              <option value="">Select a role...</option>
              {roles.map((r, i) => (
                <option key={`${r.role_key}-${i}`} value={r.role_name}>
                  {r.role_name} ({r.scope_level})
                </option>
              ))}
            </select>
          )}
        </div>
      )}

      {/* PRIVILEGE_REDUCTION: one step down */}
      {simType === 'PRIVILEGE_REDUCTION' && (
        <div>
          <label className="block text-xs text-[var(--text-tertiary)] mb-1">Privilege Level</label>
          <p className="text-sm mb-2">
            Current: <span className="font-medium">{currentPrivilege.replace(/_/g, ' ')}</span>
          </p>
          {validTargets.length === 0 ? (
            <p className="text-sm text-[var(--text-tertiary)]">Already at lowest level.</p>
          ) : (
            <select
              value={targetPrivilege}
              onChange={(e) => setTargetPrivilege(e.target.value)}
              className="w-full bg-[var(--bg-surface)] border border-[var(--border-default)] rounded px-3 py-2 text-sm"
            >
              {validTargets.map(t => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
          )}
        </div>
      )}

      {/* OWNERSHIP_ASSIGNMENT: typeahead search */}
      {simType === 'OWNERSHIP_ASSIGNMENT' && (
        <div>
          <label className="block text-xs text-[var(--text-tertiary)] mb-1">Search for Owner</label>
          <input
            type="text"
            value={selectedOwner || ownerSearch}
            onChange={(e) => { setOwnerSearch(e.target.value); setSelectedOwner(''); }}
            className="w-full bg-[var(--bg-surface)] border border-[var(--border-default)] rounded px-3 py-2 text-sm"
            placeholder="Type to search identities..."
          />
          {ownerSearching && <p className="text-xs text-[var(--text-tertiary)] mt-1">Searching...</p>}
          {ownerResults.length > 0 && !selectedOwner && (
            <div className="mt-1 bg-[var(--bg-surface)] border border-[var(--border-default)] rounded max-h-40 overflow-y-auto">
              {ownerResults.map(r => (
                <button key={r.identity_id}
                  onClick={() => { setSelectedOwner(r.display_name); setOwnerSearch(''); setOwnerResults([]); }}
                  className="w-full text-left px-3 py-2 text-sm hover:bg-[var(--bg-raised)] transition-colors"
                >
                  {r.display_name}
                  <span className="text-xs text-[var(--text-tertiary)] ml-2">{r.identity_type.replace(/_/g, ' ')}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Submit */}
      <div className="flex items-center gap-3">
        <button
          onClick={handleSubmit}
          disabled={submitting || !isValid}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm rounded-lg transition-colors"
        >
          {submitting ? 'Running...' : 'Run Simulation'}
        </button>
        {error && <span className="text-sm text-red-400">{error}</span>}
      </div>

      {/* Before/After Diff Card */}
      {result && (
        <div className="bg-[var(--bg-surface)] border border-[var(--border-default)] rounded-lg p-4 space-y-4">
          <div className="flex items-center justify-between">
            <h5 className="font-medium text-sm">Simulation Result</h5>
            {confidence && (
              <span className={`text-xs px-2 py-0.5 rounded ${
                confidence === 'HIGH' ? 'bg-green-900/30 text-green-400' :
                confidence === 'MEDIUM' ? 'bg-yellow-900/30 text-yellow-400' :
                'bg-red-900/30 text-red-400'
              }`}>
                {confidence} confidence
              </span>
            )}
          </div>

          <div className="grid grid-cols-3 gap-4 text-sm">
            <div>
              <span className="text-xs text-[var(--text-tertiary)]">Risk Score Before</span>
              <p className="text-lg font-bold">{result.before?.risk_score?.toFixed(1) ?? result.blast_radius_before}</p>
            </div>
            <div className="text-center">
              <span className="text-xs text-[var(--text-tertiary)]">Delta</span>
              <p className={`text-lg font-bold ${result.score_delta < 0 ? 'text-green-400' : result.score_delta > 0 ? 'text-red-400' : 'text-gray-400'}`}>
                {result.score_delta > 0 ? '+' : ''}{result.score_delta.toFixed(1)}
              </p>
            </div>
            <div className="text-right">
              <span className="text-xs text-[var(--text-tertiary)]">Risk Score After</span>
              <p className="text-lg font-bold">{result.after?.risk_score?.toFixed(1) ?? result.blast_radius_after}</p>
            </div>
          </div>

          <div className="grid grid-cols-3 gap-4 text-sm border-t border-[var(--border-subtle)] pt-3">
            <div>
              <span className="text-xs text-[var(--text-tertiary)]">Blast Radius</span>
              <p className="font-mono">{result.blast_radius_before}</p>
            </div>
            <div className="text-center text-[var(--text-tertiary)]">{'\u2192'}</div>
            <div className="text-right">
              <span className="text-xs text-[var(--text-tertiary)]">Blast Radius</span>
              <p className="font-mono">{result.blast_radius_after}</p>
            </div>
          </div>

          {result.before && result.after && (
            <div className="border-t border-[var(--border-subtle)] pt-3 space-y-1.5 text-sm">
              {result.before.governance !== result.after.governance && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-[var(--text-tertiary)] w-24">Governance</span>
                  <span className="text-red-400">{result.before.governance}</span>
                  <span className="text-[var(--text-tertiary)]">{'\u2192'}</span>
                  <span className="text-green-400">{result.after.governance}</span>
                </div>
              )}
              {result.before.privilege_level !== result.after.privilege_level && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-[var(--text-tertiary)] w-24">Privilege</span>
                  <span className="text-red-400">{result.before.privilege_level}</span>
                  <span className="text-[var(--text-tertiary)]">{'\u2192'}</span>
                  <span className="text-green-400">{result.after.privilege_level}</span>
                </div>
              )}
              {result.before.risk_label !== result.after.risk_label && (
                <div className="flex items-center gap-2">
                  <span className="text-xs text-[var(--text-tertiary)] w-24">Risk Label</span>
                  <span className="text-red-400">{result.before.risk_label}</span>
                  <span className="text-[var(--text-tertiary)]">{'\u2192'}</span>
                  <span className="text-green-400">{result.after.risk_label}</span>
                </div>
              )}
            </div>
          )}

          {result.narrative && (
            <p className="text-sm text-[var(--text-secondary)] border-t border-[var(--border-subtle)] pt-3">
              {result.narrative}
            </p>
          )}
          <button
            onClick={() => onComplete(result)}
            className="px-3 py-1.5 bg-green-800/40 hover:bg-green-700/40 text-green-300 text-sm rounded transition-colors"
          >
            Done
          </button>
        </div>
      )}
    </div>
  );
}

// ── Main Page ────────────────────────────────────────────────────────

const TABS = ['Overview', 'Blast Radius', 'Activity', 'Simulations'] as const;
type Tab = typeof TABS[number];

export default function IdentityDetailV1() {
  const { id } = useParams<{ id: string }>();
  const identityId = id || '';

  const [state, setState] = useState<IdentityState | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>('Overview');

  const fetchState = useCallback(async () => {
    if (!identityId) return;
    setLoading(true);
    setError(null);
    try {
      const data = await getIdentityState(identityId);
      setState(data);
    } catch (err: any) {
      setError(err?.message || 'Failed to load identity');
    } finally {
      setLoading(false);
    }
  }, [identityId]);

  useEffect(() => { fetchState(); }, [fetchState]);

  // ── Loading state ──
  if (loading) {
    return (
      <div className="min-h-screen bg-[var(--bg-deep)] text-[var(--text-primary)]">
        <div className="max-w-[1200px] mx-auto px-6 py-6">
          <div className="h-6 w-48 bg-slate-700/50 animate-pulse rounded mb-6" />
          <div className="flex gap-4 mb-6">
            {TABS.map((t) => (
              <div key={t} className="h-8 w-28 bg-slate-700/50 animate-pulse rounded" />
            ))}
          </div>
          <SkeletonCard />
          <div className="mt-4"><SkeletonCard /></div>
        </div>
      </div>
    );
  }

  // ── Error state ──
  if (error) {
    return (
      <div className="min-h-screen bg-[var(--bg-deep)] text-[var(--text-primary)]">
        <div className="max-w-[1200px] mx-auto px-6 py-6">
          <Link to="/identities" className="text-sm text-blue-400 hover:underline mb-4 inline-block">&larr; Back to Identities</Link>
          <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-8 text-center mt-6">
            <p className="text-red-400 text-lg mb-2">Failed to load identity</p>
            <p className="text-sm text-red-300/70 mb-4">{error}</p>
            <button
              onClick={fetchState}
              className="px-4 py-2 bg-red-800/40 hover:bg-red-700/40 rounded text-red-300 text-sm transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (!state) return null;

  const riskBadgeCls = RISK_BADGE[state.risk.label] || RISK_BADGE.info;

  return (
    <div className="min-h-screen bg-[var(--bg-deep)] text-[var(--text-primary)]">
      <div className="max-w-[1200px] mx-auto px-6 py-6">
        {/* Breadcrumb + header */}
        <Link to="/identities" className="text-sm text-blue-400 hover:underline mb-4 inline-block">&larr; Back to Identities</Link>

        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-semibold">{state.profile.display_name}</h1>
            <p className="text-sm text-[var(--text-secondary)] mt-1">
              {capitalize(state.profile.identity_type)} &middot; {state.profile.cloud_id.toUpperCase()} &middot; {capitalize(state.profile.status)}
            </p>
          </div>
          <span className={`inline-block px-3 py-1.5 text-sm rounded-full border font-bold ${riskBadgeCls}`}>
            {state.risk.score.toFixed(1)} {state.risk.label.toUpperCase()}
          </span>
        </div>

        {/* Tab bar */}
        <div className="flex gap-1 border-b border-[var(--border-default)] mb-6">
          {TABS.map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-4 py-2.5 text-sm font-medium transition-colors relative ${
                activeTab === tab
                  ? 'text-[var(--text-primary)]'
                  : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]'
              }`}
            >
              {tab}
              {activeTab === tab && (
                <div className="absolute bottom-0 left-0 right-0 h-0.5 bg-blue-500" />
              )}
            </button>
          ))}
        </div>

        {/* Tab content with per-tab error boundary */}
        <TabErrorBoundary tab={activeTab}>
          {activeTab === 'Overview' && <OverviewTab state={state} />}
          {activeTab === 'Blast Radius' && (
            <BlastRadiusTab blastRadius={state.blast_radius} identityName={state.profile.display_name} />
          )}
          {activeTab === 'Activity' && <ActivityTab activity={state.activity} />}
          {activeTab === 'Simulations' && <SimulationsTab identityId={identityId} identityState={state} />}
        </TabErrorBoundary>

        {/* Data context footer */}
        <div className="mt-6 text-xs text-[var(--text-tertiary)] flex items-center gap-4">
          <span>Mode: {state.data_context.data_mode}</span>
          <span>Computed: {formatRelativeTime(state.data_context.computed_at)}</span>
          {state.data_context.is_stale && <span className="text-amber-400">Stale data</span>}
        </div>
      </div>
    </div>
  );
}
