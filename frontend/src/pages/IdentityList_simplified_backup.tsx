/**
 * Identity List — Enterprise v1
 *
 * Wired to GET /api/v1/identities (Phase 3 engine).
 * Renders 7 columns from live engine data. No mocked values.
 */

import React, { useCallback, useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  listIdentities,
  type IdentityListRow,
  type IdentityType,
  type RiskLabel,
  type CloudProvider,
  type DataContextDTO,
} from '../services/identityEngineApi';

// ── Theme constants (no hardcoded colors) ────────────────────────────

const IDENTITY_TYPE_ICON: Record<string, string> = {
  human_user: '\u{1F464}',
  guest_user: '\u{1F465}',
  service_principal: '\u{2699}\u{FE0F}',
  managed_identity: '\u{1F916}',
  app_registration: '\u{1F4CB}',
  ai_agent: '\u{1F9E0}',
};

const IDENTITY_TYPE_LABEL: Record<string, string> = {
  human_user: 'Human User',
  guest_user: 'Guest User',
  service_principal: 'Service Principal',
  managed_identity: 'Managed Identity',
  app_registration: 'App Registration',
  ai_agent: 'AI Agent',
};

const LIFECYCLE_COLORS: Record<string, string> = {
  Active: 'text-green-400',
  Dormant: 'text-amber-400',
  Provisioned: 'text-blue-400',
  Disabled: 'text-gray-500',
  Expired: 'text-red-400',
};

const LIFECYCLE_LABELS: Record<string, string> = {
  Active: 'Active',
  Dormant: 'Dormant',
  Provisioned: 'Provisioned',
  Disabled: 'Disabled',
  Expired: 'Expired',
};

const GOVERNANCE_STYLES: Record<string, { label: string; cls: string }> = {
  Governed: { label: 'Governed', cls: 'bg-green-900/30 text-green-400 border border-green-700/40' },
  Ungoverned: { label: 'Ungoverned', cls: 'bg-amber-900/30 text-amber-400 border border-amber-700/40' },
  Orphaned: { label: 'Orphaned', cls: 'bg-red-900/30 text-red-400 border border-red-700/40' },
  PolicyViolation: { label: 'Violation', cls: 'bg-red-900/30 text-red-400 border border-red-700/40' },
};

const PRIVILEGE_STYLES: Record<string, { label: string; cls: string }> = {
  highly_privileged: { label: 'Critical', cls: 'bg-red-900/30 text-red-400 border border-red-700/40' },
  privileged: { label: 'High', cls: 'bg-orange-900/30 text-orange-400 border border-orange-700/40' },
  standard: { label: 'Standard', cls: 'bg-slate-800/40 text-slate-400 border border-slate-700/40' },
};

const RISK_BADGE_STYLES: Record<string, string> = {
  Critical: 'bg-red-900/30 text-red-400 border border-red-700/40',
  High: 'bg-orange-900/30 text-orange-400 border border-orange-700/40',
  Medium: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/40',
  Low: 'bg-green-900/30 text-green-400 border border-green-700/40',
  Info: 'bg-blue-900/30 text-blue-400 border border-blue-700/40',
};

const DATA_FRESHNESS: Record<string, { label: string; cls: string; tooltip: string }> = {
  live: { label: 'Live', cls: 'text-green-400', tooltip: 'Data from the most recent engine run' },
  snapshot: { label: 'Snapshot', cls: 'text-blue-400', tooltip: 'Data from a point-in-time snapshot' },
  stale: { label: 'Stale', cls: 'text-amber-400', tooltip: 'Data may be outdated' },
  none: { label: 'None', cls: 'text-gray-500', tooltip: 'No data source available' },
};

// ── Helpers ──────────────────────────────────────────────────────────

function formatRelativeTime(iso: string | null): string {
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

function freshnessKey(ctx: DataContextDTO): string {
  if (ctx.is_stale) return 'stale';
  if (ctx.data_mode === 'snapshot') return 'snapshot';
  return 'live';
}

// ── Skeleton row ─────────────────────────────────────────────────────

function SkeletonRow() {
  return (
    <tr className="border-b border-[var(--border-subtle)]">
      {Array.from({ length: 7 }).map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 rounded bg-slate-700/50 animate-pulse" style={{ width: `${60 + (i * 10) % 40}%` }} />
        </td>
      ))}
    </tr>
  );
}

// ── Page size ────────────────────────────────────────────────────────

const PAGE_SIZE = 50;

// ── Component ────────────────────────────────────────────────────────

export default function IdentityListV1() {
  const [rows, setRows] = useState<IdentityListRow[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Filters
  const [typeFilter, setTypeFilter] = useState<IdentityType | ''>('');
  const [riskFilter, setRiskFilter] = useState<RiskLabel | ''>('');
  const [cloudFilter, setCloudFilter] = useState<CloudProvider | ''>('');

  const fetchPage = useCallback(async (pageOffset: number) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listIdentities({
        limit: PAGE_SIZE,
        offset: pageOffset,
        identity_type: typeFilter || undefined,
        risk_label: riskFilter || undefined,
        cloud_provider: cloudFilter || undefined,
      });
      setRows(resp.items);
      setTotal(resp.total);
      setOffset(pageOffset);
    } catch (err: any) {
      setError(err?.message || 'Failed to load identities');
      setRows([]);
      setTotal(0);
    } finally {
      setLoading(false);
    }
  }, [typeFilter, riskFilter, cloudFilter]);

  useEffect(() => { fetchPage(0); }, [fetchPage]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;

  return (
    <div className="min-h-screen bg-[var(--bg-deep)] text-[var(--text-primary)]">
      <div className="max-w-[1600px] mx-auto px-6 py-6">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-semibold">Identities</h1>
            <p className="text-sm text-[var(--text-secondary)] mt-1">
              {total} identities from live engine
            </p>
          </div>
        </div>

        {/* Filters */}
        <div className="flex items-center gap-3 mb-4">
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value as IdentityType | '')}
            className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)]"
          >
            <option value="">All Types</option>
            <option value="human_user">Human User</option>
            <option value="guest_user">Guest User</option>
            <option value="service_principal">Service Principal</option>
            <option value="managed_identity">Managed Identity</option>
            <option value="app_registration">App Registration</option>
          </select>

          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value as RiskLabel | '')}
            className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)]"
          >
            <option value="">All Risk</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>

          <select
            value={cloudFilter}
            onChange={(e) => setCloudFilter(e.target.value as CloudProvider | '')}
            className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-md px-3 py-1.5 text-sm text-[var(--text-primary)]"
          >
            <option value="">All Clouds</option>
            <option value="azure">Azure</option>
            <option value="aws">AWS</option>
            <option value="gcp">GCP</option>
          </select>
        </div>

        {/* Error state */}
        {error && (
          <div className="bg-red-900/20 border border-red-700/40 rounded-lg p-4 mb-4 flex items-center justify-between">
            <span className="text-red-400 text-sm">{error}</span>
            <button
              onClick={() => fetchPage(offset)}
              className="text-sm px-3 py-1 bg-red-800/40 hover:bg-red-700/40 rounded text-red-300 transition-colors"
            >
              Retry
            </button>
          </div>
        )}

        {/* Table */}
        <div className="bg-[var(--bg-raised)] border border-[var(--border-default)] rounded-lg overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-[var(--bg-surface)] border-b border-[var(--border-default)]">
                  <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Identity</th>
                  <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Lifecycle</th>
                  <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Governance</th>
                  <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Privilege</th>
                  <th className="text-right px-4 py-3 font-medium text-[var(--text-secondary)]">Risk</th>
                  <th className="text-left px-4 py-3 font-medium text-[var(--text-secondary)]">Last Activity</th>
                  <th className="text-center px-4 py-3 font-medium text-[var(--text-secondary)]">Data</th>
                </tr>
              </thead>
              <tbody>
                {loading
                  ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
                  : rows.length === 0
                    ? (
                      <tr>
                        <td colSpan={7} className="text-center py-16 text-[var(--text-secondary)]">
                          <div className="space-y-2">
                            <p className="text-lg">No identities found</p>
                            <p className="text-sm text-[var(--text-tertiary)]">
                              Run a discovery scan to populate identity data, or adjust your filters.
                            </p>
                          </div>
                        </td>
                      </tr>
                    )
                    : rows.map((row) => {
                        const lifecycle = LIFECYCLE_COLORS[row.lifecycle_state] || 'text-gray-500';
                        const lifecycleLabel = LIFECYCLE_LABELS[row.lifecycle_state] || row.lifecycle_state || '\u2014';
                        const gov = GOVERNANCE_STYLES[row.governance] || GOVERNANCE_STYLES.Ungoverned;
                        const priv = PRIVILEGE_STYLES[row.privilege_level] || PRIVILEGE_STYLES.standard;
                        const riskBadge = RISK_BADGE_STYLES[row.risk_label] || RISK_BADGE_STYLES.Info;
                        const freshness = DATA_FRESHNESS[freshnessKey(row.data_context)] || DATA_FRESHNESS.none;

                        return (
                          <tr
                            key={row.identity_id}
                            className="border-b border-[var(--border-subtle)] hover:bg-[var(--bg-surface)] transition-colors"
                          >
                            {/* Col 1: Identity name + type icon */}
                            <td className="px-4 py-3">
                              <Link
                                to={`/identities/${encodeURIComponent(row.identity_id)}`}
                                className="hover:underline"
                              >
                                <div className="flex items-center gap-2">
                                  <span className="text-base" title={IDENTITY_TYPE_LABEL[row.identity_type] || row.identity_type}>
                                    {IDENTITY_TYPE_ICON[row.identity_type] || '\u{2753}'}
                                  </span>
                                  <div>
                                    <span className="text-[var(--text-primary)] font-medium">
                                      {row.display_name || '\u2014'}
                                    </span>
                                    <span className="block text-xs text-[var(--text-tertiary)]">
                                      {IDENTITY_TYPE_LABEL[row.identity_type] || row.identity_type}
                                    </span>
                                  </div>
                                </div>
                              </Link>
                            </td>

                            {/* Col 2: Lifecycle state */}
                            <td className="px-4 py-3">
                              <span className={`text-sm font-medium ${lifecycle}`}>
                                {lifecycleLabel}
                              </span>
                            </td>

                            {/* Col 3: Governance */}
                            <td className="px-4 py-3">
                              <span className={`inline-block px-2 py-0.5 text-xs rounded-full ${gov.cls}`}>
                                {gov.label}
                              </span>
                            </td>

                            {/* Col 4: Privilege level */}
                            <td className="px-4 py-3">
                              <span className={`inline-block px-2 py-0.5 text-xs rounded-full ${priv.cls}`}>
                                {priv.label}
                              </span>
                            </td>

                            {/* Col 5: Risk score + label */}
                            <td className="px-4 py-3 text-right">
                              <span className={`inline-block px-2 py-0.5 text-xs rounded-full ${riskBadge}`}>
                                {(row.risk_label || 'Info').toUpperCase()}
                              </span>
                              <span className="block text-xs text-[var(--text-tertiary)] mt-0.5">
                                {row.risk_score != null ? row.risk_score.toFixed(1) : '\u2014'}
                              </span>
                            </td>

                            {/* Col 6: Last activity */}
                            <td className="px-4 py-3 text-sm text-[var(--text-secondary)]">
                              {formatRelativeTime(row.last_seen)}
                            </td>

                            {/* Col 7: Data freshness */}
                            <td className="px-4 py-3 text-center">
                              <span
                                className={`text-xs ${freshness.cls}`}
                                title={freshness.tooltip}
                              >
                                {freshness.label}
                              </span>
                            </td>
                          </tr>
                        );
                      })
                }
              </tbody>
            </table>
          </div>
        </div>

        {/* Pagination */}
        {!loading && total > PAGE_SIZE && (
          <div className="flex items-center justify-between mt-4 text-sm text-[var(--text-secondary)]">
            <span>
              Showing {offset + 1}\u2013{Math.min(offset + PAGE_SIZE, total)} of {total}
            </span>
            <div className="flex items-center gap-2">
              <button
                disabled={currentPage <= 1}
                onClick={() => fetchPage(offset - PAGE_SIZE)}
                className="px-3 py-1 bg-[var(--bg-raised)] border border-[var(--border-default)] rounded disabled:opacity-40 hover:bg-[var(--bg-surface)] transition-colors"
              >
                Previous
              </button>
              <span>Page {currentPage} of {totalPages}</span>
              <button
                disabled={currentPage >= totalPages}
                onClick={() => fetchPage(offset + PAGE_SIZE)}
                className="px-3 py-1 bg-[var(--bg-raised)] border border-[var(--border-default)] rounded disabled:opacity-40 hover:bg-[var(--bg-surface)] transition-colors"
              >
                Next
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
