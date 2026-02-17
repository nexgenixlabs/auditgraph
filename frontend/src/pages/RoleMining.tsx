import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { Link } from 'react-router-dom';

// ── Types ─────────────────────────────────────────────────────

interface Summary {
  total_roles: number;
  total_identities: number;
  unused: number;
  redundant: number;
  orphaned: number;
  toxic_combos: number;
  overprivileged: number;
  optimization_pct: number;
}

interface Evidence {
  last_activity_time: string | null;
  last_activity_source: string | null;
  evidence_count: number;
  window_days: number;
  confidence: string;
  detail: string;
  additional_sources?: Array<{ source: string; time: string | null; detail: string; status?: string }>;
}

interface ToxicCombo {
  finding_id: string;
  identity_id: string;
  identity_name: string;
  identity_category: string;
  rule_id: string;
  title: string;
  category: string;
  risk_score: number;
  risk_level: string;
  matched_roles: string[];
  matched_capabilities: string[];
  scope: string;
  scope_type: string;
  reasoning: string;
  recommendation: string;
  assignment_methods: string[];
  blast_radius: string;
}

interface UnusedFinding {
  identity_id: string;
  identity_name: string;
  identity_category: string;
  role_name: string;
  source: string;
  finding_type: string;
  risk_level: string;
  scope: string | null;
  scope_type: string;
  days_since_assigned: number | null;
  assignment_method: string;
  recommendation: string;
  evidence: Evidence;
  blast_radius: string;
}

interface RedundantFinding {
  identity_id: string;
  identity_name: string;
  identity_category: string;
  role_name: string;
  source: string;
  scope: string | null;
  scope_type: string;
  superseded_by: string;
  recommendation: string;
  risk_level: string;
  blast_radius: string;
  assignment_method: string;
}

interface OrphanedFinding {
  identity_id: string;
  identity_name: string;
  identity_category: string;
  role_name: string;
  source: string;
  scope: string | null;
  scope_type: string;
  reason: string;
  recommendation: string;
  risk_level: string;
  assignment_method: string;
}

interface Finding {
  identity_id: string;
  identity_name: string;
  identity_category: string;
  role_name: string;
  source: string;
  type: string;
  risk_level: string;
  days_since_assigned: number | null;
  scope: string | null;
  recommendation: string;
  assignment_method?: string;
}

interface RoleBundle {
  roles: string[];
  sources: string[];
  identity_count: number;
  identities: string[];
  capabilities: string[];
  risk_tags: string[];
  risk_level: string;
}

interface RoleFrequency {
  role_name: string;
  source: string;
  assignment_count: number;
}

interface RoleMiningData {
  summary: Summary;
  toxic_combos: ToxicCombo[];
  unused_findings: UnusedFinding[];
  redundant_findings: RedundantFinding[];
  orphaned_findings: OrphanedFinding[];
  findings: Finding[];
  role_bundles: RoleBundle[];
  role_frequency: RoleFrequency[];
}

// ── Constants ─────────────────────────────────────────────────

const TYPE_CONFIG: Record<string, { label: string; bg: string; text: string }> = {
  definitely_unused: { label: 'Unused', bg: 'bg-red-50', text: 'text-red-700' },
  likely_unused: { label: 'Likely Unused', bg: 'bg-orange-50', text: 'text-orange-700' },
  potentially_unused: { label: 'Potentially Unused', bg: 'bg-amber-50', text: 'text-amber-600' },
  redundant: { label: 'Redundant', bg: 'bg-yellow-50', text: 'text-yellow-700' },
  orphaned: { label: 'Orphaned', bg: 'bg-purple-50', text: 'text-purple-700' },
  overprivileged: { label: 'Over-Privileged', bg: 'bg-amber-50', text: 'text-amber-700' },
};

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-600 bg-red-50 border-red-200',
  high: 'text-orange-600 bg-orange-50 border-orange-200',
  medium: 'text-yellow-700 bg-yellow-50 border-yellow-200',
  low: 'text-blue-600 bg-blue-50 border-blue-200',
  unknown: 'text-gray-500 bg-gray-50 border-gray-200',
};

const BLAST_COLORS: Record<string, string> = {
  critical: 'text-red-700 bg-red-100',
  high: 'text-orange-700 bg-orange-100',
  medium: 'text-yellow-700 bg-yellow-100',
  low: 'text-green-700 bg-green-100',
};

const CONFIDENCE_COLORS: Record<string, string> = {
  HIGH: 'text-green-700 bg-green-50',
  MED: 'text-yellow-700 bg-yellow-50',
  LOW: 'text-gray-600 bg-gray-50',
};

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MI',
  managed_identity_user: 'User MI',
  human_user: 'Human',
  guest: 'Guest',
  microsoft_internal: 'MS Internal',
};

const TOXIC_CATEGORY_ICONS: Record<string, string> = {
  god_mode: '\u26A0\uFE0F',
  privilege_escalation: '\u2B06\uFE0F',
  data_exfil: '\uD83D\uDCE4',
  lateral_movement: '\u2194\uFE0F',
};

// ── Component ─────────────────────────────────────────────────

export default function RoleMining() {
  const [data, setData] = useState<RoleMiningData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [windowDays, setWindowDays] = useState(90);
  const [activeTab, setActiveTab] = useState<'toxic' | 'findings' | 'bundles'>('toxic');

  // Filters
  const [typeFilter, setTypeFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  const [searchTerm, setSearchTerm] = useState('');
  const [confidenceFilter, setConfidenceFilter] = useState('');
  const [sourceFilter, setSourceFilter] = useState('');
  const [assignmentMethodFilter, setAssignmentMethodFilter] = useState('');

  // Evidence drawer
  const [evidenceDrawer, setEvidenceDrawer] = useState<UnusedFinding | null>(null);

  // Toxic combo detail
  const [expandedToxic, setExpandedToxic] = useState<string | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/role-mining?window_days=${windowDays}`);
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      setData(await res.json());
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [windowDays]);

  useEffect(() => { loadData(); }, [loadData]);

  const filteredFindings = useMemo(() => {
    if (!data) return [];
    return data.findings.filter(f => {
      if (typeFilter && f.type !== typeFilter) return false;
      if (riskFilter && f.risk_level !== riskFilter) return false;
      if (sourceFilter && f.source !== sourceFilter) return false;
      if (assignmentMethodFilter && (f.assignment_method || 'direct') !== assignmentMethodFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return f.identity_name.toLowerCase().includes(term) || f.role_name.toLowerCase().includes(term);
      }
      return true;
    });
  }, [data, typeFilter, riskFilter, sourceFilter, assignmentMethodFilter, searchTerm]);

  const filteredToxic = useMemo(() => {
    if (!data) return [];
    return data.toxic_combos.filter(t => {
      if (riskFilter && t.risk_level !== riskFilter) return false;
      if (searchTerm) {
        const term = searchTerm.toLowerCase();
        return t.identity_name.toLowerCase().includes(term) || t.title.toLowerCase().includes(term);
      }
      return true;
    });
  }, [data, riskFilter, searchTerm]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-72" />
          <div className="grid grid-cols-6 gap-4">
            {[...Array(6)].map((_, i) => <div key={i} className="h-20 bg-gray-100 rounded-xl" />)}
          </div>
          <div className="h-96 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-700">
          <div className="font-semibold">Error loading role mining data</div>
          <div className="text-sm mt-1">{error}</div>
        </div>
      </div>
    );
  }

  if (!data) return null;
  const { summary, role_frequency, role_bundles, toxic_combos, unused_findings } = data;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Role Mining & Optimization</h2>
          <p className="text-sm text-gray-600 mt-1">Toxic combinations, unused roles, redundancy, and access optimization</p>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-500">Window:</label>
          <select
            value={windowDays}
            onChange={e => setWindowDays(Number(e.target.value))}
            className="px-2 py-1 border rounded text-xs bg-white"
          >
            <option value={30}>30 days</option>
            <option value={90}>90 days</option>
            <option value={180}>180 days</option>
            <option value={365}>365 days</option>
          </select>
        </div>
      </div>

      {/* Summary Cards — 6 cards */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4">
        <SummaryCard label="Total Roles" value={summary.total_roles} bg="bg-white" text="text-gray-900" />
        <SummaryCard label="Toxic Combos" value={summary.toxic_combos} bg="bg-red-50" text="text-red-700" border="border-red-200"
          sub={summary.toxic_combos > 0 ? 'Requires immediate review' : undefined} />
        <SummaryCard label="Unused" value={summary.unused} bg="bg-orange-50" text="text-orange-700" border="border-orange-200" />
        <SummaryCard label="Redundant" value={summary.redundant} bg="bg-yellow-50" text="text-yellow-700" border="border-yellow-200" />
        <SummaryCard label="Orphaned" value={summary.orphaned} bg="bg-purple-50" text="text-purple-700" border="border-purple-200" />
        <SummaryCard label="Optimization" value={`${summary.optimization_pct}%`} bg="bg-blue-50" text="text-blue-700" border="border-blue-200"
          sub="of roles actionable" />
      </div>

      {/* Tab Bar */}
      <div className="flex border-b gap-0">
        {([
          ['toxic', `Toxic Combinations (${toxic_combos.length})`],
          ['findings', `Findings (${filteredFindings.length})`],
          ['bundles', `Bundles & Analytics`],
        ] as [string, string][]).map(([key, label]) => (
          <button
            key={key}
            onClick={() => setActiveTab(key as 'toxic' | 'findings' | 'bundles')}
            className={`px-5 py-2.5 text-sm font-medium border-b-2 transition ${
              activeTab === key
                ? 'border-blue-600 text-blue-700'
                : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ─── Tab: Toxic Combinations ─── */}
      {activeTab === 'toxic' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap items-center gap-3">
            <input
              type="text" placeholder="Search identity or rule..."
              value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm w-56 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white">
              <option value="">All Risk</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
            </select>
          </div>

          {filteredToxic.length === 0 ? (
            <div className="bg-green-50 border border-green-200 rounded-xl p-8 text-center">
              <div className="text-green-700 font-semibold">No Toxic Combinations Detected</div>
              <div className="text-sm text-green-600 mt-1">No dangerous role combinations found in current assignments</div>
            </div>
          ) : (
            <div className="space-y-3">
              {filteredToxic.map(t => {
                const expanded = expandedToxic === t.finding_id;
                const rc = RISK_COLORS[t.risk_level] || RISK_COLORS.unknown;
                const bc = BLAST_COLORS[t.blast_radius] || BLAST_COLORS.low;
                return (
                  <div key={t.finding_id} className={`bg-white border rounded-xl overflow-hidden ${
                    t.risk_level === 'critical' ? 'border-red-300' : 'border-orange-200'
                  }`}>
                    {/* Header row */}
                    <button
                      onClick={() => setExpandedToxic(expanded ? null : t.finding_id)}
                      className="w-full px-5 py-4 flex items-center gap-3 text-left hover:bg-gray-50 transition"
                    >
                      <span className="text-lg">{TOXIC_CATEGORY_ICONS[t.category] || '\u26A0\uFE0F'}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-gray-900 text-sm">{t.title}</span>
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${rc}`}>
                            {t.risk_level}
                          </span>
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${bc}`}>
                            Blast: {t.blast_radius}
                          </span>
                        </div>
                        <div className="flex items-center gap-2 mt-1">
                          <Link to={`/identities/${t.identity_id}`}
                            onClick={e => e.stopPropagation()}
                            className="text-blue-600 hover:underline text-xs font-medium">
                            {t.identity_name}
                          </Link>
                          <span className="text-gray-400 text-xs">·</span>
                          <span className="text-xs text-gray-500">{CATEGORY_LABELS[t.identity_category] || t.identity_category}</span>
                          <span className="text-gray-400 text-xs">·</span>
                          <span className="text-xs text-gray-500">{t.scope}</span>
                        </div>
                      </div>
                      <span className="text-xs text-gray-400 font-mono">{t.rule_id}</span>
                      <svg className={`w-4 h-4 text-gray-400 transition-transform ${expanded ? 'rotate-180' : ''}`}
                        fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                      </svg>
                    </button>

                    {/* Expanded detail */}
                    {expanded && (
                      <div className="px-5 pb-5 space-y-3 border-t bg-gray-50">
                        <div className="pt-3">
                          <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Matched Roles</div>
                          <div className="flex flex-wrap gap-1.5">
                            {t.matched_roles.map((r, i) => (
                              <span key={i} className="px-2 py-0.5 bg-red-100 text-red-800 rounded text-xs font-medium">{r}</span>
                            ))}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Capabilities</div>
                          <div className="flex flex-wrap gap-1">
                            {t.matched_capabilities.map((c, i) => (
                              <span key={i} className="px-1.5 py-0.5 bg-gray-200 text-gray-700 rounded text-[10px] font-mono">{c}</span>
                            ))}
                          </div>
                        </div>
                        <div>
                          <div className="text-xs font-semibold text-gray-500 uppercase mb-1">Why This Is Dangerous</div>
                          <p className="text-sm text-gray-700 leading-relaxed">{t.reasoning}</p>
                        </div>
                        <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                          <div className="text-xs font-semibold text-blue-700 uppercase mb-1">Recommendation</div>
                          <p className="text-sm text-blue-800">{t.recommendation}</p>
                        </div>
                        <div className="flex items-center gap-4 text-xs text-gray-500">
                          <span>Score: <span className="font-semibold text-gray-700">{t.risk_score}/100</span></span>
                          <span>Assignment: {t.assignment_methods.join(', ')}</span>
                          <span>Scope: {t.scope_type}</span>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ─── Tab: Findings (legacy + enhanced) ─── */}
      {activeTab === 'findings' && (
        <div className="bg-white border rounded-xl shadow-sm overflow-hidden">
          {/* Filter Bar */}
          <div className="px-6 py-4 border-b flex flex-wrap items-center gap-3">
            <input type="text" placeholder="Search identity or role..."
              value={searchTerm} onChange={e => setSearchTerm(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm w-56 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white focus:ring-2 focus:ring-blue-500">
              <option value="">All Types</option>
              {Object.entries(TYPE_CONFIG).map(([k, v]) => (
                <option key={k} value={k}>{v.label}</option>
              ))}
            </select>
            <select value={riskFilter} onChange={e => setRiskFilter(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white focus:ring-2 focus:ring-blue-500">
              <option value="">All Risk</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
            <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white">
              <option value="">All Sources</option>
              <option value="azure">Azure RBAC</option>
              <option value="entra">Entra ID</option>
            </select>
            <select value={assignmentMethodFilter} onChange={e => setAssignmentMethodFilter(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white">
              <option value="">All Methods</option>
              <option value="direct">Direct</option>
              <option value="pim_eligible">PIM Eligible</option>
              <option value="pim_eligible_group">PIM Eligible (Group)</option>
              <option value="pim_active">PIM Active</option>
            </select>
            <select value={confidenceFilter} onChange={e => setConfidenceFilter(e.target.value)}
              className="px-3 py-1.5 border rounded-lg text-sm bg-white">
              <option value="">All Confidence</option>
              <option value="HIGH">High</option>
              <option value="MED">Medium</option>
              <option value="LOW">Low</option>
            </select>
            <span className="text-xs text-gray-500 ml-auto">{filteredFindings.length} findings</span>
          </div>

          {/* Unused findings with evidence */}
          {unused_findings.length > 0 && !typeFilter && !confidenceFilter && (
            <div className="px-6 py-3 bg-orange-50 border-b border-orange-100">
              <div className="text-xs font-semibold text-orange-700">
                {unused_findings.filter(f => f.evidence.confidence === 'HIGH').length} confirmed unused (HIGH confidence) ·{' '}
                {unused_findings.filter(f => f.evidence.confidence === 'MED').length} likely unused (MED) ·{' '}
                {unused_findings.filter(f => f.evidence.confidence === 'LOW').length} unverified (LOW)
              </div>
            </div>
          )}

          {filteredFindings.length === 0 ? (
            <div className="px-6 py-12 text-center">
              <div className="text-gray-400 font-medium">No findings match your filters</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-gray-50 border-b text-left">
                    <th className="px-4 py-3 font-medium text-gray-600">Identity</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Category</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Role</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Source</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Type</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Risk</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Scope</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Age</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Evidence</th>
                    <th className="px-4 py-3 font-medium text-gray-600">Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredFindings.map((f, i) => {
                    const tc = TYPE_CONFIG[f.type] || { label: f.type, bg: 'bg-gray-50', text: 'text-gray-600' };
                    const rc = RISK_COLORS[f.risk_level] || RISK_COLORS.unknown;
                    // Find matching unused finding for evidence link
                    const unusedMatch = unused_findings.find(
                      u => u.identity_id === f.identity_id && u.role_name === f.role_name && u.source === f.source
                    );
                    return (
                      <tr key={i} className="border-b last:border-b-0 hover:bg-gray-50 transition">
                        <td className="px-4 py-3">
                          <Link to={`/identities/${f.identity_id}`} className="text-blue-600 hover:underline font-medium text-xs">
                            {f.identity_name}
                          </Link>
                        </td>
                        <td className="px-4 py-3 text-gray-600 text-xs">
                          {CATEGORY_LABELS[f.identity_category] || f.identity_category || '-'}
                        </td>
                        <td className="px-4 py-3 font-medium text-gray-900 text-xs">{f.role_name}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                            f.source === 'entra' ? 'bg-indigo-50 text-indigo-600' : 'bg-sky-50 text-sky-600'
                          }`}>{f.source}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${tc.bg} ${tc.text}`}>{tc.label}</span>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${rc}`}>{f.risk_level}</span>
                        </td>
                        <td className="px-4 py-3 text-gray-500 text-[10px] max-w-[120px] truncate" title={f.scope || ''}>
                          {f.scope ? (f.scope.length > 30 ? `...${f.scope.slice(-25)}` : f.scope) : '-'}
                        </td>
                        <td className="px-4 py-3 text-gray-500 text-xs">
                          {f.days_since_assigned != null ? `${f.days_since_assigned}d` : '-'}
                        </td>
                        <td className="px-4 py-3">
                          {unusedMatch ? (
                            <button
                              onClick={() => setEvidenceDrawer(unusedMatch)}
                              className={`px-2 py-0.5 rounded text-[10px] font-semibold cursor-pointer hover:opacity-80 ${
                                CONFIDENCE_COLORS[unusedMatch.evidence.confidence] || CONFIDENCE_COLORS.LOW
                              }`}
                            >
                              {unusedMatch.evidence.confidence} conf.
                            </button>
                          ) : (
                            <span className="text-gray-300 text-xs">-</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-gray-600 text-[11px] max-w-[200px]">{f.recommendation}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ─── Tab: Bundles & Analytics ─── */}
      {activeTab === 'bundles' && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Role Frequency */}
          <div className="bg-white border rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-900 mb-3">Most Assigned Roles</h3>
            {role_frequency.length === 0 ? (
              <div className="text-sm text-gray-400 text-center py-6">No role data available</div>
            ) : (
              <div className="space-y-2">
                {role_frequency.map((r, i) => {
                  const maxCount = role_frequency[0]?.assignment_count || 1;
                  const pct = Math.round((r.assignment_count / maxCount) * 100);
                  return (
                    <div key={i} className="flex items-center gap-3">
                      <div className="w-40 truncate text-xs text-gray-700 font-medium" title={r.role_name}>{r.role_name}</div>
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold uppercase ${
                        r.source === 'entra' ? 'bg-indigo-50 text-indigo-500' : 'bg-sky-50 text-sky-500'
                      }`}>{r.source}</span>
                      <div className="flex-1 bg-gray-100 rounded-full h-4 overflow-hidden">
                        <div className="bg-blue-500 h-full rounded-full transition-all" style={{ width: `${pct}%` }} />
                      </div>
                      <div className="text-xs font-semibold text-gray-600 w-8 text-right">{r.assignment_count}</div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Role Bundles (enhanced) */}
          <div className="bg-white border rounded-xl p-5">
            <h3 className="text-sm font-semibold text-gray-900 mb-1">Common Role Bundles</h3>
            <p className="text-xs text-gray-500 mb-3">Role sets assigned together across 2+ identities, with risk tags</p>
            {role_bundles.length === 0 ? (
              <div className="text-sm text-gray-400 text-center py-6">No common bundles found — roles are unique per identity</div>
            ) : (
              <div className="space-y-2">
                {role_bundles.map((b, i) => {
                  const brc = RISK_COLORS[b.risk_level] || RISK_COLORS.low;
                  return (
                    <div key={i} className={`p-3 rounded-lg border ${
                      b.risk_level === 'critical' ? 'border-red-200 bg-red-50/30' :
                      b.risk_level === 'high' ? 'border-orange-200 bg-orange-50/30' : 'border-gray-200 bg-gray-50'
                    }`}>
                      <div className="flex items-center gap-2 flex-wrap">
                        {b.roles.map((role, j) => (
                          <React.Fragment key={j}>
                            {j > 0 && <span className="text-gray-400 text-xs">+</span>}
                            <span className="px-2 py-0.5 text-xs font-medium bg-blue-100 text-blue-700 rounded truncate max-w-[180px]" title={role}>
                              {role}
                            </span>
                          </React.Fragment>
                        ))}
                        <span className={`ml-auto px-2 py-0.5 rounded-full text-[10px] font-bold uppercase ${brc}`}>
                          {b.risk_level}
                        </span>
                        <span className="text-xs text-gray-500 whitespace-nowrap">{b.identity_count} identities</span>
                      </div>
                      {b.risk_tags.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {b.risk_tags.map((tag, j) => (
                            <span key={j} className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded text-[9px] font-medium">{tag}</span>
                          ))}
                        </div>
                      )}
                      {b.identities.length > 0 && (
                        <div className="text-[10px] text-gray-500 mt-1.5 truncate">
                          {b.identities.slice(0, 5).join(', ')}{b.identities.length > 5 ? ` +${b.identities.length - 5} more` : ''}
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ─── Evidence Drawer ─── */}
      {evidenceDrawer && (
        <div className="fixed inset-0 z-50 flex justify-end">
          <div className="absolute inset-0 bg-black/30" onClick={() => setEvidenceDrawer(null)} />
          <div className="relative w-full max-w-md bg-white shadow-xl overflow-y-auto">
            <div className="sticky top-0 bg-white border-b px-6 py-4 flex items-center justify-between">
              <h3 className="text-sm font-bold text-gray-900">Evidence Details</h3>
              <button onClick={() => setEvidenceDrawer(null)} className="text-gray-400 hover:text-gray-600">
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            <div className="px-6 py-5 space-y-5">
              {/* Identity info */}
              <div>
                <div className="text-xs text-gray-500 font-medium mb-1">Identity</div>
                <Link to={`/identities/${evidenceDrawer.identity_id}`} className="text-blue-600 hover:underline font-semibold text-sm">
                  {evidenceDrawer.identity_name}
                </Link>
                <div className="text-xs text-gray-500 mt-0.5">{CATEGORY_LABELS[evidenceDrawer.identity_category] || evidenceDrawer.identity_category}</div>
              </div>

              {/* Role info */}
              <div>
                <div className="text-xs text-gray-500 font-medium mb-1">Role</div>
                <div className="text-sm font-medium text-gray-900">{evidenceDrawer.role_name}</div>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${
                    evidenceDrawer.source === 'entra' ? 'bg-indigo-50 text-indigo-600' : 'bg-sky-50 text-sky-600'
                  }`}>{evidenceDrawer.source}</span>
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                    BLAST_COLORS[evidenceDrawer.blast_radius] || BLAST_COLORS.low
                  }`}>Blast: {evidenceDrawer.blast_radius}</span>
                </div>
              </div>

              {/* Evidence */}
              <div className="bg-gray-50 rounded-lg p-4 space-y-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-500 font-medium">Confidence:</span>
                  <span className={`px-2 py-0.5 rounded text-xs font-bold ${
                    CONFIDENCE_COLORS[evidenceDrawer.evidence.confidence] || CONFIDENCE_COLORS.LOW
                  }`}>{evidenceDrawer.evidence.confidence}</span>
                </div>
                <div>
                  <span className="text-xs text-gray-500 font-medium">Detail:</span>
                  <p className="text-sm text-gray-700 mt-0.5">{evidenceDrawer.evidence.detail}</p>
                </div>
                {evidenceDrawer.evidence.last_activity_time && (
                  <div>
                    <span className="text-xs text-gray-500 font-medium">Last Activity:</span>
                    <div className="text-sm text-gray-700 mt-0.5">
                      {new Date(evidenceDrawer.evidence.last_activity_time).toLocaleString()}
                      {evidenceDrawer.evidence.last_activity_source && (
                        <span className="text-xs text-gray-500 ml-2">({evidenceDrawer.evidence.last_activity_source})</span>
                      )}
                    </div>
                  </div>
                )}
                <div className="flex items-center gap-4 text-xs text-gray-500 pt-2 border-t">
                  <span>Window: {evidenceDrawer.evidence.window_days} days</span>
                  <span>Evidence count: {evidenceDrawer.evidence.evidence_count}</span>
                </div>
              </div>

              {/* Additional Evidence Sources */}
              {!!evidenceDrawer.evidence.additional_sources && evidenceDrawer.evidence.additional_sources.length > 0 && (
                <div>
                  <div className="text-xs text-gray-500 font-medium mb-2">Additional Evidence</div>
                  <div className="space-y-2">
                    {evidenceDrawer.evidence.additional_sources.map((src, idx) => (
                      <div key={idx} className="bg-indigo-50 border border-indigo-200 rounded-lg p-3 flex items-start gap-2">
                        <span className="px-1.5 py-0.5 bg-indigo-100 text-indigo-700 rounded text-[9px] font-semibold uppercase whitespace-nowrap">
                          {src.source.replace('_', ' ')}
                        </span>
                        <div className="flex-1 min-w-0">
                          <div className="text-xs text-gray-700">{src.detail}</div>
                          {src.time && (
                            <div className="text-[10px] text-gray-500 mt-0.5">
                              {new Date(src.time).toLocaleString()}
                            </div>
                          )}
                        </div>
                        {!!src.status && (
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                            src.status === 'Active' ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-600'
                          }`}>{src.status}</span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Scope */}
              <div>
                <div className="text-xs text-gray-500 font-medium mb-1">Scope</div>
                <div className="text-xs text-gray-700 font-mono break-all bg-gray-50 rounded p-2">{evidenceDrawer.scope || '/'}</div>
                <div className="text-[10px] text-gray-400 mt-0.5">Type: {evidenceDrawer.scope_type} · Method: {evidenceDrawer.assignment_method}</div>
              </div>

              {/* Recommendation */}
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-3">
                <div className="text-xs font-semibold text-blue-700 uppercase mb-1">Recommendation</div>
                <p className="text-sm text-blue-800">{evidenceDrawer.recommendation}</p>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Summary Card ──────────────────────────────────────────────

function SummaryCard({ label, value, bg, text, border, sub }: {
  label: string; value: string | number; bg: string; text: string; border?: string; sub?: string;
}) {
  return (
    <div className={`${bg} border ${border || 'border-gray-200'} rounded-xl p-4`}>
      <div className={`text-xs font-medium ${text}`}>{label}</div>
      <div className={`text-2xl font-bold ${text} mt-1`}>{value}</div>
      {sub && <div className={`text-[10px] text-gray-500 mt-0.5`}>{sub}</div>}
    </div>
  );
}
