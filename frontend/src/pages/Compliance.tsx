import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from 'recharts';
import { useToast } from '../components/ToastProvider';

interface EvidenceIdentity {
  id: number;
  identity_id: string;
  display_name: string;
  risk_level: string;
  risk_score: number;
  identity_category: string;
  reason: string;
}

interface RemediationPlaybook {
  id: number;
  title: string;
  description: string;
  impact: string;
  effort: string;
}

interface ComplianceControl {
  control_id: string;
  name: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
  metric: string;
  value: number;
  pass_threshold: string;
  drilldown_url: string | null;
  evidence_count: number;
  evidence_identities: EvidenceIdentity[];
  remediation_playbooks: RemediationPlaybook[];
}

interface ComplianceFramework {
  name: string;
  version: string | null;
  controls: ComplianceControl[];
  score: number;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  total_controls: number;
}

interface GapAnalysisResponse {
  generated_at: string;
  run_id: number;
  overall_score: number;
  total_controls: number;
  passing: number;
  warnings: number;
  failing: number;
  frameworks: Record<string, ComplianceFramework>;
}

interface TrendFramework {
  name: string;
  score: number;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  total_controls: number;
}

interface TrendRun {
  run_id: number;
  date: string | null;
  overall_score: number;
  frameworks: Record<string, TrendFramework>;
}

const FW_COLORS: Record<string, string> = {
  soc2: '#3b82f6',
  hipaa: '#ef4444',
  pci_dss: '#f59e0b',
  nist_800_53: '#8b5cf6',
  cis_azure: '#10b981',
  iso_27001: '#ec4899',
};

const STATUS_CONFIG = {
  pass: { bg: 'bg-green-50', border: 'border-green-200', text: 'text-green-700', dot: 'bg-green-500', label: 'Pass' },
  warn: { bg: 'bg-yellow-50', border: 'border-yellow-200', text: 'text-yellow-700', dot: 'bg-yellow-500', label: 'Warning' },
  fail: { bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-700', dot: 'bg-red-500', label: 'Fail' },
};

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-green-100 text-green-700',
  info: 'bg-gray-100 text-gray-600',
};

function ScoreRing({ score, size = 56 }: { score: number; size?: number }) {
  const radius = (size - 8) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = score >= 80 ? '#22c55e' : score >= 50 ? '#eab308' : '#ef4444';

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={radius} fill="none" stroke="#e5e7eb" strokeWidth={4} />
        <circle
          cx={size / 2} cy={size / 2} r={radius} fill="none"
          stroke={color} strokeWidth={4} strokeLinecap="round"
          strokeDasharray={circumference} strokeDashoffset={offset}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-xs font-bold text-gray-900">{score}%</span>
      </div>
    </div>
  );
}

export default function Compliance() {
  const [data, setData] = useState<GapAnalysisResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedFw, setExpandedFw] = useState<string | null>(null);
  const [expandedControl, setExpandedControl] = useState<string | null>(null);
  const [showGapOnly, setShowGapOnly] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [trendData, setTrendData] = useState<TrendRun[] | null>(null);
  const { addToast } = useToast();

  async function handleExport(format: 'csv' | 'json') {
    setExporting(true);
    try {
      if (format === 'csv') {
        const res = await fetch('/api/compliance/gap-analysis?format=csv');
        if (!res.ok) throw new Error(`Export failed (${res.status})`);
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `compliance-gap-analysis-${new Date().toISOString().slice(0, 10)}.csv`;
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const res = await fetch('/api/compliance/gap-analysis');
        if (!res.ok) throw new Error(`Export failed (${res.status})`);
        const exportData = await res.json();
        const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `compliance-gap-analysis-${new Date().toISOString().slice(0, 10)}.json`;
        a.click();
        URL.revokeObjectURL(url);
      }
      addToast(`Gap analysis exported as ${format.toUpperCase()}`, 'success');
    } catch (e: any) {
      addToast(e?.message || 'Export failed', 'error');
    } finally {
      setExporting(false);
    }
  }

  useEffect(() => {
    async function load() {
      try {
        const [gapRes, trendRes] = await Promise.all([
          fetch('/api/compliance/gap-analysis'),
          fetch('/api/compliance/trends?limit=20'),
        ]);
        if (!gapRes.ok) throw new Error(`API error: ${gapRes.status}`);
        const json: GapAnalysisResponse = await gapRes.json();
        setData(json);
        const keys = Object.keys(json.frameworks);
        if (keys.length > 0) setExpandedFw(keys[0]);
        if (trendRes.ok) {
          const trendJson = await trendRes.json();
          setTrendData(trendJson.runs || []);
        }
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : 'Failed to load compliance data');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return (
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3].map(i => <div key={i} className="h-40 bg-gray-100 rounded-xl" />)}
          </div>
          <div className="h-64 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-center">
          <p className="text-red-700 font-medium">{error || 'No compliance data available'}</p>
          <p className="text-sm text-red-500 mt-1">Run a discovery scan to generate compliance posture data.</p>
        </div>
      </div>
    );
  }

  const frameworks = Object.entries(data.frameworks);

  // Gap analysis: all non-passing controls across all frameworks
  const gaps: (ComplianceControl & { framework_name: string; framework_key: string })[] = [];
  for (const [key, fw] of frameworks) {
    for (const ctrl of fw.controls) {
      if (ctrl.status !== 'pass') {
        gaps.push({ ...ctrl, framework_name: fw.name, framework_key: key });
      }
    }
  }
  gaps.sort((a, b) => (a.status === 'fail' ? 0 : 1) - (b.status === 'fail' ? 0 : 1));

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Compliance Gap Analysis</h2>
          <p className="text-sm text-gray-500 mt-1">
            {frameworks.length} active framework{frameworks.length !== 1 ? 's' : ''} &middot; {data.total_controls} controls evaluated
          </p>
        </div>
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <button
              onClick={() => handleExport('csv')}
              disabled={exporting}
              className="px-2.5 py-1 text-xs font-medium text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-lg hover:bg-emerald-100 disabled:opacity-50"
            >
              CSV
            </button>
            <button
              onClick={() => handleExport('json')}
              disabled={exporting}
              className="px-2.5 py-1 text-xs font-medium text-purple-700 bg-purple-50 border border-purple-200 rounded-lg hover:bg-purple-100 disabled:opacity-50"
            >
              JSON
            </button>
          </div>
          <ScoreRing score={data.overall_score} size={64} />
          <div className="text-right">
            <div className="text-2xl font-bold text-gray-900">{data.overall_score}%</div>
            <div className="text-xs text-gray-500">Overall Score</div>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center">
          <div className="text-2xl font-bold text-green-700">{data.passing}</div>
          <div className="text-xs text-green-600 font-medium mt-1">Controls Passing</div>
        </div>
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-center">
          <div className="text-2xl font-bold text-yellow-700">{data.warnings}</div>
          <div className="text-xs text-yellow-600 font-medium mt-1">Warnings</div>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-center">
          <div className="text-2xl font-bold text-red-700">{data.failing}</div>
          <div className="text-xs text-red-600 font-medium mt-1">Failing</div>
        </div>
      </div>

      {/* Compliance Trend Chart */}
      {trendData && trendData.length > 1 && (
        <div className="bg-white rounded-xl border shadow-sm p-6">
          <h3 className="text-base font-semibold text-gray-900 mb-4">Compliance Score Trend</h3>
          <ResponsiveContainer width="100%" height={260}>
            <LineChart data={trendData.map(r => {
              const point: Record<string, any> = {
                date: r.date ? new Date(r.date).toLocaleDateString() : `Run ${r.run_id}`,
                overall: r.overall_score,
              };
              for (const [fk, fw] of Object.entries(r.frameworks)) {
                point[fk] = fw.score;
              }
              return point;
            })}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} tickFormatter={v => `${v}%`} />
              <Tooltip
                // eslint-disable-next-line @typescript-eslint/no-explicit-any
                formatter={(value: any, name: any) => [`${value ?? 0}%`, name === 'overall' ? 'Overall' : (trendData[0]?.frameworks[name]?.name || name)]}
                labelStyle={{ fontWeight: 600 }}
              />
              <Legend formatter={(value: string) => value === 'overall' ? 'Overall' : (trendData[0]?.frameworks[value]?.name || value)} />
              <Line type="monotone" dataKey="overall" stroke="#111827" strokeWidth={2.5} strokeDasharray="6 3" dot={false} />
              {Object.keys(trendData[0]?.frameworks || {}).map(fk => (
                <Line key={fk} type="monotone" dataKey={fk} stroke={FW_COLORS[fk] || '#6b7280'} strokeWidth={1.5} dot={false} />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Framework cards */}
      <div className="space-y-4">
        {frameworks.map(([key, fw]) => {
          const isExpanded = expandedFw === key;
          return (
            <div key={key} className="bg-white rounded-xl border shadow-sm overflow-hidden">
              {/* Framework header */}
              <button
                onClick={() => setExpandedFw(isExpanded ? null : key)}
                className="w-full flex items-center justify-between px-6 py-4 hover:bg-gray-50 transition"
              >
                <div className="flex items-center gap-4">
                  <div className="relative">
                    <ScoreRing score={fw.score} size={48} />
                    {trendData && trendData.length >= 2 && (() => {
                      const prev = trendData[trendData.length - 2]?.frameworks[key]?.score;
                      if (prev == null) return null;
                      const delta = fw.score - prev;
                      if (delta > 0) return (
                        <span className="absolute -top-1 -right-1 text-emerald-600 text-xs font-bold" title={`+${delta}% from previous run`}>
                          <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 17a.75.75 0 01-.75-.75V5.612L5.29 9.77a.75.75 0 01-1.08-1.04l5.25-5.5a.75.75 0 011.08 0l5.25 5.5a.75.75 0 11-1.08 1.04l-3.96-4.158V16.25A.75.75 0 0110 17z" clipRule="evenodd" /></svg>
                        </span>
                      );
                      if (delta < 0) return (
                        <span className="absolute -top-1 -right-1 text-red-600 text-xs font-bold" title={`${delta}% from previous run`}>
                          <svg className="w-3.5 h-3.5" fill="currentColor" viewBox="0 0 20 20"><path fillRule="evenodd" d="M10 3a.75.75 0 01.75.75v10.638l3.96-4.158a.75.75 0 111.08 1.04l-5.25 5.5a.75.75 0 01-1.08 0l-5.25-5.5a.75.75 0 111.08-1.04l3.96 4.158V3.75A.75.75 0 0110 3z" clipRule="evenodd" /></svg>
                        </span>
                      );
                      return (
                        <span className="absolute -top-1 -right-1 text-gray-400 text-xs font-bold" title="No change from previous run">&ndash;</span>
                      );
                    })()}
                  </div>
                  <div className="text-left">
                    <div className="text-base font-semibold text-gray-900 flex items-center gap-2">
                      {fw.name}
                      {fw.version && (
                        <span className="px-1.5 py-0.5 bg-gray-100 text-gray-500 text-[10px] font-medium rounded">
                          {fw.version}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5">
                      {fw.pass_count} pass &middot; {fw.warn_count} warn &middot; {fw.fail_count} fail
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <div className="flex gap-1">
                    {fw.controls.map((ctrl, i) => (
                      <span
                        key={i}
                        className={`w-2.5 h-2.5 rounded-full ${STATUS_CONFIG[ctrl.status].dot}`}
                        title={`${ctrl.control_id}: ${ctrl.name} — ${ctrl.status}`}
                      />
                    ))}
                  </div>
                  <svg
                    className={`w-5 h-5 text-gray-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                    fill="none" viewBox="0 0 24 24" stroke="currentColor"
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </button>

              {/* Expanded controls */}
              {isExpanded && (
                <div className="border-t px-6 py-4 space-y-2">
                  {fw.controls.map(ctrl => {
                    const cfg = STATUS_CONFIG[ctrl.status];
                    const controlKey = `${key}-${ctrl.control_id}`;
                    const isControlExpanded = expandedControl === controlKey;
                    const isNonPassing = ctrl.status !== 'pass';

                    return (
                      <div key={ctrl.control_id}>
                        <div
                          onClick={() => isNonPassing && setExpandedControl(isControlExpanded ? null : controlKey)}
                          className={`flex items-center justify-between px-4 py-3 rounded-lg border ${cfg.bg} ${cfg.border} ${isNonPassing ? 'cursor-pointer hover:shadow-sm transition' : ''}`}
                        >
                          <div className="flex items-center gap-3 min-w-0 flex-1">
                            <span className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
                            <div className="min-w-0">
                              <div className="text-sm font-medium text-gray-900">
                                <span className="text-gray-500 font-mono text-xs mr-2">{ctrl.control_id}</span>
                                {ctrl.name}
                              </div>
                              <div className="text-xs text-gray-600 mt-0.5">{ctrl.detail}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${cfg.bg} ${cfg.text}`}>
                              {cfg.label}
                            </span>
                            {isNonPassing && ctrl.evidence_count > 0 && (
                              <span className="text-[10px] text-gray-500 font-medium">
                                {ctrl.evidence_count} identit{ctrl.evidence_count === 1 ? 'y' : 'ies'}
                              </span>
                            )}
                            {isNonPassing && (
                              <svg
                                className={`w-4 h-4 text-gray-400 transition-transform ${isControlExpanded ? 'rotate-180' : ''}`}
                                fill="none" viewBox="0 0 24 24" stroke="currentColor"
                              >
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                              </svg>
                            )}
                            {!isNonPassing && ctrl.drilldown_url && (
                              <Link
                                to={ctrl.drilldown_url}
                                className="text-xs text-blue-600 hover:text-blue-700 font-medium"
                                onClick={e => e.stopPropagation()}
                              >
                                View
                              </Link>
                            )}
                          </div>
                        </div>

                        {/* Expanded evidence + playbooks */}
                        {isControlExpanded && isNonPassing && (
                          <div className="ml-5 mt-2 mb-3 space-y-3">
                            {/* Evidence identities */}
                            {ctrl.evidence_identities.length > 0 && (
                              <div className="bg-white border rounded-lg overflow-hidden">
                                <div className="px-4 py-2 bg-gray-50 border-b flex justify-between items-center">
                                  <span className="text-xs font-medium text-gray-700">
                                    Evidence: {ctrl.evidence_count} identit{ctrl.evidence_count === 1 ? 'y' : 'ies'} contributing to this gap
                                  </span>
                                  {ctrl.drilldown_url && (
                                    <Link to={ctrl.drilldown_url} className="text-xs text-blue-600 hover:text-blue-700 font-medium">
                                      View All
                                    </Link>
                                  )}
                                </div>
                                <table className="w-full text-xs">
                                  <thead>
                                    <tr className="bg-gray-50 text-left text-[10px] font-medium text-gray-500 uppercase">
                                      <th className="px-3 py-2">Identity</th>
                                      <th className="px-3 py-2">Category</th>
                                      <th className="px-3 py-2">Risk</th>
                                      <th className="px-3 py-2">Score</th>
                                      <th className="px-3 py-2">Reason</th>
                                    </tr>
                                  </thead>
                                  <tbody className="divide-y divide-gray-100">
                                    {ctrl.evidence_identities.slice(0, 10).map(ev => (
                                      <tr key={ev.id} className="hover:bg-gray-50">
                                        <td className="px-3 py-2">
                                          <Link to={`/identities/${ev.identity_id}`} className="text-blue-600 hover:underline font-medium">
                                            {ev.display_name}
                                          </Link>
                                        </td>
                                        <td className="px-3 py-2 text-gray-500">
                                          {(ev.identity_category || 'unknown').replace(/_/g, ' ')}
                                        </td>
                                        <td className="px-3 py-2">
                                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${RISK_COLORS[ev.risk_level] || 'bg-gray-100 text-gray-600'}`}>
                                            {ev.risk_level}
                                          </span>
                                        </td>
                                        <td className="px-3 py-2 font-mono text-gray-700">{ev.risk_score}</td>
                                        <td className="px-3 py-2 text-gray-600">{ev.reason}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                                {ctrl.evidence_identities.length > 10 && (
                                  <div className="px-4 py-2 border-t text-xs text-gray-500 text-center">
                                    Showing 10 of {ctrl.evidence_count}
                                    {ctrl.drilldown_url && (
                                      <Link to={ctrl.drilldown_url} className="text-blue-600 hover:underline ml-1">
                                        — View all
                                      </Link>
                                    )}
                                  </div>
                                )}
                              </div>
                            )}

                            {/* Remediation playbooks */}
                            {ctrl.remediation_playbooks.length > 0 && (
                              <div>
                                <div className="text-xs font-medium text-gray-700 mb-2">Remediation Playbooks</div>
                                <div className="space-y-2">
                                  {ctrl.remediation_playbooks.map(pb => (
                                    <div key={pb.id} className="border rounded-lg p-3 bg-blue-50 border-blue-200">
                                      <div className="flex items-center justify-between">
                                        <div className="text-sm font-medium text-gray-900">{pb.title}</div>
                                        <div className="flex gap-1.5">
                                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                            pb.impact === 'critical' ? 'bg-red-100 text-red-700' : pb.impact === 'high' ? 'bg-orange-100 text-orange-700' : 'bg-yellow-100 text-yellow-700'
                                          }`}>
                                            {pb.impact} impact
                                          </span>
                                          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${
                                            pb.effort === 'low' ? 'bg-green-100 text-green-700' : pb.effort === 'medium' ? 'bg-yellow-100 text-yellow-700' : 'bg-red-100 text-red-700'
                                          }`}>
                                            {pb.effort} effort
                                          </span>
                                        </div>
                                      </div>
                                      <p className="text-xs text-gray-600 mt-1">{pb.description}</p>
                                    </div>
                                  ))}
                                </div>
                              </div>
                            )}

                            {ctrl.evidence_identities.length === 0 && ctrl.remediation_playbooks.length === 0 && (
                              <div className="text-xs text-gray-400 py-2 pl-2">
                                No specific evidence identities or playbooks matched for this control.
                                {ctrl.drilldown_url && (
                                  <Link to={ctrl.drilldown_url} className="text-blue-600 hover:underline ml-1">Investigate</Link>
                                )}
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Gap Analysis Summary Table */}
      {gaps.length > 0 && (
        <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">Cross-Framework Gaps</h3>
              <p className="text-xs text-gray-500 mt-0.5">
                {gaps.length} control{gaps.length !== 1 ? 's' : ''} requiring attention across all frameworks
              </p>
            </div>
            <button
              onClick={() => setShowGapOnly(!showGapOnly)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition ${
                showGapOnly
                  ? 'bg-red-50 text-red-700 border-red-200'
                  : 'bg-gray-50 text-gray-600 border-gray-200 hover:bg-gray-100'
              }`}
            >
              {showGapOnly ? 'Showing Failures Only' : 'Show All Gaps'}
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase">
                  <th className="px-6 py-3">Framework</th>
                  <th className="px-4 py-3">Control</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3 text-right">Current</th>
                  <th className="px-4 py-3 text-right">Required</th>
                  <th className="px-4 py-3 text-right">Evidence</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {gaps
                  .filter(g => !showGapOnly || g.status === 'fail')
                  .map((gap, i) => {
                    const cfg = STATUS_CONFIG[gap.status];
                    return (
                      <tr key={`${gap.framework_key}-${gap.control_id}-${i}`} className="hover:bg-gray-50">
                        <td className="px-6 py-3 text-xs font-medium text-gray-700">{gap.framework_name}</td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-500">{gap.control_id}</td>
                        <td className="px-4 py-3 text-gray-900">{gap.name}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${cfg.bg} ${cfg.text}`}>
                            {cfg.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right font-mono text-gray-900">{gap.value}</td>
                        <td className="px-4 py-3 text-right font-mono text-gray-500">{gap.pass_threshold}</td>
                        <td className="px-4 py-3 text-right text-xs text-gray-500">{gap.evidence_count}</td>
                        <td className="px-4 py-3 text-right">
                          {gap.drilldown_url && (
                            <Link
                              to={gap.drilldown_url}
                              className="text-xs text-blue-600 hover:text-blue-700 font-medium"
                            >
                              Investigate
                            </Link>
                          )}
                        </td>
                      </tr>
                    );
                  })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {gaps.length === 0 && (
        <div className="bg-green-50 border border-green-200 rounded-xl p-6 text-center">
          <div className="text-green-700 font-semibold">All Controls Passing</div>
          <p className="text-sm text-green-600 mt-1">
            Your identity posture meets all enabled compliance framework requirements.
          </p>
        </div>
      )}
    </div>
  );
}
