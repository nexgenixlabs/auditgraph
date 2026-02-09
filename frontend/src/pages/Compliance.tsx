import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

interface ComplianceControl {
  id: string;
  name: string;
  status: 'pass' | 'warn' | 'fail';
  detail: string;
  metric: string;
  value: number;
  pass_threshold: string;
  drilldown_url: string | null;
}

interface ComplianceFramework {
  name: string;
  version: string | null;
  description: string | null;
  controls: ComplianceControl[];
  score: number;
  pass_count: number;
  warn_count: number;
  fail_count: number;
  total_controls: number;
}

type ScorecardData = Record<string, ComplianceFramework>;

const STATUS_CONFIG = {
  pass: { bg: 'bg-green-50', border: 'border-green-200', text: 'text-green-700', dot: 'bg-green-500', label: 'Pass' },
  warn: { bg: 'bg-yellow-50', border: 'border-yellow-200', text: 'text-yellow-700', dot: 'bg-yellow-500', label: 'Warning' },
  fail: { bg: 'bg-red-50', border: 'border-red-200', text: 'text-red-700', dot: 'bg-red-500', label: 'Fail' },
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
  const [data, setData] = useState<ScorecardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedFw, setExpandedFw] = useState<string | null>(null);
  const [showGapOnly, setShowGapOnly] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const res = await fetch('/api/dashboard/compliance');
        if (!res.ok) throw new Error(`API error: ${res.status}`);
        const json = await res.json();
        setData(json);
        // Auto-expand first framework
        const keys = Object.keys(json);
        if (keys.length > 0) setExpandedFw(keys[0]);
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

  const frameworks = Object.entries(data);
  const totalControls = frameworks.reduce((sum, [, fw]) => sum + fw.total_controls, 0);
  const totalPassing = frameworks.reduce((sum, [, fw]) => sum + fw.pass_count, 0);
  const overallScore = totalControls > 0 ? Math.round((totalPassing / totalControls) * 100) : 0;

  // Gap analysis: all non-passing controls across all frameworks
  const gaps: (ComplianceControl & { framework_name: string; framework_key: string })[] = [];
  for (const [key, fw] of frameworks) {
    for (const ctrl of fw.controls) {
      if (ctrl.status !== 'pass') {
        gaps.push({ ...ctrl, framework_name: fw.name, framework_key: key });
      }
    }
  }
  // Sort: fail first, then warn
  gaps.sort((a, b) => (a.status === 'fail' ? 0 : 1) - (b.status === 'fail' ? 0 : 1));

  return (
    <div className="max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Compliance Posture</h2>
          <p className="text-sm text-gray-500 mt-1">
            {frameworks.length} active framework{frameworks.length !== 1 ? 's' : ''} &middot; {totalControls} controls evaluated
          </p>
        </div>
        <div className="flex items-center gap-4">
          <ScoreRing score={overallScore} size={64} />
          <div className="text-right">
            <div className="text-2xl font-bold text-gray-900">{overallScore}%</div>
            <div className="text-xs text-gray-500">Overall Score</div>
          </div>
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-3 gap-4">
        <div className="bg-green-50 border border-green-200 rounded-xl p-4 text-center">
          <div className="text-2xl font-bold text-green-700">{totalPassing}</div>
          <div className="text-xs text-green-600 font-medium mt-1">Controls Passing</div>
        </div>
        <div className="bg-yellow-50 border border-yellow-200 rounded-xl p-4 text-center">
          <div className="text-2xl font-bold text-yellow-700">
            {frameworks.reduce((sum, [, fw]) => sum + fw.warn_count, 0)}
          </div>
          <div className="text-xs text-yellow-600 font-medium mt-1">Warnings</div>
        </div>
        <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-center">
          <div className="text-2xl font-bold text-red-700">
            {frameworks.reduce((sum, [, fw]) => sum + fw.fail_count, 0)}
          </div>
          <div className="text-xs text-red-600 font-medium mt-1">Failing</div>
        </div>
      </div>

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
                  <ScoreRing score={fw.score} size={48} />
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
                  {/* Status summary dots */}
                  <div className="flex gap-1">
                    {fw.controls.map((ctrl, i) => (
                      <span
                        key={i}
                        className={`w-2.5 h-2.5 rounded-full ${STATUS_CONFIG[ctrl.status].dot}`}
                        title={`${ctrl.id}: ${ctrl.name} — ${ctrl.status}`}
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
                  {fw.description && (
                    <p className="text-xs text-gray-500 mb-3">{fw.description}</p>
                  )}
                  {fw.controls.map(ctrl => {
                    const cfg = STATUS_CONFIG[ctrl.status];
                    return (
                      <div
                        key={ctrl.id}
                        className={`flex items-center justify-between px-4 py-3 rounded-lg border ${cfg.bg} ${cfg.border}`}
                      >
                        <div className="flex items-center gap-3 min-w-0 flex-1">
                          <span className={`w-2 h-2 rounded-full flex-shrink-0 ${cfg.dot}`} />
                          <div className="min-w-0">
                            <div className="text-sm font-medium text-gray-900">
                              <span className="text-gray-500 font-mono text-xs mr-2">{ctrl.id}</span>
                              {ctrl.name}
                            </div>
                            <div className="text-xs text-gray-600 mt-0.5">{ctrl.detail}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3 flex-shrink-0 ml-4">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${cfg.bg} ${cfg.text}`}>
                            {cfg.label}
                          </span>
                          {ctrl.drilldown_url && (
                            <Link
                              to={ctrl.drilldown_url}
                              className="text-xs text-blue-600 hover:text-blue-700 font-medium"
                            >
                              View
                            </Link>
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* Gap Analysis */}
      {gaps.length > 0 && (
        <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
          <div className="px-6 py-4 border-b flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-gray-900">Gap Analysis</h3>
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
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {gaps
                  .filter(g => !showGapOnly || g.status === 'fail')
                  .map((gap, i) => {
                    const cfg = STATUS_CONFIG[gap.status];
                    return (
                      <tr key={`${gap.framework_key}-${gap.id}-${i}`} className="hover:bg-gray-50">
                        <td className="px-6 py-3 text-xs font-medium text-gray-700">{gap.framework_name}</td>
                        <td className="px-4 py-3 font-mono text-xs text-gray-500">{gap.id}</td>
                        <td className="px-4 py-3 text-gray-900">{gap.name}</td>
                        <td className="px-4 py-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-semibold uppercase ${cfg.bg} ${cfg.text}`}>
                            {cfg.label}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-right font-mono text-gray-900">{gap.value}</td>
                        <td className="px-4 py-3 text-right font-mono text-gray-500">{gap.pass_threshold}</td>
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
