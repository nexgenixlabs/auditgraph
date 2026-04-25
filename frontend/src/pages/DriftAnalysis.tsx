import React, { useState, useEffect } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { DN } from '../components/dashboard/ciso-shared';
import PrivilegeDrift from './PrivilegeDrift';
import DriftHistory from './DriftHistory';

// ── Baseline data from GET /api/drift/baseline ──

interface BaselineData {
  scan_count: number;
  baseline_date?: string;
  total_identities?: number;
  privileged_identities?: number;
  role_assignments?: number;
}

// ── State 1: Zero scans ──

function ZeroScansState() {
  return (
    <div className="flex-1 flex items-center justify-center p-8">
      <div className="text-center max-w-md">
        <div className="w-12 h-12 rounded-full bg-[#111827] border border-white/10 flex items-center justify-center mx-auto mb-4">
          <svg className="w-5 h-5 text-gray-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 6v6h4.5m4.5 0a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
        </div>
        <h2 className="text-sm font-semibold text-gray-200 mb-2">Run your first scan to establish baseline</h2>
        <p className="text-xs text-gray-400 leading-relaxed mb-5">
          Drift Analysis tracks changes between scans — new identities, removed access, and privilege escalations.
        </p>
        <DN navigateTo="/settings/connections">
          <button className="px-4 py-2 rounded-lg text-xs font-medium text-white bg-[#24A2A1] hover:bg-[#1d8a89] transition cursor-pointer">
            Run First Scan &rarr;
          </button>
        </DN>
      </div>
    </div>
  );
}

// ── State 2: Single scan — baseline captured ──

function BaselineState({ data }: { data: BaselineData }) {
  const baselineDate = data.baseline_date
    ? new Date(data.baseline_date).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })
    : 'Unknown';

  return (
    <div className="flex-1 overflow-auto p-4 space-y-4">
      <div>
        <h1 className="text-sm font-semibold text-gray-200">Drift Analysis</h1>
        <p className="text-xs text-gray-400 mt-0.5">Identity change detection between scans</p>
      </div>

      {/* Progress card */}
      <div className="bg-[#111827] border-l-[3px] border-[#24A2A1] rounded-lg p-4">
        <p className="text-sm font-semibold text-gray-200">Baseline Captured</p>
        <p className="text-xs text-gray-400 mt-1">
          Scan 1 of 2 complete. Run a second scan to start detecting drift.
        </p>
        <div className="mt-3 flex items-center gap-3">
          <div className="flex-1 h-1.5 bg-[#1e2d4a] rounded-full overflow-hidden">
            <div className="h-full w-1/2 bg-[#24A2A1] rounded-full" />
          </div>
        </div>
        <div className="flex items-center justify-between mt-1.5">
          <span className="text-[10px] text-[#24A2A1] font-medium">Step 1: Baseline &#10003;</span>
          <span className="text-[10px] text-gray-500">Step 2: Compare</span>
        </div>
      </div>

      {/* Baseline summary */}
      <div className="bg-[#111827] border border-white/5 rounded-lg p-4 space-y-3">
        <p className="text-xs font-medium text-gray-300">
          Baseline established {baselineDate}
        </p>
        <div className="grid grid-cols-3 gap-4">
          <div>
            <p className="text-lg font-semibold text-gray-100 font-mono">{(data.total_identities ?? 0).toLocaleString()}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Identities catalogued</p>
          </div>
          <div>
            <p className="text-lg font-semibold text-gray-100 font-mono">{(data.privileged_identities ?? 0).toLocaleString()}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Privileged identities</p>
          </div>
          <div>
            <p className="text-lg font-semibold text-gray-100 font-mono">{(data.role_assignments ?? 0).toLocaleString()}</p>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider">Role assignments</p>
          </div>
        </div>
      </div>

      <DN navigateTo="/settings/connections">
        <button className="px-4 py-2 rounded-lg text-xs font-medium text-white bg-[#24A2A1] hover:bg-[#1d8a89] transition cursor-pointer">
          Run Second Scan &rarr;
        </button>
      </DN>
    </div>
  );
}

// ── State 3: Full drift view (2+ scans) — tabbed ──

type DriftTab = 'changes' | 'history' | 'escalations';

function FullDriftView() {
  const [tab, setTab] = useState<DriftTab>('changes');

  const tabs: { key: DriftTab; label: string }[] = [
    { key: 'changes', label: 'Changes' },
    { key: 'history', label: 'History' },
    { key: 'escalations', label: 'Escalations' },
  ];

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      {/* Tab bar */}
      <div className="flex items-center gap-1 px-4 pt-3 pb-0 flex-shrink-0">
        {tabs.map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            className={`px-3 py-1.5 rounded-t text-xs font-medium transition ${
              tab === t.key
                ? 'text-[#24A2A1] bg-[#111827] border border-white/5 border-b-0'
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-hidden">
        {tab === 'changes' && <PrivilegeDrift />}
        {tab === 'history' && <DriftHistory />}
        {tab === 'escalations' && <PrivilegeDrift key="esc" />}
      </div>
    </div>
  );
}

// ── Main DriftAnalysis page ──

export default function DriftAnalysis() {
  const { withConnection, loading: connectionLoading, connections } = useConnection();
  const [baseline, setBaseline] = useState<BaselineData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (connectionLoading || connections.length === 0) return;
    setLoading(true);
    fetch(withConnection('/api/drift/baseline'))
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setBaseline(d))
      .catch(() => setBaseline({ scan_count: 0 }))
      .finally(() => setLoading(false));
  }, [withConnection, connectionLoading, connections.length]);

  if (loading || !baseline) {
    return (
      <div className="flex-1 flex items-center justify-center">
        <div className="w-5 h-5 border-2 border-[#24A2A1] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (baseline.scan_count === 0) return <ZeroScansState />;
  if (baseline.scan_count === 1) return <BaselineState data={baseline} />;
  return <FullDriftView />;
}
