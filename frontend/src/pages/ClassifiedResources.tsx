/**
 * AG-193 follow-up — Classified Resources page
 *
 * Landing for the Unified Identity Graph "Storage / KV / SQL" + "Classified
 * Data" tier clicks. Shows the actual resources backing the Data Sources
 * tier count, with classification provenance and zone link.
 *
 * URL: /data-classification[?classification=PHI|PCI|PII|...]
 */
import React, { useEffect, useMemo, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';

const CLASSES = [
  { key: 'PHI',          color: '#dc2626' },
  { key: 'PCI',          color: '#ea580c' },
  { key: 'PII',          color: '#d97706' },
  { key: 'SOURCE',       color: '#7c3aed' },
  { key: 'HR',           color: '#0891b2' },
  { key: 'FINANCIAL',    color: '#059669' },
  { key: 'CONFIDENTIAL', color: '#475569' },
] as const;

const SOURCE_LABEL: Record<string, string> = {
  manual: 'Manual',
  regex_override: 'Regex Override',
  scope_rule: 'Data Trust Zone',
  purview: 'Purview',
  tag: 'Azure Tag',
  name_pattern: 'Name Pattern',
};

interface ResourceRow {
  resource_id: string;
  name: string;
  kind: string;
  classification: string;
  source: string;
  confidence: number;
  rule_id: number | null;
  asserted_by: string | null;
  subscription_id: string | null;
  resource_group: string | null;
}

interface Resp {
  resources: ResourceRow[];
  count: number;
  by_classification: Record<string, number>;
  by_source: Record<string, number>;
}

function confBand(conf: number): { label: string; color: string } {
  if (conf >= 85) return { label: 'High',   color: '#10b981' };
  if (conf >= 60) return { label: 'Medium', color: '#fbbf24' };
  return                    { label: 'Low',    color: '#94a3b8' };
}

export default function ClassifiedResources() {
  const [params, setParams] = useSearchParams();
  const classFilter = params.get('classification') || '';
  const sourceFilter = params.get('source') || '';

  const [data, setData] = useState<Resp | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setLoading(true);
    const q = new URLSearchParams();
    if (classFilter) q.set('classification', classFilter);
    if (sourceFilter) q.set('source', sourceFilter);
    q.set('limit', '500');
    fetch(`/api/resources/classified?${q.toString()}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [classFilter, sourceFilter]);

  const totals = useMemo(() => {
    const byClass = data?.by_classification || {};
    const total = Object.values(byClass).reduce((a, b) => a + b, 0);
    return { total, byClass };
  }, [data]);

  function setClass(c: string) {
    const next = new URLSearchParams(params);
    if (c) next.set('classification', c); else next.delete('classification');
    setParams(next, { replace: true });
  }

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-5">
      <div>
        <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-violet-400">Graph Intelligence · Data Sources</p>
        <h1 className="text-2xl font-bold text-white mt-1">Classified Resources</h1>
        <p className="text-sm text-slate-400 mt-2 max-w-3xl leading-relaxed">
          Every resource carrying a data classification — Storage / Key Vault / SQL / Cosmos / generic. AuditGraph
          reads names + tags + Data Trust Zones to assign these labels; we never read the data itself.
        </p>
        <p className="text-[11px] text-slate-500 mt-2">
          Configure scope in{' '}
          <Link to="/settings/data-trust-zones" className="text-violet-400 hover:underline">Settings → Data Trust Zones</Link>.
        </p>
      </div>

      {/* Class filter chips */}
      <div className="flex items-center gap-2 flex-wrap">
        <button onClick={() => setClass('')}
          className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition ${
            !classFilter ? 'bg-slate-700 text-white border-slate-500' : 'text-slate-400 border-slate-700 hover:text-white'
          }`}>
          All · {totals.total.toLocaleString()}
        </button>
        {CLASSES.map(c => {
          const n = totals.byClass[c.key] || 0;
          const active = classFilter === c.key;
          return (
            <button key={c.key} onClick={() => setClass(c.key)}
              className="px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider border transition"
              style={{
                background: active ? `${c.color}33` : 'transparent',
                borderColor: active ? c.color : '#334155',
                color: active ? c.color : (n === 0 ? '#475569' : '#94a3b8'),
              }}>
              {c.key} · {n}
            </button>
          );
        })}
      </div>

      {loading && <p className="text-[11px] text-slate-500 text-center py-10">Loading…</p>}

      {/* Empty state */}
      {!loading && (data?.resources.length ?? 0) === 0 && (
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 p-8 text-center">
          <p className="text-sm text-slate-300 font-semibold">No classified resources yet</p>
          <p className="text-[12px] text-slate-500 mt-1 max-w-md mx-auto">
            Add a Data Trust Zone or tag your sensitive Azure resources, then re-run discovery.
          </p>
          <Link to="/settings/data-trust-zones" className="inline-block mt-4 px-3 py-1.5 rounded-lg text-xs font-medium bg-violet-500 hover:bg-violet-400 text-white">
            Add a Zone →
          </Link>
        </div>
      )}

      {/* Resource table */}
      {!loading && (data?.resources.length ?? 0) > 0 && (
        <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-slate-800/40 border-b border-slate-700/40">
              <tr>
                <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Resource</th>
                <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Kind</th>
                <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Class</th>
                <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Source</th>
                <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Confidence</th>
                <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Resource Group</th>
              </tr>
            </thead>
            <tbody>
              {(data?.resources || []).map((r, i) => {
                const c = CLASSES.find(x => x.key === r.classification);
                const band = confBand(r.confidence);
                return (
                  <tr key={`${r.resource_id}-${i}`} className="border-b border-slate-800/40 hover:bg-slate-800/30 transition">
                    <td className="p-3 font-mono text-slate-200">
                      <span className="truncate block max-w-xs" title={r.resource_id}>{r.name}</span>
                    </td>
                    <td className="p-3 text-slate-400">{r.kind}</td>
                    <td className="p-3">
                      <span className="px-1.5 py-0.5 rounded text-[9px] font-bold uppercase tracking-wider"
                        style={{ background: `${c?.color || '#94a3b8'}22`, color: c?.color || '#94a3b8' }}>
                        {r.classification}
                      </span>
                    </td>
                    <td className="p-3 text-slate-300">{SOURCE_LABEL[r.source] || r.source}</td>
                    <td className="p-3">
                      <span className="inline-flex items-center gap-1">
                        <span className="w-1.5 h-1.5 rounded-full" style={{ background: band.color }} />
                        <span className="text-slate-300">{r.confidence}</span>
                        <span className="text-slate-500 text-[10px]">({band.label})</span>
                      </span>
                    </td>
                    <td className="p-3 text-slate-400 font-mono truncate max-w-xs" title={r.resource_group || ''}>
                      {r.resource_group || '—'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          <div className="p-3 border-t border-slate-700/40 text-[10px] text-slate-500 flex items-center justify-between">
            <span>Showing {data?.count || 0} resources</span>
            {sourceFilter && (
              <button onClick={() => setParams(new URLSearchParams())} className="text-violet-400 hover:underline">
                Clear filters
              </button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
