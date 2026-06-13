/**
 * AG-193 (Sprint 1) — Exposure Derivation Drawer
 *
 * Side-drawer that opens when any $X.XM exposure value is clicked across
 * Executive Posture / CISODashboard / Exposure Explorer. Shows the
 * components that built the number so a CISO can audit-defend it.
 *
 * Sprint 1 v1: classification (PHI/PCI/PII), active zones, resource
 * count, by_source breakdown, by_confidence_band, per-asset rate.
 * Sprint 2 adds: reachable identities, attack paths terminating here,
 * individual contributing resources.
 */
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

interface DerivationResponse {
  classification: string;
  zones: Array<{ id: number; scope_type: string; scope_value: string; asserted_by: string | null; asserted_at: string | null }>;
  resource_count: number;
  by_source: Record<string, number>;
  by_confidence_band: { high: number; medium: number; low: number };
  per_asset: number;
  value: number;
  source_doc: string;
}

const SOURCE_LABELS: Record<string, string> = {
  manual: 'Manual override (admin)',
  regex_override: 'Regex override (tenant settings)',
  scope_rule: 'Data Trust Zone (CISO asserted)',
  purview: 'Microsoft Purview',
  tag: 'Azure tag',
  name_pattern: 'Name pattern (heuristic)',
};

const CLASS_COLORS: Record<string, string> = {
  PHI: '#dc2626', PCI: '#ea580c', PII: '#d97706',
  SOURCE: '#7c3aed', HR: '#0891b2', FINANCIAL: '#059669', CONFIDENTIAL: '#475569',
};

function fmtMoney(v: number): string {
  if (v >= 1_000_000) return `$${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return `$${(v / 1_000).toFixed(1)}K`;
  return `$${v.toLocaleString()}`;
}

export function ExposureDerivationDrawer({
  classification, open, onClose,
}: {
  classification: string | null;
  open: boolean;
  onClose: () => void;
}) {
  const [data, setData] = useState<DerivationResponse | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!open || !classification) return;
    setLoading(true);
    fetch(`/api/exposure/derivation/${classification}`)
      .then(r => r.ok ? r.json() : null)
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [open, classification]);

  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open || !classification) return null;

  const color = CLASS_COLORS[classification] || '#94a3b8';

  return (
    <div className="fixed inset-0 z-50 flex items-stretch justify-end bg-black/60 backdrop-blur-sm"
      onClick={onClose} role="dialog" aria-modal="true">
      <div className="w-full max-w-[560px] bg-slate-900 border-l border-white/10 overflow-y-auto"
        onClick={e => e.stopPropagation()}>

        <header className="sticky top-0 z-10 bg-slate-900/95 backdrop-blur border-b border-white/10 px-6 py-4 flex items-start justify-between gap-3">
          <div>
            <p className="text-[10px] uppercase tracking-[0.2em] font-bold" style={{ color }}>
              {classification} · Potential Exposure Impact
            </p>
            <h2 className="text-lg font-bold text-white mt-0.5">Where this number comes from</h2>
          </div>
          <button onClick={onClose} aria-label="Close"
            className="text-slate-400 hover:text-white text-xl leading-none w-8 h-8 rounded-lg hover:bg-slate-800 flex items-center justify-center transition">
            ×
          </button>
        </header>

        <div className="px-6 py-5 space-y-5">
          {loading && <p className="text-[11px] text-slate-500">Loading…</p>}

          {data && (
            <>
              {/* Headline */}
              <div className="rounded-xl p-4 border" style={{ background: `${color}10`, borderColor: `${color}40` }}>
                <p className="text-[10px] uppercase tracking-wider font-bold text-slate-400">{classification} Subtotal</p>
                <p className="text-5xl font-bold font-mono mt-1" style={{ color }}>{fmtMoney(data.value)}</p>
                <p className="text-[11px] text-slate-400 mt-2">
                  {data.resource_count.toLocaleString()} classified resources × {fmtMoney(data.per_asset)} per asset
                </p>
                <p className="text-[10px] text-slate-500 mt-1">{data.source_doc}</p>
              </div>

              {/* Full formula breakdown — peer feedback 2026-06-12.
                  Shows the math behind the total so a CFO/CISO can re-derive
                  it from the drawer alone. */}
              <TotalBreakdownSection />

              {/* What this is / what it isn't — honest claim block */}
              <CaveatBlock />

              {/* Zones */}
              <div>
                <h3 className="text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-2">
                  Active Data Trust Zones ({data.zones.length})
                </h3>
                {data.zones.length === 0 ? (
                  <p className="text-[11px] text-slate-500 italic">
                    No CISO-asserted zones for {classification} yet.{' '}
                    <Link to="/settings/data-trust-zones" className="text-violet-400 hover:underline">Add one →</Link>
                  </p>
                ) : (
                  <div className="space-y-1.5">
                    {data.zones.map(z => (
                      <div key={z.id} className="p-2.5 rounded-lg bg-slate-800/40 border border-slate-700/40">
                        <p className="text-sm font-mono text-white truncate">{z.scope_value}</p>
                        <p className="text-[10px] text-slate-500 mt-0.5">
                          {z.scope_type}
                          {z.asserted_by && ` · ${z.asserted_by}`}
                          {z.asserted_at && ` · ${new Date(z.asserted_at).toLocaleDateString()}`}
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* By source */}
              <div>
                <h3 className="text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-2">By Classification Source</h3>
                <div className="space-y-1.5">
                  {Object.entries(data.by_source).sort((a, b) => b[1] - a[1]).map(([src, cnt]) => (
                    <div key={src} className="flex items-center justify-between p-2 rounded-lg bg-slate-800/40 border border-slate-700/40">
                      <span className="text-xs text-slate-300">{SOURCE_LABELS[src] || src}</span>
                      <span className="text-xs font-mono font-bold text-white">{cnt.toLocaleString()}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Confidence bands */}
              <div>
                <h3 className="text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-2">Confidence Bands</h3>
                <div className="grid grid-cols-3 gap-2">
                  <Band label="High" count={data.by_confidence_band.high}    color="#10b981" hint="zone / manual / regex / purview" />
                  <Band label="Med"  count={data.by_confidence_band.medium}  color="#fbbf24" hint="tag" />
                  <Band label="Low"  count={data.by_confidence_band.low}     color="#94a3b8" hint="name pattern" />
                </div>
              </div>

              {/* Sprint 2 — full lineage */}
              <LineageSection classification={data.classification} />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

interface BusinessImpactResp {
  phi_assets: { count: number; value: number; per_asset: number };
  pci_assets: { count: number; value: number; per_asset: number };
  pii_assets: { count: number; value: number; per_asset: number };
  ai_models:  {
    count: number; value: number; per_asset: number;
    with_reach_count?: number; attributable_exposure?: number;
    attributable_phi?: number; attributable_pci?: number; attributable_pii?: number;
  };
  total_exposure: number;
  source: string;
}

function TotalBreakdownSection() {
  const [bi, setBi] = useState<BusinessImpactResp | null>(null);
  useEffect(() => {
    fetch('/api/dashboard/business-impact')
      .then(r => r.ok ? r.json() : null)
      .then(setBi)
      .catch(() => {});
  }, []);
  if (!bi) return null;
  // Only PHI/PCI/PII rows are additive. AI is rendered as a non-additive
  // attribution row below — see founder feedback 2026-06-13: "count × $0
  // is structurally misleading because AI doesn't add a dollar line."
  const dataRows: { key: string; label: string; color: string; row: { count: number; value: number; per_asset: number } }[] = [
    { key: 'PHI', label: 'PHI Assets', color: CLASS_COLORS.PHI, row: bi.phi_assets },
    { key: 'PCI', label: 'PCI Assets', color: CLASS_COLORS.PCI, row: bi.pci_assets },
    { key: 'PII', label: 'PII Assets', color: CLASS_COLORS.PII, row: bi.pii_assets },
  ];
  const ai = bi.ai_models;
  const aiWithReach = ai.with_reach_count ?? 0;
  const aiAttribution = ai.attributable_exposure ?? 0;
  return (
    <div>
      <h3 className="text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-2">Total Exposure Formula</h3>
      <div className="rounded-xl bg-slate-800/40 border border-slate-700/40 overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-slate-900/40 border-b border-slate-700/40">
            <tr>
              <th className="text-left p-2.5 text-[9px] uppercase tracking-wider font-bold text-slate-500">Class</th>
              <th className="text-right p-2.5 text-[9px] uppercase tracking-wider font-bold text-slate-500">Count</th>
              <th className="text-right p-2.5 text-[9px] uppercase tracking-wider font-bold text-slate-500">×&nbsp;Per Asset</th>
              <th className="text-right p-2.5 text-[9px] uppercase tracking-wider font-bold text-slate-500">=&nbsp;Subtotal</th>
            </tr>
          </thead>
          <tbody>
            {dataRows.map(r => (
              <tr key={r.key} className="border-b border-slate-800/40 last:border-0">
                <td className="p-2.5">
                  <span className="inline-flex items-center gap-1.5">
                    <span className="w-1.5 h-1.5 rounded-full" style={{ background: r.color }} />
                    <span className="text-slate-300">{r.label}</span>
                  </span>
                </td>
                <td className="p-2.5 text-right text-slate-300 font-mono">{r.row.count.toLocaleString()}</td>
                <td className="p-2.5 text-right text-slate-400 font-mono">{fmtMoney(r.row.per_asset)}</td>
                <td className="p-2.5 text-right text-white font-mono font-bold">{fmtMoney(r.row.value)}</td>
              </tr>
            ))}
            <tr className="bg-slate-900/60 border-t-2 border-slate-700">
              <td className="p-2.5 text-[10px] uppercase tracking-wider font-bold text-slate-400">Total (classified data)</td>
              <td className="p-2.5" />
              <td className="p-2.5" />
              <td className="p-2.5 text-right text-red-400 font-mono font-bold text-base">{fmtMoney(bi.total_exposure)}</td>
            </tr>
          </tbody>
        </table>
      </div>

      {/* AI attribution — rendered separately so it doesn't read as
          "$0 added to the total". AI is attribution, not contribution. */}
      <div className="mt-3 rounded-xl bg-slate-800/30 border border-slate-700/40 p-3">
        <div className="flex items-center justify-between mb-1">
          <span className="inline-flex items-center gap-1.5 text-[11px] text-slate-300 font-semibold">
            <span className="w-1.5 h-1.5 rounded-full" style={{ background: '#a855f7' }} />
            AI Workloads — Attribution (non-additive)
          </span>
          <span className="text-[10px] text-slate-500">share of total reachable by AI</span>
        </div>
        <div className="grid grid-cols-3 gap-3 text-[11px]">
          <div>
            <p className="text-[9px] uppercase tracking-wider text-slate-500">Discovered</p>
            <p className="text-base font-mono font-bold text-white">{ai.count.toLocaleString()}</p>
          </div>
          <div>
            <p className="text-[9px] uppercase tracking-wider text-slate-500">Reach Classified</p>
            <p className="text-base font-mono font-bold" style={{ color: aiWithReach > 0 ? '#fbbf24' : '#10b981' }}>
              {aiWithReach.toLocaleString()}
            </p>
          </div>
          <div>
            <p className="text-[9px] uppercase tracking-wider text-slate-500">Attributable $$</p>
            <p className="text-base font-mono font-bold" style={{ color: aiAttribution > 0 ? '#f87171' : '#10b981' }}>
              {fmtMoney(aiAttribution)}
            </p>
          </div>
        </div>
        {aiWithReach === 0 && ai.count > 0 && (
          <p className="text-[10px] text-emerald-400/80 mt-2">
            ✓ AI workloads are correctly segregated — none have RBAC reach to classified data.
          </p>
        )}
        {aiWithReach > 0 && (
          <p className="text-[10px] text-amber-400/80 mt-2">
            {aiWithReach} AI workload{aiWithReach > 1 ? 's' : ''} can reach classified data — see Top Reach by AI Model on the dashboard.
          </p>
        )}
      </div>

      <p className="text-[10px] text-slate-500 mt-2">
        {bi.source}.{' '}
        <Link to="/settings/exposure-defaults" className="text-violet-400 hover:underline">Edit per-asset defaults →</Link>
      </p>
    </div>
  );
}

function CaveatBlock() {
  return (
    <div className="rounded-xl bg-slate-800/30 border border-slate-700/40 p-4">
      <h3 className="text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-2">What This Is — And Isn't</h3>
      <div className="grid grid-cols-2 gap-3 text-[11px]">
        <div>
          <p className="text-emerald-400 font-bold mb-1.5">What it is</p>
          <ul className="space-y-1 text-slate-400 leading-snug list-disc list-inside marker:text-emerald-400/60">
            <li>A benchmark estimate using public breach-cost data</li>
            <li>A way to compare assets and prioritize remediation</li>
            <li>Re-derivable from the table above</li>
          </ul>
        </div>
        <div>
          <p className="text-amber-400 font-bold mb-1.5">What it isn't</p>
          <ul className="space-y-1 text-slate-400 leading-snug list-disc list-inside marker:text-amber-400/60">
            <li>An actuarial loss model</li>
            <li>A probability-weighted breach prediction</li>
            <li>Insurance-grade quantification</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

function LineageSection({ classification }: { classification: string }) {
  const [lineage, setLineage] = useState<{
    reachable_identities: number;
    attack_paths_terminating: number;
    internet_reachable_resources: number;
  } | null>(null);
  useEffect(() => {
    fetch(`/api/exposure/derivation/${classification}/lineage`)
      .then(r => r.ok ? r.json() : null)
      .then(setLineage);
  }, [classification]);
  if (!lineage) return null;
  return (
    <div>
      <h3 className="text-[10px] uppercase tracking-wider font-bold text-slate-400 mb-2">Exposure Chain</h3>
      <div className="space-y-1.5">
        <LineageRow icon="👤" label="Reachable identities (with role assignments)"  value={lineage.reachable_identities} />
        <LineageRow icon="⚔️" label="Multi-hop attack paths terminating here"        value={lineage.attack_paths_terminating} />
        <LineageRow icon="🌐" label="Internet-reachable classified resources"        value={lineage.internet_reachable_resources} />
      </div>
    </div>
  );
}

function LineageRow({ icon, label, value }: { icon: string; label: string; value: number }) {
  return (
    <div className="flex items-center justify-between p-2 rounded-lg bg-slate-800/40 border border-slate-700/40">
      <span className="text-xs text-slate-300 flex items-center gap-2"><span>{icon}</span>{label}</span>
      <span className="text-xs font-mono font-bold text-white">{value.toLocaleString()}</span>
    </div>
  );
}

function Band({ label, count, color, hint }: { label: string; count: number; color: string; hint: string }) {
  return (
    <div className="rounded-lg p-2.5 border text-center"
      style={{ background: `${color}10`, borderColor: `${color}33` }}>
      <p className="text-[9px] uppercase tracking-wider font-bold" style={{ color }}>{label}</p>
      <p className="text-xl font-bold font-mono mt-1 text-white">{count.toLocaleString()}</p>
      <p className="text-[9px] text-slate-500 mt-0.5">{hint}</p>
    </div>
  );
}
