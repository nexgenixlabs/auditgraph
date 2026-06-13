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
              {classification} Exposure
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
                <p className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Total Exposure</p>
                <p className="text-5xl font-bold font-mono mt-1" style={{ color }}>{fmtMoney(data.value)}</p>
                <p className="text-[11px] text-slate-400 mt-2">
                  {data.resource_count.toLocaleString()} classified resources × {fmtMoney(data.per_asset)} per asset
                </p>
                <p className="text-[10px] text-slate-500 mt-1">{data.source_doc}</p>
              </div>

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
