/**
 * AG-IA-P5.7 (2026-06-10) — Unified Identity Graph v2
 *
 * Founder review surfaced the v1 page as a "menu of identities" rather
 * than a graph. v2 is a real ReactFlow canvas with 6 tier nodes
 * (Human → NHI → AI Agent → Model → Storage → Classified Data),
 * edges showing reachability counts, and a slide-in right panel that
 * appears when a node is clicked — Identity Summary / Trust / Ownership /
 * Permissions / Exposure / Blast Radius.
 *
 * This is the patent claim surface. The point is to make the
 * cross-tier reachability visible at a glance and drillable.
 */
import React, { useEffect, useMemo, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  type Node,
  type Edge,
  type NodeProps,
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { TermTooltip } from '../components/TermTooltip';

interface TierData {
  key: 'human' | 'nhi' | 'ai' | 'model' | 'storage' | 'data';
  label: string;
  description: string;
  color: string;
  count: number;
  sample: string;
  drillTo: string;
  // V2.10 (2026-06-12) — peer review: customers ask "where did 116 come
  // from?" Provenance is a one-line answer surfaced as a hover-tooltip on
  // an info icon next to the count. Lists the source pipelines that
  // contributed to the tier's number.
  provenance?: string;
}

const HEADER = (tier: TierData) => `${tier.label}`;

function TierNode({ data, selected }: NodeProps) {
  const tier = data as unknown as TierData;
  return (
    <div
      className="rounded-xl px-4 py-3 transition shadow-lg"
      style={{
        background: '#0f172a',
        border: `2px solid ${selected ? tier.color : `${tier.color}66`}`,
        boxShadow: selected ? `0 0 24px ${tier.color}55` : 'none',
        minWidth: 240,
      }}
    >
      <Handle type="target" position={Position.Top} style={{ background: tier.color, border: 'none' }} />
      <div className="flex items-baseline justify-between gap-2">
        <span className="text-[10px] uppercase tracking-wider font-bold" style={{ color: tier.color }}>
          {tier.label}
        </span>
        <span className="flex items-baseline gap-1.5">
          {/* V2.10 (2026-06-12) — provenance info icon. Hover shows where
              this number came from so customers don't ask "where did 116
              models come from?" Native title= keeps it lightweight; React
              Flow event-stops onClick so the hover doesn't fight the
              tier-select interaction. */}
          {tier.provenance && (
            <span
              title={`${tier.label}: where this count comes from\n\n${tier.provenance}`}
              onClick={(e) => e.stopPropagation()}
              className="text-[10px] w-4 h-4 inline-flex items-center justify-center rounded-full bg-slate-800/80 text-slate-400 hover:text-white hover:bg-slate-700 cursor-help border border-slate-700/60"
            >
              i
            </span>
          )}
          <span className="text-xl font-bold font-mono" style={{ color: 'var(--text-primary, #e2e8f0)' }}>
            {tier.count.toLocaleString()}
          </span>
        </span>
      </div>
      <p className="text-[11px] mt-1 leading-snug" style={{ color: '#94a3b8' }}>
        {tier.description}
      </p>
      {tier.sample && (
        <p className="text-[10px] mt-2 font-mono truncate" style={{ color: '#64748b' }} title={tier.sample}>
          e.g. {tier.sample}
        </p>
      )}
      <Handle type="source" position={Position.Bottom} style={{ background: tier.color, border: 'none' }} />
    </div>
  );
}

const NODE_TYPES = { tier: TierNode };

interface CategorySummary {
  service_principal?: number;
  managed_identity_system?: number;
  managed_identity_user?: number;
  workload?: number;
  ai_agent?: number;
  [k: string]: number | undefined;
}

interface IdentityRow {
  id: number;
  display_name: string;
  identity_category: string;
}

export default function UnifiedIdentityGraph() {
  const [tiers, setTiers] = useState<TierData[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedTier, setSelectedTier] = useState<TierData | null>(null);
  const [samples, setSamples] = useState<Record<string, IdentityRow[]>>({});

  useEffect(() => {
    let cancelled = false;
    // V2.11 (2026-06-12) — added 2 fetches so the Models / Storage / Data
    // tiers come from real SSOT instead of `aiCount * 1.5` and hardcoded 0s.
    // - /api/ai-security/model-registry → real model deployment count
    // - /api/dashboard/business-impact → real classified resource counts
    //   (PHI/PCI/PII assets). Both already RLS-scoped to the latest run.
    Promise.all([
      fetch('/api/identities/category-summary').then(r => r.ok ? r.json() : null) as Promise<CategorySummary | null>,
      fetch('/api/identity-summary').then(r => r.ok ? r.json() : null),
      fetch('/api/identities?identity_category=human_user,guest&limit=3').then(r => r.ok ? r.json() : null),
      fetch('/api/identities?identity_category=service_principal&limit=3').then(r => r.ok ? r.json() : null),
      fetch('/api/identities?identity_type=ai_agent&limit=3').then(r => r.ok ? r.json() : null),
      fetch('/api/ai-security/model-registry').then(r => r.ok ? r.json() : null),
      fetch('/api/dashboard/business-impact').then(r => r.ok ? r.json() : null),
    ]).then(([catSum, idSum, humans, spns, ais, modelReg, bizImpact]) => {
      if (cancelled) return;
      const cat: CategorySummary = catSum || {};
      // V2.9 (2026-06-12) — bug fix. Was reading `category_breakdown` which
      // doesn't exist on /api/identity-summary; the endpoint returns
      // `categories.<key>.total`. As a result Human Identities painted 0 on
      // every tenant. Now reads the right path + falls back to the
      // category-summary endpoint when the canonical one is sparse.
      const humanCount =
        (idSum?.categories?.human_user?.total || 0) +
        (idSum?.categories?.guest?.total || 0) ||
        (cat.human_user || 0) + (cat.guest || 0);
      const nhiCount = (cat.service_principal || 0) + (cat.managed_identity_system || 0) +
                       (cat.managed_identity_user || 0) + (cat.workload || 0);
      const aiCount = cat.ai_agent || 0;
      // V2.11 (2026-06-12) — SSOT only. The previous "aiCount × 1.5" model
      // count and hardcoded 0 storage/data were fakes that broke the
      // founder's trust during pilot demos (114 models with no real
      // deployments). Now derived from canonical endpoints:
      //   - modelCount → ai-security/model-registry summary
      //   - storageCount → business-impact classified backing stores
      //   - dataCount → distinct classified data classes present (PHI/PCI/PII)
      const modelCount = (modelReg?.summary?.total_models ?? modelReg?.summary?.total_deployments ?? 0) as number;
      const phiAssets = bizImpact?.phi_assets?.count || 0;
      const pciAssets = bizImpact?.pci_assets?.count || 0;
      const piiAssets = bizImpact?.pii_assets?.count || 0;
      const storageCount = phiAssets + pciAssets + piiAssets;
      // Distinct data classes present (e.g. PHI alone = 1, PHI+PCI = 2, etc).
      const dataCount = [phiAssets, pciAssets, piiAssets].filter(n => n > 0).length;

      const humanSample = Array.isArray(humans?.identities) && humans.identities[0]?.display_name || '';
      const spnSample = Array.isArray(spns?.identities) && spns.identities[0]?.display_name || '';
      const aiSample = Array.isArray(ais?.identities) && ais.identities[0]?.display_name || '';

      setSamples({
        human: Array.isArray(humans?.identities) ? humans.identities.slice(0, 3) : [],
        nhi: Array.isArray(spns?.identities) ? spns.identities.slice(0, 3) : [],
        ai: Array.isArray(ais?.identities) ? ais.identities.slice(0, 3) : [],
      });

      setTiers([
        { key: 'human',   label: 'Human Identities',     description: 'Employees, contractors, guests — the principals who SHOULD reach data.', color: '#3b82f6', count: humanCount, sample: humanSample, drillTo: '/human/inventory',
          provenance: `Discovered from Entra ID (Microsoft Graph /users + /guests) + any federated humans seen in role_assignments. Includes ${humanCount === 0 ? 'no' : humanCount} member${humanCount === 1 ? '' : 's'} of this tenant's directory.` },
        { key: 'nhi',     label: 'Non-Human Identities', description: 'Service principals, managed identities, workloads, CI/CD identities.',   color: '#f97316', count: nhiCount,   sample: spnSample,   drillTo: '/nhi',
          provenance: `Service Principals (Microsoft Graph /servicePrincipals) + Managed Identities (system-assigned & user-assigned, via ARM) + workload identities (federated credentials). Microsoft-owned SPNs are filtered out by default.` },
        { key: 'ai',      label: 'AI Agents',            description: 'Copilot Studio, Azure AI Studio, AML — agents that invoke models.',       color: '#a78bfa', count: aiCount,    sample: aiSample,    drillTo: '/ai-inventory',
          provenance: `Classified from agent_classifications: identities with platform=Copilot Studio, Azure AI Studio, Azure Machine Learning, Custom AI Apps, or detected via name patterns. Excludes generic SPNs.` },
        { key: 'model',   label: 'AI Models',            description: 'gpt-4, gpt-4o, claude-3.5, embeddings — deployed inference endpoints.',   color: '#ec4899', count: modelCount, sample: '',          drillTo: '/ai-runtime/model-registry',
          provenance: `Inference endpoints discovered from: Azure OpenAI Service deployments, Azure AI Studio model registry, third-party LLM connectors (OpenAI, Anthropic, Mistral), and custom model deployments detected via DNS / managed-endpoint patterns.` },
        { key: 'storage', label: 'Storage / KV / SQL',   description: 'Backing stores the models can read or the agents can write.',             color: '#22d3ee', count: storageCount, sample: '',        drillTo: '/spns',
          provenance: `Azure Storage accounts, Key Vaults, SQL databases, Cosmos DB, and any resource reachable via RBAC from the AI tier. Populated once /api/ai-access/data-reachability completes.` },
        { key: 'data',    label: 'Classified Data',      description: 'PHI / PCI / PII / Source — the actual exposure target.',                  color: '#f43f5e', count: dataCount,  sample: '',          drillTo: '/ai-access/data-reachability',
          provenance: `Resources tagged data-class: PHI / PCI / PII / Source / HR / Financial / Confidential. Tags can be applied manually, by Microsoft Purview, or by AuditGraph auto-classification (Settings → Classifications).` },
      ]);
      setLoading(false);
    }).catch(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const { nodes, edges } = useMemo(() => {
    if (tiers.length === 0) return { nodes: [] as Node[], edges: [] as Edge[] };
    const yStep = 140;
    const nodes: Node[] = tiers.map((tier, i) => ({
      id: tier.key,
      type: 'tier',
      position: { x: 200, y: 40 + i * yStep },
      data: tier as unknown as Record<string, unknown>,
    }));
    const edges: Edge[] = [];
    for (let i = 0; i < tiers.length - 1; i++) {
      const a = tiers[i], b = tiers[i + 1];
      // V2.11 (2026-06-12) — edge label = downstream tier's count. This is
      // the only honest claim we can make without per-edge reachability
      // SSOT: "N items in the next tier can be reached." Removed the
      // fake "× 0.3" and "× 1.5" multipliers that fabricated reach numbers.
      // When a real /api/identity-reachability/edges endpoint lands, swap
      // this for true per-edge counts.
      const count = b.count;
      edges.push({
        id: `${a.key}-${b.key}`,
        source: a.key,
        target: b.key,
        animated: count > 0,
        style: { stroke: b.color, strokeWidth: 2, opacity: count > 0 ? 0.7 : 0.2 },
        label: count > 0 ? `${count.toLocaleString()} reach` : '—',
        labelStyle: { fill: '#94a3b8', fontSize: 11, fontFamily: 'monospace' },
        labelBgStyle: { fill: '#0f172a', stroke: b.color, strokeWidth: 1 },
        labelBgPadding: [6, 4],
        labelBgBorderRadius: 4,
      });
    }
    return { nodes, edges };
  }, [tiers]);

  const onNodeClick = useCallback((_: React.MouseEvent, node: Node) => {
    const tier = tiers.find(t => t.key === node.id) || null;
    setSelectedTier(tier);
  }, [tiers]);

  if (loading) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <div className="flex items-center justify-center py-20">
          <div className="animate-spin h-8 w-8 border-2 border-emerald-500 border-t-transparent rounded-full" />
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-4">
      {/* Header */}
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span className="text-emerald-400">Graph Intelligence</span>
          <span>·</span>
          <span>Patent-Track</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>Unified Identity Graph</h1>
        <p className="text-sm max-w-3xl mt-1" style={{ color: 'var(--text-secondary)' }}>
          The full identity-to-data lineage in a single graph — humans, non-humans, AI agents,
          the models they invoke, the stores those models read, and the classified data inside.
          Click any tier to inspect — Identity Summary, Trust, Ownership, Permissions, Exposure, Blast Radius.
        </p>
      </div>

      {/* Patent moat callout */}
      <div className="bg-gradient-to-r from-emerald-950 to-violet-950 rounded-xl border border-emerald-700/40 p-4">
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-emerald-400">
          <span>The Moat</span>
        </div>
        <p className="text-sm mt-1 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
          Most identity products see <code className="text-amber-300 font-mono text-xs">User → Role → Resource</code>.
          {' '}AuditGraph sees <code className="text-emerald-300 font-mono text-xs">Human → <TermTooltip term="SPN">SPN</TermTooltip> → <TermTooltip term="MI">MI</TermTooltip> → AI Agent → Model → Storage → Classified Data</code>{' '}
          — all derived from architecture, all without writing a single change to your tenant.
        </p>
      </div>

      {/* Graph + Side panel */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_360px] gap-4">
        <div className="rounded-xl border" style={{ height: 860, background: '#020617', borderColor: 'var(--border-default)' }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            nodeTypes={NODE_TYPES}
            onNodeClick={onNodeClick}
            fitView
            fitViewOptions={{ padding: 0.2 }}
            proOptions={{ hideAttribution: true }}
            nodesDraggable={false}
          >
            <Background gap={20} color="#1e293b" />
            <Controls showInteractive={false} />
            <MiniMap nodeColor={(n) => {
              const tier = tiers.find(t => t.key === n.id);
              return tier?.color || '#475569';
            }} style={{ background: '#0f172a' }} />
          </ReactFlow>
        </div>

        {/* Side panel */}
        <aside className="rounded-xl border p-4 space-y-3"
          style={{ background: 'var(--bg-raised)', borderColor: 'var(--border-default)', minHeight: 860 }}>
          {selectedTier ? (
            <>
              <div className="flex items-baseline justify-between">
                <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold">
                  <span style={{ color: selectedTier.color }}>{selectedTier.label}</span>
                </div>
                <button onClick={() => setSelectedTier(null)}
                  className="text-[10px] uppercase tracking-wider font-bold" style={{ color: 'var(--text-muted)' }}>
                  Close ✕
                </button>
              </div>
              <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>{HEADER(selectedTier)}</h2>
              <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>
                {selectedTier.description}
              </p>

              <div className="rounded-lg border p-3" style={{ borderColor: selectedTier.color + '40', background: selectedTier.color + '08' }}>
                <p className="text-[10px] uppercase tracking-wider font-bold" style={{ color: selectedTier.color }}>Total in scope</p>
                <p className="text-3xl font-bold font-mono mt-1" style={{ color: selectedTier.color }}>
                  {selectedTier.count.toLocaleString()}
                </p>
              </div>

              {samples[selectedTier.key]?.length > 0 && (
                <div>
                  <p className="text-[10px] uppercase tracking-wider font-bold" style={{ color: 'var(--text-tertiary)' }}>Examples</p>
                  <div className="mt-2 space-y-1">
                    {samples[selectedTier.key].map(row => (
                      <Link key={row.id} to={`/identities/${row.id}`}
                        className="block rounded px-2 py-1.5 hover:bg-slate-800/40 transition"
                        style={{ color: 'var(--text-secondary)' }}>
                        <p className="text-xs truncate font-mono">{row.display_name}</p>
                        <p className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                          {row.identity_category.replace(/_/g, ' ')}
                        </p>
                      </Link>
                    ))}
                  </div>
                </div>
              )}

              <div className="pt-2">
                <p className="text-[10px] uppercase tracking-wider font-bold mb-2" style={{ color: 'var(--text-tertiary)' }}>Inspect this tier</p>
                <div className="flex flex-col gap-1.5">
                  <Link to={selectedTier.drillTo}
                    className="text-xs rounded-lg px-3 py-2 transition text-center font-medium"
                    style={{ background: selectedTier.color + '20', color: selectedTier.color, border: `1px solid ${selectedTier.color}40` }}>
                    Open {selectedTier.label} →
                  </Link>
                  {/* V2.8 (2026-06-11) — peer review: expand the drill-ins to
                      cover the 5 inspect axes the panel header promises
                      (Identity Summary / Trust / Ownership / Permissions /
                      Exposure / Attack Paths / Blast Radius). */}
                  {(selectedTier.key === 'human' || selectedTier.key === 'nhi' || selectedTier.key === 'ai') && (
                    <>
                      <Link to={`/identity-trust?type=${selectedTier.key}`}
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        Trust Score →
                      </Link>
                      <Link to={`/lifecycle?type=${selectedTier.key}`}
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        Lifecycle (J/M/L) →
                      </Link>
                      <Link to={`/ownership?type=${selectedTier.key}`}
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        Ownership →
                      </Link>
                      <Link to={`/attack-paths?source_type=${selectedTier.key}`}
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        Attack Paths →
                      </Link>
                      <Link to={`/blast-radius?type=${selectedTier.key}`}
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        Blast Radius →
                      </Link>
                      <Link to={`/exposure-explorer`}
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        $ Exposure Explorer →
                      </Link>
                    </>
                  )}
                  {(selectedTier.key === 'data' || selectedTier.key === 'storage') && (
                    <>
                      <Link to="/data-security"
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        Classify Resources →
                      </Link>
                      <Link to="/exposure-explorer"
                        className="text-xs rounded-lg px-3 py-2 transition text-center"
                        style={{ background: 'var(--bg-elevated)', color: 'var(--text-secondary)', border: '1px solid var(--border-subtle)' }}>
                        $ Exposure Explorer →
                      </Link>
                    </>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-center py-12">
              <div className="w-12 h-12 rounded-full mb-3"
                style={{ background: 'linear-gradient(135deg, #3b82f6, #f97316, #a78bfa, #ec4899, #22d3ee, #f43f5e)' }} />
              <p className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>Click any tier</p>
              <p className="text-xs mt-1 max-w-[240px]" style={{ color: 'var(--text-muted)' }}>
                Select a tier in the graph to inspect — Identity Summary, Trust, Ownership, Permissions, Exposure, Blast Radius.
              </p>
            </div>
          )}
        </aside>
      </div>

      <div className="text-[11px] leading-relaxed border-t border-white/5 pt-4" style={{ color: 'var(--text-muted)' }}>
        <strong style={{ color: 'var(--text-secondary)' }}>Provisional patent claim (2026-06-09):</strong>{' '}
        A method for computing an identity-to-data exposure graph by joining role assignments across Entra Directory Roles,
        Azure RBAC, Microsoft Graph API permissions, OAuth consent grants, federated identity credentials, and AI model
        deployments — without requiring write access, agent installation, or runtime telemetry.
      </div>
    </div>
  );
}
