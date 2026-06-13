import React, { useEffect, useState } from 'react';
import { Link, useParams, useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { riskDisplay } from '../utils/riskDisplay';
import { useToast } from '../components/ToastProvider';

interface RoleMeta {
  provider: string;
  name: string;
  tier: string;
  description: string;
  can_do: string[];
  cannot_do: string[];
  docs_url: string;
}

interface PathNode {
  type: 'identity' | 'role' | 'scope' | 'blast_boundary' | 'keyvault';
  label: string;
  role_meta?: RoleMeta;
  [key: string]: unknown;
}

interface AttackPathDetail {
  id: number;
  source_entity_id: string;
  source_entity_name: string;
  source_entity_type: string;
  path_type: string;
  severity: string;
  risk_score: number;
  description: string;
  narrative: string;
  impact: string;
  path_length: number;
  affected_resource_count: number;
  target_resource_id: string;
  target_resource_type: string;
  path_nodes: PathNode[];
  primary_role_meta?: RoleMeta;
  first_detected_at: string;
  last_detected_at: string;
  occurrence_count: number;
}

const PROVIDER_LABEL: Record<string, string> = {
  entra: 'Microsoft Entra',
  azure_rbac: 'Azure RBAC',
  aws_iam: 'AWS IAM',
  gcp_iam: 'GCP IAM',
  unknown: 'Unknown',
};

const TIER_STYLE: Record<string, { bg: string; text: string; border: string; label: string }> = {
  T0: { bg: 'rgba(239,68,68,0.12)', text: '#f87171', border: 'rgba(239,68,68,0.3)', label: 'T0 · Critical' },
  T1: { bg: 'rgba(249,115,22,0.12)', text: '#fb923c', border: 'rgba(249,115,22,0.3)', label: 'T1 · High' },
  T2: { bg: 'rgba(234,179,8,0.12)', text: '#facc15', border: 'rgba(234,179,8,0.3)', label: 'T2 · Medium' },
  T3: { bg: 'rgba(59,130,246,0.12)', text: '#60a5fa', border: 'rgba(59,130,246,0.3)', label: 'T3 · Low' },
  T4: { bg: 'rgba(59,130,246,0.12)', text: '#60a5fa', border: 'rgba(59,130,246,0.3)', label: 'T4 · Read-only' },
  unknown: { bg: 'rgba(107,114,128,0.12)', text: '#9ca3af', border: 'rgba(107,114,128,0.3)', label: 'Uncatalogued' },
};

function RoleAboutCard({ meta }: { meta: RoleMeta }) {
  const tier = TIER_STYLE[meta.tier] || TIER_STYLE.unknown;
  return (
    <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <h3 className="text-xs font-semibold uppercase tracking-wider mb-1" style={{ color: 'var(--text-tertiary)' }}>
            About this role
          </h3>
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-semibold" style={{ color: 'var(--text-primary)' }}>{meta.name}</span>
            <span className="text-xs font-semibold px-2 py-0.5 rounded"
              style={{ backgroundColor: tier.bg, color: tier.text, border: `1px solid ${tier.border}` }}>
              {tier.label}
            </span>
            <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded"
              style={{ color: 'var(--text-tertiary)', border: '1px solid var(--border-subtle)' }}>
              {PROVIDER_LABEL[meta.provider] || meta.provider}
            </span>
          </div>
        </div>
      </div>

      <p className="text-xs leading-relaxed mb-4" style={{ color: 'var(--text-secondary)' }}>
        {meta.description}
      </p>

      {meta.can_do.length > 0 && (
        <div className="mb-3">
          <div className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: '#10b981' }}>
            ✓ Can do
          </div>
          <ul className="space-y-1">
            {meta.can_do.map((s, i) => (
              <li key={i} className="text-xs leading-relaxed flex gap-2" style={{ color: 'var(--text-secondary)' }}>
                <span style={{ color: '#10b981' }}>•</span><span>{s}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {meta.cannot_do.length > 0 && (
        <div className="mb-3">
          <div className="text-[10px] font-semibold uppercase tracking-wider mb-1.5" style={{ color: '#f87171' }}>
            ✗ Cannot do
          </div>
          <ul className="space-y-1">
            {meta.cannot_do.map((s, i) => (
              <li key={i} className="text-xs leading-relaxed flex gap-2" style={{ color: 'var(--text-secondary)' }}>
                <span style={{ color: '#f87171' }}>•</span><span>{s}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {meta.docs_url && (
        <a href={meta.docs_url} target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-1 text-xs hover:underline mt-1"
          style={{ color: '#60a5fa' }}>
          Official documentation ↗
        </a>
      )}
    </div>
  );
}

const SEV_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'rgba(239,68,68,0.12)', text: '#f87171', border: 'rgba(239,68,68,0.3)' },
  high: { bg: 'rgba(249,115,22,0.12)', text: '#fb923c', border: 'rgba(249,115,22,0.3)' },
  medium: { bg: 'rgba(234,179,8,0.12)', text: '#facc15', border: 'rgba(234,179,8,0.3)' },
  low: { bg: 'rgba(59,130,246,0.12)', text: '#60a5fa', border: 'rgba(59,130,246,0.3)' },
};

const TYPE_LABELS: Record<string, string> = {
  PRIVILEGE_ESCALATION: 'Privilege Escalation',
  KEYVAULT_SECRET_ACCESS: 'Key Vault Access',
  SPN_SECRET_EXPOSURE: 'Secret Exposure',
  ROLE_CHAINING: 'Role Chaining',
  direct_escalation: 'Direct Escalation',
  lateral_movement: 'Lateral Movement',
  sensitive_data_exposure: 'Data Exposure',
  cross_tenant_risk: 'Cross-Tenant',
  privilege_accumulation: 'Privilege Accumulation',
};

const NODE_COLORS: Record<string, string> = {
  identity: '#3B82F6',
  role: '#EF4444',
  entra_role: '#EF4444',
  scope: '#A855F7',
  target: '#A855F7',
  blast_boundary: '#F59E0B',
  keyvault: '#0891B2',
  resource: '#10B981',
};

const NODE_ICONS: Record<string, string> = {
  identity: '\uD83D\uDC64',
  role: '\uD83D\uDD12',
  entra_role: '\uD83D\uDD12',
  scope: '\uD83C\uDF10',
  target: '\uD83C\uDFAF',
  blast_boundary: '\uD83D\uDCA5',
  keyvault: '\uD83D\uDD11',
  resource: '\uD83D\uDCE6',
};

export default function AttackPathDetailPage() {
  const { pathId } = useParams<{ pathId: string }>();
  const navigate = useNavigate();
  const { withConnection } = useConnection();
  const { addToast } = useToast();
  const [path, setPath] = useState<AttackPathDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [rqState, setRqState] = useState<'idle' | 'adding' | 'added' | 'exists'>('idle');
  const [rqItemId, setRqItemId] = useState<number | null>(null);

  useEffect(() => {
    if (!pathId) return;
    setLoading(true);
    fetch(`/api/attack-paths/${pathId}?${withConnection('')}`)
      .then(r => {
        if (!r.ok) throw new Error(r.status === 404 ? 'Attack path not found' : 'Failed to load');
        return r.json();
      })
      .then(setPath)
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [pathId, withConnection]);

  async function addToRemediationQueue() {
    if (!path || rqState === 'adding') return;
    setRqState('adding');
    try {
      const res = await fetch('/api/remediation-queue', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          attack_path_id: path.id,
          identity_id: path.source_entity_id || null,
          title: path.description || `Attack path for ${path.source_entity_name}`,
          description: path.narrative || null,
          severity: (path.severity || 'medium').toUpperCase(),
        }),
      });

      if (res.status === 409) {
        const data = await res.json();
        setRqItemId(data.existing?.id ?? null);
        setRqState('exists');
        return; // No error toast for 409
      }

      if (!res.ok) {
        const err = await res.json().catch(() => ({ error: 'Failed to add' }));
        throw new Error(err.error || 'Failed to add');
      }

      const created = await res.json();
      setRqItemId(created.id);
      setRqState('added');
      addToast('Added to remediation queue', 'success');
    } catch (e) {
      setRqState('idle');
      addToast(e instanceof Error ? e.message : 'Failed to add', 'error');
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full" />
      </div>
    );
  }

  if (error || !path) {
    return (
      <div className="p-6 max-w-[1000px] mx-auto">
        <Link to="/attack-paths" className="text-sm text-blue-500 hover:underline">&larr; Back to Attack Paths</Link>
        <div className="mt-8 text-center py-16 rounded-xl border" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
          <p className="text-sm" style={{ color: 'var(--text-secondary)' }}>{error || 'Path not found'}</p>
        </div>
      </div>
    );
  }

  const sev = path.severity?.toLowerCase() || 'low';
  const sevStyle = SEV_COLORS[sev] || SEV_COLORS.low;
  const nodes = path.path_nodes || [];

  return (
    <div className="p-6 max-w-[1100px] mx-auto">
      {/* Breadcrumb */}
      <div className="flex items-center gap-2 mb-5">
        <Link to="/attack-paths" className="text-sm hover:underline" style={{ color: 'var(--text-secondary)' }}>&larr; Attack Paths</Link>
        <span className="text-xs" style={{ color: 'var(--text-tertiary)' }}>/</span>
        <span className="text-sm font-medium" style={{ color: 'var(--text-primary)' }}>Path #{path.id}</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left column: Source entity card + Path chain + Narrative */}
        <div className="lg:col-span-2 space-y-5">
          {/* Source Entity Card */}
          <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-lg font-bold" style={{ color: 'var(--text-primary)' }}>{path.source_entity_name || 'Unknown'}</h2>
                <div className="flex items-center gap-3 mt-1.5">
                  <span className="text-xs px-2 py-0.5 rounded font-medium" style={{ backgroundColor: 'rgba(139,92,246,0.12)', color: '#a78bfa', border: '1px solid rgba(139,92,246,0.3)' }}>
                    {path.source_entity_type}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded font-medium" style={{ backgroundColor: sevStyle.bg, color: sevStyle.text, border: `1px solid ${sevStyle.border}` }}>
                    {TYPE_LABELS[path.path_type] || path.path_type}
                  </span>
                </div>
              </div>
              {path.source_entity_id && (
                <button onClick={() => navigate(`/identities/${path.source_entity_id}`)}
                  className="text-xs px-3 py-1.5 rounded-lg border transition-colors hover:bg-[var(--bg-elevated)]"
                  style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}>
                  View Identity &rarr;
                </button>
              )}
            </div>
          </div>

          {/* Path Chain Visualization */}
          {/* AG-PILOT-ATTACK-PATH-ANIMATION (2026-06-09): customer reported
              the attack-path animation regression. Reintroduced a CSS-only
              cinematic \u2014 each node fades in + each arrow slides in,
              staggered 220ms per hop. No JS state, no ReactFlow. Plays
              once on mount; subsequent navigations replay because the
              component re-mounts with new path id. */}
          {nodes.length > 0 && (
            <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-4" style={{ color: 'var(--text-tertiary)' }}>
                Escalation Chain
              </h3>
              <style>{`
                @keyframes ag-chain-node-in {
                  0%   { opacity: 0; transform: translateY(6px) scale(0.94); }
                  100% { opacity: 1; transform: translateY(0) scale(1); }
                }
                @keyframes ag-chain-arrow-in {
                  0%   { opacity: 0; transform: translateX(-8px); }
                  100% { opacity: 1; transform: translateX(0); }
                }
                .ag-chain-node {
                  opacity: 0;
                  animation: ag-chain-node-in 320ms ease-out forwards;
                }
                .ag-chain-arrow {
                  opacity: 0;
                  animation: ag-chain-arrow-in 220ms ease-out forwards;
                }
              `}</style>
              <div className="flex items-center gap-0 overflow-x-auto pb-2">
                {nodes.map((node, i) => (
                  <React.Fragment key={i}>
                    {i > 0 && (
                      <div className="flex-shrink-0 w-8 flex items-center justify-center ag-chain-arrow"
                           style={{ animationDelay: `${i * 220 - 100}ms` }}>
                        <svg width="32" height="16" viewBox="0 0 32 16">
                          <line x1="0" y1="8" x2="24" y2="8" stroke="var(--text-tertiary)" strokeWidth="1.5" strokeDasharray={i === nodes.length - 1 ? '4 2' : 'none'} />
                          <polygon points="24,4 32,8 24,12" fill="var(--text-tertiary)" />
                        </svg>
                      </div>
                    )}
                    <div className="flex-shrink-0 rounded-lg px-4 py-3 border min-w-[120px] text-center ag-chain-node"
                      style={{
                        backgroundColor: `${NODE_COLORS[node.type] || '#64748b'}12`,
                        borderColor: `${NODE_COLORS[node.type] || '#64748b'}40`,
                        animationDelay: `${i * 220}ms`,
                      }}>
                      <div className="text-base mb-1">{NODE_ICONS[node.type] || '\u2022'}</div>
                      <div className="text-xs font-semibold truncate max-w-[140px]" style={{ color: NODE_COLORS[node.type] || 'var(--text-primary)' }}>
                        {node.label}
                      </div>
                      <div className="text-[10px] uppercase tracking-wider mt-0.5" style={{ color: 'var(--text-tertiary)' }}>
                        {node.type.replace('_', ' ')}
                      </div>
                    </div>
                  </React.Fragment>
                ))}
              </div>

              {/* Node legend */}
              <div className="flex flex-wrap gap-3 mt-4 pt-3 border-t" style={{ borderColor: 'var(--border-subtle)' }}>
                {Object.entries(NODE_COLORS).map(([type, color]) => (
                  <span key={type} className="flex items-center gap-1.5 text-[10px]" style={{ color: 'var(--text-tertiary)' }}>
                    <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: color }} />
                    {NODE_ICONS[type]} {type.replace('_', ' ')}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Narrative & Description */}
          {(path.narrative || path.description) && (
            <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
                Analysis
              </h3>
              {path.description && (
                <p className="text-sm mb-3" style={{ color: 'var(--text-primary)' }}>{path.description}</p>
              )}
              {path.narrative && (
                <p className="text-xs leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{path.narrative}</p>
              )}
              {path.impact && (
                <div className="mt-3 pt-3 border-t" style={{ borderColor: 'var(--border-subtle)' }}>
                  <span className="text-xs font-semibold" style={{ color: 'var(--text-tertiary)' }}>Impact: </span>
                  <span className="text-xs" style={{ color: 'var(--text-secondary)' }}>{path.impact}</span>
                </div>
              )}
            </div>
          )}

          {/* About this role — per-role metadata from the central registry.
              Render one card per role node so paths chaining multiple roles
              get one panel each. Falls back to primary_role_meta when nodes
              don't carry enrichment. */}
          {(() => {
            const seen = new Set<string>();
            const cards: RoleMeta[] = [];
            (path.path_nodes || []).forEach((n) => {
              if (n.role_meta && !seen.has(n.role_meta.name)) {
                seen.add(n.role_meta.name);
                cards.push(n.role_meta);
              }
            });
            if (cards.length === 0 && path.primary_role_meta) {
              cards.push(path.primary_role_meta);
            }
            return cards.map((m) => <RoleAboutCard key={m.name} meta={m} />);
          })()}
        </div>

        {/* Right column: Risk breakdown + Details */}
        <div className="space-y-5">
          {/* Risk Score Card */}
          <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
              Risk Assessment
            </h3>
            <div className="flex items-baseline gap-3 mb-4">
              {/* CVSS-aligned 0-10 only (2026-05-31 directive) */}
              <span className="text-3xl font-bold font-mono" style={{ color: sevStyle.text }} title="CVSS-aligned 0-10 severity (FIRST.org CVSS 3.1)">
                {riskDisplay(path) ?? '—'}
              </span>
              <span className="text-xs font-mono text-gray-400 self-center">CVSS</span>
              <span className="text-xs font-semibold px-2 py-0.5 rounded"
                style={{ backgroundColor: sevStyle.bg, color: sevStyle.text, border: `1px solid ${sevStyle.border}` }}>
                {sev.toUpperCase()}
              </span>
            </div>

            <div className="space-y-2.5">
              <InfoRow label="Path Type" value={TYPE_LABELS[path.path_type] || path.path_type} />
              <InfoRow label="Source Type" value={path.source_entity_type || '-'} />
              {path.path_length > 0 && (
                <InfoRow label="Path Length" value={`${path.path_length} hops`} />
              )}
              {path.affected_resource_count > 0 && (
                <InfoRow label="Affected Resources" value={String(path.affected_resource_count)} highlight />
              )}
              {path.target_resource_type && (
                <InfoRow label="Target Type" value={path.target_resource_type} />
              )}
              {path.occurrence_count > 1 && (
                <InfoRow label="Occurrences" value={String(path.occurrence_count)} />
              )}
            </div>
          </div>

          {/* Timeline */}
          <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
            <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
              Timeline
            </h3>
            <div className="space-y-2.5">
              {path.first_detected_at && (
                <InfoRow label="First Detected" value={new Date(path.first_detected_at).toLocaleDateString()} />
              )}
              {path.last_detected_at && (
                <InfoRow label="Last Detected" value={new Date(path.last_detected_at).toLocaleDateString()} />
              )}
            </div>
          </div>

          {/* Quick Actions */}
          {path.source_entity_id && (
            <div className="rounded-xl border p-5" style={{ borderColor: 'var(--border-default)', backgroundColor: 'var(--bg-primary)' }}>
              <h3 className="text-xs font-semibold uppercase tracking-wider mb-3" style={{ color: 'var(--text-tertiary)' }}>
                Quick Actions
              </h3>
              <div className="space-y-2">
                <ActionButton label="View Identity Detail" onClick={() => navigate(`/identities/${path.source_entity_id}`)} />
                <ActionButton label="View Access Graph" onClick={() => navigate(`/identities/${path.source_entity_id}?tab=access_graph`)} />
                {rqState === 'idle' && (
                  <ActionButton label="Add to Remediation Queue" onClick={addToRemediationQueue} />
                )}
                {rqState === 'adding' && (
                  <div className="w-full text-center text-xs px-3 py-2 rounded-lg border"
                    style={{ color: 'var(--text-tertiary)', borderColor: 'var(--border-default)' }}>
                    Adding...
                  </div>
                )}
                {rqState === 'added' && rqItemId && (
                  <ActionButton label="View in Queue" onClick={() => navigate(`/remediation-queue/${rqItemId}`)} />
                )}
                {rqState === 'exists' && rqItemId && (
                  <ActionButton label="Already in Queue — View" onClick={() => navigate(`/remediation-queue/${rqItemId}`)} />
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function InfoRow({ label, value, highlight }: { label: string; value: string; highlight?: boolean }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span style={{ color: 'var(--text-tertiary)' }}>{label}</span>
      <span className="font-medium" style={{ color: highlight ? '#ef4444' : 'var(--text-primary)' }}>{value}</span>
    </div>
  );
}

function ActionButton({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button onClick={onClick}
      className="w-full text-left text-xs px-3 py-2 rounded-lg border transition-colors hover:bg-[var(--bg-elevated)]"
      style={{ color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}>
      {label} &rarr;
    </button>
  );
}
