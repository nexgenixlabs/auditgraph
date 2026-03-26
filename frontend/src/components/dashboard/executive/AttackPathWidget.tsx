import React from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS, type DangerousIdentity } from '../../../constants/ciso';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';

interface AttackPathWidgetProps {
  identities: DangerousIdentity[];
  compact?: boolean;
  attackPathCount?: number;
}

type NodeType = 'identity' | 'role' | 'resource' | 'privilege';

interface GraphNode { id: string; label: string; type: NodeType; tooltip: string; }
interface GraphEdge { from: string; to: string; }

const NODE_COLORS: Record<NodeType, string> = {
  identity: '#3B82F6',
  role: '#EF4444',
  resource: '#A855F7',
  privilege: '#F59E0B',
};

const NODE_ICONS: Record<NodeType, string> = {
  identity: '\uD83D\uDC64',
  role: '\uD83D\uDD12',
  resource: '\uD83D\uDCC1',
  privilege: '\u26A0',
};

export function AttackPathWidget({ identities, compact = false, attackPathCount: apCountProp }: AttackPathWidgetProps) {
  const navigate = useNavigate();
  const topId = identities[0];
  const pathCount = apCountProp ?? identities.length;

  // Build graph from top dangerous identity
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];

  if (topId) {
    const factors = topId.key_risk_factors || [];
    const hasPriv = factors.some((f: string) => /privilege|owner|admin|contributor/i.test(f));
    const hasCred = factors.some((f: string) => /credential|secret|cert|key/i.test(f));

    const roleName = hasPriv
      ? (factors.find((f: string) => /owner/i.test(f)) ? 'Subscription Owner' : factors.find((f: string) => /admin/i.test(f)) ? 'Admin Role' : 'Contributor Role')
      : 'Role Assignment';
    const resourceName = hasCred ? 'Key Vault' : 'Resource Scope';
    const privName = hasCred ? 'Secrets Access' : 'Data Access';

    nodes.push(
      { id: 'n0', label: topId.display_name?.split(/[@.]/)[0] || 'Identity', type: 'identity', tooltip: `Identity: ${topId.display_name || 'Unknown'}\nCategory: ${topId.identity_category}\nRisk Score: ${topId.risk_score}` },
      { id: 'n1', label: roleName, type: 'role', tooltip: `Role: ${roleName}\nGrants escalation path through privilege assignment` },
      { id: 'n2', label: resourceName, type: 'resource', tooltip: `Resource: ${resourceName}\nTarget resource in the escalation chain` },
      { id: 'n3', label: privName, type: 'privilege', tooltip: `Privilege: ${privName}\nFinal privilege gained through this attack path` },
    );
    edges.push({ from: 'n0', to: 'n1' }, { from: 'n1', to: 'n2' }, { from: 'n2', to: 'n3' });
  }

  // Risk assessment
  let riskSignals = 0;
  if (topId) {
    if (topId.blast_radius_score >= 60) riskSignals += 2; else if (topId.blast_radius_score >= 30) riskSignals += 1;
    if (topId.tier === 'T0') riskSignals += 2; else if (topId.tier === 'T1') riskSignals += 1;
    if (nodes.some(n => /secret/i.test(n.label))) riskSignals += 2;
    if (edges.length >= 3) riskSignals += 1;
  }
  const pathRisk = riskSignals >= 5 ? 'High' : riskSignals >= 2 ? 'Medium' : 'Low';
  const pathRiskColor = pathRisk === 'High' ? COLORS.danger : pathRisk === 'Medium' ? COLORS.warning : COLORS.success;

  // SVG layout
  const svgW = compact ? 320 : 520;
  const svgH = compact ? 90 : 110;
  const nodeW = compact ? 72 : 100;
  const nodeH = compact ? 28 : 36;
  const spacing = nodes.length > 1 ? (svgW - nodeW) / (nodes.length - 1) : 0;
  const cy = svgH / 2;

  const nodePositions = nodes.map((_, i) => ({ cx: nodeW / 2 + i * spacing, cy }));
  const labelMaxLen = compact ? 8 : 12;

  return (
    <CISOCard>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: compact ? 6 : 10 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <SectionTitle>Identity Attack Paths</SectionTitle>
          {compact && (
            <DN navigateTo="/graph-findings">
              <span style={{ fontSize: 11, fontWeight: 700, fontFamily: FONT.mono, color: pathCount > 0 ? COLORS.danger : COLORS.textDim }}>{pathCount} paths</span>
            </DN>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {topId && (
            <span style={{
              fontSize: 9, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
              background: `${pathRiskColor}18`, color: pathRiskColor,
              border: `1px solid ${pathRiskColor}30`, fontFamily: FONT.mono,
            }}>
              {pathRisk} Risk
            </span>
          )}
          <DN navigateTo="/graph-findings">
            <span style={{ fontSize: 9, color: COLORS.accent, fontFamily: FONT.ui }}>View All {'\u2192'}</span>
          </DN>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 20 }}>
        {/* Left: Path count + action (hidden in compact mode) */}
        {!compact && (
          <div style={{ minWidth: 140 }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <DN navigateTo="/graph-findings">
                <span style={{ fontSize: 32, fontWeight: 700, fontFamily: FONT.mono, color: pathCount > 0 ? COLORS.danger : COLORS.textDim }}>{pathCount}</span>
              </DN>
              <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>paths detected</span>
            </div>
            {topId && (
              <div style={{ marginTop: 8, fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                Blast radius: <span style={{ fontWeight: 600, color: COLORS.text }}>{topId.blast_radius_score}</span>
                <br />
                Risk score: <span style={{ fontWeight: 600, color: COLORS.text }}>{topId.risk_score}</span>
              </div>
            )}
            <button onClick={() => navigate('/attack-simulator')} style={{
              marginTop: 10, padding: '6px 14px', borderRadius: 6, fontSize: 10, fontWeight: 600,
              background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
              cursor: 'pointer', fontFamily: FONT.ui,
            }}>Explore Paths</button>
          </div>
        )}

        {/* SVG graph */}
        <div style={{ flex: 1 }}>
          {!compact && (
            <div style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 4 }}>
              {topId ? 'Top Escalation Chain' : 'No paths detected'}
            </div>
          )}
          {nodes.length > 0 && (
            <svg width={svgW} height={svgH} style={{ display: 'block', cursor: topId ? 'pointer' : 'default' }}
              onClick={topId ? () => navigate(`/identities/${topId.identity_id || topId.id}`) : undefined}>
              <defs>
                <marker id="atk-arrow" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto">
                  <path d="M0 0 L10 3.5 L0 7z" fill={COLORS.textDim} />
                </marker>
              </defs>

              {/* Edges */}
              {edges.map((e, i) => {
                const fromIdx = nodes.findIndex(n => n.id === e.from);
                const toIdx = nodes.findIndex(n => n.id === e.to);
                if (fromIdx < 0 || toIdx < 0) return null;
                const x1 = nodePositions[fromIdx].cx + nodeW / 2;
                const y1 = nodePositions[fromIdx].cy;
                const x2 = nodePositions[toIdx].cx - nodeW / 2;
                const y2 = nodePositions[toIdx].cy;
                return (
                  <line key={`e-${i}`} x1={x1} y1={y1} x2={x2} y2={y2}
                    stroke={COLORS.textDim} strokeWidth={1.5} markerEnd="url(#atk-arrow)"
                    strokeDasharray={i === edges.length - 1 ? '4 2' : 'none'} />
                );
              })}

              {/* Nodes */}
              {nodes.map((n, i) => {
                const pos = nodePositions[i];
                const c = NODE_COLORS[n.type];
                const rx = pos.cx - nodeW / 2;
                const ry = pos.cy - nodeH / 2;
                return (
                  <g key={n.id}>
                    <title>{n.tooltip}</title>
                    <rect x={rx} y={ry} width={nodeW} height={nodeH} rx={compact ? 4 : 6}
                      fill={`${c}18`} stroke={c} strokeWidth={1.5} />
                    <circle cx={rx + (compact ? 9 : 12)} cy={pos.cy} r={compact ? 2.5 : 3.5} fill={c} />
                    <text x={rx + (compact ? 16 : 20)} y={pos.cy + 1} fill={c} fontSize={compact ? 8 : 10} fontWeight={600}
                      fontFamily={FONT.ui} dominantBaseline="central">
                      {n.label.length > labelMaxLen ? n.label.slice(0, labelMaxLen) + '\u2026' : n.label}
                    </text>
                    {!compact && (
                      <text x={pos.cx} y={ry + nodeH + 12} fill={COLORS.textMuted} fontSize={8}
                        fontFamily={FONT.ui} textAnchor="middle"
                        style={{ textTransform: 'uppercase', letterSpacing: '0.06em' } as React.CSSProperties}>
                        {n.type}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          )}
          {topId && !compact && (
            <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 2 }}>
              Click graph to view identity detail {'\u2192'}
            </div>
          )}
        </div>
      </div>

      {/* Node type legend (hidden in compact mode) */}
      {!compact && (
        <div style={{ display: 'flex', gap: 12, marginTop: 10, paddingTop: 10, borderTop: `1px solid ${COLORS.border}` }}>
          {(['identity', 'role', 'resource', 'privilege'] as NodeType[]).map(t => (
            <span key={t} style={{ fontSize: 9, display: 'flex', alignItems: 'center', gap: 3, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: NODE_COLORS[t] }} />
              {NODE_ICONS[t]} {t.charAt(0).toUpperCase() + t.slice(1)}
            </span>
          ))}
        </div>
      )}
    </CISOCard>
  );
}
