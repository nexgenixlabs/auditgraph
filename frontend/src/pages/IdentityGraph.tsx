import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import AIInvestigateDrawer from '../components/AIInvestigateDrawer';

/* ─── Focused View Types ───────────────────────────────────────────── */

interface TopAttackPath {
  id: number;
  source_entity_id: string;
  source_entity_name: string;
  source_entity_type: string;
  path_type: string;
  severity: string;
  risk_score: number;
  description: string;
  narrative: string | null;
  impact: string | null;
  path_length: number;
  affected_resource_count: number;
  first_detected_at: string;
  last_detected_at: string;
  occurrence_count: number;
  target_resource_id: string | null;
  target_resource_type: string | null;
  highest_role: string | null;
  has_keyvault_access: boolean;
  has_subscription_scope: boolean;
  has_no_owner: boolean;
  path_nodes: Array<{ type: string; id: string; label: string; detail?: string }>;
}

/* ─── Types ─────────────────────────────────────────────────────────── */

interface IdentityTooltip {
  name: string;
  identity_type: string;
  roles: string[];
  subscriptions: string[];
  credential_count: number;
  credential_risk: string;
  risk_score: number;
  activity_status: string;
}

interface RoleTooltip {
  role_name: string;
  privilege_level: string;
  scopes: string[];
  identity_count: number;
  identities: string[];
}

interface ResourceTooltip {
  resource_name: string;
  resource_type: string;
  accessor_count: number;
  accessors: Array<{ identity: string; role: string }>;
}

interface SubscriptionTooltip {
  subscription_name: string;
  identity_count: number;
  high_privilege_count: number;
}

type NodeTooltip = IdentityTooltip | RoleTooltip | ResourceTooltip | SubscriptionTooltip;

interface EdgeTooltipData {
  relationship: string;
  source_label: string;
  target_label: string;
  role: string;
  scope: string;
}

interface ApiNode {
  id: string;
  type: string;
  label?: string;
  risk_level?: string;
  is_attack_path?: boolean;
  tooltip?: NodeTooltip;
  is_ai_agent?: boolean;
  ai_agent_type?: string;
  ai_platform?: string;
  ai_confidence?: number;
}

interface ApiEdge {
  source: string;
  target: string;
  type: string;
  is_attack_path?: boolean;
  tooltip?: EdgeTooltipData;
}

interface GraphNode {
  id: string;
  label: string;
  type: string;
  risk_level: string;
  isAttackPath: boolean;
  tooltip: NodeTooltip | null;
  // AI Identity Governance (e440e07): nodes whose identity has an
  // agent_classifications row get a teal ring + AI badge + click→drawer
  is_ai_agent?: boolean;
  ai_agent_type?: string;      // ai_agent | ai_privileged_human | possible_ai_agent
  ai_platform?: string;        // copilot_studio | azure_openai | azure_ml | ...
  ai_confidence?: number;
}

interface GraphEdge {
  source: string;
  target: string;
  type: string;
  isAttackPath: boolean;
  tooltip: EdgeTooltipData | null;
}

interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
  attackPaths: AttackPath[];
  attackPathCount: number;
  truncated: boolean;
}

interface AttackPath {
  identity: string;
  identity_label: string;
  role: string;
  target: string;
  target_label: string;
  target_type: string;
}

interface CloudConnection {
  id: number;
  label: string;
  cloud: string;
  status: string;
}

interface IdentityDetail {
  display_name: string;
  identity_id: string;
  identity_type: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  activity_status: string;
  credential_count: number;
  credential_risk: string;
  roles?: Array<{ role_name: string; scope: string }>;
  subscriptions?: string[];
}

/* ─── Constants ─────────────────────────────────────────────────────── */

const RISK_NODE_COLOR: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#94a3b8',
};

const TYPE_NODE_COLOR: Record<string, string> = {
  identity: '#60a5fa',
  service_principal: '#c084fc',
  managed_identity: '#22d3ee',
  guest: '#fb923c',
  role: '#fbbf24',
  resource: '#34d399',
  subscription: '#f87171',
};

const NODE_SIZE: Record<string, number> = {
  identity: 24,
  service_principal: 22,
  managed_identity: 20,
  guest: 22,
  role: 18,
  resource: 16,
  subscription: 28,
};

const EDGE_COLOR: Record<string, string> = {
  assigned_role: '#64748b',
  grants_access: '#22d3ee',
  contains_resource: '#6b7280',
  escalation_path: '#ef4444',
};

const RISK_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-green-500/20 text-green-400 border-green-500/30',
};

const ATTACK_EDGE_COLOR = '#ef4444';
const ATTACK_NODE_GLOW = '#f97316';

/* ─── Helpers ───────────────────────────────────────────────────────── */

function deriveLabel(id: string): string {
  if (id.startsWith('role:')) return id.slice(5);
  if (id.includes('/')) {
    const parts = id.split('/');
    return parts[parts.length - 1];
  }
  return id.length > 24 ? id.slice(0, 10) + '...' + id.slice(-8) : id;
}

function mapApiResponse(raw: Record<string, unknown>): GraphData {
  const apiNodes = (raw.nodes || []) as ApiNode[];
  const apiEdges = (raw.edges || []) as ApiEdge[];
  return {
    nodes: apiNodes.map(n => ({
      id: n.id,
      label: n.label || deriveLabel(n.id),
      type: n.type,
      risk_level: n.risk_level || 'low',
      isAttackPath: !!n.is_attack_path,
      tooltip: (n.tooltip as NodeTooltip) || null,
      is_ai_agent: !!n.is_ai_agent,
      ai_agent_type: n.ai_agent_type,
      ai_platform: n.ai_platform,
      ai_confidence: n.ai_confidence,
    })),
    edges: apiEdges.map(e => ({
      source: e.source,
      target: e.target,
      type: e.type,
      isAttackPath: !!e.is_attack_path,
      tooltip: (e.tooltip as EdgeTooltipData) || null,
    })),
    attackPaths: ((raw.attack_paths || []) as AttackPath[]),
    attackPathCount: (raw.attack_path_count as number) || 0,
    truncated: !!raw.truncated,
  };
}

/** Point-to-segment distance for edge hover detection. */
function pointToSegmentDist(
  px: number, py: number,
  x1: number, y1: number,
  x2: number, y2: number,
): number {
  const dx = x2 - x1;
  const dy = y2 - y1;
  const lenSq = dx * dx + dy * dy;
  if (lenSq === 0) return Math.hypot(px - x1, py - y1);
  let t = ((px - x1) * dx + (py - y1) * dy) / lenSq;
  t = Math.max(0, Math.min(1, t));
  return Math.hypot(px - (x1 + t * dx), py - (y1 + t * dy));
}

/* ─── Component ─────────────────────────────────────────────────────── */

const IdentityGraph: React.FC = () => {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [graphData, setGraphData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [highlightedNode, setHighlightedNode] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<'identity' | 'attack'>('identity');

  // Page mode: focused (top paths) or full (canvas graph)
  const [pageMode, setPageMode] = useState<'focused' | 'full'>('focused');
  const [topPaths, setTopPaths] = useState<TopAttackPath[]>([]);
  const [topPathsTotal, setTopPathsTotal] = useState(0);
  const [topPathsLoading, setTopPathsLoading] = useState(false);
  const [expandedPathId, setExpandedPathId] = useState<number | null>(null);
  const [simulationId, setSimulationId] = useState('');
  const [connectionId, setConnectionId] = useState('');
  const [identityId, setIdentityId] = useState('');
  const [connections, setConnections] = useState<CloudConnection[]>([]);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(1);
  const [dragging, setDragging] = useState(false);
  const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
  const [nodePositions, setNodePositions] = useState<Record<string, { x: number; y: number }>>({});
  const [colorMode, setColorMode] = useState<'type' | 'risk'>('type');

  // Tooltip state
  const [tooltipNode, setTooltipNode] = useState<GraphNode | null>(null);
  const [tooltipEdge, setTooltipEdge] = useState<GraphEdge | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });

  // Side panel state
  const [selectedDetail, setSelectedDetail] = useState<IdentityDetail | null>(null);
  const [aiDrawerIdentityId, setAiDrawerIdentityId] = useState<string | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [panelOpen, setPanelOpen] = useState(false);

  // Attack path highlight state
  const [activeAttackPath, setActiveAttackPath] = useState<AttackPath | null>(null);
  const [showPathPanel, setShowPathPanel] = useState(false);
  const [pathFilter, setPathFilter] = useState<'All' | 'Critical' | 'High'>('All');

  // Fetch connections
  useEffect(() => {
    (async () => {
      try {
        const res = await fetch(withConnection('/api/client/connections'));
        if (res.ok) {
          const data = await res.json();
          const conns: CloudConnection[] = (data.connections || []).filter(
            (c: CloudConnection) => c.status === 'connected'
          );
          setConnections(conns);
          if (conns.length > 0 && !connectionId) {
            setConnectionId(String(conns[0].id));
          }
        }
      } catch { /* ignore */ }
    })();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Fetch top attack paths for focused view
  useEffect(() => {
    if (pageMode !== 'focused') return;
    (async () => {
      setTopPathsLoading(true);
      try {
        const res = await fetch(withConnection('/api/attack-paths?limit=5'));
        if (res.ok) {
          const data = await res.json();
          setTopPaths(data.paths || []);
          setTopPathsTotal(data.total || 0);
        }
      } catch { /* ignore */ }
      setTopPathsLoading(false);
    })();
  }, [pageMode]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-load graph when switching to full mode with a connection but no data
  const autoLoadRef = useRef(false);
  useEffect(() => {
    if (pageMode === 'full' && connectionId && !graphData && !loading && !autoLoadRef.current) {
      autoLoadRef.current = true;
      fetchIdentityGraph();
    }
    if (pageMode === 'focused') {
      autoLoadRef.current = false;
    }
  }, [pageMode, connectionId, graphData, loading]); // eslint-disable-line react-hooks/exhaustive-deps

  const computeLayout = useCallback((data: GraphData) => {
    const positions: Record<string, { x: number; y: number }> = {};
    const width = 1200;
    const groups: Record<string, GraphNode[]> = {};
    for (const node of data.nodes) {
      const t = node.type || 'identity';
      if (!groups[t]) groups[t] = [];
      groups[t].push(node);
    }
    const typeOrder = ['subscription', 'identity', 'guest', 'service_principal', 'managed_identity', 'role', 'resource'];
    let yOffset = 80;
    for (const type of typeOrder) {
      const group = groups[type] || [];
      const cols = Math.max(Math.ceil(Math.sqrt(group.length * 2)), 1);
      group.forEach((node, i) => {
        const col = i % cols;
        const row = Math.floor(i / cols);
        positions[node.id] = {
          x: 100 + col * (width / (cols + 1)),
          y: yOffset + row * 70,
        };
      });
      yOffset += Math.ceil(group.length / Math.max(Math.ceil(Math.sqrt(group.length * 2)), 1)) * 70 + 50;
    }
    setNodePositions(positions);
  }, []);

  /* ── Fetch functions ──────────────────────────────────────────────── */

  const fetchIdentityGraph = async () => {
    if (!connectionId) return;
    setLoading(true);
    setActiveAttackPath(null);
    try {
      const res = await fetch(withConnection(`/api/graph/visualization?connection_id=${connectionId}`));
      if (res.ok) {
        const raw = await res.json();
        const mapped = mapApiResponse(raw);
        setGraphData(mapped);
        computeLayout(mapped);
      }
    } catch (err) {
      console.error('Failed to fetch graph:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchNeighborhood = async () => {
    if (!identityId) return;
    setLoading(true);
    try {
      const res = await fetch(withConnection(`/api/graph/identity/${encodeURIComponent(identityId)}`));
      if (res.ok) {
        const raw = await res.json();
        const mapped = mapApiResponse(raw);
        setGraphData(mapped);
        computeLayout(mapped);
      }
    } catch (err) {
      console.error('Failed to fetch neighborhood:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchAttackGraph = async () => {
    if (!simulationId) return;
    setLoading(true);
    try {
      const res = await fetch(withConnection(`/api/graph/attack-path/${simulationId}`));
      if (res.ok) {
        const raw = await res.json();
        const mapped = mapApiResponse(raw);
        setGraphData(mapped);
        computeLayout(mapped);
      }
    } catch (err) {
      console.error('Failed to fetch attack graph:', err);
    } finally {
      setLoading(false);
    }
  };

  const fetchIdentityDetail = async (nodeId: string) => {
    setDetailLoading(true);
    setPanelOpen(true);
    setSelectedDetail(null);
    try {
      const res = await fetch(withConnection(`/api/identities/${encodeURIComponent(nodeId)}`));
      if (res.ok) {
        const data = await res.json();
        setSelectedDetail({
          display_name: data.display_name || nodeId,
          identity_id: data.identity_id || nodeId,
          identity_type: data.identity_type || '',
          identity_category: data.identity_category || '',
          risk_level: data.risk_level || 'low',
          risk_score: data.risk_score || 0,
          activity_status: data.activity_status || 'unknown',
          credential_count: data.credential_count || 0,
          credential_risk: data.credential_risk || 'none',
          roles: data.roles || [],
          subscriptions: data.subscriptions || [],
        });
      }
    } catch { /* ignore */ }
    setDetailLoading(false);
  };

  /* ── Determine active attack path nodes/edges for highlighting ───── */

  const attackHighlight = useCallback((): { nodes: Set<string>; edges: Set<string> } => {
    const nodes = new Set<string>();
    const edges = new Set<string>();
    if (activeAttackPath) {
      nodes.add(activeAttackPath.identity);
      nodes.add('role:' + activeAttackPath.role);
      nodes.add(activeAttackPath.target);
      edges.add(activeAttackPath.identity + '|' + 'role:' + activeAttackPath.role);
      edges.add('role:' + activeAttackPath.role + '|' + activeAttackPath.target);
    }
    return { nodes, edges };
  }, [activeAttackPath]);

  /* ── Canvas rendering ─────────────────────────────────────────────── */

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas || !graphData) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    canvas.width = canvas.offsetWidth * dpr;
    canvas.height = canvas.offsetHeight * dpr;
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, canvas.offsetWidth, canvas.offsetHeight);
    ctx.save();
    ctx.translate(pan.x, pan.y);
    ctx.scale(zoom, zoom);

    const atkHL = attackHighlight();
    const showAttackMode = viewMode === 'attack' || !!activeAttackPath;

    // ─── Draw edges ───
    for (const edge of graphData.edges) {
      const src = nodePositions[edge.source];
      const tgt = nodePositions[edge.target];
      if (!src || !tgt) continue;

      const edgeKey = edge.source + '|' + edge.target;
      const isActiveAtkEdge = atkHL.edges.has(edgeKey);
      const isAtkEdge = edge.isAttackPath;

      // Determine opacity
      let alpha = 0.5;
      if (highlightedNode) {
        alpha = (edge.source === highlightedNode || edge.target === highlightedNode) ? 1 : 0.1;
      }
      if (showAttackMode && activeAttackPath) {
        alpha = isActiveAtkEdge ? 1 : 0.08;
      }

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);

      if (isActiveAtkEdge) {
        ctx.strokeStyle = ATTACK_EDGE_COLOR;
        ctx.lineWidth = 3;
        ctx.setLineDash([]);
      } else if (isAtkEdge && showAttackMode) {
        ctx.strokeStyle = '#f87171';
        ctx.lineWidth = 2;
        ctx.setLineDash([6, 3]);
      } else {
        ctx.strokeStyle = EDGE_COLOR[edge.type] || '#475569';
        ctx.lineWidth = edge.type === 'escalation_path' ? 2 : 1;
        ctx.setLineDash([]);
      }

      ctx.globalAlpha = alpha;
      ctx.stroke();
      ctx.setLineDash([]);

      // Draw arrowhead for attack path edges
      if ((isActiveAtkEdge || (isAtkEdge && showAttackMode)) && alpha > 0.3) {
        const angle = Math.atan2(tgt.y - src.y, tgt.x - src.x);
        const tgtSize = NODE_SIZE[graphData.nodes.find(n => n.id === edge.target)?.type || 'identity'] || 16;
        const ax = tgt.x - Math.cos(angle) * (tgtSize / 2 + 4);
        const ay = tgt.y - Math.sin(angle) * (tgtSize / 2 + 4);
        ctx.beginPath();
        ctx.moveTo(ax, ay);
        ctx.lineTo(ax - 8 * Math.cos(angle - 0.4), ay - 8 * Math.sin(angle - 0.4));
        ctx.lineTo(ax - 8 * Math.cos(angle + 0.4), ay - 8 * Math.sin(angle + 0.4));
        ctx.closePath();
        ctx.fillStyle = isActiveAtkEdge ? ATTACK_EDGE_COLOR : '#f87171';
        ctx.globalAlpha = alpha;
        ctx.fill();
      }
    }

    ctx.globalAlpha = 1;

    // ─── Draw nodes ───
    for (const node of graphData.nodes) {
      const pos = nodePositions[node.id];
      if (!pos) continue;

      const size = NODE_SIZE[node.type] || 16;
      const isHighlighted = highlightedNode === node.id;
      const nodeLabel = node.label || node.id;
      const isSearchMatch = searchTerm && nodeLabel.toLowerCase().includes(searchTerm.toLowerCase());
      const isAtkNode = node.isAttackPath;
      const isActiveAtkNode = atkHL.nodes.has(node.id);

      // Alpha
      let alpha = 1;
      if (highlightedNode && !isHighlighted) alpha = 0.3;
      if (showAttackMode && activeAttackPath) {
        alpha = isActiveAtkNode ? 1 : 0.15;
      }
      ctx.globalAlpha = alpha;

      // Pick color
      let color: string;
      if (isSearchMatch) {
        color = '#f59e0b';
      } else if (isActiveAtkNode) {
        color = ATTACK_NODE_GLOW;
      } else if (colorMode === 'risk') {
        color = RISK_NODE_COLOR[node.risk_level] || RISK_NODE_COLOR.low;
      } else {
        color = TYPE_NODE_COLOR[node.type] || '#94a3b8';
      }

      // Attack path glow ring
      if ((isAtkNode || isActiveAtkNode) && showAttackMode && alpha > 0.3) {
        ctx.beginPath();
        ctx.arc(pos.x, pos.y, size / 2 + 4, 0, Math.PI * 2);
        ctx.strokeStyle = ATTACK_EDGE_COLOR;
        ctx.lineWidth = 2;
        ctx.globalAlpha = alpha * 0.6;
        ctx.stroke();
        ctx.globalAlpha = alpha;
      }

      // Node circle
      ctx.beginPath();
      ctx.arc(pos.x, pos.y, size / 2, 0, Math.PI * 2);
      ctx.fillStyle = color;
      ctx.fill();

      // AI Agent ring (teal #24A2A1) — drawn before highlight ring so the
      // white highlight ring still wins when selected.
      if (node.is_ai_agent) {
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#24A2A1';
        ctx.stroke();
      }

      // Highlight / search ring
      if (isHighlighted || isSearchMatch) {
        ctx.lineWidth = 2;
        ctx.strokeStyle = '#ffffff';
        ctx.stroke();
      }

      // AI badge (small teal pill bottom-right of node)
      if (node.is_ai_agent && alpha > 0.3) {
        const badgeX = pos.x + size / 2 - 1;
        const badgeY = pos.y + size / 2 - 1;
        ctx.fillStyle = '#24A2A1';
        ctx.beginPath();
        ctx.arc(badgeX, badgeY, 6, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = '#06090f';
        ctx.font = 'bold 7px Inter, system-ui, sans-serif';
        ctx.textAlign = 'center';
        ctx.textBaseline = 'middle';
        ctx.fillText('AI', badgeX, badgeY + 0.5);
        ctx.textBaseline = 'alphabetic';
      }

      // Risk dot indicator (top-right)
      if (node.risk_level && node.risk_level !== 'low' && colorMode === 'type') {
        ctx.beginPath();
        ctx.arc(pos.x + size / 2 - 2, pos.y - size / 2 + 2, 4, 0, Math.PI * 2);
        ctx.fillStyle = RISK_NODE_COLOR[node.risk_level] || RISK_NODE_COLOR.low;
        ctx.fill();
        ctx.lineWidth = 1;
        ctx.strokeStyle = '#0f172a';
        ctx.stroke();
      }

      // Label
      ctx.fillStyle = '#e2e8f0';
      ctx.font = '10px Inter, system-ui, sans-serif';
      ctx.textAlign = 'center';
      const display = nodeLabel.length > 24 ? nodeLabel.slice(0, 22) + '...' : nodeLabel;
      ctx.fillText(display, pos.x, pos.y + size / 2 + 14);
    }

    ctx.restore();
  }, [graphData, nodePositions, pan, zoom, highlightedNode, searchTerm, colorMode, viewMode, activeAttackPath, attackHighlight]);

  /* ── Mouse handlers ───────────────────────────────────────────────── */

  const handleMouseDown = (e: React.MouseEvent) => {
    setDragging(true);
    setDragStart({ x: e.clientX - pan.x, y: e.clientY - pan.y });
  };

  const handleMouseMove = (e: React.MouseEvent) => {
    if (dragging) {
      setPan({ x: e.clientX - dragStart.x, y: e.clientY - dragStart.y });
      setTooltipNode(null);
      setTooltipEdge(null);
      return;
    }

    if (!graphData || !canvasRef.current) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = (e.clientX - rect.left - pan.x) / zoom;
    const my = (e.clientY - rect.top - pan.y) / zoom;

    // Check nodes first
    for (const node of graphData.nodes) {
      const pos = nodePositions[node.id];
      if (!pos) continue;
      const size = NODE_SIZE[node.type] || 16;
      const dx = mx - pos.x;
      const dy = my - pos.y;
      if (dx * dx + dy * dy < (size / 2 + 6) * (size / 2 + 6)) {
        setTooltipNode(node);
        setTooltipEdge(null);
        setTooltipPos({ x: e.clientX + 12, y: e.clientY - 8 });
        return;
      }
    }

    // Check edges
    for (const edge of graphData.edges) {
      const src = nodePositions[edge.source];
      const tgt = nodePositions[edge.target];
      if (!src || !tgt) continue;
      const dist = pointToSegmentDist(mx, my, src.x, src.y, tgt.x, tgt.y);
      if (dist < 8) {
        setTooltipEdge(edge);
        setTooltipNode(null);
        setTooltipPos({ x: e.clientX + 12, y: e.clientY - 8 });
        return;
      }
    }

    setTooltipNode(null);
    setTooltipEdge(null);
  };

  const handleMouseUp = () => setDragging(false);

  const handleWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    setZoom(z => Math.max(0.1, Math.min(5, z * delta)));
  };

  const findNodeAt = (e: React.MouseEvent): GraphNode | null => {
    if (!graphData || !canvasRef.current) return null;
    const rect = canvasRef.current.getBoundingClientRect();
    const mx = (e.clientX - rect.left - pan.x) / zoom;
    const my = (e.clientY - rect.top - pan.y) / zoom;
    for (const node of graphData.nodes) {
      const pos = nodePositions[node.id];
      if (!pos) continue;
      const size = NODE_SIZE[node.type] || 16;
      const dx = mx - pos.x;
      const dy = my - pos.y;
      if (dx * dx + dy * dy < (size / 2) * (size / 2) * 4) return node;
    }
    return null;
  };

  const handleCanvasClick = (e: React.MouseEvent) => {
    const node = findNodeAt(e);
    if (node) {
      setHighlightedNode(prev => prev === node.id ? null : node.id);
      // AI-classified identities open the AI investigate drawer; other
      // identities open the standard detail panel.
      if (node.is_ai_agent) {
        setAiDrawerIdentityId(node.id);
        setActiveAttackPath(null);
        return;
      }
      const identityTypes = ['identity', 'service_principal', 'managed_identity', 'guest'];
      if (identityTypes.includes(node.type)) {
        fetchIdentityDetail(node.id);
        // If in attack mode, highlight attack paths from this identity
        if (graphData) {
          const path = graphData.attackPaths.find(ap => ap.identity === node.id);
          setActiveAttackPath(path || null);
        }
      } else {
        setActiveAttackPath(null);
      }
    } else {
      setHighlightedNode(null);
      setActiveAttackPath(null);
    }
  };

  const filteredNodes = graphData?.nodes.filter(n => {
    const lbl = n.label || n.id;
    return searchTerm ? lbl.toLowerCase().includes(searchTerm.toLowerCase()) : true;
  }) || [];

  const selectedLabel = connections.find(c => String(c.id) === connectionId)?.label;

  /* ─── Tooltip Renderer ────────────────────────────────────────────── */

  const renderNodeTooltip = (node: GraphNode) => {
    const tip = node.tooltip;
    if (!tip) return null;
    const ntype = node.type;

    if (ntype === 'identity' || ntype === 'service_principal' || ntype === 'managed_identity' || ntype === 'guest') {
      const t = tip as IdentityTooltip;
      return (
        <div className="space-y-1.5">
          <div className="font-medium text-white text-xs">{t.name}</div>
          <div className="text-slate-400 text-[10px]">{t.identity_type || ntype.replace(/_/g, ' ')}</div>
          <div className="flex items-center gap-2 text-[10px]">
            <span className={`px-1.5 py-0.5 rounded ${RISK_BADGE[node.risk_level] || RISK_BADGE.low} border`}>{node.risk_level}</span>
            <span className="text-slate-400">Score: {t.risk_score}</span>
            <span className="text-slate-400">{t.activity_status}</span>
          </div>
          {t.roles.length > 0 && (
            <div className="text-[10px]">
              <span className="text-slate-400">Roles: </span>
              <span className="text-yellow-400">{t.roles.join(', ')}</span>
            </div>
          )}
          {t.subscriptions.length > 0 && (
            <div className="text-[10px]">
              <span className="text-slate-400">Subs: </span>
              <span className="text-red-400">{t.subscriptions.join(', ')}</span>
            </div>
          )}
          <div className="text-[10px] text-slate-400">
            Credentials: {t.credential_count}{t.credential_risk !== 'none' ? ` (${t.credential_risk})` : ''}
          </div>
        </div>
      );
    }

    if (ntype === 'role') {
      const t = tip as RoleTooltip;
      return (
        <div className="space-y-1.5">
          <div className="font-medium text-yellow-400 text-xs">{t.role_name}</div>
          <div className="flex items-center gap-2 text-[10px]">
            <span className={`px-1.5 py-0.5 rounded ${RISK_BADGE[node.risk_level] || RISK_BADGE.low} border`}>{node.risk_level}</span>
            <span className="text-slate-400">Privilege: {t.privilege_level}</span>
          </div>
          <div className="text-[10px] text-slate-400">{t.identity_count} identities assigned</div>
          {t.identities.length > 0 && (
            <div className="text-[10px]">
              <span className="text-slate-400">Assigned to: </span>
              <span className="text-blue-400">{t.identities.slice(0, 4).join(', ')}{t.identities.length > 4 ? '...' : ''}</span>
            </div>
          )}
          {t.scopes.length > 0 && (
            <div className="text-[10px]">
              <span className="text-slate-400">Scopes: </span>
              <span className="text-green-400">{t.scopes.join(', ')}</span>
            </div>
          )}
        </div>
      );
    }

    if (ntype === 'resource') {
      const t = tip as ResourceTooltip;
      return (
        <div className="space-y-1.5">
          <div className="font-medium text-green-400 text-xs">{t.resource_name}</div>
          {t.resource_type && <div className="text-[10px] text-slate-400">{t.resource_type}</div>}
          <div className="text-[10px] text-slate-400">{t.accessor_count} identities can access</div>
          {t.accessors.length > 0 && (
            <div className="text-[10px] space-y-0.5">
              {t.accessors.slice(0, 4).map((a, i) => (
                <div key={i}><span className="text-blue-400">{a.identity}</span> <span className="text-slate-500">via</span> <span className="text-yellow-400">{a.role}</span></div>
              ))}
            </div>
          )}
        </div>
      );
    }

    if (ntype === 'subscription') {
      const t = tip as SubscriptionTooltip;
      return (
        <div className="space-y-1.5">
          <div className="font-medium text-red-400 text-xs">{t.subscription_name}</div>
          <div className="text-[10px] text-slate-400">{t.identity_count} identities with access</div>
          {t.high_privilege_count > 0 && (
            <div className="text-[10px] text-orange-400">{t.high_privilege_count} high-privilege role assignments</div>
          )}
        </div>
      );
    }

    return null;
  };

  const renderEdgeTooltip = (edge: GraphEdge) => {
    const tip = edge.tooltip;
    if (!tip) return null;

    // Build a natural language description
    let sentence = '';
    if (edge.type === 'assigned_role') {
      sentence = `${tip.source_label} assigned ${tip.role} role`;
    } else if (edge.type === 'grants_access') {
      sentence = `${tip.source_label} grants access to ${tip.target_label}`;
    } else if (edge.type === 'contains_resource') {
      sentence = `${tip.source_label} contains ${tip.target_label}`;
    } else {
      sentence = `${tip.source_label} ${tip.relationship} ${tip.target_label}`;
    }

    return (
      <div className="space-y-1">
        <div className="text-xs text-white">{sentence}</div>
        <div className="flex items-center gap-2 text-[10px]">
          <span className="text-slate-400">{tip.relationship}</span>
          {edge.isAttackPath && (
            <span className="px-1.5 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/30 text-[9px]">Attack Path</span>
          )}
        </div>
      </div>
    );
  };

  /* ─── Focused View helpers ─────────────────────────────────────────── */

  const SEVERITY_BADGE: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-green-500/20 text-green-400 border-green-500/30',
  };

  const PATH_TYPE_LABEL: Record<string, string> = {
    direct_escalation: 'Privilege Escalation',
    ownership_chain: 'Ownership Chain',
    pim_escalation: 'PIM Escalation',
    lateral_movement: 'Lateral Movement',
    sensitive_data_exposure: 'Sensitive Data',
    external_identity_risk: 'External Identity',
  };

  const NODE_TYPE_ICON: Record<string, string> = {
    identity: '\u{1F464}',
    entra_role: '\u{1F6E1}',
    role: '\u{1F6E1}',
    target: '\u{1F3AF}',
    resource: '\u{1F4E6}',
    permission: '\u{1F511}',
    keyvault: '\u{1F512}',
    subscription: '\u2601',
  };

  /* ─── Render ──────────────────────────────────────────────────────── */

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Identity Graph</h1>
          <p className="text-sm text-slate-400 mt-1">Cloud IAM attack path visualization</p>
        </div>
        <div className="flex items-center gap-2">
          {/* Page mode toggle */}
          <div className="flex items-center bg-slate-800 rounded-lg p-0.5">
            <button
              onClick={() => setPageMode('focused')}
              className={`px-3 py-1.5 text-sm rounded-md transition ${pageMode === 'focused' ? 'bg-blue-500/20 text-blue-400 font-medium' : 'text-slate-400 hover:text-slate-300'}`}
            >
              Focused View
            </button>
            <button
              onClick={() => setPageMode('full')}
              className={`px-3 py-1.5 text-sm rounded-md transition ${pageMode === 'full' ? 'bg-blue-500/20 text-blue-400 font-medium' : 'text-slate-400 hover:text-slate-300'}`}
            >
              Full Graph
            </button>
          </div>
          {pageMode === 'full' && (
            <>
              <span className="text-slate-600">|</span>
              <button
                onClick={() => { setViewMode('identity'); setActiveAttackPath(null); }}
                className={`px-3 py-1.5 text-sm rounded ${viewMode === 'identity' ? 'bg-blue-500/20 text-blue-400' : 'bg-slate-800 text-slate-400'}`}
              >
                Identity Graph
              </button>
              <button
                onClick={() => setViewMode('attack')}
                className={`px-3 py-1.5 text-sm rounded ${viewMode === 'attack' ? 'bg-red-500/20 text-red-400' : 'bg-slate-800 text-slate-400'}`}
              >
                Attack Paths
              </button>
              <span className="text-slate-600">|</span>
              <button
                onClick={() => setColorMode(m => m === 'type' ? 'risk' : 'type')}
                className="px-3 py-1.5 text-sm rounded bg-slate-800 text-slate-400 hover:text-white"
              >
                Color: {colorMode === 'type' ? 'Type' : 'Risk'}
              </button>
            </>
          )}
        </div>
      </div>

      {/* ═══════════ Focused View ═══════════ */}
      {pageMode === 'focused' && (
        <div className="space-y-4">
          {topPathsLoading ? (
            <div className="flex items-center justify-center h-64 text-slate-400">Loading top attack paths...</div>
          ) : topPaths.length === 0 ? (
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-xl p-8 text-center">
              <div className="text-4xl mb-3">{'\u{1F6E1}'}</div>
              <h3 className="text-lg font-semibold text-white mb-1">No Attack Paths Detected</h3>
              <p className="text-sm text-slate-400 mb-4 max-w-md mx-auto">
                Run a discovery scan to analyze your environment for privilege escalation paths, lateral movement, and misconfigurations.
              </p>
              <button
                onClick={() => setPageMode('full')}
                className="px-4 py-2 text-sm bg-blue-500/20 text-blue-400 rounded-lg hover:bg-blue-500/30 transition"
              >
                Open Full Graph
              </button>
            </div>
          ) : (
            <>
              {/* Summary banner */}
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-center text-lg">
                    {'\u{1F6A8}'}
                  </div>
                  <div>
                    <div className="text-white font-semibold text-sm">
                      {topPathsTotal} Attack Path{topPathsTotal !== 1 ? 's' : ''} Detected
                    </div>
                    <div className="text-xs text-slate-400 mt-0.5">
                      Showing top {topPaths.length} highest-risk paths &middot; Ranked by severity and risk score
                    </div>
                  </div>
                </div>
                <button
                  onClick={() => setPageMode('full')}
                  className="px-3 py-1.5 text-xs bg-slate-700 text-slate-300 rounded hover:bg-slate-600 transition flex-shrink-0"
                >
                  View Full Graph
                </button>
              </div>

              {/* Path cards */}
              <div className="space-y-3">
                {topPaths.map((path, idx) => {
                  const isExpanded = expandedPathId === path.id;
                  return (
                    <div
                      key={path.id}
                      className="bg-slate-800/50 border border-slate-700/50 rounded-xl overflow-hidden hover:border-slate-600/50 transition"
                    >
                      {/* Card header */}
                      <div
                        className="p-4 cursor-pointer"
                        onClick={() => setExpandedPathId(isExpanded ? null : path.id)}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="flex items-start gap-3 min-w-0">
                            <div className="flex-shrink-0 w-7 h-7 rounded-full bg-slate-700 flex items-center justify-center text-xs font-bold text-slate-300">
                              {idx + 1}
                            </div>
                            <div className="min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`px-2 py-0.5 text-[10px] font-medium rounded border ${SEVERITY_BADGE[path.severity] || SEVERITY_BADGE.medium}`}>
                                  {path.severity.toUpperCase()}
                                </span>
                                <span className="text-[10px] text-slate-500">
                                  {PATH_TYPE_LABEL[path.path_type] || path.path_type.replace(/_/g, ' ')}
                                </span>
                                <span className="text-[10px] font-mono text-slate-500">
                                  Score: {path.risk_score}
                                </span>
                              </div>
                              <p className="text-sm text-white font-medium mt-1.5 truncate">{path.description}</p>
                              {/* Warning badges */}
                              <div className="flex items-center gap-1.5 mt-2 flex-wrap">
                                {path.has_keyvault_access && (
                                  <span className="px-1.5 py-0.5 text-[10px] rounded bg-purple-500/15 text-purple-400 border border-purple-500/20">
                                    {'\u{1F512}'} Key Vault Access
                                  </span>
                                )}
                                {path.has_no_owner && (
                                  <span className="px-1.5 py-0.5 text-[10px] rounded bg-amber-500/15 text-amber-400 border border-amber-500/20">
                                    {'\u26A0'} No Owner
                                  </span>
                                )}
                                {path.has_subscription_scope && (
                                  <span className="px-1.5 py-0.5 text-[10px] rounded bg-red-500/15 text-red-400 border border-red-500/20">
                                    {'\u2601'} Subscription Scope
                                  </span>
                                )}
                                {path.occurrence_count > 1 && (
                                  <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-500/15 text-slate-400 border border-slate-500/20">
                                    Seen {path.occurrence_count}x
                                  </span>
                                )}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 flex-shrink-0">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                setViewMode('attack');
                                if (connections.length > 0 && !connectionId) {
                                  setConnectionId(String(connections[0].id));
                                }
                                setPageMode('full');
                              }}
                              className="px-3 py-1.5 text-xs bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 transition"
                            >
                              Investigate
                            </button>
                            <svg
                              className={`w-4 h-4 text-slate-400 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                              fill="none" stroke="currentColor" viewBox="0 0 24 24"
                            >
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                            </svg>
                          </div>
                        </div>
                      </div>

                      {/* Expanded detail */}
                      {isExpanded && (
                        <div className="border-t border-slate-700/50 p-4 bg-slate-900/30">
                          {/* Path chain */}
                          {path.path_nodes && path.path_nodes.length > 0 && (
                            <div className="mb-4">
                              <div className="text-xs text-slate-400 font-medium mb-2">Escalation Chain</div>
                              <div className="flex items-center gap-1 flex-wrap">
                                {path.path_nodes.map((node, ni) => (
                                  <React.Fragment key={ni}>
                                    {ni > 0 && (
                                      <svg className="w-4 h-4 text-red-400 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                                      </svg>
                                    )}
                                    <span className="inline-flex items-center gap-1 px-2 py-1 rounded bg-slate-800 border border-slate-700/50 text-xs">
                                      <span>{NODE_TYPE_ICON[node.type] || '\u2022'}</span>
                                      <span className="text-white">{node.label}</span>
                                      {node.detail && (
                                        <span className="text-slate-500 text-[10px]">({node.detail})</span>
                                      )}
                                    </span>
                                  </React.Fragment>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Narrative & Impact */}
                          <div className="grid grid-cols-2 gap-4">
                            {path.narrative && (
                              <div>
                                <div className="text-xs text-slate-400 font-medium mb-1">Narrative</div>
                                <p className="text-xs text-slate-300 leading-relaxed">{path.narrative}</p>
                              </div>
                            )}
                            {path.impact && (
                              <div>
                                <div className="text-xs text-slate-400 font-medium mb-1">Impact</div>
                                <p className="text-xs text-slate-300 leading-relaxed">{path.impact}</p>
                              </div>
                            )}
                          </div>

                          {/* Metadata row */}
                          <div className="flex items-center gap-4 mt-3 pt-3 border-t border-slate-700/30 text-[10px] text-slate-500">
                            <span>Source: {path.source_entity_name || path.source_entity_id}</span>
                            <span>Type: {path.source_entity_type?.replace(/_/g, ' ')}</span>
                            <span>Hops: {path.path_length}</span>
                            {path.affected_resource_count > 0 && (
                              <span>Resources at risk: {path.affected_resource_count}</span>
                            )}
                            {path.highest_role && <span>Highest role: {path.highest_role}</span>}
                            <span>First seen: {new Date(path.first_detected_at).toLocaleDateString()}</span>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>

              {/* "View all" footer */}
              {topPathsTotal > 5 && (
                <div className="text-center">
                  <button
                    onClick={() => setPageMode('full')}
                    className="text-xs text-blue-400 hover:text-blue-300"
                  >
                    View all {topPathsTotal} attack paths in Full Graph &rarr;
                  </button>
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* ═══════════ Full Graph View ═══════════ */}
      {pageMode === 'full' && (<>

      {/* Attack Path Info Banner (amber/informational) */}
      {!!graphData && graphData.attackPathCount > 0 && (
        <div
          className="rounded-lg border flex items-center justify-between"
          style={{ background: 'rgba(120,53,15,0.4)', borderColor: '#d97706', padding: '10px 16px' }}
        >
          <div className="flex items-center gap-3">
            <span className="text-lg">{'\u{1F6E1}'}</span>
            <div>
              <div className="text-amber-200 font-semibold text-sm">
                {graphData.attackPathCount.toLocaleString()} Lateral Movement Path{graphData.attackPathCount > 1 ? 's' : ''} Identified
              </div>
              <div className="text-amber-300/70 text-xs mt-0.5">
                Privilege escalation paths detected across connected resources. Select a path to highlight.
              </div>
            </div>
          </div>
          <div className="flex gap-2 flex-shrink-0">
            <button
              onClick={() => setShowPathPanel(true)}
              className="px-3 py-1.5 rounded text-xs font-medium text-white bg-amber-600 hover:bg-amber-500 transition"
            >
              View Paths
            </button>
            {activeAttackPath && (
              <button
                onClick={() => { setActiveAttackPath(null); setHighlightedNode(null); }}
                className="px-3 py-1.5 rounded text-xs font-medium bg-slate-700 text-slate-300 hover:bg-slate-600"
              >
                Reset View
              </button>
            )}
          </div>
        </div>
      )}

      {/* Controls */}
      <div className="flex items-center gap-4 bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
        {viewMode === 'identity' ? (
          <>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Connection:</label>
              <select
                value={connectionId}
                onChange={e => setConnectionId(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white min-w-[160px]"
              >
                <option value="">Select connection...</option>
                {connections.map(c => (
                  <option key={c.id} value={String(c.id)}>
                    {c.label} ({c.cloud})
                  </option>
                ))}
              </select>
              <button
                onClick={fetchIdentityGraph}
                disabled={loading || !connectionId}
                className="px-3 py-1 text-xs bg-blue-500/20 text-blue-400 rounded hover:bg-blue-500/30 disabled:opacity-50"
              >
                Load Graph
              </button>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Identity ID:</label>
              <input
                type="text"
                value={identityId}
                onChange={e => setIdentityId(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white w-48"
                placeholder="identity-uuid"
              />
              <button
                onClick={fetchNeighborhood}
                disabled={loading || !identityId}
                className="px-3 py-1 text-xs bg-cyan-500/20 text-cyan-400 rounded hover:bg-cyan-500/30 disabled:opacity-50"
              >
                Neighborhood
              </button>
            </div>
          </>
        ) : (
          <div className="flex items-center gap-3">
            <div className="flex items-center gap-2">
              <label className="text-xs text-slate-400">Connection:</label>
              <select
                value={connectionId}
                onChange={e => setConnectionId(e.target.value)}
                className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white min-w-[160px]"
              >
                <option value="">Select connection...</option>
                {connections.map(c => (
                  <option key={c.id} value={String(c.id)}>
                    {c.label} ({c.cloud})
                  </option>
                ))}
              </select>
              <button
                onClick={fetchIdentityGraph}
                disabled={loading || !connectionId}
                className="px-3 py-1 text-xs bg-red-500/20 text-red-400 rounded hover:bg-red-500/30 disabled:opacity-50"
              >
                Load Attack Paths
              </button>
            </div>
            {!activeAttackPath && graphData && graphData.attackPathCount > 0 && (
              <span className="text-xs text-slate-400">Click an identity or select a path above to highlight</span>
            )}
            {activeAttackPath && (
              <button
                onClick={() => { setActiveAttackPath(null); setHighlightedNode(null); }}
                className="px-2 py-1 text-xs bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
              >
                Clear Highlight
              </button>
            )}
          </div>
        )}

        <div className="ml-auto flex items-center gap-2">
          <input
            type="text"
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
            className="bg-slate-900 border border-slate-700 rounded px-2 py-1 text-sm text-white w-48"
            placeholder="Search nodes..."
          />
          <button
            onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }); }}
            className="px-2 py-1 text-xs bg-slate-700 text-slate-300 rounded hover:bg-slate-600"
          >
            Reset View
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-slate-400 flex-wrap">
        {colorMode === 'type' ? (
          Object.entries(TYPE_NODE_COLOR).map(([type, color]) => (
            <div key={type} className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-full inline-block" style={{ backgroundColor: color }} />
              <span>{type.replace(/_/g, ' ')}</span>
            </div>
          ))
        ) : (
          Object.entries(RISK_NODE_COLOR).map(([level, color]) => (
            <div key={level} className="flex items-center gap-1">
              <span className="w-3 h-3 rounded-full inline-block" style={{ backgroundColor: color }} />
              <span>{level}</span>
            </div>
          ))
        )}
        <span className="text-slate-600">|</span>
        {Object.entries(EDGE_COLOR).map(([type, color]) => (
          <div key={type} className="flex items-center gap-1">
            <span className="w-4 h-0.5 inline-block" style={{ backgroundColor: color }} />
            <span>{type.replace(/_/g, ' ')}</span>
          </div>
        ))}
        <div className="flex items-center gap-1">
          <span className="w-4 h-0.5 inline-block" style={{ backgroundColor: ATTACK_EDGE_COLOR }} />
          <span className="text-red-400">attack path</span>
        </div>
      </div>

      {/* Graph Canvas + Side Panel */}
      <div className="flex gap-4 relative">
        {/* Canvas */}
        <div
          className="bg-slate-900/50 border border-slate-700/50 rounded-lg overflow-hidden relative"
          style={{ height: '600px', flex: showPathPanel ? '1 1 0' : '1 1 0', minWidth: 0 }}
        >
          {loading ? (
            <div className="flex items-center justify-center h-full text-slate-400">Loading graph...</div>
          ) : !graphData ? (
            <div className="flex items-center justify-center h-full text-slate-400">
              Select a connection and click Load Graph to visualize
            </div>
          ) : graphData.nodes.length === 0 ? (
            <div className="flex items-center justify-center h-full text-slate-400">No graph data available for this connection</div>
          ) : (
            <canvas
              ref={canvasRef}
              className="w-full h-full cursor-grab active:cursor-grabbing"
              onMouseDown={handleMouseDown}
              onMouseMove={handleMouseMove}
              onMouseUp={handleMouseUp}
              onMouseLeave={() => { handleMouseUp(); setTooltipNode(null); setTooltipEdge(null); }}
              onWheel={handleWheel}
              onClick={handleCanvasClick}
            />
          )}

          {/* Truncation info */}
          {graphData?.truncated && (
            <div
              className="absolute top-2 left-2 rounded-md border px-3 py-1.5 text-xs"
              style={{ background: 'rgba(30,41,59,0.9)', borderColor: '#334155', color: '#94A3B8' }}
            >
              Showing highest-risk subgraph ({graphData.nodes.length} of {graphData.nodes.length + 50}+ identities).
              Search by Identity ID above to explore specific identities.
            </div>
          )}
        </div>

        {/* Attack Path Sidebar Panel */}
        {showPathPanel && graphData && graphData.attackPaths.length > 0 && (
          <div
            className="w-80 flex-shrink-0 rounded-lg border overflow-y-auto"
            style={{ height: '600px', background: '#1E293B', borderColor: 'rgba(255,255,255,0.08)' }}
          >
            <div className="p-3">
              <div className="flex items-center justify-between mb-3">
                <span className="font-semibold text-sm text-white">
                  Attack Paths ({graphData.attackPathCount.toLocaleString()})
                </span>
                <button
                  onClick={() => setShowPathPanel(false)}
                  className="text-slate-400 hover:text-white text-sm"
                >
                  &#10005;
                </button>
              </div>

              {/* Filter tabs */}
              <div className="flex gap-1.5 mb-3">
                {(['All', 'Critical', 'High'] as const).map(level => (
                  <button
                    key={level}
                    onClick={() => setPathFilter(level)}
                    className="px-2.5 py-1 rounded-full text-xs border cursor-pointer"
                    style={{
                      background: pathFilter === level ? '#DC2626' : 'transparent',
                      borderColor: pathFilter === level ? '#DC2626' : '#334155',
                      color: 'white',
                    }}
                  >
                    {level}
                  </button>
                ))}
              </div>

              {/* Path list */}
              <div className="space-y-1.5">
                {graphData.attackPaths
                  .filter(ap => {
                    if (pathFilter === 'All') return true;
                    // Filter by target type as proxy for severity
                    if (pathFilter === 'Critical') return ap.target_type === 'subscription';
                    return true;
                  })
                  .slice(0, 50)
                  .map((path, i) => (
                    <button
                      key={i}
                      onClick={() => {
                        setActiveAttackPath(path);
                        setHighlightedNode(path.identity);
                        setViewMode('attack');
                      }}
                      className="w-full text-left rounded-md p-2.5 border transition-colors"
                      style={{
                        background: activeAttackPath?.identity === path.identity
                          ? 'rgba(220,38,38,0.15)' : 'rgba(255,255,255,0.04)',
                        borderColor: activeAttackPath?.identity === path.identity
                          ? '#DC2626' : 'transparent',
                      }}
                    >
                      <div className="text-xs font-medium text-slate-100">
                        {path.identity_label}
                      </div>
                      <div className="text-[11px] text-slate-400 mt-1">
                        &rarr; {path.role} &rarr; {path.target_label}
                      </div>
                      <div className="text-[10px] text-slate-500 mt-0.5">
                        {path.target_type?.replace(/_/g, ' ')}
                      </div>
                    </button>
                  ))}
                {graphData.attackPaths.length > 50 && (
                  <div className="text-center text-slate-500 text-xs py-2">
                    Showing 50 of {graphData.attackPaths.length.toLocaleString()} paths
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Floating Tooltip */}
        {(tooltipNode || tooltipEdge) && (
          <div
            className="fixed z-50 bg-slate-900/95 border border-slate-600/50 rounded-lg shadow-xl px-3 py-2 max-w-xs pointer-events-none backdrop-blur-sm"
            style={{ left: tooltipPos.x, top: tooltipPos.y }}
          >
            {tooltipNode && renderNodeTooltip(tooltipNode)}
            {tooltipEdge && renderEdgeTooltip(tooltipEdge)}
          </div>
        )}

        {/* Identity Detail Side Panel */}
        {panelOpen && (
          <div className="w-80 bg-slate-800/80 border border-slate-700/50 rounded-lg overflow-y-auto flex-shrink-0" style={{ height: '600px' }}>
            <div className="flex items-center justify-between p-3 border-b border-slate-700/50">
              <h3 className="text-sm font-semibold text-white">Identity Detail</h3>
              <button
                onClick={() => { setPanelOpen(false); setSelectedDetail(null); }}
                className="text-slate-400 hover:text-white text-lg leading-none"
              >
                &times;
              </button>
            </div>

            {detailLoading ? (
              <div className="flex items-center justify-center h-40 text-slate-400 text-sm">Loading...</div>
            ) : !selectedDetail ? (
              <div className="p-4 text-slate-400 text-sm">Identity not found.</div>
            ) : (
              <div className="p-4 space-y-4">
                <div>
                  <p className="text-white font-medium text-sm">{selectedDetail.display_name}</p>
                  <p className="text-slate-400 text-xs mt-0.5 font-mono">{selectedDetail.identity_id}</p>
                </div>

                <div className="flex items-center gap-2 flex-wrap">
                  <span className={`px-2 py-0.5 text-xs rounded border ${RISK_BADGE[selectedDetail.risk_level] || RISK_BADGE.low}`}>
                    {selectedDetail.risk_level}
                  </span>
                  <span className="px-2 py-0.5 text-xs rounded bg-slate-700 text-slate-300">
                    {selectedDetail.activity_status}
                  </span>
                  {selectedDetail.identity_category && (
                    <span className="px-2 py-0.5 text-xs rounded bg-slate-700 text-slate-300">
                      {selectedDetail.identity_category.replace(/_/g, ' ')}
                    </span>
                  )}
                </div>

                {/* Attack path warning */}
                {graphData?.attackPaths.some(ap => ap.identity === selectedDetail.identity_id) && (
                  <div className="bg-red-500/10 border border-red-500/30 rounded p-2">
                    <p className="text-xs text-red-400 font-medium">Attack Path Detected</p>
                    <p className="text-[10px] text-red-300 mt-0.5">
                      This identity has a high-privilege escalation path
                    </p>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-2">
                  <div className="bg-slate-900/50 rounded p-2">
                    <p className="text-xs text-slate-400">Risk Score</p>
                    <p className="text-lg font-semibold text-white">{selectedDetail.risk_score}</p>
                  </div>
                  <div className="bg-slate-900/50 rounded p-2">
                    <p className="text-xs text-slate-400">Credentials</p>
                    <p className="text-lg font-semibold text-white">{selectedDetail.credential_count}</p>
                  </div>
                </div>

                {selectedDetail.credential_risk && selectedDetail.credential_risk !== 'none' && (
                  <div className="bg-red-500/10 border border-red-500/20 rounded p-2">
                    <p className="text-xs text-red-400">Credential Risk: {selectedDetail.credential_risk}</p>
                  </div>
                )}

                {!!selectedDetail.roles && selectedDetail.roles.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-400 mb-1.5">Roles ({selectedDetail.roles.length})</p>
                    <div className="space-y-1 max-h-32 overflow-y-auto">
                      {selectedDetail.roles.map((r, i) => (
                        <div key={i} className="flex items-center justify-between bg-slate-900/50 rounded px-2 py-1">
                          <span className="text-xs text-yellow-400">{r.role_name}</span>
                          <span className="text-xs text-slate-500 truncate ml-2 max-w-[120px]" title={r.scope}>
                            {r.scope ? r.scope.split('/').pop() : ''}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {!!selectedDetail.subscriptions && selectedDetail.subscriptions.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-400 mb-1.5">Subscriptions ({selectedDetail.subscriptions.length})</p>
                    <div className="space-y-1">
                      {selectedDetail.subscriptions.map((s, i) => (
                        <div key={i} className="bg-slate-900/50 rounded px-2 py-1">
                          <span className="text-xs text-red-400">{s}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <a
                  href={`/identities/${selectedDetail.identity_id}`}
                  className="block text-center text-xs text-blue-400 hover:text-blue-300 bg-blue-500/10 rounded py-2 mt-2"
                >
                  Open Full Identity Detail
                </a>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Stats bar */}
      {!!graphData && graphData.nodes.length > 0 && (
        <div className="flex items-center gap-6 text-xs text-slate-400">
          <span>Nodes: {graphData.nodes.length}</span>
          <span>Edges: {graphData.edges.length}</span>
          {graphData.attackPathCount > 0 && (
            <span className="text-red-400">Attack Paths: {graphData.attackPathCount}</span>
          )}
          {selectedLabel && <span>Connection: {selectedLabel}</span>}
          {searchTerm && <span>Search matches: {filteredNodes.length}</span>}
          <span>Zoom: {Math.round(zoom * 100)}%</span>
        </div>
      )}

      {/* Node list for search results */}
      {searchTerm && filteredNodes.length > 0 && (
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50 max-h-48 overflow-y-auto">
          {filteredNodes.slice(0, 20).map(node => (
            <div
              key={node.id}
              className="px-4 py-2 flex items-center justify-between cursor-pointer hover:bg-slate-700/30"
              onClick={() => setHighlightedNode(node.id)}
            >
              <div className="flex items-center gap-2">
                <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: TYPE_NODE_COLOR[node.type] || '#94a3b8' }} />
                <span className="text-sm text-white">{node.label}</span>
                {node.isAttackPath && (
                  <span className="px-1 py-0.5 text-[9px] rounded bg-red-500/20 text-red-400 border border-red-500/30">ATK</span>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className={`px-1.5 py-0.5 text-[10px] rounded ${RISK_BADGE[node.risk_level] || ''}`}>{node.risk_level}</span>
                <span className="text-xs text-slate-500">{node.type.replace(/_/g, ' ')}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      </>)}

      {/* AI Investigate Drawer — opens when an AI-classified node is clicked. */}
      {aiDrawerIdentityId && (
        <AIInvestigateDrawer
          identityId={aiDrawerIdentityId}
          onClose={() => setAiDrawerIdentityId(null)}
        />
      )}
    </div>
  );
};

export default IdentityGraph;
