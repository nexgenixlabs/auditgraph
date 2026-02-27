import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useToast } from '../components/ToastProvider';
import { useAuth } from '../contexts/AuthContext';
import { useConnection } from '../contexts/ConnectionContext';
import { SnapshotContextHeader } from '../components/ui/SnapshotContextHeader';

/* ------------------------------------------------------------------ */
/* Types                                                               */
/* ------------------------------------------------------------------ */

interface Campaign {
  id: number;
  name: string;
  description: string | null;
  status: 'active' | 'completed' | 'archived';
  campaign_type: string;
  scope_filters: Record<string, unknown>;
  scope_clouds: string[] | null;
  scope_description: string | null;
  risk_focus: string | null;
  deadline: string | null;
  created_by: number;
  creator_name: string;
  total_reviews: number;
  completed_reviews: number;
  approved_count: number;
  revoked_count: number;
  flagged_count: number;
  created_at: string;
  updated_at: string;
  completed_at: string | null;
}

interface ReviewItem {
  id: number;
  campaign_id: number;
  identity_id: string;
  identity_display_name: string;
  identity_risk_level: string;
  identity_category: string;
  identity_type: string;
  identity_db_id: number;
  access_role: string | null;
  access_scope: string | null;
  cloud_provider: string | null;
  risk_score: number;
  risk_factors: Array<{ factor: string; points: number; detail?: string }>;
  last_used_date: string | null;
  last_used_days: number | null;
  privilege_level: string | null;
  credential_risk: string | null;
  credential_risk_level: string | null;
  ai_recommendation: string | null;
  ai_recommendation_reason: string | null;
  reviewer_name: string | null;
  decision: string | null;
  notes: string | null;
  decided_at: string | null;
  review_due_date: string | null;
  created_at: string;
}

interface Metrics {
  active_count: number;
  overdue_count: number;
  completion_rate: number;
  high_risk_pending: number;
  revocation_rate: number;
  nhi_percentage: number;
}

/* ------------------------------------------------------------------ */
/* Dark Theme Constants                                                */
/* ------------------------------------------------------------------ */

const AR = {
  bg: 'var(--bg-primary)',
  surface: 'var(--bg-secondary)',
  surfaceBorder: 'var(--border-default)',
  surfaceHover: 'var(--bg-hover)',
  text: 'var(--text-primary)',
  textSecondary: 'var(--text-secondary)',
  textMuted: 'var(--text-tertiary)',
  severity: { critical: '#FF1744', high: '#FF6D00', medium: '#FFB300', low: '#42A5F5' } as Record<string, string>,
  decision: {
    approve: { bg: 'rgba(74,222,128,0.12)', text: '#4ADE80', label: 'Approved' },
    revoke: { bg: 'rgba(255,23,68,0.12)', text: '#FF1744', label: 'Revoked' },
    flag: { bg: 'rgba(255,179,0,0.12)', text: '#FFB300', label: 'Flagged' },
    downgrade: { bg: 'rgba(139,92,246,0.12)', text: '#A78BFA', label: 'Downgrade' },
    convert_pim: { bg: 'rgba(96,165,250,0.12)', text: '#60A5FA', label: 'Convert PIM' },
    rotate_secret: { bg: 'rgba(251,146,60,0.12)', text: '#FB923C', label: 'Rotate Secret' },
  } as Record<string, { bg: string; text: string; label: string }>,
  ai: {
    Revoke: { bg: 'rgba(255,23,68,0.15)', text: '#FF1744', border: 'rgba(255,23,68,0.3)' },
    Downgrade: { bg: 'rgba(139,92,246,0.15)', text: '#A78BFA', border: 'rgba(139,92,246,0.3)' },
    Approve: { bg: 'rgba(74,222,128,0.15)', text: '#4ADE80', border: 'rgba(74,222,128,0.3)' },
    'Convert to PIM': { bg: 'rgba(96,165,250,0.15)', text: '#60A5FA', border: 'rgba(96,165,250,0.3)' },
    'Rotate Secret': { bg: 'rgba(251,146,60,0.15)', text: '#FB923C', border: 'rgba(251,146,60,0.3)' },
  } as Record<string, { bg: string; text: string; border: string }>,
  cloud: { Azure: '#0078D4', AWS: '#FF9900', GCP: '#4285F4' } as Record<string, string>,
  mono: "'JetBrains Mono', monospace",
  accent: '#8B5CF6',
};

const CAMPAIGN_TYPE_LABELS: Record<string, string> = {
  general: 'General',
  privileged_access: 'Privileged Access',
  nhi_review: 'Non-Human Identity',
  dormant_cleanup: 'Dormant Cleanup',
  guest_access: 'Guest Access',
  credential_risk: 'Credential Risk',
};

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MI',
  managed_identity_user: 'User MI',
  human_user: 'Human',
  guest: 'Guest',
  microsoft_internal: 'MSFT Internal',
};

const PRIVILEGE_COLORS: Record<string, string> = {
  Privileged: '#FF1744',
  Elevated: '#FF6D00',
  Standard: '#42A5F5',
  'PIM Eligible': '#A78BFA',
};

const CRED_RISK_COLORS: Record<string, string> = {
  critical: '#FF1744',
  high: '#FF6D00',
  medium: '#FFB300',
  low: '#4ADE80',
  none: 'rgba(255,255,255,0.3)',
};

const ALL_DECISIONS = [
  { key: 'approve', label: 'Approve', color: '#4ADE80' },
  { key: 'revoke', label: 'Revoke', color: '#FF1744' },
  { key: 'flag', label: 'Flag', color: '#FFB300' },
  { key: 'downgrade', label: 'Downgrade', color: '#A78BFA' },
  { key: 'convert_pim', label: 'Convert PIM', color: '#60A5FA' },
  { key: 'rotate_secret', label: 'Rotate Secret', color: '#FB923C' },
];

/* ------------------------------------------------------------------ */
/* Component                                                           */
/* ------------------------------------------------------------------ */

export default function AccessReviews() {
  const navigate = useNavigate();
  const { addToast } = useToast();
  const { user } = useAuth();
  const { withConnection, selectedConnectionId } = useConnection();
  const isAdmin = user?.role === 'admin';

  // Campaigns
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [metrics, setMetrics] = useState<Metrics | null>(null);

  // Expanded campaign reviews
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [reviews, setReviews] = useState<ReviewItem[]>([]);
  const [reviewsTotal, setReviewsTotal] = useState(0);
  const [reviewsLoading, setReviewsLoading] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());

  // Review filters
  const [reviewStatus, setReviewStatus] = useState<string>('');
  const [reviewRisk, setReviewRisk] = useState<string>('');
  const [reviewType, setReviewType] = useState<string>('');
  const [reviewSearch, setReviewSearch] = useState('');
  const [reviewSort, setReviewSort] = useState<{ col: string; dir: 'asc' | 'desc' }>({ col: 'risk_score', dir: 'desc' });
  const [reviewPage, setReviewPage] = useState(0);
  const PAGE_SIZE = 50;

  // Side panel
  const [panelReview, setPanelReview] = useState<ReviewItem | null>(null);

  // Create modal
  const [showModal, setShowModal] = useState(false);
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [formDeadline, setFormDeadline] = useState('');
  const [formRiskLevels, setFormRiskLevels] = useState<string[]>([]);
  const [formCategories, setFormCategories] = useState<string[]>([]);
  const [formType, setFormType] = useState('general');
  const [creating, setCreating] = useState(false);

  /* ---- Data Loading ---- */

  const loadCampaigns = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const url = statusFilter ? `/api/access-reviews?status=${statusFilter}` : '/api/access-reviews';
      const res = await fetch(withConnection(url));
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setCampaigns(data.campaigns || []);
    } catch {
      setLoadError('Failed to load access review campaigns. Check your connection and try again.');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, withConnection]);

  const loadMetrics = useCallback(async () => {
    try {
      const res = await fetch(withConnection('/api/access-reviews/metrics'));
      if (!res.ok) return;
      setMetrics(await res.json());
    } catch { /* ignore */ }
  }, [withConnection]);

  useEffect(() => { loadCampaigns(); loadMetrics(); }, [loadCampaigns, loadMetrics, selectedConnectionId]);

  const loadReviews = useCallback(async (campaignId: number, page = 0) => {
    setReviewsLoading(true);
    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(page * PAGE_SIZE),
        sort_by: reviewSort.col,
        sort_dir: reviewSort.dir,
      });
      if (reviewStatus) params.set('status', reviewStatus);
      if (reviewRisk) params.set('risk_level', reviewRisk);
      if (reviewType) params.set('identity_type', reviewType);
      if (reviewSearch.trim()) params.set('search', reviewSearch.trim());

      const res = await fetch(withConnection(`/api/access-reviews/${campaignId}?${params}`));
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setReviews(data.reviews || []);
      setReviewsTotal(data.total || 0);
    } catch {
      addToast('Failed to load reviews', 'error');
    } finally {
      setReviewsLoading(false);
    }
  }, [reviewSort, reviewStatus, reviewRisk, reviewType, reviewSearch, addToast, withConnection]);

  function toggleExpand(id: number) {
    if (expandedId === id) {
      setExpandedId(null);
      setReviews([]);
      setSelectedIds(new Set());
      setPanelReview(null);
    } else {
      setExpandedId(id);
      setSelectedIds(new Set());
      setPanelReview(null);
      setReviewPage(0);
      loadReviews(id, 0);
    }
  }

  // Reload reviews when filters/sort change
  useEffect(() => {
    if (expandedId) {
      setReviewPage(0);
      loadReviews(expandedId, 0);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [reviewSort, reviewStatus, reviewRisk, reviewType, reviewSearch]);

  /* ---- Actions ---- */

  async function handleCreate() {
    if (!formName.trim()) return;
    const hasScope = formRiskLevels.length > 0 || formCategories.length > 0;
    if (!hasScope) {
      addToast('Select at least one risk level or identity category', 'error');
      return;
    }
    setCreating(true);
    try {
      const res = await fetch(withConnection('/api/access-reviews'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formName.trim(),
          description: formDesc.trim(),
          deadline: formDeadline || null,
          campaign_type: formType,
          scope: {
            risk_levels: formRiskLevels.length > 0 ? formRiskLevels : undefined,
            identity_categories: formCategories.length > 0 ? formCategories : undefined,
          },
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `Error: ${res.status}`);
      }
      const data = await res.json();
      addToast(`Campaign created with ${data.review_count} identities`, 'success');
      setShowModal(false);
      setFormName(''); setFormDesc(''); setFormDeadline('');
      setFormRiskLevels([]); setFormCategories([]); setFormType('general');
      loadCampaigns();
      loadMetrics();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to create campaign';
      addToast(msg, 'error');
    } finally {
      setCreating(false);
    }
  }

  async function handleDecision(reviewId: number, decision: string) {
    if (!expandedId) return;
    try {
      const res = await fetch(withConnection(`/api/access-reviews/${expandedId}/reviews/${reviewId}`), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
      });
      if (!res.ok) throw new Error(`Error: ${res.status}`);
      loadReviews(expandedId, reviewPage);
      loadCampaigns();
      loadMetrics();
    } catch {
      addToast('Failed to set decision', 'error');
    }
  }

  async function handleBulkDecision(decision: string) {
    if (!expandedId || selectedIds.size === 0) return;
    try {
      const res = await fetch(withConnection(`/api/access-reviews/${expandedId}/reviews/bulk`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ review_ids: Array.from(selectedIds), decision }),
      });
      if (!res.ok) throw new Error(`Error: ${res.status}`);
      const data = await res.json();
      addToast(`${decision}: ${data.updated_count} reviews`, 'success');
      setSelectedIds(new Set());
      loadReviews(expandedId, reviewPage);
      loadCampaigns();
      loadMetrics();
    } catch {
      addToast('Bulk action failed', 'error');
    }
  }

  async function handleStatusChange(campaignId: number, newStatus: string) {
    try {
      const res = await fetch(withConnection(`/api/access-reviews/${campaignId}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `Error: ${res.status}`);
      }
      addToast(`Campaign ${newStatus}`, 'success');
      loadCampaigns();
      loadMetrics();
      if (expandedId === campaignId) { setExpandedId(null); setReviews([]); }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to update';
      addToast(msg, 'error');
    }
  }

  async function handleDelete(campaignId: number) {
    if (!window.confirm('Delete this archived campaign?')) return;
    try {
      const res = await fetch(withConnection(`/api/access-reviews/${campaignId}`), { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `Error: ${res.status}`);
      }
      addToast('Campaign deleted', 'success');
      loadCampaigns();
      loadMetrics();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to delete';
      addToast(msg, 'error');
    }
  }

  function toggleSort(col: string) {
    setReviewSort(prev =>
      prev.col === col ? { col, dir: prev.dir === 'asc' ? 'desc' : 'asc' } : { col, dir: 'desc' }
    );
  }

  function toggleCheckbox(scope: 'risk' | 'category', value: string) {
    if (scope === 'risk') {
      setFormRiskLevels(prev => prev.includes(value) ? prev.filter(v => v !== value) : [...prev, value]);
    } else {
      setFormCategories(prev => prev.includes(value) ? prev.filter(v => v !== value) : [...prev, value]);
    }
  }

  const pendingReviews = reviews.filter(r => !r.decision);
  function toggleSelectAll() {
    if (selectedIds.size === pendingReviews.length && pendingReviews.length > 0) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(pendingReviews.map(r => r.id)));
    }
  }

  function daysUntil(deadline: string | null): string {
    if (!deadline) return '';
    const diff = Math.ceil((new Date(deadline).getTime() - Date.now()) / 86400000);
    if (diff < 0) return 'Overdue';
    if (diff === 0) return 'Due today';
    return `${diff}d left`;
  }

  function riskColor(level: string): string {
    return AR.severity[level?.toLowerCase()] || 'rgba(255,255,255,0.3)';
  }

  function usageDot(days: number | null): { color: string; label: string } {
    if (days === null || days === undefined) return { color: 'rgba(255,255,255,0.2)', label: 'Unknown' };
    if (days <= 7) return { color: '#4ADE80', label: `${days}d ago` };
    if (days <= 30) return { color: '#FFB300', label: `${days}d ago` };
    if (days <= 90) return { color: '#FF6D00', label: `${days}d ago` };
    return { color: '#FF1744', label: `${days}d ago` };
  }

  const totalPages = Math.ceil(reviewsTotal / PAGE_SIZE);

  /* ---- Render ---- */

  const FILTER_OPTIONS = [
    { value: '', label: 'All' },
    { value: 'active', label: 'Active' },
    { value: 'completed', label: 'Completed' },
    { value: 'archived', label: 'Archived' },
  ];

  return (
    <div style={{ background: AR.bg, color: AR.text, fontFamily: "'Inter', sans-serif" }}
         className="min-h-screen -m-4 -mt-4 p-8">
      <style>{`
        @keyframes ar-fade-up { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        .ar-card { animation: ar-fade-up 0.4s ease-out both; }
        .ar-card:nth-child(1) { animation-delay: 0s; }
        .ar-card:nth-child(2) { animation-delay: 0.05s; }
        .ar-card:nth-child(3) { animation-delay: 0.1s; }
        .ar-card:nth-child(4) { animation-delay: 0.15s; }
        .ar-card:nth-child(5) { animation-delay: 0.2s; }
        .ar-card:nth-child(6) { animation-delay: 0.25s; }
        .ar-row:hover { background: rgba(255,255,255,0.03) !important; }
        .ar-pill { transition: all 0.15s ease; cursor: pointer; }
        .ar-pill:hover { filter: brightness(1.2); }
      `}</style>

      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 32 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 4 }}>
            <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: 2, color: AR.accent,
                           background: 'rgba(139,92,246,0.1)', padding: '4px 10px', borderRadius: 4,
                           fontFamily: AR.mono, textTransform: 'uppercase' }}>
              ACCESS GOVERNANCE
            </span>
          </div>
          <h1 style={{ fontSize: 28, fontWeight: 700, margin: '8px 0 4px', letterSpacing: -0.5 }}>
            Access Review Campaigns
          </h1>
          <p style={{ color: AR.textMuted, fontSize: 13 }}>
            Risk-aware access certification with AI-powered recommendations
          </p>
          <SnapshotContextHeader />
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowModal(true)}
            style={{ background: AR.accent, color: '#fff', border: 'none', padding: '10px 20px',
                     borderRadius: 8, fontSize: 13, fontWeight: 600, cursor: 'pointer',
                     transition: 'all 0.2s ease' }}
            onMouseEnter={e => (e.currentTarget.style.filter = 'brightness(1.2)')}
            onMouseLeave={e => (e.currentTarget.style.filter = 'none')}
          >
            + New Campaign
          </button>
        )}
      </div>

      {/* Metrics Cards */}
      {metrics && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 16, marginBottom: 28 }}>
          {[
            { label: 'Active Campaigns', value: metrics.active_count, color: '#4ADE80', to: '/access-reviews?status=active' },
            { label: 'Overdue', value: metrics.overdue_count, color: metrics.overdue_count > 0 ? '#FF1744' : AR.textMuted, to: '/access-reviews?status=overdue' },
            { label: 'Completion Rate', value: `${metrics.completion_rate}%`, color: '#60A5FA', to: '' },
            { label: 'High Risk Pending', value: metrics.high_risk_pending, color: '#FF6D00', to: '/identities?risk_level=high' },
            { label: 'Revocation Rate', value: `${metrics.revocation_rate}%`, color: '#FF1744', to: '' },
            { label: 'NHI Coverage', value: `${metrics.nhi_percentage}%`, color: '#A78BFA', to: '/workload-identities' },
          ].map((card, i) => (
            <div key={i} className="ar-card" style={{
              background: AR.surface, border: `1px solid ${AR.surfaceBorder}`, borderRadius: 12,
              padding: '20px 16px', textAlign: 'center',
              cursor: card.to ? 'pointer' : 'default',
            }}
            onClick={card.to ? () => navigate(card.to) : undefined}
            >
              <div style={{ fontSize: 10, fontWeight: 600, letterSpacing: 1.5, color: AR.textMuted,
                            textTransform: 'uppercase', marginBottom: 8, fontFamily: AR.mono }}>
                {card.label}
              </div>
              <div style={{
                fontSize: 28, fontWeight: 700, color: card.color, fontFamily: AR.mono,
                ...(card.to ? { borderBottom: '1px dashed currentColor', display: 'inline-block' } : {}),
              }}>
                {card.value}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Campaign Status Filter */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 20 }}>
        {FILTER_OPTIONS.map(opt => (
          <button
            key={opt.value}
            onClick={() => setStatusFilter(opt.value)}
            className="ar-pill"
            style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, border: 'none',
              background: statusFilter === opt.value ? AR.accent : AR.surface,
              color: statusFilter === opt.value ? '#fff' : AR.textSecondary,
              outline: statusFilter === opt.value ? 'none' : `1px solid ${AR.surfaceBorder}`,
            }}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {/* Loading */}
      {loading && campaigns.length === 0 && !loadError && (
        <div style={{ textAlign: 'center', padding: 60, color: AR.textMuted }}>Loading campaigns...</div>
      )}

      {/* Error State */}
      {!loading && loadError && (
        <div style={{ background: AR.surface, border: '1px solid rgba(220,38,38,0.3)', borderRadius: 12,
                      padding: 60, textAlign: 'center' }}>
          <div style={{ fontSize: 14, color: '#dc2626', fontWeight: 600, marginBottom: 8 }}>Unable to load campaigns</div>
          <div style={{ color: AR.textMuted, fontSize: 13, marginBottom: 16 }}>{loadError}</div>
          <button onClick={loadCampaigns} style={{
            padding: '8px 20px', borderRadius: 8, border: `1px solid ${AR.surfaceBorder}`,
            background: AR.surface, color: AR.text, fontSize: 13, cursor: 'pointer',
          }}>Retry</button>
        </div>
      )}

      {/* Empty State */}
      {!loading && !loadError && campaigns.length === 0 && (
        <div style={{ background: AR.surface, border: `1px solid ${AR.surfaceBorder}`, borderRadius: 12,
                      padding: 60, textAlign: 'center' }}>
          <div style={{ fontSize: 40, marginBottom: 12 }}>&#128203;</div>
          <div style={{ fontWeight: 600, marginBottom: 4 }}>No access review campaigns</div>
          <div style={{ color: AR.textMuted, fontSize: 13 }}>Create a campaign to start reviewing identity access</div>
        </div>
      )}

      {/* Campaign Cards */}
      {campaigns.map(c => {
        const pct = c.total_reviews > 0 ? Math.round((c.completed_reviews / c.total_reviews) * 100) : 0;
        const pending = c.total_reviews - c.completed_reviews;
        const expanded = expandedId === c.id;
        const deadlineStr = daysUntil(c.deadline);
        const overdue = deadlineStr === 'Overdue';
        const typeLabel = CAMPAIGN_TYPE_LABELS[c.campaign_type] || c.campaign_type;

        return (
          <div key={c.id} className="ar-card" style={{
            background: AR.surface, border: `1px solid ${expanded ? AR.accent + '40' : AR.surfaceBorder}`,
            borderRadius: 12, marginBottom: 12, overflow: 'hidden',
            transition: 'border-color 0.2s ease',
          }}>
            {/* Campaign Header */}
            <div
              style={{ padding: '16px 20px', cursor: 'pointer', transition: 'background 0.15s ease' }}
              onClick={() => toggleExpand(c.id)}
              onMouseEnter={e => (e.currentTarget.style.background = AR.surfaceHover)}
              onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={AR.textMuted}
                       strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
                       style={{ transform: expanded ? 'rotate(90deg)' : 'none', transition: 'transform 0.2s ease' }}>
                    <path d="M9 5l7 7-7 7" />
                  </svg>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                      <span style={{ fontWeight: 600, fontSize: 15 }}>{c.name}</span>
                      <span style={{
                        padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                        textTransform: 'uppercase', fontFamily: AR.mono,
                        background: c.status === 'active' ? 'rgba(74,222,128,0.12)' :
                                    c.status === 'completed' ? 'rgba(96,165,250,0.12)' : 'rgba(255,255,255,0.06)',
                        color: c.status === 'active' ? '#4ADE80' :
                               c.status === 'completed' ? '#60A5FA' : AR.textMuted,
                      }}>{c.status}</span>
                      <span style={{
                        padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                        background: 'rgba(139,92,246,0.1)', color: '#A78BFA',
                      }}>{typeLabel}</span>
                      {deadlineStr && (
                        <span style={{ fontSize: 11, color: overdue ? '#FF1744' : AR.textMuted, fontWeight: overdue ? 600 : 400 }}>
                          {deadlineStr}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: 11, color: AR.textMuted, marginTop: 2 }}>
                      by {c.creator_name} &middot; {new Date(c.created_at).toLocaleDateString()}
                      {c.description && <span> &mdash; {c.description}</span>}
                    </div>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
                  <div style={{ display: 'flex', gap: 12, fontSize: 11, fontFamily: AR.mono }}>
                    <span style={{ color: '#4ADE80' }}>{c.approved_count} approved</span>
                    <span style={{ color: '#FF1744' }}>{c.revoked_count} revoked</span>
                    <span style={{ color: '#FFB300' }}>{c.flagged_count} flagged</span>
                    <span style={{ color: AR.textMuted }}>{pending} pending</span>
                  </div>

                  {isAdmin && c.status === 'active' && (
                    <button onClick={e => { e.stopPropagation(); handleStatusChange(c.id, 'completed'); }}
                      style={{ padding: '4px 12px', fontSize: 11, fontWeight: 600, borderRadius: 6, border: 'none',
                               background: 'rgba(96,165,250,0.12)', color: '#60A5FA', cursor: 'pointer' }}>
                      Complete
                    </button>
                  )}
                  {isAdmin && c.status === 'completed' && (
                    <button onClick={e => { e.stopPropagation(); handleStatusChange(c.id, 'archived'); }}
                      style={{ padding: '4px 12px', fontSize: 11, fontWeight: 600, borderRadius: 6, border: 'none',
                               background: AR.surface, color: AR.textMuted, cursor: 'pointer',
                               outline: `1px solid ${AR.surfaceBorder}` }}>
                      Archive
                    </button>
                  )}
                  {isAdmin && c.status === 'archived' && (
                    <button onClick={e => { e.stopPropagation(); handleDelete(c.id); }}
                      style={{ padding: '4px 12px', fontSize: 11, fontWeight: 600, borderRadius: 6, border: 'none',
                               background: 'rgba(255,23,68,0.1)', color: '#FF1744', cursor: 'pointer' }}>
                      Delete
                    </button>
                  )}
                </div>
              </div>

              {/* Progress Bar */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 12 }}>
                <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,0.06)', borderRadius: 2 }}>
                  <div style={{
                    height: 4, borderRadius: 2, transition: 'width 0.6s ease-out',
                    width: `${pct}%`,
                    background: pct === 100 ? '#4ADE80' : AR.accent,
                  }} />
                </div>
                <span style={{ fontSize: 11, color: AR.textMuted, fontFamily: AR.mono, minWidth: 50, textAlign: 'right' }}>
                  {pct}%
                </span>
              </div>
            </div>

            {/* Expanded Reviews */}
            {expanded && (
              <div style={{ borderTop: `1px solid ${AR.surfaceBorder}`, padding: '16px 20px' }}>
                {/* Review Filters */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                  <input
                    type="text"
                    placeholder="Search identities..."
                    value={reviewSearch}
                    onChange={e => setReviewSearch(e.target.value)}
                    style={{ padding: '6px 12px', fontSize: 12, borderRadius: 6, border: 'none',
                             background: 'rgba(255,255,255,0.06)', color: AR.text, outline: 'none',
                             width: 200 }}
                  />
                  <select value={reviewStatus} onChange={e => setReviewStatus(e.target.value)}
                    style={{ padding: '6px 10px', fontSize: 11, borderRadius: 6, border: 'none',
                             background: 'rgba(255,255,255,0.06)', color: AR.textSecondary, cursor: 'pointer' }}>
                    <option value="">All Status</option>
                    <option value="pending">Pending</option>
                    <option value="decided">Decided</option>
                    <option value="approve">Approved</option>
                    <option value="revoke">Revoked</option>
                    <option value="flag">Flagged</option>
                  </select>
                  <select value={reviewRisk} onChange={e => setReviewRisk(e.target.value)}
                    style={{ padding: '6px 10px', fontSize: 11, borderRadius: 6, border: 'none',
                             background: 'rgba(255,255,255,0.06)', color: AR.textSecondary, cursor: 'pointer' }}>
                    <option value="">All Risk</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select value={reviewType} onChange={e => setReviewType(e.target.value)}
                    style={{ padding: '6px 10px', fontSize: 11, borderRadius: 6, border: 'none',
                             background: 'rgba(255,255,255,0.06)', color: AR.textSecondary, cursor: 'pointer' }}>
                    <option value="">All Types</option>
                    <option value="human">Human</option>
                    <option value="service_principal">Service Principal</option>
                    <option value="managed_identity">Managed Identity</option>
                  </select>
                  <span style={{ fontSize: 11, color: AR.textMuted, fontFamily: AR.mono, marginLeft: 'auto' }}>
                    {reviewsTotal} identities
                  </span>
                </div>

                {/* Bulk Actions */}
                {selectedIds.size > 0 && c.status === 'active' && (
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, padding: '10px 14px',
                    background: 'rgba(139,92,246,0.08)', borderRadius: 8, border: `1px solid rgba(139,92,246,0.2)`,
                  }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: '#A78BFA', fontFamily: AR.mono }}>
                      {selectedIds.size} selected
                    </span>
                    {ALL_DECISIONS.map(d => (
                      <button key={d.key} onClick={() => handleBulkDecision(d.key)}
                        style={{ padding: '4px 10px', fontSize: 10, fontWeight: 600, borderRadius: 4, border: 'none',
                                 background: `${d.color}18`, color: d.color, cursor: 'pointer' }}>
                        {d.label}
                      </button>
                    ))}
                  </div>
                )}

                {reviewsLoading ? (
                  <div style={{ textAlign: 'center', padding: 40, color: AR.textMuted }}>Loading reviews...</div>
                ) : reviews.length === 0 ? (
                  <div style={{ textAlign: 'center', padding: 40, color: AR.textMuted, fontSize: 13 }}>
                    No identities match the current filters
                  </div>
                ) : (
                  <div style={{ display: 'flex', gap: 0 }}>
                    {/* Review Table */}
                    <div style={{ flex: 1, overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                        <thead>
                          <tr style={{ borderBottom: `1px solid ${AR.surfaceBorder}` }}>
                            {c.status === 'active' && (
                              <th style={{ padding: '8px 6px', width: 32 }}>
                                <input type="checkbox"
                                  checked={pendingReviews.length > 0 && selectedIds.size === pendingReviews.length}
                                  onChange={toggleSelectAll}
                                  style={{ accentColor: AR.accent }}
                                />
                              </th>
                            )}
                            {[
                              { key: 'identity_display_name', label: 'Identity' },
                              { key: 'risk_score', label: 'Risk Score' },
                              { key: 'identity_risk_level', label: 'Risk Level' },
                              { key: 'privilege_level', label: 'Privilege' },
                              { key: 'ai_recommendation', label: 'AI Rec.' },
                              { key: 'access_role', label: 'Role' },
                              { key: 'last_used_days', label: 'Last Used' },
                              { key: 'credential_risk_level', label: 'Cred Risk' },
                              { key: 'decision', label: 'Decision' },
                            ].map(col => (
                              <th key={col.key}
                                onClick={() => toggleSort(col.key)}
                                style={{
                                  padding: '8px 8px', textAlign: 'left', color: AR.textMuted, fontWeight: 600,
                                  fontSize: 10, letterSpacing: 0.5, textTransform: 'uppercase', cursor: 'pointer',
                                  fontFamily: AR.mono, userSelect: 'none', whiteSpace: 'nowrap',
                                }}>
                                {col.label}
                                {reviewSort.col === col.key && (
                                  <span style={{ marginLeft: 4 }}>{reviewSort.dir === 'asc' ? '\u25B2' : '\u25BC'}</span>
                                )}
                              </th>
                            ))}
                            {c.status === 'active' && (
                              <th style={{ padding: '8px 8px', textAlign: 'right', color: AR.textMuted,
                                           fontWeight: 600, fontSize: 10, fontFamily: AR.mono, letterSpacing: 0.5 }}>
                                ACTIONS
                              </th>
                            )}
                          </tr>
                        </thead>
                        <tbody>
                          {reviews.map(r => {
                            const dec = r.decision ? AR.decision[r.decision] : null;
                            const isPending = !r.decision;
                            const aiStyle = r.ai_recommendation ? AR.ai[r.ai_recommendation] : null;
                            const usage = usageDot(r.last_used_days);
                            const privColor = PRIVILEGE_COLORS[r.privilege_level || ''] || AR.textMuted;
                            const credColor = CRED_RISK_COLORS[r.credential_risk_level || 'none'] || AR.textMuted;
                            const isSelected = panelReview?.id === r.id;

                            return (
                              <tr key={r.id} className="ar-row"
                                  style={{
                                    borderBottom: `1px solid ${AR.surfaceBorder}`,
                                    background: isSelected ? 'rgba(139,92,246,0.06)' : 'transparent',
                                    cursor: 'pointer', transition: 'background 0.15s ease',
                                  }}
                                  onClick={() => setPanelReview(r)}>
                                {c.status === 'active' && (
                                  <td style={{ padding: '8px 6px' }} onClick={e => e.stopPropagation()}>
                                    {isPending && (
                                      <input type="checkbox"
                                        checked={selectedIds.has(r.id)}
                                        onChange={() => {
                                          const next = new Set(selectedIds);
                                          if (next.has(r.id)) next.delete(r.id); else next.add(r.id);
                                          setSelectedIds(next);
                                        }}
                                        style={{ accentColor: AR.accent }}
                                      />
                                    )}
                                  </td>
                                )}

                                {/* Identity */}
                                <td style={{ padding: '8px 8px', maxWidth: 200 }}>
                                  <div style={{ fontWeight: 500, fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {r.identity_display_name || r.identity_id}
                                  </div>
                                  <div style={{ fontSize: 10, color: AR.textMuted }}>
                                    {CATEGORY_LABELS[r.identity_category] || r.identity_type || ''}
                                    {r.cloud_provider && (
                                      <span style={{ marginLeft: 6, color: AR.cloud[r.cloud_provider] || AR.textMuted }}>
                                        {r.cloud_provider}
                                      </span>
                                    )}
                                  </div>
                                </td>

                                {/* Risk Score */}
                                <td style={{ padding: '8px 8px', fontFamily: AR.mono, fontWeight: 700 }}>
                                  <span style={{
                                    color: (r.risk_score || 0) >= 70 ? '#FF1744' :
                                           (r.risk_score || 0) >= 40 ? '#FF6D00' :
                                           (r.risk_score || 0) >= 20 ? '#FFB300' : '#4ADE80',
                                  }}>
                                    {r.risk_score ?? '-'}
                                  </span>
                                </td>

                                {/* Risk Level */}
                                <td style={{ padding: '8px 8px' }}>
                                  <span style={{
                                    padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                                    textTransform: 'uppercase', fontFamily: AR.mono,
                                    background: `${riskColor(r.identity_risk_level)}18`,
                                    color: riskColor(r.identity_risk_level),
                                  }}>
                                    {r.identity_risk_level || 'N/A'}
                                  </span>
                                </td>

                                {/* Privilege */}
                                <td style={{ padding: '8px 8px' }}>
                                  {r.privilege_level && (
                                    <span style={{
                                      padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                                      background: `${privColor}18`, color: privColor,
                                    }}>
                                      {r.privilege_level}
                                    </span>
                                  )}
                                </td>

                                {/* AI Recommendation */}
                                <td style={{ padding: '8px 8px' }}>
                                  {r.ai_recommendation && aiStyle && (
                                    <span style={{
                                      padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                                      background: aiStyle.bg, color: aiStyle.text,
                                      border: `1px solid ${aiStyle.border}`,
                                    }}>
                                      {r.ai_recommendation}
                                    </span>
                                  )}
                                </td>

                                {/* Role */}
                                <td style={{ padding: '8px 8px', fontSize: 11, color: AR.textSecondary,
                                             maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                  {r.access_role || '-'}
                                </td>

                                {/* Last Used */}
                                <td style={{ padding: '8px 8px' }}>
                                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                                    <span style={{
                                      width: 6, height: 6, borderRadius: '50%', background: usage.color,
                                      display: 'inline-block',
                                    }} />
                                    <span style={{ fontSize: 11, color: AR.textSecondary, fontFamily: AR.mono }}>
                                      {usage.label}
                                    </span>
                                  </span>
                                </td>

                                {/* Credential Risk */}
                                <td style={{ padding: '8px 8px' }}>
                                  {r.credential_risk_level && r.credential_risk_level !== 'none' ? (
                                    <span style={{
                                      padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                                      textTransform: 'uppercase',
                                      background: `${credColor}18`, color: credColor,
                                    }}>
                                      {r.credential_risk_level}
                                    </span>
                                  ) : (
                                    <span style={{ fontSize: 11, color: AR.textMuted }}>-</span>
                                  )}
                                </td>

                                {/* Decision */}
                                <td style={{ padding: '8px 8px' }}>
                                  {dec ? (
                                    <span style={{
                                      padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 700,
                                      background: dec.bg, color: dec.text,
                                    }}>
                                      {dec.label}
                                    </span>
                                  ) : (
                                    <span style={{ fontSize: 11, color: AR.textMuted }}>Pending</span>
                                  )}
                                </td>

                                {/* Actions */}
                                {c.status === 'active' && (
                                  <td style={{ padding: '8px 8px', textAlign: 'right' }} onClick={e => e.stopPropagation()}>
                                    {isPending && (
                                      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 4 }}>
                                        <button onClick={() => handleDecision(r.id, 'approve')}
                                          style={{ padding: '2px 8px', fontSize: 10, fontWeight: 600, borderRadius: 4,
                                                   border: 'none', background: 'rgba(74,222,128,0.12)', color: '#4ADE80',
                                                   cursor: 'pointer' }}>
                                          Approve
                                        </button>
                                        <button onClick={() => handleDecision(r.id, 'revoke')}
                                          style={{ padding: '2px 8px', fontSize: 10, fontWeight: 600, borderRadius: 4,
                                                   border: 'none', background: 'rgba(255,23,68,0.12)', color: '#FF1744',
                                                   cursor: 'pointer' }}>
                                          Revoke
                                        </button>
                                        <button onClick={() => handleDecision(r.id, 'flag')}
                                          style={{ padding: '2px 8px', fontSize: 10, fontWeight: 600, borderRadius: 4,
                                                   border: 'none', background: 'rgba(255,179,0,0.12)', color: '#FFB300',
                                                   cursor: 'pointer' }}>
                                          Flag
                                        </button>
                                      </div>
                                    )}
                                  </td>
                                )}
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>

                      {/* Pagination */}
                      {totalPages > 1 && (
                        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 8, marginTop: 16 }}>
                          <button
                            disabled={reviewPage === 0}
                            onClick={() => { const p = reviewPage - 1; setReviewPage(p); loadReviews(c.id, p); }}
                            style={{ padding: '4px 12px', fontSize: 11, borderRadius: 6, border: 'none',
                                     background: AR.surface, color: reviewPage === 0 ? AR.textMuted : AR.textSecondary,
                                     cursor: reviewPage === 0 ? 'not-allowed' : 'pointer',
                                     outline: `1px solid ${AR.surfaceBorder}`, opacity: reviewPage === 0 ? 0.5 : 1 }}>
                            Prev
                          </button>
                          <span style={{ fontSize: 11, color: AR.textMuted, fontFamily: AR.mono }}>
                            Page {reviewPage + 1} of {totalPages}
                          </span>
                          <button
                            disabled={reviewPage >= totalPages - 1}
                            onClick={() => { const p = reviewPage + 1; setReviewPage(p); loadReviews(c.id, p); }}
                            style={{ padding: '4px 12px', fontSize: 11, borderRadius: 6, border: 'none',
                                     background: AR.surface, color: reviewPage >= totalPages - 1 ? AR.textMuted : AR.textSecondary,
                                     cursor: reviewPage >= totalPages - 1 ? 'not-allowed' : 'pointer',
                                     outline: `1px solid ${AR.surfaceBorder}`, opacity: reviewPage >= totalPages - 1 ? 0.5 : 1 }}>
                            Next
                          </button>
                        </div>
                      )}
                    </div>

                    {/* Risk Intelligence Side Panel */}
                    {panelReview && (
                      <div style={{
                        width: 340, minWidth: 340, marginLeft: 16, padding: 20,
                        background: 'rgba(255,255,255,0.02)', border: `1px solid ${AR.surfaceBorder}`,
                        borderRadius: 12, overflowY: 'auto', maxHeight: 600,
                      }}>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                          <span style={{ fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1,
                                         color: AR.accent, fontFamily: AR.mono }}>
                            RISK INTELLIGENCE
                          </span>
                          <button onClick={() => setPanelReview(null)}
                            style={{ background: 'none', border: 'none', color: AR.textMuted, cursor: 'pointer', fontSize: 16 }}>
                            &times;
                          </button>
                        </div>

                        {/* Identity Info */}
                        <div style={{ marginBottom: 20 }}>
                          <div style={{ fontWeight: 600, fontSize: 14, marginBottom: 4 }}>
                            {panelReview.identity_display_name}
                          </div>
                          <div style={{ fontSize: 11, color: AR.textMuted, wordBreak: 'break-all' }}>
                            {panelReview.identity_id}
                          </div>
                          <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
                            <span style={{
                              padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                              background: `${riskColor(panelReview.identity_risk_level)}18`,
                              color: riskColor(panelReview.identity_risk_level),
                            }}>
                              {panelReview.identity_risk_level?.toUpperCase()}
                            </span>
                            {panelReview.privilege_level && (
                              <span style={{
                                padding: '2px 8px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                                background: `${PRIVILEGE_COLORS[panelReview.privilege_level] || AR.textMuted}18`,
                                color: PRIVILEGE_COLORS[panelReview.privilege_level] || AR.textMuted,
                              }}>
                                {panelReview.privilege_level}
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Risk Score Gauge */}
                        <div style={{
                          textAlign: 'center', padding: 20, marginBottom: 20,
                          background: 'rgba(255,255,255,0.02)', borderRadius: 8,
                          border: `1px solid ${AR.surfaceBorder}`,
                        }}>
                          <div style={{
                            fontSize: 36, fontWeight: 700, fontFamily: AR.mono,
                            color: (panelReview.risk_score || 0) >= 70 ? '#FF1744' :
                                   (panelReview.risk_score || 0) >= 40 ? '#FF6D00' : '#4ADE80',
                          }}>
                            {panelReview.risk_score ?? 0}
                          </div>
                          <div style={{ fontSize: 10, color: AR.textMuted, textTransform: 'uppercase', letterSpacing: 1,
                                       fontFamily: AR.mono }}>
                            REVIEW RISK SCORE
                          </div>
                        </div>

                        {/* AI Recommendation */}
                        {panelReview.ai_recommendation && (
                          <div style={{
                            marginBottom: 20, padding: 14, borderRadius: 8,
                            background: (AR.ai[panelReview.ai_recommendation]?.bg) || 'rgba(255,255,255,0.04)',
                            border: `1px solid ${AR.ai[panelReview.ai_recommendation]?.border || AR.surfaceBorder}`,
                          }}>
                            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1,
                                         color: AR.textMuted, fontFamily: AR.mono, marginBottom: 6 }}>
                              AI RECOMMENDATION
                            </div>
                            <div style={{
                              fontSize: 14, fontWeight: 700,
                              color: AR.ai[panelReview.ai_recommendation]?.text || AR.text,
                              marginBottom: 6,
                            }}>
                              {panelReview.ai_recommendation}
                            </div>
                            {panelReview.ai_recommendation_reason && (
                              <div style={{ fontSize: 11, color: AR.textSecondary, lineHeight: 1.5 }}>
                                {panelReview.ai_recommendation_reason}
                              </div>
                            )}
                          </div>
                        )}

                        {/* Risk Factors */}
                        {Array.isArray(panelReview.risk_factors) && panelReview.risk_factors.length > 0 && (
                          <div style={{ marginBottom: 20 }}>
                            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1,
                                         color: AR.textMuted, fontFamily: AR.mono, marginBottom: 8 }}>
                              RISK FACTORS
                            </div>
                            {panelReview.risk_factors.map((f, i) => (
                              <div key={i} style={{
                                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                                padding: '6px 0', borderBottom: `1px solid ${AR.surfaceBorder}`,
                              }}>
                                <div>
                                  <div style={{ fontSize: 12, color: AR.textSecondary }}>{f.factor}</div>
                                  {f.detail && <div style={{ fontSize: 10, color: AR.textMuted }}>{f.detail}</div>}
                                </div>
                                <span style={{
                                  fontFamily: AR.mono, fontWeight: 700, fontSize: 12,
                                  color: f.points > 0 ? '#FF6D00' : f.points < 0 ? '#4ADE80' : AR.textMuted,
                                }}>
                                  {f.points > 0 ? '+' : ''}{f.points}
                                </span>
                              </div>
                            ))}
                          </div>
                        )}

                        {/* Details */}
                        <div style={{ marginBottom: 16 }}>
                          <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1,
                                       color: AR.textMuted, fontFamily: AR.mono, marginBottom: 8 }}>
                            ACCESS DETAILS
                          </div>
                          {[
                            { label: 'Role', value: panelReview.access_role },
                            { label: 'Scope', value: panelReview.access_scope },
                            { label: 'Cloud', value: panelReview.cloud_provider },
                            { label: 'Credential Risk', value: panelReview.credential_risk },
                            { label: 'Last Activity', value: panelReview.last_used_days != null ? `${panelReview.last_used_days} days ago` : 'Unknown' },
                          ].map((item, i) => (
                            <div key={i} style={{
                              display: 'flex', justifyContent: 'space-between', padding: '5px 0',
                              borderBottom: `1px solid ${AR.surfaceBorder}`,
                            }}>
                              <span style={{ fontSize: 11, color: AR.textMuted }}>{item.label}</span>
                              <span style={{ fontSize: 11, color: AR.textSecondary, maxWidth: 180, textAlign: 'right',
                                             overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {item.value || '-'}
                              </span>
                            </div>
                          ))}
                        </div>

                        {/* Quick Decision Buttons */}
                        {c.status === 'active' && !panelReview.decision && (
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                            <div style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1,
                                         color: AR.textMuted, fontFamily: AR.mono, marginBottom: 4 }}>
                              QUICK DECISION
                            </div>
                            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
                              {ALL_DECISIONS.map(d => (
                                <button key={d.key} onClick={() => handleDecision(panelReview.id, d.key)}
                                  style={{ padding: '8px 12px', fontSize: 11, fontWeight: 600, borderRadius: 6,
                                           border: 'none', background: `${d.color}18`, color: d.color,
                                           cursor: 'pointer', transition: 'all 0.15s ease' }}
                                  onMouseEnter={e => (e.currentTarget.style.filter = 'brightness(1.3)')}
                                  onMouseLeave={e => (e.currentTarget.style.filter = 'none')}>
                                  {d.label}
                                </button>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Open Full Detail Link */}
                        <div style={{ marginTop: 16, textAlign: 'center' }}>
                          <a href={`/identities/${panelReview.identity_id}`}
                            style={{ fontSize: 11, color: AR.accent, textDecoration: 'none' }}>
                            Open Full Identity Detail &rarr;
                          </a>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        );
      })}

      {/* Create Campaign Modal */}
      {showModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 50, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)' }}
               onClick={() => setShowModal(false)} />
          <div style={{
            position: 'relative', background: '#111318', borderRadius: 16,
            border: `1px solid ${AR.surfaceBorder}`, width: '100%', maxWidth: 540,
            margin: '0 16px', padding: 28, maxHeight: '90vh', overflowY: 'auto',
          }}>
            <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 20 }}>New Access Review Campaign</div>

            {/* Name */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: AR.textSecondary, marginBottom: 6 }}>
                Campaign Name *
              </label>
              <input type="text" value={formName} onChange={e => setFormName(e.target.value)}
                placeholder="e.g. Q1 2026 Privileged Access Review"
                style={{ width: '100%', padding: '10px 14px', fontSize: 13, borderRadius: 8, border: 'none',
                         background: 'rgba(255,255,255,0.06)', color: AR.text, outline: 'none',
                         boxSizing: 'border-box' }}
              />
            </div>

            {/* Campaign Type */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: AR.textSecondary, marginBottom: 6 }}>
                Campaign Type
              </label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {Object.entries(CAMPAIGN_TYPE_LABELS).map(([key, label]) => (
                  <button key={key} onClick={() => setFormType(key)}
                    className="ar-pill"
                    style={{
                      padding: '6px 12px', fontSize: 11, fontWeight: 600, borderRadius: 6, border: 'none',
                      background: formType === key ? AR.accent : 'rgba(255,255,255,0.06)',
                      color: formType === key ? '#fff' : AR.textSecondary,
                    }}>
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Description */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: AR.textSecondary, marginBottom: 6 }}>
                Description
              </label>
              <textarea value={formDesc} onChange={e => setFormDesc(e.target.value)} rows={2}
                style={{ width: '100%', padding: '10px 14px', fontSize: 13, borderRadius: 8, border: 'none',
                         background: 'rgba(255,255,255,0.06)', color: AR.text, outline: 'none', resize: 'vertical',
                         boxSizing: 'border-box' }}
              />
            </div>

            {/* Deadline */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: AR.textSecondary, marginBottom: 6 }}>
                Deadline
              </label>
              <input type="date" value={formDeadline} onChange={e => setFormDeadline(e.target.value)}
                style={{ width: '100%', padding: '10px 14px', fontSize: 13, borderRadius: 8, border: 'none',
                         background: 'rgba(255,255,255,0.06)', color: AR.text, outline: 'none',
                         boxSizing: 'border-box', colorScheme: 'dark' }}
              />
            </div>

            {/* Risk Levels */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: AR.textSecondary, marginBottom: 8 }}>
                Risk Levels
              </label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {['critical', 'high', 'medium', 'low', 'info'].map(level => {
                  const active = formRiskLevels.includes(level);
                  const color = AR.severity[level] || AR.textMuted;
                  return (
                    <button key={level} onClick={() => toggleCheckbox('risk', level)}
                      style={{
                        padding: '4px 12px', fontSize: 11, fontWeight: 700, borderRadius: 4, border: 'none',
                        textTransform: 'uppercase', cursor: 'pointer',
                        background: active ? `${color}30` : 'rgba(255,255,255,0.04)',
                        color: active ? color : AR.textMuted,
                        outline: active ? `1px solid ${color}60` : `1px solid ${AR.surfaceBorder}`,
                      }}>
                      {level}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Identity Categories */}
            <div style={{ marginBottom: 24 }}>
              <label style={{ display: 'block', fontSize: 12, fontWeight: 600, color: AR.textSecondary, marginBottom: 8 }}>
                Identity Categories
              </label>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {Object.entries(CATEGORY_LABELS).map(([key, label]) => {
                  const active = formCategories.includes(key);
                  return (
                    <button key={key} onClick={() => toggleCheckbox('category', key)}
                      style={{
                        padding: '4px 12px', fontSize: 11, fontWeight: 600, borderRadius: 4, border: 'none',
                        cursor: 'pointer',
                        background: active ? 'rgba(139,92,246,0.15)' : 'rgba(255,255,255,0.04)',
                        color: active ? '#A78BFA' : AR.textMuted,
                        outline: active ? '1px solid rgba(139,92,246,0.3)' : `1px solid ${AR.surfaceBorder}`,
                      }}>
                      {label}
                    </button>
                  );
                })}
              </div>
            </div>

            {/* Modal Actions */}
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 12 }}>
              <button onClick={() => setShowModal(false)}
                style={{ padding: '10px 20px', fontSize: 13, color: AR.textMuted, background: 'none',
                         border: 'none', cursor: 'pointer' }}>
                Cancel
              </button>
              <button onClick={handleCreate}
                disabled={creating || !formName.trim() || (formRiskLevels.length === 0 && formCategories.length === 0)}
                style={{
                  padding: '10px 24px', fontSize: 13, fontWeight: 600, borderRadius: 8, border: 'none',
                  background: AR.accent, color: '#fff', cursor: 'pointer',
                  opacity: (creating || !formName.trim() || (formRiskLevels.length === 0 && formCategories.length === 0)) ? 0.5 : 1,
                }}>
                {creating ? 'Creating...' : 'Create Campaign'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
