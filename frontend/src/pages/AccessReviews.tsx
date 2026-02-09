import React, { useState, useEffect, useCallback } from 'react';
import { useToast } from '../components/ToastProvider';
import { useAuth } from '../contexts/AuthContext';

interface Campaign {
  id: number;
  name: string;
  description: string | null;
  status: 'active' | 'completed' | 'archived';
  scope_filters: { risk_levels?: string[]; identity_categories?: string[]; identity_ids?: string[] };
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
  reviewer_name: string | null;
  decision: 'approve' | 'revoke' | 'flag' | null;
  notes: string | null;
  decided_at: string | null;
  created_at: string;
}

const RISK_COLORS: Record<string, string> = {
  critical: 'text-red-600 bg-red-50',
  high: 'text-orange-600 bg-orange-50',
  medium: 'text-yellow-700 bg-yellow-50',
  low: 'text-blue-600 bg-blue-50',
  info: 'text-gray-500 bg-gray-50',
};

const STATUS_COLORS: Record<string, string> = {
  active: 'text-green-700 bg-green-50 border-green-200',
  completed: 'text-blue-700 bg-blue-50 border-blue-200',
  archived: 'text-gray-600 bg-gray-50 border-gray-200',
};

const DECISION_CONFIG: Record<string, { label: string; bg: string; text: string }> = {
  approve: { label: 'Approved', bg: 'bg-green-50', text: 'text-green-700' },
  revoke: { label: 'Revoked', bg: 'bg-red-50', text: 'text-red-700' },
  flag: { label: 'Flagged', bg: 'bg-yellow-50', text: 'text-yellow-700' },
};

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System Managed Identity',
  managed_identity_user: 'User Managed Identity',
  human_user: 'Human User',
  guest: 'Guest',
  microsoft_internal: 'Microsoft Internal',
};

export default function AccessReviews() {
  const { addToast } = useToast();
  const { user } = useAuth();
  const isAdmin = user?.role === 'admin';

  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [statusFilter, setStatusFilter] = useState<string>('');

  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [reviews, setReviews] = useState<ReviewItem[]>([]);
  const [reviewsLoading, setReviewsLoading] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());

  const [showModal, setShowModal] = useState(false);
  const [formName, setFormName] = useState('');
  const [formDesc, setFormDesc] = useState('');
  const [formDeadline, setFormDeadline] = useState('');
  const [formRiskLevels, setFormRiskLevels] = useState<string[]>([]);
  const [formCategories, setFormCategories] = useState<string[]>([]);
  const [creating, setCreating] = useState(false);

  const loadCampaigns = useCallback(async () => {
    setLoading(true);
    try {
      const url = statusFilter ? `/api/access-reviews?status=${statusFilter}` : '/api/access-reviews';
      const res = await fetch(url);
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setCampaigns(data.campaigns || []);
    } catch {
      addToast('Failed to load campaigns', 'error');
    } finally {
      setLoading(false);
    }
  }, [statusFilter, addToast]);

  useEffect(() => { loadCampaigns(); }, [loadCampaigns]);

  const loadReviews = useCallback(async (campaignId: number) => {
    setReviewsLoading(true);
    try {
      const res = await fetch(`/api/access-reviews/${campaignId}`);
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setReviews(data.reviews || []);
    } catch {
      addToast('Failed to load reviews', 'error');
    } finally {
      setReviewsLoading(false);
    }
  }, [addToast]);

  function toggleExpand(id: number) {
    if (expandedId === id) {
      setExpandedId(null);
      setReviews([]);
      setSelectedIds(new Set());
    } else {
      setExpandedId(id);
      setSelectedIds(new Set());
      loadReviews(id);
    }
  }

  async function handleCreate() {
    if (!formName.trim()) return;
    const hasScope = formRiskLevels.length > 0 || formCategories.length > 0;
    if (!hasScope) {
      addToast('Select at least one risk level or identity category', 'error');
      return;
    }
    setCreating(true);
    try {
      const res = await fetch('/api/access-reviews', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: formName.trim(),
          description: formDesc.trim(),
          deadline: formDeadline || null,
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
      setFormRiskLevels([]); setFormCategories([]);
      loadCampaigns();
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
      const res = await fetch(`/api/access-reviews/${expandedId}/reviews/${reviewId}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ decision }),
      });
      if (!res.ok) throw new Error(`Error: ${res.status}`);
      loadReviews(expandedId);
      loadCampaigns();
    } catch {
      addToast('Failed to set decision', 'error');
    }
  }

  async function handleBulkDecision(decision: string) {
    if (!expandedId || selectedIds.size === 0) return;
    try {
      const res = await fetch(`/api/access-reviews/${expandedId}/reviews/bulk`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ review_ids: Array.from(selectedIds), decision }),
      });
      if (!res.ok) throw new Error(`Error: ${res.status}`);
      const data = await res.json();
      addToast(`${decision}: ${data.updated_count} reviews`, 'success');
      setSelectedIds(new Set());
      loadReviews(expandedId);
      loadCampaigns();
    } catch {
      addToast('Bulk action failed', 'error');
    }
  }

  async function handleStatusChange(campaignId: number, newStatus: string) {
    try {
      const res = await fetch(`/api/access-reviews/${campaignId}`, {
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
      if (expandedId === campaignId) { setExpandedId(null); setReviews([]); }
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to update';
      addToast(msg, 'error');
    }
  }

  async function handleDelete(campaignId: number) {
    if (!window.confirm('Delete this archived campaign?')) return;
    try {
      const res = await fetch(`/api/access-reviews/${campaignId}`, { method: 'DELETE' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.error || `Error: ${res.status}`);
      }
      addToast('Campaign deleted', 'success');
      loadCampaigns();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to delete';
      addToast(msg, 'error');
    }
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
    if (selectedIds.size === pendingReviews.length) {
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

  const FILTER_OPTIONS = [
    { value: '', label: 'All' },
    { value: 'active', label: 'Active' },
    { value: 'completed', label: 'Completed' },
    { value: 'archived', label: 'Archived' },
  ];

  if (loading && campaigns.length === 0) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-72" />
          <div className="h-12 bg-gray-100 rounded-xl" />
          <div className="h-48 bg-gray-100 rounded-xl" />
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Access Review Campaigns</h2>
          <p className="text-sm text-gray-600 mt-1">Periodic access certification for compliance and least-privilege enforcement</p>
        </div>
        {isAdmin && (
          <button
            onClick={() => setShowModal(true)}
            className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 transition"
          >
            + New Campaign
          </button>
        )}
      </div>

      {/* Status Filter */}
      <div className="flex items-center gap-2 bg-white border rounded-xl px-6 py-4">
        {FILTER_OPTIONS.map(opt => (
          <button
            key={opt.value}
            onClick={() => setStatusFilter(opt.value)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
              statusFilter === opt.value
                ? 'bg-blue-600 text-white'
                : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {/* Empty State */}
      {campaigns.length === 0 && !loading && (
        <div className="bg-white border rounded-xl p-12 text-center">
          <svg className="w-12 h-12 text-gray-300 mx-auto mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4" />
          </svg>
          <div className="text-gray-500 font-medium">No access review campaigns</div>
          <div className="text-sm text-gray-400 mt-1">Create a campaign to start reviewing identity access</div>
        </div>
      )}

      {/* Campaign Cards */}
      {campaigns.map(c => {
        const pct = c.total_reviews > 0 ? Math.round((c.completed_reviews / c.total_reviews) * 100) : 0;
        const pending = c.total_reviews - c.completed_reviews;
        const expanded = expandedId === c.id;
        const deadlineStr = daysUntil(c.deadline);
        const overdue = deadlineStr === 'Overdue';

        return (
          <div key={c.id} className="bg-white border rounded-xl shadow-sm overflow-hidden">
            {/* Campaign Header */}
            <div
              className={`px-6 py-4 cursor-pointer transition hover:bg-gray-50 ${expanded ? 'bg-blue-50/50' : ''}`}
              onClick={() => toggleExpand(c.id)}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <svg className={`w-4 h-4 text-gray-400 transition-transform ${expanded ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-gray-900">{c.name}</span>
                      <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase border ${STATUS_COLORS[c.status] || ''}`}>
                        {c.status}
                      </span>
                      {deadlineStr && (
                        <span className={`text-xs ${overdue ? 'text-red-600 font-semibold' : 'text-gray-500'}`}>
                          {deadlineStr}
                        </span>
                      )}
                    </div>
                    <div className="text-xs text-gray-500 mt-0.5">
                      Created by {c.creator_name} on {new Date(c.created_at).toLocaleDateString()}
                      {c.description && <span className="ml-2 text-gray-400">— {c.description}</span>}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-4">
                  {/* Stats */}
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-green-600 font-medium">{c.approved_count} approved</span>
                    <span className="text-red-600 font-medium">{c.revoked_count} revoked</span>
                    <span className="text-yellow-600 font-medium">{c.flagged_count} flagged</span>
                    <span className="text-gray-500">{pending} pending</span>
                  </div>

                  {/* Actions */}
                  {isAdmin && c.status === 'active' && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleStatusChange(c.id, 'completed'); }}
                      className="px-3 py-1 text-xs font-medium text-blue-700 bg-blue-50 rounded-lg hover:bg-blue-100 transition"
                    >
                      Complete
                    </button>
                  )}
                  {isAdmin && c.status === 'completed' && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleStatusChange(c.id, 'archived'); }}
                      className="px-3 py-1 text-xs font-medium text-gray-600 bg-gray-100 rounded-lg hover:bg-gray-200 transition"
                    >
                      Archive
                    </button>
                  )}
                  {isAdmin && c.status === 'archived' && (
                    <button
                      onClick={(e) => { e.stopPropagation(); handleDelete(c.id); }}
                      className="px-3 py-1 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100 transition"
                    >
                      Delete
                    </button>
                  )}
                </div>
              </div>

              {/* Progress Bar */}
              <div className="mt-3 flex items-center gap-3">
                <div className="flex-1 bg-gray-200 rounded-full h-2">
                  <div
                    className="bg-blue-600 h-2 rounded-full transition-all"
                    style={{ width: `${pct}%` }}
                  />
                </div>
                <span className="text-xs text-gray-500 font-medium w-16 text-right">{pct}% done</span>
              </div>
            </div>

            {/* Expanded Reviews */}
            {expanded && (
              <div className="border-t px-6 py-4 bg-gray-50/50">
                {reviewsLoading ? (
                  <div className="animate-pulse space-y-3">
                    <div className="h-8 bg-gray-200 rounded w-full" />
                    <div className="h-8 bg-gray-200 rounded w-full" />
                    <div className="h-8 bg-gray-200 rounded w-full" />
                  </div>
                ) : reviews.length === 0 ? (
                  <div className="text-sm text-gray-500 text-center py-4">No identities in this campaign</div>
                ) : (
                  <>
                    {/* Bulk Actions */}
                    {selectedIds.size > 0 && c.status === 'active' && (
                      <div className="flex items-center gap-2 mb-3 p-3 bg-blue-50 border border-blue-200 rounded-lg">
                        <span className="text-xs font-medium text-blue-700">{selectedIds.size} selected</span>
                        <button onClick={() => handleBulkDecision('approve')} className="px-2 py-1 text-xs font-medium text-green-700 bg-green-100 rounded hover:bg-green-200 transition">Approve</button>
                        <button onClick={() => handleBulkDecision('revoke')} className="px-2 py-1 text-xs font-medium text-red-700 bg-red-100 rounded hover:bg-red-200 transition">Revoke</button>
                        <button onClick={() => handleBulkDecision('flag')} className="px-2 py-1 text-xs font-medium text-yellow-700 bg-yellow-100 rounded hover:bg-yellow-200 transition">Flag</button>
                      </div>
                    )}

                    {/* Review Table */}
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b text-left">
                          {c.status === 'active' && (
                            <th className="px-3 py-2 w-8">
                              <input
                                type="checkbox"
                                checked={pendingReviews.length > 0 && selectedIds.size === pendingReviews.length}
                                onChange={toggleSelectAll}
                                className="rounded border-gray-300"
                              />
                            </th>
                          )}
                          <th className="px-3 py-2 font-medium text-gray-600">Identity</th>
                          <th className="px-3 py-2 font-medium text-gray-600">Risk</th>
                          <th className="px-3 py-2 font-medium text-gray-600">Category</th>
                          <th className="px-3 py-2 font-medium text-gray-600">Decision</th>
                          <th className="px-3 py-2 font-medium text-gray-600">Notes</th>
                          {c.status === 'active' && <th className="px-3 py-2 font-medium text-gray-600 text-right">Actions</th>}
                        </tr>
                      </thead>
                      <tbody>
                        {reviews.map(r => {
                          const riskColors = RISK_COLORS[r.identity_risk_level?.toLowerCase()] || 'text-gray-500 bg-gray-50';
                          const dec = r.decision ? DECISION_CONFIG[r.decision] : null;
                          const isPending = !r.decision;

                          return (
                            <tr key={r.id} className="border-b last:border-b-0 hover:bg-white transition">
                              {c.status === 'active' && (
                                <td className="px-3 py-2">
                                  {isPending && (
                                    <input
                                      type="checkbox"
                                      checked={selectedIds.has(r.id)}
                                      onChange={() => {
                                        const next = new Set(selectedIds);
                                        if (next.has(r.id)) next.delete(r.id);
                                        else next.add(r.id);
                                        setSelectedIds(next);
                                      }}
                                      className="rounded border-gray-300"
                                    />
                                  )}
                                </td>
                              )}
                              <td className="px-3 py-2">
                                <a href={`/identities/${r.identity_id}`} className="text-blue-600 hover:underline font-medium">
                                  {r.identity_display_name || r.identity_id}
                                </a>
                              </td>
                              <td className="px-3 py-2">
                                <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold uppercase ${riskColors}`}>
                                  {r.identity_risk_level || 'unknown'}
                                </span>
                              </td>
                              <td className="px-3 py-2 text-gray-600 text-xs">
                                {CATEGORY_LABELS[r.identity_category] || r.identity_category || '-'}
                              </td>
                              <td className="px-3 py-2">
                                {dec ? (
                                  <span className={`px-2 py-0.5 rounded-full text-[10px] font-semibold ${dec.bg} ${dec.text}`}>
                                    {dec.label}
                                  </span>
                                ) : (
                                  <span className="text-gray-400 text-xs">Pending</span>
                                )}
                              </td>
                              <td className="px-3 py-2 text-gray-500 text-xs max-w-[200px] truncate">
                                {r.notes || '-'}
                              </td>
                              {c.status === 'active' && (
                                <td className="px-3 py-2 text-right">
                                  {isPending && (
                                    <div className="flex items-center justify-end gap-1">
                                      <button onClick={() => handleDecision(r.id, 'approve')} className="px-2 py-0.5 text-[10px] font-medium text-green-700 bg-green-50 rounded hover:bg-green-100 transition">Approve</button>
                                      <button onClick={() => handleDecision(r.id, 'revoke')} className="px-2 py-0.5 text-[10px] font-medium text-red-700 bg-red-50 rounded hover:bg-red-100 transition">Revoke</button>
                                      <button onClick={() => handleDecision(r.id, 'flag')} className="px-2 py-0.5 text-[10px] font-medium text-yellow-700 bg-yellow-50 rounded hover:bg-yellow-100 transition">Flag</button>
                                    </div>
                                  )}
                                </td>
                              )}
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </>
                )}
              </div>
            )}
          </div>
        );
      })}

      {/* Create Campaign Modal */}
      {showModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center">
          <div className="fixed inset-0 bg-black/40" onClick={() => setShowModal(false)} />
          <div className="relative bg-white rounded-xl shadow-2xl border w-full max-w-lg mx-4 p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="text-lg font-semibold text-gray-900">New Access Review Campaign</div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Campaign Name *</label>
              <input
                type="text"
                value={formName}
                onChange={e => setFormName(e.target.value)}
                placeholder="e.g. Q1 2026 High-Risk Review"
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Description</label>
              <textarea
                value={formDesc}
                onChange={e => setFormDesc(e.target.value)}
                rows={2}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Deadline</label>
              <input
                type="date"
                value={formDeadline}
                onChange={e => setFormDeadline(e.target.value)}
                className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Risk Levels</label>
              <div className="flex flex-wrap gap-2">
                {['critical', 'high', 'medium', 'low', 'info'].map(level => (
                  <label key={level} className="flex items-center gap-1.5 text-xs">
                    <input
                      type="checkbox"
                      checked={formRiskLevels.includes(level)}
                      onChange={() => toggleCheckbox('risk', level)}
                      className="rounded border-gray-300"
                    />
                    <span className={`px-2 py-0.5 rounded-full font-semibold uppercase ${RISK_COLORS[level]}`}>{level}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Identity Categories</label>
              <div className="flex flex-wrap gap-2">
                {Object.entries(CATEGORY_LABELS).map(([key, label]) => (
                  <label key={key} className="flex items-center gap-1.5 text-xs">
                    <input
                      type="checkbox"
                      checked={formCategories.includes(key)}
                      onChange={() => toggleCheckbox('category', key)}
                      className="rounded border-gray-300"
                    />
                    <span className="text-gray-700">{label}</span>
                  </label>
                ))}
              </div>
            </div>

            <div className="flex items-center justify-end gap-3 pt-2">
              <button
                onClick={() => setShowModal(false)}
                className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800 transition"
              >
                Cancel
              </button>
              <button
                onClick={handleCreate}
                disabled={creating || !formName.trim() || (formRiskLevels.length === 0 && formCategories.length === 0)}
                className="px-4 py-2 bg-blue-600 text-white text-sm font-medium rounded-lg hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition"
              >
                {creating ? 'Creating...' : 'Create Campaign'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
