import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';

// ── Types ──────────────────────────────────────────────────────

interface Notification {
  id: number;
  event_type: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  payload: Record<string, unknown> | null;
  related_identity_id: string | null;
  related_identity_name: string | null;
  related_run_id: number | null;
  read: boolean;
  read_at: string | null;
  actioned: boolean;
  action_type: string | null;
  action_at: string | null;
  created_at: string;
}

interface NotificationStats {
  total: number;
  unread: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
}

// ── Config ─────────────────────────────────────────────────────

const SEVERITY_CONFIG: Record<string, { label: string; color: string; bg: string; border: string }> = {
  critical: { label: 'Critical', color: 'text-red-700', bg: 'bg-red-50', border: 'border-red-200' },
  high:     { label: 'High', color: 'text-orange-700', bg: 'bg-orange-50', border: 'border-orange-200' },
  medium:   { label: 'Medium', color: 'text-yellow-700', bg: 'bg-yellow-50', border: 'border-yellow-200' },
  low:      { label: 'Low', color: 'text-blue-700', bg: 'bg-blue-50', border: 'border-blue-200' },
  info:     { label: 'Info', color: 'text-gray-600', bg: 'bg-gray-50', border: 'border-gray-200' },
};

const CATEGORY_CONFIG: Record<string, { label: string; color: string; icon: string }> = {
  risk_escalation:    { label: 'Risk Escalation', color: 'text-red-600', icon: '!' },
  new_identity:       { label: 'New Identity', color: 'text-green-600', icon: '+' },
  removal:            { label: 'Removal', color: 'text-gray-600', icon: '-' },
  permission_change:  { label: 'Permission Change', color: 'text-orange-600', icon: '~' },
  credential_expiring:{ label: 'Credential', color: 'text-yellow-600', icon: 'K' },
  drift_detected:     { label: 'Drift', color: 'text-purple-600', icon: 'D' },
  discovery_completed:{ label: 'Discovery', color: 'text-blue-600', icon: 'S' },
};

function getSeverityConfig(severity: string) {
  return SEVERITY_CONFIG[severity] || SEVERITY_CONFIG.info;
}

function getCategoryConfig(category: string) {
  return CATEGORY_CONFIG[category] || { label: category, color: 'text-gray-600', icon: '?' };
}

function timeAgo(dateStr: string): string {
  const now = new Date();
  const date = new Date(dateStr);
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000);
  if (seconds < 60) return 'Just now';
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`;
  return date.toLocaleDateString();
}

// ── Component ──────────────────────────────────────────────────

export default function NotificationCenter() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [stats, setStats] = useState<NotificationStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [offset, setOffset] = useState(0);
  const [hasMore, setHasMore] = useState(true);

  // Filters
  const [severityFilter, setSeverityFilter] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string | null>(null);
  const [readFilter, setReadFilter] = useState<string>('all'); // 'all' | 'unread' | 'read'

  const LIMIT = 50;

  const loadStats = useCallback(async () => {
    try {
      const res = await fetch(withConnection('/api/notifications/stats'));
      if (res.ok) setStats(await res.json());
    } catch { /* ignore */ }
  }, [withConnection]);

  const loadNotifications = useCallback(async (reset = false) => {
    const newOffset = reset ? 0 : offset;
    setLoading(true);
    try {
      const params = new URLSearchParams({ limit: String(LIMIT), offset: String(newOffset) });
      if (severityFilter) params.set('severity', severityFilter);
      if (categoryFilter) params.set('category', categoryFilter);
      if (readFilter === 'unread') params.set('read', 'false');
      else if (readFilter === 'read') params.set('read', 'true');

      const res = await fetch(withConnection(`/api/notifications?${params}`));
      if (res.ok) {
        const data = await res.json();
        const items = data.notifications || [];
        if (reset) {
          setNotifications(items);
          setOffset(items.length);
        } else {
          setNotifications(prev => [...prev, ...items]);
          setOffset(newOffset + items.length);
        }
        setHasMore(items.length === LIMIT);
      }
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, [offset, severityFilter, categoryFilter, readFilter, withConnection]);

  useEffect(() => {
    loadStats();
    loadNotifications(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [severityFilter, categoryFilter, readFilter, selectedConnectionId]);

  async function handleMarkRead(id: number) {
    try {
      await fetch(withConnection(`/api/notifications/${id}`), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ read: true }),
      });
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true } : n));
      loadStats();
    } catch { /* ignore */ }
  }

  async function handleDismiss(id: number) {
    try {
      await fetch(withConnection(`/api/notifications/${id}`), {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action_type: 'dismiss' }),
      });
      setNotifications(prev => prev.map(n => n.id === id ? { ...n, read: true, actioned: true, action_type: 'dismiss' } : n));
      loadStats();
    } catch { /* ignore */ }
  }

  async function handleMarkAllRead() {
    try {
      await fetch(withConnection('/api/notifications/mark-all-read'), { method: 'POST' });
      setNotifications(prev => prev.map(n => ({ ...n, read: true })));
      loadStats();
    } catch { /* ignore */ }
  }

  async function handleDelete(id: number) {
    try {
      await fetch(withConnection(`/api/notifications/${id}`), { method: 'DELETE' });
      setNotifications(prev => prev.filter(n => n.id !== id));
      loadStats();
    } catch { /* ignore */ }
  }

  const severityButtons = ['critical', 'high', 'medium', 'low', 'info'] as const;
  const categoryButtons = Object.keys(CATEGORY_CONFIG);

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h2 className="text-2xl font-bold text-gray-900">Notifications</h2>
          {!!stats && stats.unread > 0 && (
            <span className="bg-red-500 text-white text-xs font-bold rounded-full px-2 py-0.5">
              {stats.unread} unread
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {!!stats && stats.unread > 0 && (
            <button
              onClick={handleMarkAllRead}
              className="px-4 py-2 text-sm font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded-lg transition"
            >
              Mark All Read
            </button>
          )}
        </div>
      </div>

      {/* Severity filter */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-gray-500 mr-1">Severity:</span>
        <button
          onClick={() => setSeverityFilter(null)}
          className={`px-3 py-1 rounded-full text-xs font-medium transition ${
            !severityFilter ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
          }`}
        >
          All
        </button>
        {severityButtons.map(sev => {
          const cfg = getSeverityConfig(sev);
          const count = stats?.by_severity?.[sev] || 0;
          return (
            <button
              key={sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition ${
                severityFilter === sev ? `${cfg.bg} ${cfg.color} ring-1 ring-current` : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {cfg.label}{count > 0 ? ` (${count})` : ''}
            </button>
          );
        })}

        <span className="mx-2 text-gray-300">|</span>

        {/* Read status */}
        <span className="text-xs font-medium text-gray-500 mr-1">Status:</span>
        {(['all', 'unread', 'read'] as const).map(r => (
          <button
            key={r}
            onClick={() => setReadFilter(r)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition capitalize ${
              readFilter === r ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}
          >
            {r}
          </button>
        ))}
      </div>

      {/* Category filter */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs font-medium text-gray-500 mr-1">Category:</span>
        <button
          onClick={() => setCategoryFilter(null)}
          className={`px-3 py-1 rounded-full text-xs font-medium transition ${
            !categoryFilter ? 'bg-gray-900 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
          }`}
        >
          All
        </button>
        {categoryButtons.map(cat => {
          const cfg = getCategoryConfig(cat);
          return (
            <button
              key={cat}
              onClick={() => setCategoryFilter(categoryFilter === cat ? null : cat)}
              className={`px-3 py-1 rounded-full text-xs font-medium transition ${
                categoryFilter === cat ? 'bg-gray-800 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
              }`}
            >
              {cfg.label}
            </button>
          );
        })}
      </div>

      {/* Notification list */}
      {!loading && notifications.length === 0 ? (
        <div className="text-center py-16">
          <svg className="w-16 h-16 mx-auto text-gray-300 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
          </svg>
          <h3 className="text-lg font-semibold text-gray-500">No notifications</h3>
          <p className="text-sm text-gray-400 mt-1">
            Alerts will appear here after discovery runs detect changes.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {notifications.map(n => {
            const sevCfg = getSeverityConfig(n.severity);
            const catCfg = getCategoryConfig(n.category);
            return (
              <div
                key={n.id}
                className={`bg-white rounded-lg border ${n.read ? 'border-gray-100' : sevCfg.border} p-4 transition hover:shadow-sm ${
                  !n.read ? 'bg-blue-50/30' : ''
                }`}
              >
                <div className="flex items-start gap-3">
                  {/* Unread indicator */}
                  <div className="flex-shrink-0 mt-1.5">
                    {!n.read ? (
                      <span className="block w-2.5 h-2.5 rounded-full bg-blue-500" />
                    ) : (
                      <span className="block w-2.5 h-2.5 rounded-full bg-transparent" />
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      {/* Severity badge */}
                      <span className={`px-1.5 py-0.5 text-[10px] font-semibold rounded ${sevCfg.bg} ${sevCfg.color}`}>
                        {sevCfg.label.toUpperCase()}
                      </span>

                      {/* Category badge */}
                      <span className={`text-[10px] font-medium ${catCfg.color}`}>
                        {catCfg.icon} {catCfg.label}
                      </span>

                      {/* Time */}
                      <span className="text-[10px] text-gray-400 ml-auto" title={n.created_at ? new Date(n.created_at).toLocaleString() : ''}>
                        {n.created_at ? timeAgo(n.created_at) : ''}
                      </span>
                    </div>

                    {/* Title */}
                    <div className={`text-sm font-medium ${n.read ? 'text-gray-600' : 'text-gray-900'}`}>
                      {n.title}
                    </div>

                    {/* Description */}
                    <div className="text-xs text-gray-500 mt-0.5">
                      {n.description}
                    </div>

                    {/* Actions */}
                    <div className="flex items-center gap-2 mt-2">
                      {!!n.related_identity_id && (
                        <button
                          onClick={() => navigate(`/identities/${n.related_identity_id}`)}
                          className="px-2 py-1 text-xs font-medium text-blue-600 bg-blue-50 hover:bg-blue-100 rounded transition"
                        >
                          View Identity
                        </button>
                      )}
                      {!n.read && (
                        <button
                          onClick={() => handleMarkRead(n.id)}
                          className="px-2 py-1 text-xs font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded transition"
                        >
                          Mark Read
                        </button>
                      )}
                      {!n.actioned && (
                        <button
                          onClick={() => handleDismiss(n.id)}
                          className="px-2 py-1 text-xs font-medium text-gray-500 hover:bg-gray-100 rounded transition"
                        >
                          Dismiss
                        </button>
                      )}
                      <button
                        onClick={() => handleDelete(n.id)}
                        className="px-2 py-1 text-xs font-medium text-red-500 hover:bg-red-50 rounded transition ml-auto"
                      >
                        Delete
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Load more */}
      {hasMore && notifications.length > 0 && (
        <div className="text-center">
          <button
            onClick={() => loadNotifications(false)}
            disabled={loading}
            className="px-6 py-2 text-sm font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
          >
            {loading ? 'Loading...' : 'Load More'}
          </button>
        </div>
      )}

      {/* Loading skeleton */}
      {loading && notifications.length === 0 && (
        <div className="space-y-3">
          {[1, 2, 3, 4, 5].map(i => (
            <div key={i} className="bg-gray-50 rounded-lg p-4 animate-pulse">
              <div className="flex items-center gap-3">
                <div className="w-2.5 h-2.5 rounded-full bg-gray-200" />
                <div className="flex-1 space-y-2">
                  <div className="h-3 bg-gray-200 rounded w-1/3" />
                  <div className="h-4 bg-gray-200 rounded w-2/3" />
                  <div className="h-3 bg-gray-200 rounded w-1/2" />
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
