import React, { useEffect, useState, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';

interface SAGovStats {
  total: number;
  compliant: number;
  needs_attention: number;
  non_compliant: number;
  unowned: number;
  dormant: number;
  credential_expired: number;
  credential_expiring: number;
  attestation_overdue: number;
  compliance_rate: number;
}

interface SAGovItem {
  identity_id: string;
  identity_db_id: number;
  display_name: string;
  identity_category: string;
  governance_status: string;
  governance_issues: string[];
  owner_display_name: string | null;
  owner_count: number;
  credential_risk: string | null;
  credential_count: number;
  attestation_status: string;
  attestation_date: string | null;
  next_attestation_due: string | null;
  attester_name: string | null;
  risk_level: string;
  risk_score: number;
  activity_status: string;
  last_sign_in: string | null;
  created_datetime: string | null;
}

const FILTER_CHIPS = [
  { key: 'all', label: 'All' },
  { key: 'unowned', label: 'Unowned' },
  { key: 'needs_attestation', label: 'Needs Attestation' },
  { key: 'credential_issues', label: 'Credential Issues' },
  { key: 'dormant', label: 'Dormant' },
];

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MI',
  managed_identity_user: 'User MI',
};

const GOV_STATUS_STYLES: Record<string, string> = {
  compliant: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400',
  needs_attention: 'bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400',
  non_compliant: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400',
};

const RISK_STYLES: Record<string, string> = {
  critical: 'bg-red-100 text-red-700',
  high: 'bg-orange-100 text-orange-700',
  medium: 'bg-yellow-100 text-yellow-700',
  low: 'bg-blue-100 text-blue-700',
  info: 'bg-gray-100 text-gray-600',
};

const CRED_STYLES: Record<string, string> = {
  expired: 'bg-red-100 text-red-700',
  expiring_soon: 'bg-yellow-100 text-yellow-700',
  healthy: 'bg-green-100 text-green-700',
  unknown: 'bg-gray-100 text-gray-500',
};

type SortField = 'display_name' | 'risk_score' | 'owner_count' | 'activity_status' | 'credential_risk' | 'last_sign_in';

export default function ServiceAccountGovernance() {
  const { isAdmin, isReader } = useAuth();
  const canAttest = isAdmin || isReader;

  const [stats, setStats] = useState<SAGovStats | null>(null);
  const [items, setItems] = useState<SAGovItem[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [activeFilter, setActiveFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [sortBy, setSortBy] = useState<SortField>('risk_score');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc');
  const [page, setPage] = useState(0);
  const pageSize = 50;

  // Attestation modal
  const [attestTarget, setAttestTarget] = useState<SAGovItem | null>(null);
  const [attestStatus, setAttestStatus] = useState('approved');
  const [attestJustification, setAttestJustification] = useState('');
  const [attestSubmitting, setAttestSubmitting] = useState(false);
  const [toast, setToast] = useState<{ msg: string; type: string } | null>(null);

  const loadData = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams({
        filter: activeFilter,
        search,
        sort_by: sortBy,
        sort_dir: sortDir,
        limit: String(pageSize),
        offset: String(page * pageSize),
      });
      const [statsRes, listRes] = await Promise.all([
        fetch('/api/service-accounts/stats'),
        fetch(`/api/service-accounts/governance?${params}`),
      ]);
      if (statsRes.ok) {
        const sd = await statsRes.json();
        setStats(sd);
      }
      if (listRes.ok) {
        const ld = await listRes.json();
        setItems(ld.items || []);
        setTotal(ld.total || 0);
      }
    } catch { /* ignore */ }
    setLoading(false);
  }, [activeFilter, search, sortBy, sortDir, page]);

  useEffect(() => { loadData(); }, [loadData]);

  function handleSort(field: SortField) {
    if (sortBy === field) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(field);
      setSortDir('desc');
    }
    setPage(0);
  }

  function sortArrow(field: SortField) {
    if (sortBy !== field) return '';
    return sortDir === 'asc' ? ' \u2191' : ' \u2193';
  }

  async function handleAttest() {
    if (!attestTarget || !attestJustification.trim()) return;
    setAttestSubmitting(true);
    try {
      const res = await fetch(`/api/service-accounts/${attestTarget.identity_id}/attest`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: attestStatus, justification: attestJustification }),
      });
      if (res.ok) {
        setToast({ msg: `Attestation recorded for ${attestTarget.display_name}`, type: 'success' });
        setAttestTarget(null);
        setAttestStatus('approved');
        setAttestJustification('');
        loadData();
      } else {
        const d = await res.json().catch(() => ({}));
        setToast({ msg: d.error || 'Attestation failed', type: 'error' });
      }
    } catch {
      setToast({ msg: 'Network error', type: 'error' });
    }
    setAttestSubmitting(false);
  }

  useEffect(() => {
    if (toast) {
      const t = setTimeout(() => setToast(null), 4000);
      return () => clearTimeout(t);
    }
  }, [toast]);

  function fmtDate(d: string | null) {
    if (!d) return '-';
    return new Date(d).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function attLabel(status: string) {
    if (status === 'never_attested') return 'Never';
    if (status === 'overdue') return 'Overdue';
    if (status === 'approved') return 'Approved';
    if (status === 'needs_review') return 'Needs Review';
    if (status === 'decommission_requested') return 'Decom.';
    return status;
  }

  const attStyles: Record<string, string> = {
    never_attested: 'bg-gray-100 text-gray-600',
    overdue: 'bg-red-100 text-red-700',
    approved: 'bg-green-100 text-green-700',
    needs_review: 'bg-yellow-100 text-yellow-700',
    decommission_requested: 'bg-purple-100 text-purple-700',
  };

  const totalPages = Math.ceil(total / pageSize);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Service Account Governance</h1>
        <p className="text-sm text-gray-500 dark:text-gray-400 mt-1">
          Governance policies, attestation tracking, and compliance status for non-human identities
        </p>
      </div>

      {/* Summary Cards */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 p-4">
            <div className="text-xs text-gray-500 dark:text-gray-400 font-medium">Total SAs</div>
            <div className="text-2xl font-bold text-gray-900 dark:text-white mt-1">{stats.total}</div>
            <div className="text-[10px] text-gray-400 mt-1">{stats.compliance_rate}% compliant</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-green-200 dark:border-green-800 p-4">
            <div className="text-xs text-green-600 dark:text-green-400 font-medium">Compliant</div>
            <div className="text-2xl font-bold text-green-700 dark:text-green-300 mt-1">{stats.compliant}</div>
            <div className="text-[10px] text-gray-400 mt-1">All checks pass</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-yellow-200 dark:border-yellow-800 p-4">
            <div className="text-xs text-yellow-600 dark:text-yellow-400 font-medium">Needs Attention</div>
            <div className="text-2xl font-bold text-yellow-700 dark:text-yellow-300 mt-1">{stats.needs_attention}</div>
            <div className="text-[10px] text-gray-400 mt-1">Minor issues</div>
          </div>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-red-200 dark:border-red-800 p-4">
            <div className="text-xs text-red-600 dark:text-red-400 font-medium">Non-Compliant</div>
            <div className="text-2xl font-bold text-red-700 dark:text-red-300 mt-1">{stats.non_compliant}</div>
            <div className="text-[10px] text-gray-400 mt-1">Critical issues</div>
          </div>
        </div>
      )}

      {/* Detail stats row */}
      {stats && stats.total > 0 && (
        <div className="flex flex-wrap gap-3 text-xs">
          <span className="px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">
            Unowned: <strong>{stats.unowned}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">
            Dormant: <strong>{stats.dormant}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">
            Cred Expired: <strong>{stats.credential_expired}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">
            Cred Expiring: <strong>{stats.credential_expiring}</strong>
          </span>
          <span className="px-2.5 py-1 rounded-full bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400">
            Attestation Overdue: <strong>{stats.attestation_overdue}</strong>
          </span>
        </div>
      )}

      {/* Filters + Search */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex gap-1">
          {FILTER_CHIPS.map(f => (
            <button
              key={f.key}
              onClick={() => { setActiveFilter(f.key); setPage(0); }}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition ${
                activeFilter === f.key
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-100 dark:bg-gray-800 text-gray-600 dark:text-gray-400 hover:bg-gray-200'
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <input
          type="text"
          placeholder="Search by name..."
          value={search}
          onChange={e => { setSearch(e.target.value); setPage(0); }}
          className="px-3 py-1.5 border border-gray-300 dark:border-gray-600 rounded-lg text-xs bg-white dark:bg-gray-700 text-gray-900 dark:text-white w-48"
        />
      </div>

      {/* Table */}
      <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-sm text-gray-400">Loading...</div>
        ) : items.length === 0 ? (
          <div className="p-12 text-center text-sm text-gray-400">
            No service accounts found{activeFilter !== 'all' ? ' matching this filter' : ''}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-gray-50 dark:bg-gray-900/50 border-b border-gray-200 dark:border-gray-700">
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400 cursor-pointer hover:text-blue-600"
                      onClick={() => handleSort('display_name')}>
                    Name{sortArrow('display_name')}
                  </th>
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400">Category</th>
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400">Governance</th>
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400 cursor-pointer hover:text-blue-600"
                      onClick={() => handleSort('owner_count')}>
                    Owner{sortArrow('owner_count')}
                  </th>
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400 cursor-pointer hover:text-blue-600"
                      onClick={() => handleSort('credential_risk')}>
                    Credentials{sortArrow('credential_risk')}
                  </th>
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400">Attestation</th>
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400 cursor-pointer hover:text-blue-600"
                      onClick={() => handleSort('risk_score')}>
                    Risk{sortArrow('risk_score')}
                  </th>
                  <th className="text-left px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400 cursor-pointer hover:text-blue-600"
                      onClick={() => handleSort('last_sign_in')}>
                    Last Active{sortArrow('last_sign_in')}
                  </th>
                  {canAttest && (
                    <th className="text-center px-3 py-2.5 font-semibold text-gray-600 dark:text-gray-400">Action</th>
                  )}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100 dark:divide-gray-700/50">
                {items.map(item => (
                  <tr key={item.identity_id} className="hover:bg-gray-50 dark:hover:bg-gray-700/30 transition">
                    <td className="px-3 py-2.5">
                      <Link to={`/identities/${item.identity_id}`}
                            className="text-blue-600 hover:underline font-medium truncate block max-w-[200px]"
                            title={item.display_name}>
                        {item.display_name}
                      </Link>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="px-1.5 py-0.5 rounded text-[10px] font-medium bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-400">
                        {CATEGORY_LABELS[item.identity_category] || item.identity_category}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${GOV_STATUS_STYLES[item.governance_status] || 'bg-gray-100 text-gray-600'}`}>
                        {item.governance_status === 'non_compliant' ? 'Non-Compliant' :
                         item.governance_status === 'needs_attention' ? 'Attention' : 'Compliant'}
                      </span>
                      {item.governance_issues.length > 0 && (
                        <div className="text-[9px] text-gray-400 mt-0.5">
                          {item.governance_issues.map(i => i.replace(/_/g, ' ')).join(', ')}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      {item.owner_count > 0 ? (
                        <span className="text-gray-700 dark:text-gray-300">{item.owner_display_name || `${item.owner_count} owner(s)`}</span>
                      ) : (
                        <span className="text-red-600 font-medium">None</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${CRED_STYLES[item.credential_risk || ''] || CRED_STYLES.unknown}`}>
                        {item.credential_risk || 'N/A'}
                      </span>
                      {item.credential_count > 0 && (
                        <span className="text-[9px] text-gray-400 ml-1">({item.credential_count})</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${attStyles[item.attestation_status] || attStyles.never_attested}`}>
                        {attLabel(item.attestation_status)}
                      </span>
                      {item.attestation_date && (
                        <div className="text-[9px] text-gray-400 mt-0.5">{fmtDate(item.attestation_date)}</div>
                      )}
                    </td>
                    <td className="px-3 py-2.5">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${RISK_STYLES[item.risk_level] || 'bg-gray-100 text-gray-500'}`}>
                        {item.risk_level || 'info'}
                      </span>
                      <span className="text-[9px] text-gray-400 ml-1">{item.risk_score}</span>
                    </td>
                    <td className="px-3 py-2.5 text-gray-500 dark:text-gray-400">
                      {fmtDate(item.last_sign_in)}
                    </td>
                    {canAttest && (
                      <td className="px-3 py-2.5 text-center">
                        <button
                          onClick={() => { setAttestTarget(item); setAttestStatus('approved'); setAttestJustification(''); }}
                          className="px-2 py-1 rounded text-[10px] font-medium bg-blue-50 text-blue-600 hover:bg-blue-100 dark:bg-blue-900/30 dark:text-blue-400 transition"
                        >
                          Attest
                        </button>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-gray-200 dark:border-gray-700">
            <span className="text-xs text-gray-500">{total} total</span>
            <div className="flex gap-1">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                      className="px-2.5 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 disabled:opacity-40">
                Prev
              </button>
              <span className="px-2.5 py-1 text-xs text-gray-500">{page + 1}/{totalPages}</span>
              <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
                      className="px-2.5 py-1 rounded text-xs bg-gray-100 dark:bg-gray-700 disabled:opacity-40">
                Next
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Attestation Modal */}
      {attestTarget && (
        <div className="fixed inset-0 bg-black/40 flex items-center justify-center z-50" onClick={() => setAttestTarget(null)}>
          <div className="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 shadow-xl w-full max-w-md mx-4 p-6 space-y-4"
               onClick={e => e.stopPropagation()}>
            <div>
              <h3 className="text-sm font-bold text-gray-900 dark:text-white">Attest Service Account</h3>
              <p className="text-xs text-gray-500 mt-1">{attestTarget.display_name}</p>
            </div>

            <div className="space-y-2">
              <label className="block text-xs font-medium text-gray-700 dark:text-gray-300">Decision</label>
              {['approved', 'needs_review', 'decommission_requested'].map(opt => (
                <label key={opt} className="flex items-center gap-2 text-xs text-gray-700 dark:text-gray-300 cursor-pointer">
                  <input type="radio" name="att_status" value={opt}
                         checked={attestStatus === opt}
                         onChange={() => setAttestStatus(opt)}
                         className="text-blue-600" />
                  {opt === 'approved' ? 'Approved — Still needed' :
                   opt === 'needs_review' ? 'Needs Review — Uncertain' :
                   'Decommission Requested — Should be removed'}
                </label>
              ))}
            </div>

            <div>
              <label className="block text-xs font-medium text-gray-700 dark:text-gray-300 mb-1">Justification</label>
              <textarea
                value={attestJustification}
                onChange={e => setAttestJustification(e.target.value)}
                rows={3}
                placeholder="Why is this service account still needed?"
                className="w-full px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg text-xs bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>

            <div className="flex justify-end gap-2">
              <button onClick={() => setAttestTarget(null)}
                      className="px-4 py-2 rounded-lg text-xs text-gray-600 hover:bg-gray-100 dark:hover:bg-gray-700">
                Cancel
              </button>
              <button onClick={handleAttest}
                      disabled={attestSubmitting || !attestJustification.trim()}
                      className={`px-4 py-2 rounded-lg text-xs font-medium text-white transition ${
                        attestSubmitting || !attestJustification.trim()
                          ? 'bg-gray-400 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
                      }`}>
                {attestSubmitting ? 'Submitting...' : 'Submit Attestation'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Toast */}
      {toast && (
        <div className={`fixed bottom-6 right-6 z-50 px-4 py-2.5 rounded-lg shadow-lg text-xs font-medium ${
          toast.type === 'success' ? 'bg-green-600 text-white' : 'bg-red-600 text-white'
        }`}>
          {toast.msg}
        </div>
      )}
    </div>
  );
}
