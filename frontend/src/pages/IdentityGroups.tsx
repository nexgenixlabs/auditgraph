import React, { useState, useEffect, useCallback } from 'react';
import { Link } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { riskDisplay } from '../utils/riskDisplay';
import { useConnection } from '../contexts/ConnectionContext';

interface Group {
  id: number;
  name: string;
  description: string | null;
  color: string;
  group_type: 'custom' | 'auto';
  auto_criteria: Record<string, unknown> | null;
  member_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  avg_risk_score: number;
  creator_name: string | null;
  created_at: string;
  category_breakdown?: Record<string, number>;
}

interface GroupDetail extends Group {
  members: MemberRow[];
}

interface MemberRow {
  identity_id: string;
  display_name: string;
  identity_category: string;
  cloud: string;
  risk_level: string;
  risk_score: number;
  activity_status: string;
  last_seen_auth: string | null;
}

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-400',
  medium: 'bg-yellow-400',
  low: 'bg-blue-400',
  info: 'bg-gray-300',
};

const CATEGORY_LABELS: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'System MI',
  managed_identity_user: 'User MI',
  human_user: 'Human',
  guest: 'Guest',
  microsoft_internal: 'MS Internal',
};

const COLOR_PRESETS = ['#3B82F6', '#6366F1', '#8B5CF6', '#EC4899', '#F59E0B', '#10B981'];

export default function IdentityGroups() {
  const { user } = useAuth();
  const { withConnection, selectedConnectionId } = useConnection();
  const canEdit = user?.role === 'admin' || user?.role === 'reader';

  const [groups, setGroups] = useState<Group[]>([]);
  const [loading, setLoading] = useState(true);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [detail, setDetail] = useState<GroupDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [compareIds, setCompareIds] = useState<number[]>([]);
  const [compareData, setCompareData] = useState<Group[] | null>(null);
  const [compareLoading, setCompareLoading] = useState(false);

  // Add member modal
  const [showAddMember, setShowAddMember] = useState(false);
  const [searchIdentities, setSearchIdentities] = useState<MemberRow[]>([]);
  const [memberSearch, setMemberSearch] = useState('');
  const [memberSearchLoading, setMemberSearchLoading] = useState(false);

  const loadGroups = useCallback(async () => {
    setLoading(true);
    try {
      const res = await fetch(withConnection('/api/groups'));
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const json = await res.json();
      setGroups(json.groups || []);
    } catch {
      console.error('Failed to load groups');
    } finally {
      setLoading(false);
    }
  }, [withConnection]);

  useEffect(() => { loadGroups(); }, [loadGroups, selectedConnectionId]);

  const loadDetail = useCallback(async (id: number) => {
    setDetailLoading(true);
    try {
      const res = await fetch(withConnection(`/api/groups/${id}`));
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const json: GroupDetail = await res.json();
      setDetail(json);
    } catch {
      console.error('Failed to load group detail');
    } finally {
      setDetailLoading(false);
    }
  }, [withConnection]);

  const toggleExpand = (id: number) => {
    if (expandedId === id) {
      setExpandedId(null);
      setDetail(null);
    } else {
      setExpandedId(id);
      loadDetail(id);
    }
  };

  const toggleCompare = (id: number) => {
    setCompareIds(prev =>
      prev.includes(id) ? prev.filter(x => x !== id) : prev.length < 3 ? [...prev, id] : prev
    );
  };

  const runCompare = async () => {
    if (compareIds.length < 2) return;
    setCompareLoading(true);
    try {
      const res = await fetch(withConnection(`/api/groups/compare?ids=${compareIds.join(',')}`));
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const json = await res.json();
      setCompareData(json.groups || []);
    } catch {
      console.error('Failed to compare groups');
    } finally {
      setCompareLoading(false);
    }
  };

  const deleteGroup = async (id: number) => {
    if (!window.confirm('Delete this group?')) return;
    try {
      const res = await fetch(withConnection(`/api/groups/${id}`), { method: 'DELETE' });
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      setExpandedId(null);
      loadGroups();
    } catch {
      console.error('Failed to delete group');
    }
  };

  const removeMember = async (groupId: number, identityId: string) => {
    try {
      const res = await fetch(withConnection(`/api/groups/${groupId}/members`), {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_ids: [identityId] }),
      });
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      loadDetail(groupId);
      loadGroups();
    } catch {
      console.error('Failed to remove member');
    }
  };

  const searchForIdentities = async (term: string) => {
    if (!term || term.length < 2) { setSearchIdentities([]); return; }
    setMemberSearchLoading(true);
    try {
      const res = await fetch(withConnection(`/api/identities?search=${encodeURIComponent(term)}&limit=10`));
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const json = await res.json();
      setSearchIdentities((json.identities || []).map((i: Record<string, unknown>) => ({
        identity_id: i.identity_id as string,
        display_name: i.display_name as string,
        identity_category: (i.identity_category || '') as string,
        cloud: (i.cloud || 'azure') as string,
        risk_level: (i.risk_level || 'unknown') as string,
        risk_score: (i.risk_score || 0) as number,
        activity_status: (i.activity_status || '') as string,
        last_seen_auth: (i.last_seen_auth || null) as string | null,
      })));
    } catch {
      setSearchIdentities([]);
    } finally {
      setMemberSearchLoading(false);
    }
  };

  const addMember = async (identityId: string) => {
    if (!expandedId) return;
    try {
      const res = await fetch(withConnection(`/api/groups/${expandedId}/members`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identity_ids: [identityId] }),
      });
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      loadDetail(expandedId);
      loadGroups();
      setShowAddMember(false);
      setMemberSearch('');
      setSearchIdentities([]);
    } catch {
      console.error('Failed to add member');
    }
  };

  // Risk bar component
  const RiskBar = ({ g, width = 'w-full' }: { g: Group; width?: string }) => {
    const total = g.member_count || 1;
    return (
      <div className={`${width} h-2 rounded-full bg-gray-100 overflow-hidden flex`}>
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map(level => {
          const pct = (g[level] / total) * 100;
          return pct > 0 ? (
            <div key={level} className={`${RISK_COLORS[level]} h-full`} style={{ width: `${pct}%` }} />
          ) : null;
        })}
      </div>
    );
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-4">
          <div className="h-8 bg-gray-200 rounded w-48" />
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {[1, 2, 3, 4].map(i => <div key={i} className="h-40 bg-gray-100 rounded-xl" />)}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Identity Groups</h2>
          <p className="text-sm text-gray-600 mt-1">Organize identities by team, department, or application</p>
        </div>
        <div className="flex items-center gap-3">
          {compareIds.length >= 2 && (
            <button
              onClick={runCompare}
              disabled={compareLoading}
              className="px-4 py-2 text-sm font-medium text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 transition disabled:opacity-50"
            >
              {compareLoading ? 'Comparing...' : `Compare ${compareIds.length} Groups`}
            </button>
          )}
          {compareIds.length > 0 && (
            <button onClick={() => { setCompareIds([]); setCompareData(null); }} className="text-sm text-gray-500 hover:text-gray-700">
              Clear
            </button>
          )}
          {canEdit && (
            <button
              onClick={() => setShowCreate(true)}
              className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition"
            >
              + Create Group
            </button>
          )}
        </div>
      </div>

      {/* Comparison View */}
      {!!compareData && compareData.length >= 2 && (
        <div className="bg-white border rounded-xl p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-900">Group Comparison</h3>
            <button onClick={() => setCompareData(null)} className="text-xs text-gray-400 hover:text-gray-600">Close</button>
          </div>
          <div className={`grid gap-6 ${compareData.length === 2 ? 'grid-cols-2' : 'grid-cols-3'}`}>
            {compareData.map(g => (
              <div key={g.id} className="border rounded-xl p-4" style={{ borderLeftColor: g.color, borderLeftWidth: 4 }}>
                <div className="font-semibold text-gray-900 text-sm mb-3">{g.name}</div>
                <div className="space-y-3 text-xs">
                  <div className="flex justify-between"><span className="text-gray-500">Members</span><span className="font-bold text-gray-900">{g.member_count}</span></div>
                  <div className="flex justify-between"><span className="text-gray-500">Avg Risk Score</span><span className="font-bold text-gray-900">{/* CVSS-aligned 0-10 (2026-05-31 directive) */}{riskDisplay({ risk_score: g.avg_risk_score }) ?? '—'}</span></div>
                  <div>
                    <div className="text-gray-500 mb-1">Risk Distribution</div>
                    <RiskBar g={g} />
                    <div className="flex gap-2 mt-1 text-[10px]">
                      {g.critical > 0 && <span className="text-red-600">{g.critical} crit</span>}
                      {g.high > 0 && <span className="text-orange-600">{g.high} high</span>}
                      {g.medium > 0 && <span className="text-yellow-700">{g.medium} med</span>}
                      {g.low > 0 && <span className="text-blue-600">{g.low} low</span>}
                    </div>
                  </div>
                  {!!g.category_breakdown && (
                    <div>
                      <div className="text-gray-500 mb-1">Categories</div>
                      <div className="flex flex-wrap gap-1">
                        {Object.entries(g.category_breakdown).map(([cat, cnt]) => (
                          <span key={cat} className="px-1.5 py-0.5 bg-gray-100 rounded text-[10px] text-gray-600">
                            {CATEGORY_LABELS[cat] || cat}: {cnt}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Group Cards */}
      {groups.length === 0 ? (
        <div className="bg-white border rounded-xl p-12 text-center">
          <div className="text-gray-400 font-medium">No groups yet</div>
          <div className="text-sm text-gray-300 mt-1">Create a group to organize your identities</div>
        </div>
      ) : (
        <div className="space-y-3">
          {groups.map(g => (
            <div key={g.id}>
              <div
                className={`bg-white border rounded-xl overflow-hidden transition hover:shadow-sm ${expandedId === g.id ? 'ring-2 ring-blue-200' : ''}`}
                style={{ borderLeftColor: g.color, borderLeftWidth: 4 }}
              >
                <div className="px-5 py-4 flex items-center gap-4">
                  {/* Compare checkbox */}
                  <input
                    type="checkbox"
                    checked={compareIds.includes(g.id)}
                    onChange={() => toggleCompare(g.id)}
                    className="w-4 h-4 rounded border-gray-300 text-indigo-600 focus:ring-indigo-500"
                    title="Select for comparison"
                  />

                  {/* Name + description */}
                  <button className="flex-1 text-left min-w-0" onClick={() => toggleExpand(g.id)}>
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-gray-900 text-sm">{g.name}</span>
                      {g.group_type === 'auto' && (
                        <span className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-gray-100 text-gray-500 uppercase">Auto</span>
                      )}
                    </div>
                    {g.description && <div className="text-xs text-gray-500 mt-0.5 truncate">{g.description}</div>}
                  </button>

                  {/* Member count */}
                  <div className="text-center">
                    <div className="text-lg font-bold text-gray-900">{g.member_count}</div>
                    <div className="text-[10px] text-gray-400">members</div>
                  </div>

                  {/* Risk bar */}
                  <div className="w-32">
                    <RiskBar g={g} />
                    <div className="flex gap-1.5 mt-1 text-[10px]">
                      {g.critical > 0 && <span className="text-red-600 font-semibold">{g.critical}</span>}
                      {g.high > 0 && <span className="text-orange-500 font-semibold">{g.high}</span>}
                      {g.medium > 0 && <span className="text-yellow-600 font-semibold">{g.medium}</span>}
                    </div>
                  </div>

                  {/* Avg risk */}
                  <div className="text-right w-16">
                    <div className="text-sm font-bold text-gray-700">{/* CVSS-aligned 0-10 (2026-05-31 directive) */}{riskDisplay({ risk_score: g.avg_risk_score }) ?? '—'}</div>
                    <div className="text-[10px] text-gray-400">avg risk</div>
                  </div>

                  {/* Expand chevron */}
                  <svg className={`w-5 h-5 text-gray-400 transition-transform ${expandedId === g.id ? 'rotate-180' : ''}`}
                    fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </div>
              </div>

              {/* Expanded Detail */}
              {expandedId === g.id && (
                <div className="bg-white border border-t-0 rounded-b-xl px-5 py-4">
                  {detailLoading ? (
                    <div className="animate-pulse space-y-3">
                      <div className="h-4 bg-gray-200 rounded w-48" />
                      <div className="h-32 bg-gray-100 rounded" />
                    </div>
                  ) : detail ? (
                    <div className="space-y-4">
                      {/* Actions */}
                      <div className="flex items-center gap-3">
                        {canEdit && g.group_type === 'custom' && (
                          <>
                            <button onClick={() => setShowAddMember(true)} className="px-3 py-1.5 text-xs font-medium text-blue-700 bg-blue-50 rounded-lg hover:bg-blue-100 transition">
                              + Add Members
                            </button>
                            <button onClick={() => deleteGroup(g.id)} className="px-3 py-1.5 text-xs font-medium text-red-600 bg-red-50 rounded-lg hover:bg-red-100 transition">
                              Delete Group
                            </button>
                          </>
                        )}
                        <span className="ml-auto text-xs text-gray-400">
                          {detail.members.length} members
                        </span>
                      </div>

                      {/* Add member modal */}
                      {showAddMember && (
                        <div className="border rounded-lg p-4 bg-gray-50">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-semibold text-gray-700">Search identities to add</span>
                            <button onClick={() => { setShowAddMember(false); setMemberSearch(''); setSearchIdentities([]); }} className="text-xs text-gray-400 hover:text-gray-600">Close</button>
                          </div>
                          <input
                            type="text"
                            placeholder="Type identity name..."
                            value={memberSearch}
                            onChange={e => { setMemberSearch(e.target.value); searchForIdentities(e.target.value); }}
                            className="w-full px-3 py-1.5 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                          />
                          {memberSearchLoading && <div className="text-xs text-gray-400 mt-2">Searching...</div>}
                          {searchIdentities.length > 0 && (
                            <div className="mt-2 max-h-48 overflow-y-auto space-y-1">
                              {searchIdentities.map(si => {
                                const alreadyMember = detail.members.some(m => m.identity_id === si.identity_id);
                                return (
                                  <div key={si.identity_id} className="flex items-center justify-between px-2 py-1.5 rounded hover:bg-white text-xs">
                                    <div>
                                      <span className="font-medium text-gray-900">{si.display_name}</span>
                                      <span className="ml-2 text-gray-400">{CATEGORY_LABELS[si.identity_category] || si.identity_category}</span>
                                    </div>
                                    {alreadyMember ? (
                                      <span className="text-[10px] text-gray-400">Already member</span>
                                    ) : (
                                      <button onClick={() => addMember(si.identity_id)} className="text-blue-600 hover:text-blue-800 font-medium">Add</button>
                                    )}
                                  </div>
                                );
                              })}
                            </div>
                          )}
                        </div>
                      )}

                      {/* Members table */}
                      {detail.members.length === 0 ? (
                        <div className="text-center py-8 text-gray-400 text-sm">No members in this group</div>
                      ) : (
                        <div className="overflow-x-auto">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="bg-gray-50 border-b text-left">
                                <th className="px-3 py-2 font-medium text-gray-600 text-xs">Identity</th>
                                <th className="px-3 py-2 font-medium text-gray-600 text-xs">Category</th>
                                <th className="px-3 py-2 font-medium text-gray-600 text-xs">Cloud</th>
                                <th className="px-3 py-2 font-medium text-gray-600 text-xs">Risk</th>
                                <th className="px-3 py-2 font-medium text-gray-600 text-xs">Score</th>
                                <th className="px-3 py-2 font-medium text-gray-600 text-xs">Activity</th>
                                {canEdit && g.group_type === 'custom' && (
                                  <th className="px-3 py-2 font-medium text-gray-600 text-xs w-16" />
                                )}
                              </tr>
                            </thead>
                            <tbody>
                              {detail.members.map(m => (
                                <tr key={m.identity_id} className="border-b last:border-b-0 hover:bg-gray-50 transition">
                                  <td className="px-3 py-2">
                                    <Link to={`/identities/${encodeURIComponent(m.identity_id)}`} className="text-blue-600 hover:underline font-medium text-xs">
                                      {m.display_name}
                                    </Link>
                                  </td>
                                  <td className="px-3 py-2 text-xs text-gray-600">{CATEGORY_LABELS[m.identity_category] || m.identity_category || '-'}</td>
                                  <td className="px-3 py-2">
                                    <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase bg-sky-50 text-sky-600">{m.cloud}</span>
                                  </td>
                                  <td className="px-3 py-2">
                                    <span className={`px-1.5 py-0.5 rounded-full text-[10px] font-semibold uppercase ${
                                      m.risk_level === 'critical' ? 'bg-red-50 text-red-700'
                                        : m.risk_level === 'high' ? 'bg-orange-50 text-orange-700'
                                        : m.risk_level === 'medium' ? 'bg-yellow-50 text-yellow-700'
                                        : 'bg-blue-50 text-blue-700'
                                    }`}>{m.risk_level}</span>
                                  </td>
                                  {/* CVSS-aligned 0-10 only (2026-05-31 directive) */}
                                  <td className="px-3 py-2 text-xs font-semibold text-gray-700 tabular-nums" title="CVSS-aligned 0-10 (FIRST.org CVSS 3.1)">{riskDisplay(m) ?? '—'}</td>
                                  <td className="px-3 py-2 text-xs text-gray-500">{m.activity_status || '-'}</td>
                                  {canEdit && g.group_type === 'custom' && (
                                    <td className="px-3 py-2">
                                      <button onClick={() => removeMember(g.id, m.identity_id)} className="text-red-500 hover:text-red-700 text-[10px] font-medium">Remove</button>
                                    </td>
                                  )}
                                </tr>
                              ))}
                            </tbody>
                          </table>
                        </div>
                      )}
                    </div>
                  ) : null}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Create Group Modal */}
      {showCreate && <CreateGroupModal onClose={() => setShowCreate(false)} onCreated={() => { setShowCreate(false); loadGroups(); }} />}
    </div>
  );
}


function CreateGroupModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [color, setColor] = useState('#3B82F6');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const handleCreate = async () => {
    if (!name.trim()) { setError('Name is required'); return; }
    setSaving(true);
    setError('');
    try {
      const res = await fetch('/api/groups', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: name.trim(), description: description.trim() || null, color }),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || `API error: ${res.status}`);
      }
      onCreated();
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to create');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40">
      <div className="bg-white rounded-2xl shadow-xl w-full max-w-md p-6" onClick={e => e.stopPropagation()}>
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Create Group</h3>

        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder="e.g., Finance Team, CI/CD Pipelines"
              className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
              autoFocus
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Description (optional)</label>
            <textarea
              value={description}
              onChange={e => setDescription(e.target.value)}
              placeholder="Brief description of this group..."
              rows={2}
              className="w-full px-3 py-2 border rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">Color</label>
            <div className="flex gap-2">
              {COLOR_PRESETS.map(c => (
                <button
                  key={c}
                  onClick={() => setColor(c)}
                  className={`w-8 h-8 rounded-full border-2 transition ${color === c ? 'border-gray-900 scale-110' : 'border-transparent'}`}
                  style={{ backgroundColor: c }}
                />
              ))}
            </div>
          </div>

          {error && <div className="text-sm text-red-600">{error}</div>}
        </div>

        <div className="flex justify-end gap-3 mt-6">
          <button onClick={onClose} className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800 transition">Cancel</button>
          <button
            onClick={handleCreate}
            disabled={saving || !name.trim()}
            className="px-4 py-2 text-sm font-medium text-white bg-blue-600 rounded-lg hover:bg-blue-700 transition disabled:opacity-50"
          >
            {saving ? 'Creating...' : 'Create Group'}
          </button>
        </div>
      </div>
    </div>
  );
}
