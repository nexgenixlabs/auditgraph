/**
 * OwnershipCenter — Week 3 of the brand/IA pivot
 *
 * The SailPoint-money capability. List every NHI with no owner,
 * let governance teams assign one with a couple of clicks. Bulk
 * assignment + certification campaigns ship in Week 4.
 *
 * Sources:
 *   GET  /api/ownership/summary          — headline metrics
 *   GET  /api/ownership/unowned          — unowned NHIs (ordered by risk)
 *   GET  /api/ownership/assignments      — active assignments
 *   POST /api/ownership/assign           — assign or update an owner
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';

interface Summary {
  total_nhi: number;
  active_assigned: number;
  unowned: number;
  pct_owned: number;
  expiring_soon: number;
  exceptions: number;
}

interface UnownedItem {
  identity_db_id: number;
  identity_id: string;
  display_name: string;
  identity_category: string;
  agent_type: string | null;
  risk_level: string | null;
  risk_score: number | null;
}

interface UnownedResponse {
  items: UnownedItem[];
  total_unowned: number;
  total_nhis: number;
  pct_unowned: number;
}

interface Assignment {
  id: number;
  identity_id: string;
  owner_display_name: string;
  owner_email: string | null;
  delegate_display_name: string | null;
  status: string;
  expires_at: string | null;
  assigned_at: string | null;
}

const CAT_LABEL: Record<string, string> = {
  service_principal: 'Service Principal',
  managed_identity_system: 'Managed Identity (system)',
  managed_identity_user: 'Managed Identity (user)',
};

const RISK_DOT: Record<string, string> = {
  critical: 'bg-red-400', high: 'bg-orange-400',
  medium: 'bg-amber-400', low: 'bg-emerald-400',
};

export default function OwnershipCenter() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [unowned, setUnowned] = useState<UnownedResponse | null>(null);
  const [assignments, setAssignments] = useState<Assignment[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [assignTarget, setAssignTarget] = useState<UnownedItem | null>(null);
  const [tab, setTab] = useState<'unowned' | 'assigned'>('unowned');

  const load = useCallback(() => {
    setLoading(true);
    Promise.all([
      fetch('/api/ownership/summary').then(r => r.json()),
      fetch('/api/ownership/unowned').then(r => r.json()),
      fetch('/api/ownership/assignments').then(r => r.json()),
    ])
      .then(([s, u, a]) => {
        setSummary(s as Summary);
        setUnowned(u as UnownedResponse);
        setAssignments((a as { items: Assignment[] }).items || []);
        setLoading(false);
      })
      .catch((e: Error) => { setError(e.message); setLoading(false); });
  }, []);

  useEffect(() => { load(); }, [load]);

  const headline = useMemo(() => {
    if (!summary) return null;
    return summary.unowned > 0
      ? `${summary.unowned} of ${summary.total_nhi} non-human identities have no human owner (${100 - summary.pct_owned}% unowned).`
      : `All ${summary.total_nhi} non-human identities have an active owner — solid governance posture.`;
  }, [summary]);

  if (loading && !summary) return <div className="p-6 text-sm text-slate-400">Loading Ownership Center…</div>;
  if (error) return <div className="p-6 text-sm text-rose-400">{error}</div>;
  if (!summary || !unowned) return null;

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-slate-100">Ownership Center</h1>
        <p className="text-sm text-slate-400 max-w-3xl mt-1">
          Track human ownership of every non-human identity for governance,
          re-certification, and incident accountability. Unowned NHIs are the
          #1 indicator that an incident response will stall (nobody to call,
          nobody to revoke).
        </p>
        {/* AG-PILOT-OWNERSHIP-READONLY-BANNER (2026-06-08) */}
        <p className="text-[11px] text-amber-300 mt-2 max-w-3xl">
          AuditGraph is <strong>read-only</strong> on your tenant — owner
          assignments here record in our governance ledger. Each save returns
          an <span className="font-mono">az cli</span> snippet you can run with
          a write-permitted Azure account to mirror the ownership in your
          directory or resource tags.
        </p>
      </div>

      {/* Headline */}
      <div className={`rounded-xl border p-5 ${
        summary.unowned > 0
          ? 'border-rose-800/40 bg-rose-900/10'
          : 'border-emerald-800/40 bg-emerald-900/10'
      }`}>
        <p className={`text-[10px] uppercase tracking-wider font-bold mb-1 ${
          summary.unowned > 0 ? 'text-rose-300' : 'text-emerald-300'
        }`}>Headline</p>
        <p className={`text-xl font-semibold leading-snug ${
          summary.unowned > 0 ? 'text-rose-100' : 'text-emerald-100'
        }`}>
          {headline}
        </p>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <SummaryCard label="Owned NHIs"      value={summary.active_assigned} sub={`${summary.pct_owned}% of total`} accent="emerald" />
        <SummaryCard label="Unowned NHIs"    value={summary.unowned}         sub={`${100 - summary.pct_owned}% of total`} accent="rose" />
        <SummaryCard label="Expiring 30 days" value={summary.expiring_soon}  sub="re-cert needed" accent="amber" />
        <SummaryCard label="Active exceptions" value={summary.exceptions}    sub="under review" accent="slate" />
      </div>

      {/* Tabs */}
      <div className="flex border border-slate-800 rounded overflow-hidden text-xs w-fit">
        <button onClick={() => setTab('unowned')}
                className={`px-3 py-1.5 ${tab === 'unowned'
                  ? 'bg-violet-900/30 text-violet-200'
                  : 'text-slate-400 hover:text-slate-200'}`}>
          Unowned ({unowned.total_unowned})
        </button>
        <button onClick={() => setTab('assigned')}
                className={`px-3 py-1.5 ${tab === 'assigned'
                  ? 'bg-violet-900/30 text-violet-200'
                  : 'text-slate-400 hover:text-slate-200'}`}>
          Assigned ({assignments.length})
        </button>
      </div>

      {tab === 'unowned' ? (
        <UnownedTable items={unowned.items} onAssign={setAssignTarget} />
      ) : (
        <AssignedTable items={assignments} />
      )}

      {assignTarget && (
        <AssignModal target={assignTarget}
                     onClose={() => setAssignTarget(null)}
                     onSuccess={() => { setAssignTarget(null); load(); }} />
      )}
    </div>
  );
}

function SummaryCard({ label, value, sub, accent }:
  { label: string; value: number; sub: string; accent: 'emerald'|'rose'|'amber'|'slate' }) {
  const accentMap = {
    emerald: 'text-emerald-300', rose: 'text-rose-300',
    amber: 'text-amber-300', slate: 'text-slate-200',
  };
  return (
    <div className="rounded-xl border border-white/5 bg-slate-900/40 p-3">
      <p className="text-[10px] uppercase tracking-wider font-semibold text-slate-500">{label}</p>
      <p className={`text-3xl font-bold font-mono mt-1 ${accentMap[accent]}`}>{value.toLocaleString()}</p>
      <p className="text-[10px] text-slate-500 mt-0.5">{sub}</p>
    </div>
  );
}

function UnownedTable({ items, onAssign }: { items: UnownedItem[]; onAssign: (i: UnownedItem) => void }) {
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-emerald-800/40 bg-emerald-900/10 p-8 text-center">
        <p className="text-emerald-200 text-sm">No unowned NHIs — every non-human identity has an active owner.</p>
      </div>
    );
  }
  return (
    <div className="rounded-xl border border-white/5 overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="text-left px-3 py-2">Identity</th>
            <th className="text-left px-3 py-2 w-44">Type</th>
            <th className="text-left px-3 py-2 w-32">Risk</th>
            <th className="px-3 py-2 w-32" />
          </tr>
        </thead>
        <tbody>
          {items.map(i => (
            <tr key={i.identity_db_id} className="border-t border-white/5 hover:bg-slate-900/40">
              <td className="px-3 py-2">
                <p className="font-mono text-xs text-slate-200">{i.display_name}</p>
                <p className="text-[10px] text-slate-500 font-mono mt-0.5">{i.identity_id}</p>
              </td>
              <td className="px-3 py-2 text-xs text-slate-300">
                {CAT_LABEL[i.identity_category] || i.identity_category}
                {i.agent_type && (
                  <span className="ml-2 text-[10px] px-1.5 py-0.5 rounded bg-violet-900/30 text-violet-300 border border-violet-800/40">
                    AI
                  </span>
                )}
              </td>
              <td className="px-3 py-2">
                {i.risk_level ? (
                  <span className="inline-flex items-center gap-1.5 text-xs">
                    <span className={`w-1.5 h-1.5 rounded-full ${RISK_DOT[i.risk_level] || 'bg-slate-500'}`} />
                    <span className="text-slate-300 capitalize">{i.risk_level}</span>
                    {i.risk_score != null && <span className="text-slate-500 font-mono">({i.risk_score})</span>}
                  </span>
                ) : <span className="text-slate-500 text-xs">—</span>}
              </td>
              <td className="px-3 py-2 text-right">
                <button onClick={() => onAssign(i)}
                        className="text-xs px-3 py-1 rounded bg-violet-700 hover:bg-violet-600 text-white font-semibold"
                        title="Record an owner in AuditGraph's governance ledger + get an Azure CLI snippet to mirror it in your tenant">
                  Track owner
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AssignedTable({ items }: { items: Assignment[] }) {
  if (items.length === 0) {
    return (
      <div className="rounded-xl border border-white/5 bg-slate-900/40 p-8 text-center text-slate-500 text-sm">
        No active assignments yet. Switch to the Unowned tab and start assigning.
      </div>
    );
  }
  return (
    <div className="rounded-xl border border-white/5 overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
          <tr>
            <th className="text-left px-3 py-2">Identity</th>
            <th className="text-left px-3 py-2">Owner</th>
            <th className="text-left px-3 py-2">Delegate</th>
            <th className="text-left px-3 py-2 w-32">Status</th>
            <th className="text-right px-3 py-2 w-32">Expires</th>
          </tr>
        </thead>
        <tbody>
          {items.map(a => (
            <tr key={a.id} className="border-t border-white/5">
              <td className="px-3 py-2 font-mono text-xs text-slate-200">{a.identity_id}</td>
              <td className="px-3 py-2">
                <p className="text-xs text-slate-200">{a.owner_display_name}</p>
                {a.owner_email && <p className="text-[10px] text-slate-500">{a.owner_email}</p>}
              </td>
              <td className="px-3 py-2 text-xs text-slate-300">{a.delegate_display_name || '—'}</td>
              <td className="px-3 py-2">
                <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                  a.status === 'active' ? 'bg-emerald-900/30 text-emerald-300 border border-emerald-800/40'
                  : a.status === 'pending_review' ? 'bg-amber-900/30 text-amber-300 border border-amber-800/40'
                  : a.status === 'exception' ? 'bg-orange-900/30 text-orange-300 border border-orange-800/40'
                  : 'bg-slate-800 text-slate-500 border border-slate-700'
                }`}>
                  {a.status}
                </span>
              </td>
              <td className="px-3 py-2 text-right text-[10px] text-slate-500 font-mono">
                {a.expires_at ? a.expires_at.slice(0, 10) : '—'}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function AssignModal({ target, onClose, onSuccess }: {
  target: UnownedItem;
  onClose: () => void;
  onSuccess: () => void;
}) {
  const [ownerName, setOwnerName] = useState('');
  const [ownerEmail, setOwnerEmail] = useState('');
  const [delegate, setDelegate] = useState('');
  const [reason, setReason] = useState('');
  const [expires, setExpires] = useState<string>(() => {
    const d = new Date();
    d.setMonth(d.getMonth() + 6);
    return d.toISOString().slice(0, 10);
  });
  const [submitting, setSubmitting] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const submit = async () => {
    if (!ownerName.trim()) { setErr('Owner name is required'); return; }
    setSubmitting(true);
    setErr(null);
    try {
      const r = await fetch('/api/ownership/assign', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity_id: target.identity_id,
          owner_display_name: ownerName.trim(),
          owner_email: ownerEmail.trim() || null,
          delegate_display_name: delegate.trim() || null,
          assignment_reason: reason.trim() || null,
          expires_at: expires ? `${expires}T00:00:00Z` : null,
        }),
      });
      if (!r.ok) {
        const body = await r.json().catch(() => null);
        throw new Error(body?.error || `Failed (${r.status})`);
      }
      onSuccess();
    } catch (e) {
      setErr((e as Error).message);
      setSubmitting(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm flex items-center justify-center p-4">
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-xl w-full">
        <div className="p-5 border-b border-white/5">
          <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold">Track owner assignment</p>
          <h2 className="text-base font-bold text-slate-100 font-mono mt-1">{target.display_name}</h2>
          <p className="text-[10px] text-slate-500 font-mono mt-0.5">{target.identity_id}</p>
        </div>
        <div className="p-5 space-y-3">
          {/* AG-PILOT-OWNERSHIP-READONLY (2026-06-08): AuditGraph is
              read-only on Azure — this dialog records the owner in
              AuditGraph's governance ledger for re-cert + accountability.
              Use the CLI snippet below to mirror the owner into Azure. */}
          <div className="rounded bg-amber-900/20 border border-amber-700/30 p-2.5 text-[11px] text-amber-200 leading-relaxed">
            <strong>AuditGraph tracks ownership for governance (re-cert + accountability).</strong>
            {' '}AuditGraph uses read-only RBAC and does <em>not</em> write to Azure. To mirror this
            owner into your tenant, copy the Azure CLI snippet shown after saving and run it
            with an Azure account that has write access.
          </div>
          {err && (
            <div className="rounded bg-rose-900/30 border border-rose-800/40 p-2 text-xs text-rose-200">{err}</div>
          )}
          <Field label="Owner name *" value={ownerName} onChange={setOwnerName} placeholder="Jane Engineer" />
          <Field label="Owner email"  value={ownerEmail} onChange={setOwnerEmail} placeholder="jane@yourco.com" />
          <Field label="Delegate"     value={delegate} onChange={setDelegate} placeholder="Optional backup contact" />
          <Field label="Reason"       value={reason} onChange={setReason} placeholder="Why this owner?" />
          <div>
            <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Re-cert by</label>
            <input type="date" value={expires} onChange={e => setExpires(e.target.value)}
                   className="mt-1 w-full bg-slate-900/60 border border-slate-700 rounded p-2 text-sm text-slate-200" />
            <p className="text-[10px] text-slate-500 mt-1">Owner must re-confirm assignment by this date.</p>
          </div>

          {/* CLI snippet to mirror in Azure */}
          {ownerEmail && (
            <div>
              <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">
                Azure CLI · mirror owner in your tenant
              </label>
              <pre className="mt-1 bg-slate-950 border border-slate-800 rounded p-2 text-[10px] text-emerald-300 font-mono overflow-x-auto whitespace-pre-wrap break-all">
{`# Resolve the owner's Entra object id from email
OWNER_OID=$(az ad user show --id ${ownerEmail || 'OWNER_EMAIL'} --query id -o tsv)

# Add as App Registration owner (works for service principals / AI apps)
az ad app owner add --id ${target.identity_id} --owner-object-id $OWNER_OID

# Optionally tag the identity's primary scope with the owner label
# az tag update --resource-id <SCOPE_ID> --operation merge \\
#   --tags Owner=${ownerEmail || 'owner@yourco.com'} ReCertBy=${expires || 'YYYY-MM-DD'}`}
              </pre>
              <button
                type="button"
                onClick={() => {
                  const oid = ownerEmail || 'OWNER_EMAIL';
                  const cmd = `OWNER_OID=$(az ad user show --id ${oid} --query id -o tsv)\naz ad app owner add --id ${target.identity_id} --owner-object-id $OWNER_OID`;
                  navigator.clipboard.writeText(cmd);
                }}
                className="mt-1 text-[10px] text-violet-300 hover:text-violet-200">
                Copy CLI snippet
              </button>
            </div>
          )}
        </div>
        <div className="p-3 border-t border-white/5 flex justify-end gap-2">
          <button onClick={onClose} disabled={submitting}
                  className="text-xs text-slate-400 hover:text-slate-200 px-3 py-1.5">Cancel</button>
          <button onClick={submit} disabled={submitting}
                  className="text-xs px-3 py-1.5 rounded bg-violet-700 hover:bg-violet-600 text-white font-semibold disabled:opacity-50">
            {submitting ? 'Saving…' : 'Save to AuditGraph ledger'}
          </button>
        </div>
      </div>
    </div>
  );
}

function Field({ label, value, onChange, placeholder }:
  { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  return (
    <div>
      <label className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">{label}</label>
      <input type="text" value={value} onChange={e => onChange(e.target.value)} placeholder={placeholder}
             className="mt-1 w-full bg-slate-900/60 border border-slate-700 rounded p-2 text-sm text-slate-200" />
    </div>
  );
}
