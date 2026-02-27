import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../../contexts/ConnectionContext';

interface ExpirySummary {
  secrets: { total: number; expired: number; expiring_7d: number; expiring_30d: number; expiring_90d: number; no_expiry: number };
  keys: { total: number; expired: number; expiring_7d: number; expiring_30d: number; expiring_90d: number; no_expiry: number };
  certs: { total: number; expired: number; expiring_7d: number; expiring_30d: number; expiring_90d: number; no_expiry: number };
  timeline: Array<{ vault: string; item: string; type: string; expires_on: string }>;
}

function MiniCard({ label, total, expired, expiringSoon, onClick }: { label: string; total: number; expired: number; expiringSoon: number; onClick?: () => void }) {
  const color = expired > 0 ? 'border-red-200 bg-red-50 dark:bg-red-900/20 dark:border-red-800' :
    expiringSoon > 0 ? 'border-orange-200 bg-orange-50 dark:bg-orange-900/20 dark:border-orange-800' :
    'border-green-200 bg-green-50 dark:bg-green-900/20 dark:border-green-800';

  return (
    <button onClick={onClick} className={`border rounded-lg p-3 ${color} text-left w-full${onClick ? ' cursor-pointer hover:shadow-sm transition' : ''}`}>
      <div className="text-lg font-bold text-gray-800 dark:text-slate-200">{total}</div>
      <div className="text-[10px] font-medium text-gray-600 dark:text-slate-400 uppercase tracking-wider">{label}</div>
      <div className="flex gap-2 mt-1.5 text-[10px]">
        {expired > 0 && <span className="px-1.5 py-0.5 bg-red-100 text-red-700 rounded font-semibold">{expired} expired</span>}
        {expiringSoon > 0 && <span className="px-1.5 py-0.5 bg-orange-100 text-orange-700 rounded font-semibold">{expiringSoon} expiring</span>}
        {expired === 0 && expiringSoon === 0 && total > 0 && <span className="text-green-600 font-medium">All OK</span>}
      </div>
    </button>
  );
}

export default function ExpiryTracker() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<ExpirySummary | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch(withConnection('/api/resources/expiry-summary'))
      .then(r => r.json())
      .then(d => { setData(d); setLoading(false); })
      .catch(() => setLoading(false));
  }, [selectedConnectionId]);

  if (loading) {
    return (
      <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
        <div className="animate-pulse h-24 bg-gray-100 dark:bg-slate-800 rounded" />
      </div>
    );
  }

  if (!data) return null;

  const totalExpired = (data.secrets?.expired || 0) + (data.keys?.expired || 0) + (data.certs?.expired || 0);
  const totalExpiring = (data.secrets?.expiring_30d || 0) + (data.keys?.expiring_30d || 0) + (data.certs?.expiring_30d || 0);

  return (
    <div className="bg-white dark:bg-slate-900 rounded-lg border border-gray-200 dark:border-slate-700 p-4">
      <div className="flex items-center justify-between mb-3">
        <div>
          <h3 className="text-sm font-semibold text-gray-800 dark:text-slate-200">Key Vault Expiry Tracker</h3>
          <p className="text-[10px] text-gray-500">Secrets, Keys & Certificates lifecycle</p>
        </div>
        {(totalExpired > 0 || totalExpiring > 0) && (
          <button
            onClick={() => navigate('/key-vaults')}
            className={`px-2 py-0.5 rounded text-[10px] font-bold cursor-pointer hover:opacity-70 transition ${
              totalExpired > 0 ? 'bg-red-100 text-red-700' : 'bg-orange-100 text-orange-700'
            }`}
          >
            {totalExpired > 0 ? `${totalExpired} Expired` : `${totalExpiring} Expiring`}
          </button>
        )}
      </div>

      <div className="grid grid-cols-3 gap-2 mb-3">
        <MiniCard label="Secrets" total={data.secrets?.total || 0} expired={data.secrets?.expired || 0} expiringSoon={(data.secrets?.expiring_7d || 0) + (data.secrets?.expiring_30d || 0)} onClick={() => navigate('/key-vaults')} />
        <MiniCard label="Keys" total={data.keys?.total || 0} expired={data.keys?.expired || 0} expiringSoon={(data.keys?.expiring_7d || 0) + (data.keys?.expiring_30d || 0)} onClick={() => navigate('/key-vaults')} />
        <MiniCard label="Certificates" total={data.certs?.total || 0} expired={data.certs?.expired || 0} expiringSoon={(data.certs?.expiring_7d || 0) + (data.certs?.expiring_30d || 0)} onClick={() => navigate('/key-vaults')} />
      </div>

      {/* Upcoming expirations timeline (top 5) */}
      {data.timeline && data.timeline.length > 0 && (
        <div>
          <div className="text-[10px] uppercase tracking-wider text-gray-500 font-medium mb-1">Soonest Expirations</div>
          <div className="space-y-1">
            {data.timeline.slice(0, 5).map((item, i) => {
              const exp = new Date(item.expires_on);
              const days = Math.ceil((exp.getTime() - Date.now()) / 86400000);
              const isExpired = days < 0;
              return (
                <div key={i} className="flex items-center gap-2 text-[11px]">
                  <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${isExpired ? 'bg-red-500' : days <= 7 ? 'bg-orange-500' : days <= 30 ? 'bg-yellow-500' : 'bg-green-500'}`} />
                  <span className="text-gray-600 dark:text-slate-400 truncate flex-1">{item.vault} / {item.item}</span>
                  <span className={`text-[10px] font-medium ${isExpired ? 'text-red-600' : 'text-gray-500'}`}>
                    {isExpired ? `${Math.abs(days)}d ago` : `${days}d`}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <button
        onClick={() => navigate('/key-vaults')}
        className="mt-3 text-[10px] text-blue-600 hover:underline"
      >
        View all Key Vaults →
      </button>
    </div>
  );
}
