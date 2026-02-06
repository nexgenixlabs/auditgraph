import React from 'react';
import { useNavigate } from 'react-router-dom';

interface CredentialHealthProps {
  expired: number;
  expiringSoon: number;
  healthy: number;
  noCredentials: number;
}

export default function CredentialHealth({ expired, expiringSoon, healthy, noCredentials }: CredentialHealthProps) {
  const navigate = useNavigate();
  const total = expired + expiringSoon + healthy + noCredentials || 1;

  const segments = [
    { key: 'expired', label: 'Expired', count: expired, color: 'bg-red-500', textColor: 'text-red-700', bgColor: 'bg-red-50' },
    { key: 'expiring', label: 'Expiring (<30d)', count: expiringSoon, color: 'bg-orange-500', textColor: 'text-orange-700', bgColor: 'bg-orange-50' },
    { key: 'healthy', label: 'Healthy', count: healthy, color: 'bg-green-500', textColor: 'text-green-700', bgColor: 'bg-green-50' },
    { key: 'none', label: 'No Credentials', count: noCredentials, color: 'bg-gray-300', textColor: 'text-gray-600', bgColor: 'bg-gray-50' },
  ];

  return (
    <div className="bg-white border rounded-xl p-5">
      <div className="text-sm font-semibold text-gray-900 mb-3">Credential Health</div>

      {/* Stacked bar */}
      <div className="flex rounded-full overflow-hidden h-3 mb-4">
        {segments.map(seg => (
          seg.count > 0 ? (
            <div
              key={seg.key}
              className={`${seg.color} transition-all duration-500`}
              style={{ width: `${(seg.count / total) * 100}%` }}
              title={`${seg.label}: ${seg.count}`}
            />
          ) : null
        ))}
      </div>

      {/* Legend cards */}
      <div className="grid grid-cols-2 gap-2">
        {segments.map(seg => (
          <button
            key={seg.key}
            onClick={() => {
              if (seg.key === 'expired') navigate('/identities?credential_status=expired');
              else if (seg.key === 'expiring') navigate('/identities?credential_expiry=expiring_soon');
              else if (seg.key === 'healthy') navigate('/identities?credential_status=valid');
            }}
            className={`${seg.bgColor} rounded-lg p-2 text-left hover:opacity-80 transition`}
          >
            <div className="flex items-center gap-2">
              <div className={`w-2.5 h-2.5 rounded-full ${seg.color}`} />
              <span className="text-xs text-gray-600">{seg.label}</span>
            </div>
            <div className={`text-lg font-bold ${seg.textColor} mt-0.5`}>{seg.count}</div>
          </button>
        ))}
      </div>
    </div>
  );
}
