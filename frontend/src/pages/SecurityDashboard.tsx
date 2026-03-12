import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';

/** Shape returned by GET /api/security/overview */
interface SecurityOverview {
  discovery_metadata: {
    run_ids: number[];
    data_as_of: string | null;
  };
  posture_score: number;
  risk_score: number;
  identities: {
    total: number;
    users: number;
    service_principals: number;
    managed_identities: number;
    guests: number;
  };
  findings: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  nhi: {
    secrets_without_expiry: number;
    secrets_older_than_180_days: number;
    unused_service_principals: number;
  };
  attack_paths: {
    identities_with_paths: number;
  };
  credentials: {
    total: number;
    expired: number;
    expiring_soon: number;
  };
  cloud_providers: CloudProviderSummary[];
}

interface CloudProviderSummary {
  cloud: string;
  subscriptions: number;
  identities: number;
  attack_paths: number;
  findings: number;
}

interface CopilotResponse {
  answer: string;
  intent: string;
  suggestions: string[];
}

const CLOUD_COLOR: Record<string, string> = {
  azure: 'text-blue-400',
  aws: 'text-orange-400',
  gcp: 'text-emerald-400',
};

const CLOUD_BG: Record<string, string> = {
  azure: 'bg-blue-500/10 border-blue-500/30',
  aws: 'bg-orange-500/10 border-orange-500/30',
  gcp: 'bg-emerald-500/10 border-emerald-500/30',
};

const SecurityDashboard: React.FC = () => {
  const navigate = useNavigate();
  const [overview, setOverview] = useState<SecurityOverview | null>(null);
  const [loading, setLoading] = useState(true);
  const [copilotQuery, setCopilotQuery] = useState('');
  const [copilotResponse, setCopilotResponse] = useState<CopilotResponse | null>(null);
  const [copilotLoading, setCopilotLoading] = useState(false);

  useEffect(() => {
    const fetchOverview = async () => {
      try {
        const res = await fetch('/api/security/overview');
        if (res.ok) {
          const data = await res.json();
          setOverview(data);
        } else {
          console.warn(`[SecurityDashboard] /api/security/overview returned ${res.status}`);
        }
      } catch (e) {
        console.error('[SecurityDashboard] Failed to fetch overview:', e);
      } finally {
        setLoading(false);
      }
    };
    fetchOverview();
  }, []);

  const handleCopilotSubmit = async (queryText?: string) => {
    const q = queryText || copilotQuery;
    if (!q.trim()) return;
    setCopilotLoading(true);
    try {
      const res = await fetch('/api/security/copilot-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q }),
      });
      if (res.ok) {
        const data = await res.json();
        setCopilotResponse(data);
        setCopilotQuery('');
      }
    } catch (err) {
      console.error('Copilot query failed:', err);
    } finally {
      setCopilotLoading(false);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-400">Loading dashboard...</div>;
  }

  // Destructure with safe defaults
  const ident = overview?.identities || { total: 0, users: 0, service_principals: 0, managed_identities: 0, guests: 0 };
  const find = overview?.findings || { critical: 0, high: 0, medium: 0, low: 0 };
  const nhi = overview?.nhi || { secrets_without_expiry: 0, secrets_older_than_180_days: 0, unused_service_principals: 0 };
  const ap = overview?.attack_paths || { identities_with_paths: 0 };
  const cred = overview?.credentials || { total: 0, expired: 0, expiring_soon: 0 };
  const clouds = overview?.cloud_providers || [];
  const riskScore = overview?.risk_score || 0;
  const dataAsOf = overview?.discovery_metadata?.data_as_of;

  const riskColor = riskScore >= 100 ? 'text-red-400' :
                    riskScore >= 50 ? 'text-orange-400' :
                    riskScore >= 20 ? 'text-yellow-400' : 'text-emerald-400';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-sm text-slate-400 mt-1">
            Executive view of IAM security posture
            {dataAsOf && (
              <span className="ml-3 text-slate-500">
                Data as of: {new Date(dataAsOf).toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
              </span>
            )}
          </p>
        </div>
        <div className="text-right">
          <div className="text-xs text-slate-400 uppercase tracking-wider">Risk Score</div>
          <div className={`text-4xl font-bold ${riskColor}`}>{riskScore}</div>
        </div>
      </div>

      {/* Cloud Provider Summary */}
      {clouds.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Cloud Providers</h2>
          <div className={`grid grid-cols-${Math.min(clouds.length, 3)} gap-4`}>
            {clouds.map(provider => (
              <div key={provider.cloud} className={`border rounded-lg p-4 ${CLOUD_BG[provider.cloud] || 'bg-slate-800/50 border-slate-700/50'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-sm font-semibold uppercase ${CLOUD_COLOR[provider.cloud] || 'text-slate-300'}`}>
                    {provider.cloud}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                  <div className="flex justify-between"><span className="text-slate-400">Subscriptions</span><span className="text-white font-medium">{provider.subscriptions}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Identities</span><span className="text-white font-medium">{provider.identities}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Attack Paths</span><span className={`font-medium ${provider.attack_paths > 0 ? 'text-red-400' : 'text-white'}`}>{provider.attack_paths}</span></div>
                  <div className="flex justify-between"><span className="text-slate-400">Findings</span><span className={`font-medium ${provider.findings > 0 ? 'text-orange-400' : 'text-white'}`}>{provider.findings}</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Identity Overview */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Overview</h2>
        <div className="grid grid-cols-5 gap-4">
          <div title="View all identities" className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 cursor-pointer hover:border-slate-500/50 hover:bg-slate-800/70 transition-colors" onClick={() => navigate('/identities')}>
            <div className="text-xs text-slate-400">Total Identities</div>
            <div className="text-2xl font-bold text-white mt-1">{ident.total}</div>
          </div>
          <div title="View human user identities" className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 cursor-pointer hover:border-blue-500/50 hover:bg-slate-800/70 transition-colors" onClick={() => navigate('/identities?identity_category=human_user')}>
            <div className="text-xs text-slate-400">Users</div>
            <div className="text-2xl font-bold text-blue-400 mt-1">{ident.users}</div>
          </div>
          <div title="View service principal identities" className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 cursor-pointer hover:border-purple-500/50 hover:bg-slate-800/70 transition-colors" onClick={() => navigate('/identities?identity_category=service_principal')}>
            <div className="text-xs text-slate-400">Service Principals</div>
            <div className="text-2xl font-bold text-purple-400 mt-1">{ident.service_principals}</div>
          </div>
          <div title="View managed identities" className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 cursor-pointer hover:border-cyan-500/50 hover:bg-slate-800/70 transition-colors" onClick={() => navigate('/identities?identity_category=managed_identity_system')}>
            <div className="text-xs text-slate-400">Managed Identities</div>
            <div className="text-2xl font-bold text-cyan-400 mt-1">{ident.managed_identities}</div>
          </div>
          <div title="View guest identities" className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 cursor-pointer hover:border-amber-500/50 hover:bg-slate-800/70 transition-colors" onClick={() => navigate('/identities?identity_category=guest')}>
            <div className="text-xs text-slate-400">Guests</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{ident.guests}</div>
          </div>
        </div>
      </div>

      {/* Risk Findings */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Risk Findings</h2>
        <div className="grid grid-cols-4 gap-4">
          <div title="View critical security findings" className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 cursor-pointer hover:border-red-400/60 hover:bg-red-500/20 transition-colors" onClick={() => navigate('/security-findings?severity=critical')}>
            <div className="text-xs text-red-400">Critical</div>
            <div className="text-3xl font-bold text-red-400 mt-1">{find.critical}</div>
          </div>
          <div title="View high severity findings" className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4 cursor-pointer hover:border-orange-400/60 hover:bg-orange-500/20 transition-colors" onClick={() => navigate('/security-findings?severity=high')}>
            <div className="text-xs text-orange-400">High</div>
            <div className="text-3xl font-bold text-orange-400 mt-1">{find.high}</div>
          </div>
          <div title="View medium severity findings" className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4 cursor-pointer hover:border-yellow-400/60 hover:bg-yellow-500/20 transition-colors" onClick={() => navigate('/security-findings?severity=medium')}>
            <div className="text-xs text-yellow-400">Medium</div>
            <div className="text-3xl font-bold text-yellow-400 mt-1">{find.medium}</div>
          </div>
          <div title="View low severity findings" className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4 cursor-pointer hover:border-blue-400/60 hover:bg-blue-500/20 transition-colors" onClick={() => navigate('/security-findings?severity=low')}>
            <div className="text-xs text-blue-400">Low</div>
            <div className="text-3xl font-bold text-blue-400 mt-1">{find.low}</div>
          </div>
        </div>
      </div>

      {/* NHI Security + Privilege Escalation */}
      <div className="grid grid-cols-2 gap-6">
        {/* NHI Security */}
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">NHI Security</h2>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Secrets without expiry</span>
              <span className="text-lg font-bold text-red-400">{nhi.secrets_without_expiry}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Secrets older than 180 days</span>
              <span className="text-lg font-bold text-orange-400">{nhi.secrets_older_than_180_days}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Unused service principals</span>
              <span className="text-lg font-bold text-yellow-400">{nhi.unused_service_principals}</span>
            </div>
          </div>
        </div>

        {/* Privilege Escalation */}
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Privilege Escalation</h2>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Identities with attack paths</span>
              <span className="text-lg font-bold text-red-400">{ap.identities_with_paths}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Total credentials tracked</span>
              <span className="text-lg font-bold text-slate-300">{cred.total}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Expired credentials</span>
              <span className="text-lg font-bold text-red-400">{cred.expired}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Expiring within 30 days</span>
              <span className="text-lg font-bold text-orange-400">{cred.expiring_soon}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Security Copilot */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Security Copilot</h2>
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={copilotQuery}
              onChange={(e) => setCopilotQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCopilotSubmit()}
              placeholder="Ask about your security posture..."
              className="flex-1 bg-slate-900/50 border border-slate-600 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={() => handleCopilotSubmit()}
              disabled={copilotLoading || !copilotQuery.trim()}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm rounded transition-colors"
            >
              {copilotLoading ? 'Thinking...' : 'Ask'}
            </button>
          </div>
          {copilotResponse ? (
            <div>
              <div className="bg-slate-900/50 rounded p-3 mb-3">
                <pre className="text-sm text-slate-200 whitespace-pre-wrap font-sans">{copilotResponse.answer}</pre>
              </div>
              {copilotResponse.suggestions.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {copilotResponse.suggestions.map((s, i) => (
                    <button
                      key={i}
                      onClick={() => { setCopilotQuery(s); handleCopilotSubmit(s); }}
                      className="text-xs px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-full transition-colors"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="text-center text-sm text-slate-500">
              <p>Ask questions like:</p>
              <div className="flex flex-wrap gap-2 justify-center mt-2">
                {['Which identities are most dangerous?', 'Show open incidents', 'What is the security posture trend?'].map((s, i) => (
                  <button
                    key={i}
                    onClick={() => { setCopilotQuery(s); handleCopilotSubmit(s); }}
                    className="text-xs px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-full transition-colors"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
