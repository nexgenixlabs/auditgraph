/**
 * AG-IA-P5.4 (2026-06-10) — NHI Secrets page.
 *
 * Resolves issue #6: prior /nhi/secrets redirect landed on the full SPN
 * Dashboard which felt undifferentiated. This page is purpose-built for
 * the "show me the credential time-bombs" question — expired secrets,
 * expiring < 30d, federated-only (OIDC trust, no static secret), no
 * credentials at all (orphan check).
 */
import React, { useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import LoadingState from '../components/LoadingState';
import { NoDataInScopeState } from '../components/EmptyState';

interface NhiRow {
  id: number;
  display_name: string;
  identity_category: string;
  risk_level: string;
  risk_score: number;
  credential_count?: number;
  credential_risk?: string;
  credential_status?: string;
  credential_expiration?: string | null;
  has_federated_credentials?: boolean;
  federated_issuer_types?: string[];
}

export default function NHISecrets() {
  const { withConnection, selectedConnectionId } = useConnection();
  const navigate = useNavigate();
  const [rows, setRows] = useState<NhiRow[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetch(withConnection('/api/identities?identity_category=service_principal,managed_identity_system,managed_identity_user,workload&limit=500'))
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        if (cancelled) return;
        setRows(Array.isArray(d?.identities) ? d.identities : []);
      })
      .catch(() => {})
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [withConnection, selectedConnectionId]);

  const buckets = useMemo(() => {
    const now = Date.now();
    const thirtyDays = 30 * 24 * 60 * 60 * 1000;
    const expired = rows.filter(r => {
      if (r.credential_status === 'expired') return true;
      if (r.credential_risk === 'expired') return true;
      if (r.credential_expiration && new Date(r.credential_expiration).getTime() < now) return true;
      return false;
    });
    const expiringSoon = rows.filter(r => {
      if (r.credential_status === 'expired' || r.credential_risk === 'expired') return false;
      if (!r.credential_expiration) return false;
      const t = new Date(r.credential_expiration).getTime();
      return Number.isFinite(t) && t > now && t < now + thirtyDays;
    });
    const federatedOnly = rows.filter(r => r.has_federated_credentials && (r.credential_count ?? 0) === 0);
    const noCredentials = rows.filter(r => (r.credential_count ?? 0) === 0 && !r.has_federated_credentials && r.identity_category === 'service_principal');
    return { expired, expiringSoon, federatedOnly, noCredentials };
  }, [rows]);

  if (loading) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto">
        <LoadingState message="Loading non-human credential posture..." />
      </div>
    );
  }

  if (rows.length === 0) {
    return (
      <div className="p-6 max-w-[1400px] mx-auto space-y-4">
        <div className="px-1">
          <h1 className="text-xl font-bold" style={{ color: 'var(--text-primary)' }}>NHI Secrets &amp; Credentials</h1>
        </div>
        <NoDataInScopeState title="No non-human identities in scope" subjects="non-human identities" />
      </div>
    );
  }

  type Bucket = { label: string; rows: NhiRow[]; tone: 'critical' | 'warning' | 'info' | 'neutral'; description: string };
  const sections: Bucket[] = [
    { label: 'Expired Secrets',         rows: buckets.expired,      tone: 'critical', description: 'Active NHIs whose client secret has already lapsed — credential time-bombs. Rotate or revoke.' },
    { label: 'Expiring < 30 days',      rows: buckets.expiringSoon, tone: 'warning',  description: 'Secrets with under 30 days of life left. Pre-rotate via Key Vault to prevent outage.' },
    { label: 'Federated (OIDC) Only',   rows: buckets.federatedOnly,tone: 'info',     description: 'Workload identities that trust an external OIDC issuer (GitHub Actions, Terraform Cloud, ADO). No static secret — but verify the subject claim is scoped (not org:* or repo:* with wildcard).' },
    { label: 'No Credentials',          rows: buckets.noCredentials,tone: 'neutral',  description: 'SPNs with neither a client secret nor a federated trust. Likely abandoned — candidate for cleanup.' },
  ];
  const toneStyle = (t: Bucket['tone']) => ({
    critical: { bg: 'rgba(239,68,68,0.10)', border: 'rgba(239,68,68,0.40)', text: '#f87171' },
    warning:  { bg: 'rgba(251,146,60,0.10)', border: 'rgba(251,146,60,0.40)', text: '#fb923c' },
    info:     { bg: 'rgba(59,130,246,0.10)', border: 'rgba(59,130,246,0.40)', text: '#60a5fa' },
    neutral:  { bg: 'rgba(148,163,184,0.10)', border: 'rgba(148,163,184,0.40)', text: '#94a3b8' },
  }[t]);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      <div>
        <div className="flex items-center gap-2 text-[10px] uppercase tracking-wider font-bold text-gray-500">
          <span style={{ color: '#fb923c' }}>Identity</span>
          <span>·</span>
          <span>Non-Human</span>
          <span>·</span>
          <span>Secrets</span>
        </div>
        <h1 className="text-2xl font-bold mt-1" style={{ color: 'var(--text-primary)' }}>NHI Secrets &amp; Credentials</h1>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Credential posture for every non-human identity — expired, expiring soon, federated-only,
          and no-credential SPNs in four focused buckets. Only NHIs with credential signals appear here.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {sections.map(section => {
          const sty = toneStyle(section.tone);
          return (
            <div key={section.label} className="rounded-xl border" style={{ backgroundColor: 'var(--bg-raised)', borderColor: sty.border }}>
              <div className="px-4 py-3 border-b flex items-baseline justify-between" style={{ borderColor: 'var(--border-subtle)' }}>
                <div>
                  <h3 className="text-sm font-semibold" style={{ color: sty.text }}>{section.label}</h3>
                  <p className="text-[10px] mt-0.5 leading-snug" style={{ color: 'var(--text-muted)' }}>{section.description}</p>
                </div>
                <span className="text-2xl font-bold font-mono" style={{ color: sty.text }}>{section.rows.length}</span>
              </div>
              <div className="p-3 max-h-[300px] overflow-y-auto space-y-1">
                {section.rows.slice(0, 30).map(r => (
                  <button key={r.id} onClick={() => navigate(`/identities/${r.id}`)}
                    className="w-full text-left rounded px-2 py-1.5 hover:bg-slate-800/40 transition-colors flex items-center justify-between gap-2">
                    <div className="min-w-0 flex-1">
                      <div className="text-xs truncate" style={{ color: 'var(--text-primary)' }}>{r.display_name}</div>
                      <div className="text-[10px]" style={{ color: 'var(--text-muted)' }}>
                        {r.identity_category.replace(/_/g, ' ')}
                        {r.credential_expiration && ` · exp ${new Date(r.credential_expiration).toLocaleDateString()}`}
                      </div>
                    </div>
                    <span className="text-[10px] font-mono" style={{ color: sty.text }}>{r.risk_level}</span>
                  </button>
                ))}
                {section.rows.length === 0 && (
                  <p className="text-xs py-4 text-center" style={{ color: '#10b981' }}>
                    ✓ No identities in this bucket
                  </p>
                )}
                {section.rows.length > 30 && (
                  <p className="text-[10px] py-2 text-center" style={{ color: 'var(--text-muted)' }}>
                    + {section.rows.length - 30} more — drill in for full list
                  </p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
