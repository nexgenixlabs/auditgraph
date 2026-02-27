import React, { useState, useEffect } from 'react';
import { useToast } from '../components/ToastProvider';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import {
  downloadCSV, downloadJSON, exportFilename,
  IDENTITY_CSV_COLUMNS, COMPLIANCE_CSV_COLUMNS, DRIFT_CSV_COLUMNS,
  EXPORT_SCHEMA_VERSION, buildExportMeta,
} from '../utils/exportUtils';

interface ExportCard {
  key: string;
  title: string;
  description: string;
  formats: ('csv' | 'json' | 'zip')[];
  icon: React.ReactNode;
}

const EXPORT_CARDS: ExportCard[] = [
  {
    key: 'identities',
    title: 'Identity Inventory',
    description: 'Complete inventory of all discovered identities with risk scores, privilege tiers, credentials, and activity status.',
    formats: ['csv', 'json'],
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
      </svg>
    ),
  },
  {
    key: 'compliance',
    title: 'Compliance Posture',
    description: 'Framework evaluations with control-level pass/warn/fail status and gap analysis for audit evidence.',
    formats: ['csv', 'json'],
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
      </svg>
    ),
  },
  {
    key: 'drift',
    title: 'Drift Report',
    description: 'Latest change detection results including new/removed identities, permission and risk changes, credential events.',
    formats: ['csv', 'json'],
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16V4m0 0L3 8m4-4l4 4m6 0v12m0 0l4-4m-4 4l-4-4" />
      </svg>
    ),
  },
  {
    key: 'risk-summary',
    title: 'Risk Summary',
    description: 'Executive risk overview with risk distribution, credential health, conditional access coverage, and top risks for SIEM/GRC integration.',
    formats: ['json'],
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    ),
  },
  {
    key: 'evidence-package',
    title: 'HIPAA Evidence Package',
    description: 'Comprehensive audit evidence bundle: privileged access, compliance gaps, remediation priorities, credential health, sensitive data access — ready for HIPAA auditors.',
    formats: ['json'],
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M19 11H5m14 0a2 2 0 012 2v6a2 2 0 01-2 2H5a2 2 0 01-2-2v-6a2 2 0 012-2m14 0V9a2 2 0 00-2-2M5 11V9a2 2 0 012-2m0 0V5a2 2 0 012-2h6a2 2 0 012 2v2M7 7h10" />
      </svg>
    ),
  },
  {
    key: 'sensitive-data',
    title: 'Sensitive Data Access Map',
    description: 'Classification inventory (PHI/PCI/PII) with identity-to-resource access mappings — who can reach sensitive data and via which roles.',
    formats: ['json'],
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
      </svg>
    ),
  },
  {
    key: 'evidence-zip',
    title: 'Evidence ZIP Package',
    description: 'Complete audit evidence bundle: 8 CSV files (identities, privileged access, Entra roles, credentials, compliance, classifications, drift, activity) + MANIFEST.md — ready for auditor handoff.',
    formats: ['zip'],
    icon: (
      <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M5 8h14M5 8a2 2 0 110-4h14a2 2 0 110 4M5 8v10a2 2 0 002 2h10a2 2 0 002-2V8m-9 4h4" />
      </svg>
    ),
  },
];

const CSV_COLUMNS_MAP: Record<string, typeof IDENTITY_CSV_COLUMNS> = {
  identities: IDENTITY_CSV_COLUMNS,
  compliance: COMPLIANCE_CSV_COLUMNS,
  drift: DRIFT_CSV_COLUMNS,
};

interface SnapshotInfo {
  id: number;
  completed_at: string | null;
  total_identities: number;
}

export default function Exports() {
  const { addToast } = useToast();
  const { withConnection } = useConnection();
  const { user, activeTenantId, activeTenantName } = useAuth();
  const [downloading, setDownloading] = useState<string | null>(null);
  const [lastExported, setLastExported] = useState<Record<string, string>>({});
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [latestSnapshot, setLatestSnapshot] = useState<SnapshotInfo | null>(null);

  const tenantId = activeTenantId ?? user?.tenant_id ?? null;
  const tenantName = activeTenantName ?? user?.tenant_name ?? null;

  useEffect(() => {
    fetch(withConnection('/api/runs'))
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        const runs = data?.runs || data || [];
        if (Array.isArray(runs) && runs.length > 0) {
          setLatestSnapshot({ id: runs[0].id, completed_at: runs[0].completed_at, total_identities: runs[0].total_identities });
        }
      })
      .catch(() => {});
  }, [withConnection]);

  function getMeta() {
    return buildExportMeta(latestSnapshot?.id ?? null, tenantId, tenantName);
  }

  async function handleExport(exportType: string, format: 'csv' | 'json' | 'zip') {
    const dlKey = `${exportType}-${format}`;
    setDownloading(dlKey);
    try {
      const dateParams = (dateFrom && dateTo) ? `&from=${dateFrom}&to=${dateTo}` : '';
      const meta = getMeta();

      if (format === 'zip') {
        const res = await fetch(withConnection(`/api/export/${exportType}`) + dateParams);
        if (!res.ok) {
          const errData = await res.json().catch(() => null);
          throw new Error(errData?.error || `Export failed (${res.status})`);
        }
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `auditgraph_evidence_${new Date().toISOString().slice(0, 10)}.zip`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      } else {
        const res = await fetch(withConnection(`/api/export/${exportType}`) + dateParams);
        if (!res.ok) {
          const errData = await res.json().catch(() => null);
          throw new Error(errData?.error || `Export failed (${res.status})`);
        }
        const data = await res.json();

        if (format === 'json') {
          downloadJSON(data, exportFilename(exportType, 'json'), meta);
        } else {
          const columns = CSV_COLUMNS_MAP[exportType];
          let rows: Record<string, unknown>[] = [];

          if (exportType === 'identities') {
            rows = data.identities || [];
          } else if (exportType === 'compliance') {
            rows = (data.gap_analysis || []).map((g: any) => ({
              framework: g.framework,
              control_id: g.control_id,
              control_name: g.control_name,
              status: g.status,
              current_value: g.current_value,
              threshold: g.threshold,
              detail: g.detail,
            }));
            if (rows.length === 0 && data.all_controls) {
              rows = data.all_controls.map((c: any) => ({
                framework: c.framework,
                control_id: c.control_id,
                control_name: c.control_name,
                status: c.status,
                current_value: c.current_value,
                threshold: c.threshold,
                detail: c.detail,
              }));
            }
          } else if (exportType === 'drift') {
            rows = data.changes || [];
          }

          if (columns) {
            downloadCSV(rows, columns, exportFilename(exportType, 'csv'), meta);
          }
        }
      }

      setLastExported(prev => ({ ...prev, [dlKey]: new Date().toLocaleTimeString() }));
      addToast(`${exportType} exported as ${format.toUpperCase()}`, 'success');
    } catch (e: any) {
      addToast(e?.message || 'Export failed', 'error');
    } finally {
      setDownloading(null);
    }
  }

  return (
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-4">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold" style={{ color: 'var(--text-primary)' }}>Export Center</h2>
        <p className="text-sm mt-1" style={{ color: 'var(--text-secondary)' }}>
          Download identity, compliance, drift, and risk data for auditing, SIEM integration, or offline analysis.
        </p>
      </div>

      {/* Export Metadata Strip */}
      <div className="rounded-xl border px-5 py-4" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-default)' }}>
        <div className="flex items-center gap-2 mb-3">
          <svg className="w-4 h-4 text-blue-500" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <span className="text-xs font-semibold" style={{ color: 'var(--text-primary)' }}>Export Metadata</span>
          <span className="text-[10px] px-1.5 py-0.5 rounded bg-blue-50 text-blue-600 border border-blue-200 font-medium">Included in all exports</span>
        </div>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div>
            <div className="text-[10px] font-medium uppercase tracking-wide mb-0.5" style={{ color: 'var(--text-tertiary, var(--text-secondary))' }}>Snapshot ID</div>
            <div className="text-sm font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>
              {latestSnapshot ? `#${latestSnapshot.id}` : 'Loading...'}
            </div>
          </div>
          <div>
            <div className="text-[10px] font-medium uppercase tracking-wide mb-0.5" style={{ color: 'var(--text-tertiary, var(--text-secondary))' }}>Timestamp</div>
            <div className="text-sm font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>
              {latestSnapshot?.completed_at
                ? new Date(latestSnapshot.completed_at).toLocaleString()
                : new Date().toLocaleString()}
            </div>
          </div>
          <div>
            <div className="text-[10px] font-medium uppercase tracking-wide mb-0.5" style={{ color: 'var(--text-tertiary, var(--text-secondary))' }}>Tenant ID</div>
            <div className="text-sm font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>
              {tenantId ?? 'N/A'}
              {tenantName && <span className="text-xs font-normal ml-1" style={{ color: 'var(--text-secondary)' }}>({tenantName})</span>}
            </div>
          </div>
          <div>
            <div className="text-[10px] font-medium uppercase tracking-wide mb-0.5" style={{ color: 'var(--text-tertiary, var(--text-secondary))' }}>Schema Version</div>
            <div className="text-sm font-semibold font-mono" style={{ color: 'var(--text-primary)' }}>
              v{EXPORT_SCHEMA_VERSION}
            </div>
          </div>
        </div>
      </div>

      {/* Date range filter */}
      <div className="flex items-end gap-4 rounded-xl border px-5 py-3" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-default)' }}>
        <div className="text-xs font-medium" style={{ color: 'var(--text-secondary)' }}>Date Range (optional)</div>
        <div>
          <label className="block text-[10px] font-medium mb-0.5" style={{ color: 'var(--text-secondary)' }}>From</label>
          <input
            type="date"
            value={dateFrom}
            onChange={e => setDateFrom(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg border text-xs"
            style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-default)', color: 'var(--text-primary)' }}
          />
        </div>
        <div>
          <label className="block text-[10px] font-medium mb-0.5" style={{ color: 'var(--text-secondary)' }}>To</label>
          <input
            type="date"
            value={dateTo}
            onChange={e => setDateTo(e.target.value)}
            className="px-2.5 py-1.5 rounded-lg border text-xs"
            style={{ backgroundColor: 'var(--bg-primary)', borderColor: 'var(--border-default)', color: 'var(--text-primary)' }}
          />
        </div>
        {(dateFrom || dateTo) && (
          <button
            onClick={() => { setDateFrom(''); setDateTo(''); }}
            className="text-xs text-blue-600 hover:underline"
          >
            Clear
          </button>
        )}
        {dateFrom && dateTo && (
          <span className="text-[10px] px-2 py-0.5 rounded-full bg-blue-50 text-blue-700 border border-blue-200">
            Exports will use data from {dateFrom} to {dateTo}
          </span>
        )}
      </div>

      {/* Export cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {EXPORT_CARDS.map(card => (
          <div key={card.key} className="rounded-xl border shadow-sm p-6 flex flex-col" style={{ backgroundColor: 'var(--bg-secondary)', borderColor: 'var(--border-default)' }}>
            <div className="flex items-start gap-3 mb-3">
              <div className="p-2 rounded-lg flex-shrink-0" style={{ backgroundColor: 'rgba(59,130,246,0.1)', color: '#3B82F6' }}>
                {card.icon}
              </div>
              <div className="min-w-0">
                <h3 className="text-base font-semibold" style={{ color: 'var(--text-primary)' }}>{card.title}</h3>
                <p className="text-xs mt-0.5 leading-relaxed" style={{ color: 'var(--text-secondary)' }}>{card.description}</p>
              </div>
            </div>

            <div className="mt-auto pt-4 flex items-center gap-2 border-t">
              {card.formats.map(fmt => {
                const dlKey = `${card.key}-${fmt}`;
                const isDownloading = downloading === dlKey;
                const lastTime = lastExported[dlKey];
                return (
                  <button
                    key={fmt}
                    onClick={() => handleExport(card.key, fmt)}
                    disabled={!!downloading}
                    className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition disabled:opacity-50 ${
                      fmt === 'zip'
                        ? 'text-blue-700 bg-blue-50 border-blue-200 hover:bg-blue-100'
                        : fmt === 'json'
                        ? 'text-purple-700 bg-purple-50 border-purple-200 hover:bg-purple-100'
                        : 'text-emerald-700 bg-emerald-50 border-emerald-200 hover:bg-emerald-100'
                    }`}
                  >
                    {isDownloading ? (
                      <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                      </svg>
                    ) : (
                      <svg className="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                      </svg>
                    )}
                    {fmt.toUpperCase()}
                    {lastTime && (
                      <span className="text-[10px] text-gray-400 ml-1">{lastTime}</span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Info */}
      <div className="border rounded-xl p-4 text-xs space-y-1" style={{ backgroundColor: 'var(--bg-tertiary, var(--bg-secondary))', color: 'var(--text-secondary)', borderColor: 'var(--border-default)' }}>
        <p><strong>CSV</strong> format is optimized for spreadsheet import (Excel, Google Sheets). Metadata is prepended as comment rows (# prefix).</p>
        <p><strong>JSON</strong> format includes an <code>_export_metadata</code> envelope with Snapshot ID, Timestamp, Tenant ID, and Schema version.</p>
        <p><strong>ZIP</strong> evidence packages include metadata in the MANIFEST. All exports reflect the latest snapshot data.</p>
      </div>
    </div>
  );
}
