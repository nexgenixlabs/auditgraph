import React, { useState } from 'react';
import { useToast } from '../components/ToastProvider';
import {
  downloadCSV, downloadJSON, exportFilename,
  IDENTITY_CSV_COLUMNS, COMPLIANCE_CSV_COLUMNS, DRIFT_CSV_COLUMNS,
} from '../utils/exportUtils';

interface ExportCard {
  key: string;
  title: string;
  description: string;
  formats: ('csv' | 'json')[];
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
];

const CSV_COLUMNS_MAP: Record<string, typeof IDENTITY_CSV_COLUMNS> = {
  identities: IDENTITY_CSV_COLUMNS,
  compliance: COMPLIANCE_CSV_COLUMNS,
  drift: DRIFT_CSV_COLUMNS,
};

export default function Exports() {
  const { addToast } = useToast();
  const [downloading, setDownloading] = useState<string | null>(null);
  const [lastExported, setLastExported] = useState<Record<string, string>>({});

  async function handleExport(exportType: string, format: 'csv' | 'json') {
    const dlKey = `${exportType}-${format}`;
    setDownloading(dlKey);
    try {
      const res = await fetch(`/api/export/${exportType}`);
      if (!res.ok) {
        const errData = await res.json().catch(() => null);
        throw new Error(errData?.error || `Export failed (${res.status})`);
      }
      const data = await res.json();

      if (format === 'json') {
        downloadJSON(data, exportFilename(exportType, 'json'));
      } else {
        // CSV: flatten appropriately
        const columns = CSV_COLUMNS_MAP[exportType];
        let rows: Record<string, unknown>[] = [];

        if (exportType === 'identities') {
          rows = data.identities || [];
        } else if (exportType === 'compliance') {
          rows = (data.gap_analysis || []).map((g: any) => ({
            framework: g.framework_name,
            control_id: g.control_id,
            control_name: g.control_name,
            status: g.status,
            current_value: g.value,
            threshold: g.pass_threshold,
            detail: g.detail,
          }));
          // If no gaps, export all controls
          if (rows.length === 0 && data.all_controls) {
            rows = data.all_controls.map((c: any) => ({
              framework: c.framework_name,
              control_id: c.control_id,
              control_name: c.control_name,
              status: c.status,
              current_value: c.value,
              threshold: c.pass_threshold,
              detail: c.detail,
            }));
          }
        } else if (exportType === 'drift') {
          rows = data.changes || [];
        }

        if (columns) {
          downloadCSV(rows, columns, exportFilename(exportType, 'csv'));
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
    <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Export Center</h2>
        <p className="text-sm text-gray-500 mt-1">
          Download identity, compliance, drift, and risk data for auditing, SIEM integration, or offline analysis.
        </p>
      </div>

      {/* Export cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {EXPORT_CARDS.map(card => (
          <div key={card.key} className="bg-white rounded-xl border shadow-sm p-6 flex flex-col">
            <div className="flex items-start gap-3 mb-3">
              <div className="p-2 bg-blue-50 text-blue-600 rounded-lg flex-shrink-0">
                {card.icon}
              </div>
              <div className="min-w-0">
                <h3 className="text-base font-semibold text-gray-900">{card.title}</h3>
                <p className="text-xs text-gray-500 mt-0.5 leading-relaxed">{card.description}</p>
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
                      fmt === 'json'
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
      <div className="bg-gray-50 border rounded-xl p-4 text-xs text-gray-500 space-y-1">
        <p><strong>CSV</strong> format is optimized for spreadsheet import (Excel, Google Sheets). Compliance CSV exports gap analysis controls.</p>
        <p><strong>JSON</strong> format includes full structured data suitable for SIEM, GRC platforms, or programmatic consumption.</p>
        <p>All exports reflect the latest discovery run data. Export events are recorded in the activity log.</p>
      </div>
    </div>
  );
}
