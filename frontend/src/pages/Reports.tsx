import React, { useState } from 'react';
import { generateReport, generateExecutiveReport, generateComplianceReport } from '../utils/pdfGenerator';
import { useToast } from '../components/ToastProvider';

type ReportType = 'full' | 'executive' | 'compliance';

export default function Reports() {
  const { addToast } = useToast();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [clientName, setClientName] = useState('');
  const [lastGenerated, setLastGenerated] = useState<string | null>(null);
  const [previewData, setPreviewData] = useState<any>(null);
  const [reportType, setReportType] = useState<ReportType>('full');

  async function handleGenerate() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch('/api/reports/data');
      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setPreviewData(data);
      if (reportType === 'executive') {
        generateExecutiveReport(data, clientName || undefined);
      } else if (reportType === 'compliance') {
        let asData = null;
        try { const r = await fetch('/api/overview/attack-surface-score'); if (r.ok) asData = await r.json(); } catch {}
        generateComplianceReport(data, asData, clientName || undefined);
      } else {
        generateReport(data, clientName || undefined);
      }
      setLastGenerated(new Date().toLocaleString());
      addToast('Report generated successfully', 'success');
    } catch (e: any) {
      const msg = e?.message || 'Failed to generate report';
      setError(msg);
      addToast(msg, 'error');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-2xl font-bold text-gray-900">Reports</h2>
        <p className="text-sm text-gray-600 mt-1">
          Generate professional security audit reports for client delivery
        </p>
      </div>

      {/* Report Type Selector */}
      <div className="flex items-center gap-2 bg-gray-100 rounded-lg p-1 w-fit">
        <button
          onClick={() => setReportType('full')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition ${
            reportType === 'full' ? 'bg-white text-blue-700 shadow-sm' : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          Full Audit Report
        </button>
        <button
          onClick={() => setReportType('executive')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition ${
            reportType === 'executive' ? 'bg-white text-blue-700 shadow-sm' : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          Executive Summary
        </button>
        <button
          onClick={() => setReportType('compliance')}
          className={`px-4 py-2 rounded-md text-sm font-medium transition ${
            reportType === 'compliance' ? 'bg-white text-blue-700 shadow-sm' : 'text-gray-600 hover:text-gray-900'
          }`}
        >
          Compliance Report
        </button>
      </div>

      {/* Report Configuration */}
      <div className="bg-white rounded-xl border shadow-sm p-6 space-y-6">
        <div className="text-lg font-semibold text-gray-900">
          {reportType === 'executive' ? 'Executive Posture Report' : reportType === 'compliance' ? 'Compliance Report' : 'Generate Security Report'}
        </div>
        {reportType === 'executive' && (
          <div className="bg-indigo-50 border border-indigo-200 rounded-lg px-4 py-3 text-xs text-indigo-700">
            One-page landscape PDF for board presentations with posture score, key metrics, and trend summary.
          </div>
        )}
        {reportType === 'compliance' && (
          <div className="bg-emerald-50 border border-emerald-200 rounded-lg px-4 py-3 text-xs text-emerald-700">
            Multi-page PDF with attack surface score breakdown, SOC2/CIS/HIPAA/NIST framework mapping, credential health, and top risk identities.
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Client name input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Client / Organization Name
            </label>
            <input
              type="text"
              value={clientName}
              onChange={e => setClientName(e.target.value)}
              placeholder="e.g., Acme Corp"
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <p className="text-xs text-gray-400 mt-1">
              Appears on the cover page of the PDF report
            </p>
          </div>

          {/* Report scope */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Report Scope
            </label>
            <div className="px-3 py-2 border border-gray-200 rounded-lg bg-gray-50 text-sm text-gray-600">
              Latest discovery run (all identities)
            </div>
            <p className="text-xs text-gray-400 mt-1">
              Includes all critical and high risk identities with remediations
            </p>
          </div>
        </div>

        {/* Report contents preview */}
        <div>
          <div className="text-sm font-medium text-gray-700 mb-3">Report Contents</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              { icon: 'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z', label: 'Cover Page', desc: 'Branding + date' },
              { icon: 'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z', label: 'Executive Summary', desc: 'Posture score + risk breakdown' },
              { icon: 'M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z', label: 'Compliance', desc: 'SOC2, HIPAA, PCI-DSS, NIST' },
              { icon: 'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z', label: 'Top Risks', desc: 'Critical/High identities' },
              { icon: 'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z', label: 'Credential Health', desc: 'Expired + expiring credentials' },
              { icon: 'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z', label: 'CA Coverage', desc: 'MFA enforcement status' },
              { icon: 'M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z', label: 'Remediation Playbook', desc: 'Prioritized fix actions' },
              { icon: 'M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z', label: 'Evidence', desc: 'Data sources + methodology' },
            ].map((item, idx) => (
              <div key={idx} className="bg-gray-50 rounded-xl p-3 border">
                <div className="flex items-center gap-2 mb-1">
                  <svg className="w-4 h-4 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d={item.icon} />
                  </svg>
                  <span className="text-xs font-semibold text-gray-900">{item.label}</span>
                </div>
                <div className="text-[10px] text-gray-500">{item.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Generate button */}
        <div className="flex items-center gap-4">
          <button
            onClick={handleGenerate}
            disabled={loading}
            className={`px-6 py-3 rounded-xl text-sm font-semibold text-white transition ${
              loading
                ? 'bg-gray-400 cursor-not-allowed'
                : 'bg-blue-600 hover:bg-blue-700 shadow-sm'
            }`}
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Generating...
              </span>
            ) : (
              <span className="flex items-center gap-2">
                <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 10v6m0 0l-3-3m3 3l3-3m2 8H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
                Generate PDF Report
              </span>
            )}
          </button>

          {lastGenerated && (
            <span className="text-xs text-green-600">
              Last generated: {lastGenerated}
            </span>
          )}
        </div>

        {error && (
          <div className="bg-red-50 border border-red-200 rounded-xl p-4 text-sm text-red-700">
            {error}
          </div>
        )}
      </div>

      {/* Preview data stats (shown after first generation) */}
      {previewData && (
        <div className="bg-white rounded-xl border shadow-sm p-6 space-y-4">
          <div className="text-lg font-semibold text-gray-900">Report Data Preview</div>

          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <div className="bg-gray-50 rounded-xl p-4 text-center">
              <div className="text-xl font-bold text-gray-900">{previewData.stats?.total_identities || 0}</div>
              <div className="text-xs text-gray-500 mt-1">Total Identities</div>
            </div>
            <div className="bg-red-50 rounded-xl p-4 text-center">
              <div className="text-xl font-bold text-red-700">{previewData.stats?.critical || 0}</div>
              <div className="text-xs text-red-600 mt-1">Critical</div>
            </div>
            <div className="bg-orange-50 rounded-xl p-4 text-center">
              <div className="text-xl font-bold text-orange-700">{previewData.stats?.high || 0}</div>
              <div className="text-xs text-orange-600 mt-1">High</div>
            </div>
            <div className="bg-blue-50 rounded-xl p-4 text-center">
              <div className="text-xl font-bold text-blue-700">{previewData.top_risks?.length || 0}</div>
              <div className="text-xs text-blue-600 mt-1">Top Risks in Report</div>
            </div>
            <div className="bg-purple-50 rounded-xl p-4 text-center">
              <div className="text-xl font-bold text-purple-700">{previewData.remediation_summary?.total_actions || 0}</div>
              <div className="text-xs text-purple-600 mt-1">Remediation Actions</div>
            </div>
          </div>

          {/* Remediation breakdown */}
          {previewData.remediation_summary && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
              <div>
                <div className="text-sm font-medium text-gray-700 mb-2">By Category</div>
                <div className="space-y-1.5">
                  {Object.entries(previewData.remediation_summary.by_category as Record<string, number>).map(([cat, count]) => (
                    <div key={cat} className="flex items-center justify-between bg-gray-50 rounded-lg px-3 py-2">
                      <span className="text-xs text-gray-700 capitalize">{cat.replace(/_/g, ' ')}</span>
                      <span className="text-xs font-semibold text-gray-900">{count}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-sm font-medium text-gray-700 mb-2">By Impact</div>
                <div className="space-y-1.5">
                  {Object.entries(previewData.remediation_summary.by_impact as Record<string, number>).map(([impact, count]) => {
                    const colors: Record<string, string> = {
                      critical: 'bg-red-50 text-red-700',
                      high: 'bg-orange-50 text-orange-700',
                      medium: 'bg-yellow-50 text-yellow-700',
                      low: 'bg-green-50 text-green-700',
                    };
                    return (
                      <div key={impact} className={`flex items-center justify-between rounded-lg px-3 py-2 ${colors[impact] || 'bg-gray-50 text-gray-700'}`}>
                        <span className="text-xs capitalize font-medium">{impact}</span>
                        <span className="text-xs font-semibold">{count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
