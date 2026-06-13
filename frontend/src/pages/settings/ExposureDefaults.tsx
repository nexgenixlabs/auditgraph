/**
 * AG-193 follow-up (2026-06-12) — Per-asset exposure defaults
 *
 * Lets a tenant override the four IBM 2024 baselines used by
 * /api/dashboard/business-impact to compute Potential Exposure Impact.
 * Reuses the generic /api/settings GET/POST endpoint; backend
 * defaults to IBM 2024 when these keys are unset or non-numeric.
 *
 * URL: /settings/exposure-defaults
 * Discoverable from: DerivationDrawer "Edit per-asset defaults →"
 *                    Data Trust Zones "↗ Exposure Defaults" pill
 */
import React, { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

const IBM_DEFAULTS = {
  exposure_phi_per_asset:  720_000,
  exposure_pci_per_asset: 1_200_000,
  exposure_pii_per_asset:  540_000,
  exposure_ai_per_asset:  1_400_000,
};

const ROWS: { key: keyof typeof IBM_DEFAULTS; label: string; color: string; hint: string }[] = [
  { key: 'exposure_phi_per_asset', label: 'PHI Assets',  color: '#dc2626', hint: 'IBM 2024 healthcare/PHI median breach cost per record set' },
  { key: 'exposure_pci_per_asset', label: 'PCI Assets',  color: '#ea580c', hint: 'IBM 2024 financial/PCI median' },
  { key: 'exposure_pii_per_asset', label: 'PII Assets',  color: '#d97706', hint: 'IBM 2024 generic PII median' },
  { key: 'exposure_ai_per_asset',  label: 'AI Models',   color: '#a855f7', hint: 'AI deployment compromise estimate (proprietary)' },
];

function fmtUsd(v: number): string {
  return v.toLocaleString('en-US', { style: 'currency', currency: 'USD', maximumFractionDigits: 0 });
}

export default function ExposureDefaults() {
  const [values, setValues] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savedAt, setSavedAt] = useState<number | null>(null);

  useEffect(() => {
    fetch('/api/settings')
      .then(r => r.ok ? r.json() : null)
      .then(d => {
        const s = (d && d.settings) || {};
        setValues({
          exposure_phi_per_asset: s.exposure_phi_per_asset || '',
          exposure_pci_per_asset: s.exposure_pci_per_asset || '',
          exposure_pii_per_asset: s.exposure_pii_per_asset || '',
          exposure_ai_per_asset:  s.exposure_ai_per_asset  || '',
        });
        setLoading(false);
      })
      .catch(() => setLoading(false));
  }, []);

  async function save() {
    setSaving(true);
    try {
      const body: Record<string, string> = {};
      for (const r of ROWS) {
        const raw = (values[r.key] || '').toString().trim();
        if (raw) body[r.key] = raw;  // empty -> backend falls back to IBM
        else     body[r.key] = '';   // explicit clear
      }
      const res = await fetch('/api/settings', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (res.ok) setSavedAt(Date.now());
    } finally {
      setSaving(false);
    }
  }

  function resetAllToDefaults() {
    if (!window.confirm('Reset all four per-asset values to IBM 2024 defaults?')) return;
    setValues({
      exposure_phi_per_asset: '',
      exposure_pci_per_asset: '',
      exposure_pii_per_asset: '',
      exposure_ai_per_asset:  '',
    });
  }

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-6">
      <div>
        <p className="text-[10px] uppercase tracking-[0.2em] font-bold text-violet-400">Platform · Settings</p>
        <h1 className="text-2xl font-bold text-white mt-1">Exposure Defaults</h1>
        <p className="text-sm text-slate-400 mt-2 max-w-2xl leading-relaxed">
          Per-asset dollar values used to compute Potential Exposure Impact across the
          dashboard. Defaults come from the IBM Cost of a Data Breach Report 2024.
          Override here for tenant-specific benchmarks (industry, region, contract penalties).
        </p>
        <p className="text-[11px] text-slate-500 mt-2">
          Used by{' '}
          <Link to="/" className="text-violet-400 hover:underline">CISO Dashboard</Link>,{' '}
          <Link to="/exposure-explorer" className="text-violet-400 hover:underline">Exposure Explorer</Link>, and the{' '}
          <Link to="/data-classification" className="text-violet-400 hover:underline">Classified Resources</Link> drawer.
        </p>
      </div>

      <div className="rounded-xl bg-[#0f172a]/80 border border-white/5 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-800/40 border-b border-slate-700/40">
            <tr>
              <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Class</th>
              <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">IBM Default</th>
              <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Your Override</th>
              <th className="text-left p-3 text-[10px] uppercase tracking-wider font-bold text-slate-400">Notes</th>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr><td colSpan={4} className="p-6 text-center text-[11px] text-slate-500">Loading…</td></tr>
            )}
            {!loading && ROWS.map(r => {
              const def = IBM_DEFAULTS[r.key];
              const overrideRaw = values[r.key] || '';
              const overrideN = parseInt(overrideRaw.replace(/[^0-9]/g, ''), 10);
              return (
                <tr key={r.key} className="border-b border-slate-800/40 last:border-0">
                  <td className="p-3">
                    <span className="inline-flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full" style={{ background: r.color }} />
                      <span className="text-slate-200 font-semibold">{r.label}</span>
                    </span>
                  </td>
                  <td className="p-3 text-slate-400 font-mono">{fmtUsd(def)}</td>
                  <td className="p-3">
                    <div className="relative inline-block">
                      <span className="absolute left-2 top-1/2 -translate-y-1/2 text-slate-500 text-xs">$</span>
                      <input
                        type="text"
                        inputMode="numeric"
                        placeholder="(uses default)"
                        value={overrideRaw}
                        onChange={e => setValues(v => ({ ...v, [r.key]: e.target.value.replace(/[^0-9,]/g, '') }))}
                        className="bg-slate-900 border border-slate-700 rounded-lg pl-5 pr-2 py-1.5 text-xs text-white font-mono w-44 focus:outline-none focus:border-violet-500"
                      />
                    </div>
                    {overrideRaw && Number.isFinite(overrideN) && overrideN > 0 && (
                      <span className="block text-[10px] text-emerald-400 mt-1">= {fmtUsd(overrideN)}</span>
                    )}
                  </td>
                  <td className="p-3 text-[11px] text-slate-500 max-w-xs">{r.hint}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="rounded-xl bg-slate-800/30 border border-slate-700/40 p-4">
        <p className="text-[10px] uppercase tracking-wider font-bold text-slate-400">Honest claim</p>
        <p className="text-[11px] text-slate-400 mt-1 leading-relaxed">
          This is a benchmark used to prioritize remediation, not an actuarial loss model.
          AuditGraph does not estimate breach probability or insurance-grade loss. Leave a
          field blank to use the IBM 2024 baseline.
        </p>
      </div>

      <div className="flex items-center justify-between">
        <button
          onClick={resetAllToDefaults}
          className="text-[11px] text-slate-500 hover:text-slate-300 underline">
          Reset all to IBM defaults
        </button>
        <div className="flex items-center gap-3">
          {savedAt && (
            <span className="text-[11px] text-emerald-400">Saved · changes apply on next dashboard load</span>
          )}
          <button
            onClick={save}
            disabled={saving || loading}
            className="px-4 py-1.5 rounded-lg text-xs font-bold bg-violet-500 hover:bg-violet-400 disabled:opacity-50 disabled:cursor-not-allowed text-white">
            {saving ? 'Saving…' : 'Save'}
          </button>
        </div>
      </div>
    </div>
  );
}
