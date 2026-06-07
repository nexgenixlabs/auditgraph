/**
 * BreachCostMethodology — explains where the $ numbers come from.
 *
 * The CISO question: "How did you arrive at the dollar amount?"
 * The answer needs to be one click away from every $ surface.
 *
 * Usage:
 *   <BreachCostMethodologyButton />     // small "ⓘ Methodology" pill
 *   <BreachCostMethodologyModal open onClose ... />
 */
import React, { useState } from 'react';

export function BreachCostMethodologyButton({ compact = false }: { compact?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); setOpen(true); }}
        className={`inline-flex items-center gap-1 text-[10px] uppercase tracking-wider font-semibold
                    text-violet-300 hover:text-violet-200 border border-violet-700/40 rounded px-1.5
                    ${compact ? 'py-0' : 'py-0.5'} transition`}
        title="How is this dollar amount calculated?"
        aria-label="Open breach cost methodology"
      >
        <span aria-hidden="true">ⓘ</span>
        <span>Methodology</span>
      </button>
      {open && <BreachCostMethodologyModal onClose={() => setOpen(false)} />}
    </>
  );
}

export function BreachCostMethodologyModal({ onClose }: { onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-[60] bg-black/70 backdrop-blur-sm flex items-center justify-center p-4"
         onClick={onClose}>
      <div className="bg-[#0f172a] rounded-xl border border-white/10 max-w-3xl w-full max-h-[90vh] overflow-y-auto"
           onClick={e => e.stopPropagation()}>
        <div className="p-5 border-b border-white/5 flex items-start justify-between">
          <div>
            <p className="text-[10px] uppercase tracking-wider text-violet-300 font-bold">Breach Cost Methodology</p>
            <h2 className="text-xl font-bold text-slate-100 mt-1">How AuditGraph quantifies breach exposure in dollars</h2>
            <p className="text-xs text-slate-400 mt-1 max-w-2xl">
              Every dollar amount AuditGraph displays is computed deterministically from public,
              industry-standard cost factors. No model, no fabrication. The math below shows the
              exact formula and source for every classification.
            </p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 text-2xl leading-none"
                  aria-label="Close">×</button>
        </div>

        <div className="p-5 space-y-5 text-sm">
          {/* Formula */}
          <section>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">The formula</p>
            <pre className="bg-slate-900/60 border border-white/5 rounded p-3 text-xs font-mono text-slate-200 leading-relaxed">
exposure_low  = records × factor.low_usd
exposure_mid  = records × factor.mid_usd      ← shown as the headline
exposure_high = records × factor.high_usd
            </pre>
            <p className="text-xs text-slate-400 mt-2">
              <strong className="text-slate-200">Records</strong> = the count of classified records each
              identity can reach via RBAC + Entra directory roles.{' '}
              <strong className="text-slate-200">Factor</strong> = industry cost-per-record from the citations below.
            </p>
          </section>

          {/* Cost factor table */}
          <section>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">
              Cost factors (per record, USD)
            </p>
            <div className="rounded border border-white/5 overflow-hidden">
              <table className="w-full text-xs">
                <thead className="bg-slate-900/60 text-[10px] uppercase tracking-wider text-slate-500">
                  <tr>
                    <th className="text-left px-3 py-2">Class</th>
                    <th className="text-right px-3 py-2">Low</th>
                    <th className="text-right px-3 py-2">Mid</th>
                    <th className="text-right px-3 py-2">High</th>
                    <th className="text-left px-3 py-2">Source</th>
                  </tr>
                </thead>
                <tbody className="font-mono">
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-2 text-rose-300">PHI</td>
                    <td className="px-3 py-2 text-right text-slate-300">$408</td>
                    <td className="px-3 py-2 text-right text-slate-100">$471</td>
                    <td className="px-3 py-2 text-right text-slate-300">$535</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-sans">IBM Cost of a Data Breach 2023 — Healthcare · Ponemon Healthcare 2023</td>
                  </tr>
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-2 text-orange-300">PCI</td>
                    <td className="px-3 py-2 text-right text-slate-300">$180</td>
                    <td className="px-3 py-2 text-right text-slate-100">$303</td>
                    <td className="px-3 py-2 text-right text-slate-300">$429</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-sans">IBM Cost of a Data Breach 2023 — Financial Services · Verizon DBIR 2023</td>
                  </tr>
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-2 text-amber-300">PII</td>
                    <td className="px-3 py-2 text-right text-slate-300">$148</td>
                    <td className="px-3 py-2 text-right text-slate-100">$165</td>
                    <td className="px-3 py-2 text-right text-slate-300">$183</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-sans">IBM Cost of a Data Breach 2023 — global average</td>
                  </tr>
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-2 text-amber-300">FINANCIAL</td>
                    <td className="px-3 py-2 text-right text-slate-300">$180</td>
                    <td className="px-3 py-2 text-right text-slate-100">$303</td>
                    <td className="px-3 py-2 text-right text-slate-300">$429</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-sans">IBM CoDB 2023 Financial Services</td>
                  </tr>
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-2 text-emerald-300">HR</td>
                    <td className="px-3 py-2 text-right text-slate-300">$148</td>
                    <td className="px-3 py-2 text-right text-slate-100">$165</td>
                    <td className="px-3 py-2 text-right text-slate-300">$183</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-sans">IBM CoDB 2023 — PII baseline</td>
                  </tr>
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-2 text-blue-300">SOURCE</td>
                    <td className="px-3 py-2 text-right text-slate-300">$120</td>
                    <td className="px-3 py-2 text-right text-slate-100">$200</td>
                    <td className="px-3 py-2 text-right text-slate-300">$350</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-sans">Verizon DBIR 2023 IP theft incidents · estimated</td>
                  </tr>
                  <tr className="border-t border-white/5">
                    <td className="px-3 py-2 text-slate-300">CONFIDENTIAL</td>
                    <td className="px-3 py-2 text-right text-slate-300">$80</td>
                    <td className="px-3 py-2 text-right text-slate-100">$150</td>
                    <td className="px-3 py-2 text-right text-slate-300">$250</td>
                    <td className="px-3 py-2 text-[10px] text-slate-400 font-sans">IBM CoDB 2023 corporate data avg</td>
                  </tr>
                </tbody>
              </table>
            </div>
            <p className="text-[10px] text-slate-500 mt-2 italic">
              Factors are stored in the <code className="font-mono text-slate-300">breach_cost_factors</code>{' '}
              database table with each row carrying its source citation and effective_year. Regional
              adjustments (US / EU / APAC) and annual refreshes are supported.
            </p>
          </section>

          {/* Worked example */}
          <section>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">Worked example</p>
            <div className="bg-slate-900/60 border border-white/5 rounded p-3 text-xs space-y-2">
              <p className="text-slate-200">
                <strong>demo-ai-copilot-prod</strong> can write to a Cosmos collection containing
                <strong className="text-rose-300"> 120,000 PHI records</strong>.
              </p>
              <p className="text-slate-300 font-mono">
                exposure_low&nbsp; = 120,000 × $408 = <strong className="text-slate-100">$48.96M</strong><br />
                exposure_mid = 120,000 × $471 = <strong className="text-rose-300">$56.52M</strong> ← displayed<br />
                exposure_high = 120,000 × $535 = <strong className="text-slate-100">$64.20M</strong>
              </p>
              <p className="text-slate-400">
                Source: IBM Cost of a Data Breach 2023 — Healthcare vertical, U.S. region, all-cause
                average across confirmed breaches.
              </p>
            </div>
          </section>

          {/* What we don't do */}
          <section>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">What AuditGraph deliberately does NOT do</p>
            <ul className="text-xs text-slate-400 space-y-1 list-disc list-inside">
              <li>Forecast probability of breach. We quantify <em>consequence given compromise</em>, not likelihood.</li>
              <li>Apply ML-derived multipliers. Numbers are deterministic and auditable.</li>
              <li>Sum dollars across overlapping chains. When the same data class is reached by multiple paths, we use the MAX record count to avoid double-counting.</li>
              <li>Hide the source. Every $ on every screen can be traced back to this table.</li>
            </ul>
          </section>

          {/* References */}
          <section>
            <p className="text-[10px] uppercase tracking-wider text-slate-500 font-bold mb-2">Primary references</p>
            <ul className="text-xs text-slate-300 space-y-1">
              <li>• IBM Security — <em>Cost of a Data Breach Report 2023</em> (annual, public)</li>
              <li>• Ponemon Institute — <em>Cost of Healthcare Data Breach Report 2023</em></li>
              <li>• Verizon — <em>Data Breach Investigations Report (DBIR) 2023</em></li>
              <li>• <em>GDPR Enforcement Tracker</em> (gdprhub.eu) — for EU regulatory-fine reference points</li>
              <li>• HHS Office for Civil Rights — <em>HIPAA breach reporting database</em></li>
            </ul>
            <p className="text-[10px] text-slate-500 mt-2 italic">
              Factor values are refreshed annually as new editions of these reports are published.
              The migration that defines the current factor table is{' '}
              <code className="font-mono text-slate-300">backend/migrations/204_breach_cost_factors.sql</code>.
            </p>
          </section>
        </div>

        <div className="p-3 border-t border-white/5 flex justify-end">
          <button onClick={onClose}
                  className="text-xs px-4 py-1.5 rounded bg-violet-700 hover:bg-violet-600 text-white font-semibold">
            Got it
          </button>
        </div>
      </div>
    </div>
  );
}
