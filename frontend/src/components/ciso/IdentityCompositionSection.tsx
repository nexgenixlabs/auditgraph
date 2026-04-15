import React, { useMemo } from 'react';
import type { CISOViewModel } from '../../utils/cisoViewModel';
import { DN, InsightSentence } from '../dashboard/ciso-shared';
import { TAG_CLS } from '../../constants/cisoColors';

function buildConicGradient(cats: CISOViewModel['identity_categories']): string {
  const total = cats.reduce((s, c) => s + c.count, 0);
  if (total === 0) return '#1c2d4a';
  let cumDeg = 0;
  const stops = cats.map(c => {
    const start = cumDeg;
    cumDeg += (c.count / total) * 360;
    return `${c.chart_color} ${start}deg ${cumDeg}deg`;
  });
  return `conic-gradient(${stops.join(', ')})`;
}

export default function IdentityCompositionSection({ vm }: { vm: CISOViewModel }) {
  const cats = vm.identity_categories;
  const total = vm.total_identities;
  const insights = vm.composition_insights;

  const donutCats = useMemo(() => {
    const human = cats.find(c => c.label === 'Human Identities');
    const guest = cats.find(c => c.label === 'Guest Users');
    const nhiLabels = new Set(['Non-Human / SPNs', 'System MSIs', 'User-Assigned MSIs']);
    const nhiItems = cats.filter(c => nhiLabels.has(c.label));
    const nhiCount = nhiItems.reduce((s, c) => s + c.count, 0);
    const result: typeof cats = [];
    if (human) result.push(human);
    if (nhiCount > 0) {
      const nhiPct = total > 0 ? Math.round((nhiCount / total) * 1000) / 10 : 0;
      result.push({
        label: 'Non-Human Identities', count: nhiCount, pct: nhiPct,
        issues: [`${nhiCount} non-human identities`],
        tag: nhiItems[0]?.tag || { text: 'Tracked', variant: 'teal' },
        accent: '#24A2A1', chart_color: '#24A2A1', nav: '/workload-identities',
      });
    }
    if (guest) result.push(guest);
    return result;
  }, [cats, total]);

  if (cats.length === 0) {
    return (
      <section className="bg-[#111827] border border-white/5 rounded-lg p-4">
        <span className="text-sm font-semibold text-gray-200">Identity Composition</span>
        <p className="text-xs text-gray-400 mt-3">No identity data available.</p>
      </section>
    );
  }

  return (
    <section className="bg-[#111827] border border-white/5 rounded-lg overflow-hidden">
      <div className="p-4 border-b border-white/5 flex justify-between items-center">
        <span className="text-sm font-semibold text-gray-200">Identity Composition</span>
        <DN navigateTo={vm.total_identities_nav}>
          <span className="text-xs font-mono text-gray-400">{total.toLocaleString()} total</span>
        </DN>
      </div>

      <div className="grid gap-3 p-4" style={{ gridTemplateColumns: '160px 1fr' }}>
        <div className="flex flex-col items-center gap-3">
          <div className="relative w-[140px] h-[140px]">
            <div className="absolute inset-0 rounded-full" style={{ background: buildConicGradient(donutCats) }} />
            <div className="absolute rounded-full bg-[#111827]" style={{ inset: '20%' }} />
            <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ pointerEvents: 'none' }}>
              <DN navigateTo={vm.total_identities_nav}>
                <span className="text-2xl font-semibold text-gray-100 leading-none" style={{ pointerEvents: 'auto' }}>{total.toLocaleString()}</span>
              </DN>
              <span className="text-xs text-gray-400 mt-0.5">identities</span>
            </div>
          </div>
          <div className="space-y-1 w-full">
            {donutCats.map(c => (
              <DN key={c.label} navigateTo={c.nav}>
                <div className="flex items-center gap-1.5 py-0.5 cursor-pointer hover:opacity-80 transition">
                  <span className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: c.chart_color }} />
                  <span className="text-xs text-gray-400 flex-1 truncate">{c.label}</span>
                  <span className="text-xs font-mono text-gray-200">{c.count}</span>
                </div>
              </DN>
            ))}
          </div>
        </div>

        <div>
          <div className="grid grid-cols-2 gap-3">
            {cats.map(c => (
              <DN key={c.label} navigateTo={c.nav}>
                <div className="relative bg-[#0B1220] border border-white/5 rounded-lg p-3 overflow-hidden hover:border-white/10 transition cursor-pointer">
                  <div className="text-xs text-gray-400 uppercase tracking-wider font-medium mb-1">{c.label}</div>
                  <div className="text-xl font-semibold text-gray-100 leading-none">{c.count}</div>
                  <div className="text-xs text-gray-400 mt-1">
                    {c.issues.map((line, i) => <React.Fragment key={i}>{i > 0 && <br />}{line}</React.Fragment>)}
                  </div>
                  <span className={`inline-block mt-1 text-xs font-medium px-1.5 py-0.5 rounded-full ${TAG_CLS[c.tag.variant] || TAG_CLS.teal}`}>
                    {c.tag.text}
                  </span>
                  <div className="absolute bottom-0 inset-x-0 h-0.5" style={{ backgroundColor: c.accent }} />
                </div>
              </DN>
            ))}
          </div>
          {insights.length > 0 && (
            <div className="mt-3 border-t border-white/5 pt-3">
              {insights.map((s, i) => <InsightSentence key={i}>{s}</InsightSentence>)}
            </div>
          )}
        </div>
      </div>
    </section>
  );
}
