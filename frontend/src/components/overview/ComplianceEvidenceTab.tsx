import React, { useState } from 'react';
import {
  TenantData, Nav, Framework,
  F, P,
  Card, SectionTitle, MiniProgressBar,
  DrillableNumber, ComplianceFrameworkCard,
} from './overview-shared';

export function ComplianceEvidenceTab({ d, nav, openDrill, setActiveTab, openComplianceDetail, openExportMenu }: {
  d: TenantData; nav: Nav;
  openDrill: (title: string, filterUrl: string) => void;
  setActiveTab: (tab: string) => void;
  openComplianceDetail: (fw: Framework) => void;
  openExportMenu: (fw: Framework, rect: DOMRect) => void;
}) {
  const catIcons: Record<string, string> = { Privacy: '\uD83D\uDD12', Benchmark: '\uD83D\uDCCA', Industry: '\uD83C\uDFE5', 'Core Governance': '\uD83D\uDEE1' };
  const [collapsed, setCollapsed] = useState<Record<string, boolean>>({});
  const toggleCat = (cat: string) => setCollapsed(prev => ({ ...prev, [cat]: !prev[cat] }));
  const [highlightedMaturity, setHighlightedMaturity] = useState<string | null>(null);

  return (
    <div>
      <Card style={{ marginBottom: 16 }}>
        <SectionTitle right={<span style={{ fontFamily: F.data, fontSize: 9, color: P.accentIndigo, background: P.accentIndigoSubtle, padding: '2px 8px', borderRadius: 4 }}>Identity Controls Only</span>}>
          Compliance Posture
        </SectionTitle>
        {Object.entries(d.compliance.frameworks).map(([cat, fws]) => (
          <div key={cat} style={{ marginBottom: 20 }}>
            <div onClick={() => toggleCat(cat)}
              style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 10, display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', userSelect: 'none' }}>
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim, transition: 'transform 0.2s', display: 'inline-block',
                transform: collapsed[cat] ? 'rotate(0deg)' : 'rotate(90deg)' }}>&#9654;</span>
              <span>{catIcons[cat] || '\uD83D\uDCCB'}</span> {cat}
              <span style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint }}>({fws.length})</span>
            </div>
            {!collapsed[cat] && (
              <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(fws.length, 4)}, 1fr)`, gap: 12 }}>
                {fws.map((fw, i) => (
                  <ComplianceFrameworkCard key={i} fw={fw}
                    onOpenDetail={() => openComplianceDetail(fw)}
                    onOpenExport={(rect) => openExportMenu(fw, rect)}
                    onDrillFailing={() => {
                      const evIds = fw.controls.filter(c => c.status !== 'pass').flatMap(c => c.evidenceIdentities);
                      if (evIds.length > 0) openDrill(`${fw.name} — Failing Identities`, '/identities?risk_level=critical');
                      else openDrill(`${fw.name} — Failing Identities`, '/identities');
                    }}
                  />
                ))}
              </div>
            )}
          </div>
        ))}
      </Card>

      {/* Control Maturity + Progress */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
        <Card>
          <SectionTitle>Control Maturity</SectionTitle>
          {[
            { l: 'Preventive', v: d.compliance.controlMaturity.preventive, color: '#22c55e' },
            { l: 'Detective', v: d.compliance.controlMaturity.detective, color: '#3b82f6' },
            { l: 'Compensating', v: d.compliance.controlMaturity.compensating, color: '#eab308' },
            { l: 'Missing', v: d.compliance.controlMaturity.missing, color: '#ff4444' },
          ].map((m, i) => (
            <div key={i}
              onClick={() => setHighlightedMaturity(highlightedMaturity === m.l ? null : m.l)}
              style={{
                display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10, cursor: 'pointer',
                padding: '4px 8px', borderRadius: 6, transition: 'background 0.15s',
                background: highlightedMaturity === m.l ? P.accentIndigoFaint : 'transparent',
              }}
              onMouseEnter={e => { if (highlightedMaturity !== m.l) e.currentTarget.style.background = P.bgActive; }}
              onMouseLeave={e => { if (highlightedMaturity !== m.l) e.currentTarget.style.background = 'transparent'; }}
            >
              <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: m.color }} />
              <span style={{ fontFamily: F.ui, fontSize: 12, color: P.textSub, flex: 1 }}>{m.l}</span>
              <span style={{ fontFamily: F.data, fontSize: 14, fontWeight: 700, color: P.textBright }}>{m.v}</span>
            </div>
          ))}
        </Card>
        <Card>
          <SectionTitle>Progress &amp; Governance</SectionTitle>
          <div style={{ marginBottom: 16, cursor: 'pointer' }} onClick={() => setActiveTab('action')}>
            <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 4 }}>Remediation Progress</div>
            <MiniProgressBar value={d.compliance.remediationProgress} color={P.accentStrong} height={8} />
            <span style={{ fontFamily: F.data, fontSize: 12, color: P.textLight }}><DrillableNumber value={`${d.compliance.remediationProgress}%`} label="Remediation progress" onClick={() => setActiveTab('action')} /></span>
          </div>
          <div style={{ cursor: 'pointer' }} onClick={() => setActiveTab('governance')}>
            <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginBottom: 4 }}>SA Governance</div>
            <MiniProgressBar value={d.compliance.saGovernance} color="#eab308" height={8} />
            <span style={{ fontFamily: F.data, fontSize: 12, color: P.textLight }}><DrillableNumber value={`${d.compliance.saGovernance}%`} label="SA Governance" onClick={() => setActiveTab('governance')} /></span>
          </div>
        </Card>
      </div>
    </div>
  );
}
