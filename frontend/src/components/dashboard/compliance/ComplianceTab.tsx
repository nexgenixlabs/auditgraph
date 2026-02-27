import React, { useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { FONT, ScoreRing, CISOBadge, CISOCard, SectionTitle, DN, ProgressBar } from '../ciso-shared';
import { COLORS, getScoreColor, type TenantData, type ComplianceFramework } from '../../../constants/ciso';

interface ComplianceTabProps {
  d: TenantData;
}

export function ComplianceTab({ d }: ComplianceTabProps) {
  const navigate = useNavigate();
  const grouped = useMemo(() => {
    const groups: Record<string, ComplianceFramework[]> = {};
    d.compliance.frameworks.forEach(fw => {
      if (!groups[fw.type]) groups[fw.type] = [];
      groups[fw.type].push(fw);
    });
    return groups;
  }, [d.compliance.frameworks]);
  const typeIcons: Record<string, string> = { 'Industry': '🏢', 'Benchmark': '📐', 'Core Governance': '🛡️' };

  // Rule 32: detect if all frameworks have the same score
  const allScores = d.compliance.frameworks.map(fw => fw.score);
  const allSameScore = allScores.length > 1 && allScores.every(s => s === allScores[0]);

  // Rule 35: Export CSV handler
  const handleExportAll = useCallback(() => {
    const hasControls = d.compliance.frameworks.some(fw => fw.controls && fw.controls.length > 0);
    if (hasControls) {
      const header = 'Framework,Control ID,Control Name,Status,Severity,Evidence\n';
      const rows = d.compliance.frameworks.flatMap(fw =>
        (fw.controls || []).map(c =>
          `"${fw.name}","${c.id}","${c.name.replace(/"/g, '""')}","${c.status}","${c.severity}","${(c.evidence || '').replace(/"/g, '""')}"`
        )
      ).join('\n');
      const blob = new Blob([header + rows], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'compliance_all_controls.csv'; a.click();
      URL.revokeObjectURL(url);
    } else {
      const header = 'Framework,Type,Score,Total Controls,Failed Controls,Status,Trend\n';
      const rows = d.compliance.frameworks.map(fw =>
        `"${fw.name}","${fw.type}",${fw.score},${fw.totalControls},${fw.failedControls},"${fw.status}",${fw.trend}`
      ).join('\n');
      const blob = new Blob([header + rows], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = 'compliance_frameworks.csv'; a.click();
      URL.revokeObjectURL(url);
    }
  }, [d.compliance.frameworks]);

  const handleExportSingle = useCallback((fw: ComplianceFramework) => {
    if (fw.controls && fw.controls.length > 0) {
      const header = 'Framework,Control ID,Control Name,Status,Severity,Evidence\n';
      const rows = fw.controls.map(c =>
        `"${fw.name}","${c.id}","${c.name.replace(/"/g, '""')}","${c.status}","${c.severity}","${(c.evidence || '').replace(/"/g, '""')}"`
      ).join('\n');
      const blob = new Blob([header + rows], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${fw.id}_compliance_controls.csv`; a.click();
      URL.revokeObjectURL(url);
    } else {
      const header = 'Framework,Type,Score,Total Controls,Failed Controls,Status,Trend\n';
      const row = `"${fw.name}","${fw.type}",${fw.score},${fw.totalControls},${fw.failedControls},"${fw.status}",${fw.trend}`;
      const blob = new Blob([header + row], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `${fw.id}_compliance.csv`; a.click();
      URL.revokeObjectURL(url);
    }
  }, []);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Top bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <span title="This assessment covers identity-related controls only (authentication, authorization, lifecycle). Network, infrastructure, and application controls are not in scope.">
          <CISOBadge label="Identity Controls Only" color={COLORS.accent} />
        </span>
        <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>{d.compliance.frameworks.length} frameworks · All initial assessment</span>
        <button onClick={handleExportAll} style={{
          marginLeft: 'auto', padding: '5px 12px', borderRadius: 5, fontSize: 10, fontWeight: 600,
          background: 'transparent', color: COLORS.textSecondary, border: `1px solid ${COLORS.border}`,
          cursor: 'pointer', fontFamily: FONT.ui,
        }}>Export All</button>
      </div>

      {/* Rule 32: Informational note about identical scores */}
      {allSameScore && (
        <div style={{
          background: COLORS.accentSoft, border: `1px solid ${COLORS.accent}2e`,
          borderRadius: 8, padding: '10px 14px', fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui,
          lineHeight: 1.5,
        }}>
          All frameworks currently share the same score ({allScores[0]}/100). This is expected for initial assessments — scores will diverge as framework-specific controls are evaluated over subsequent snapshots.
        </div>
      )}

      {/* Framework Groups */}
      {Object.entries(grouped).map(([type, frameworks]) => (
        <div key={type}>
          <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, marginBottom: 10, fontFamily: FONT.ui }}>
            {typeIcons[type] || '📋'} {type} ({frameworks.length})
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
            {frameworks.map(fw => (
              <CISOCard key={fw.id} style={{ padding: '14px 16px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <ScoreRing score={fw.score} size={44} strokeWidth={3} color={getScoreColor(fw.score)} />
                  <div style={{ flex: 1 }}>
                    <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{fw.name}</div>
                    <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                      <DN navigateTo="/compliance">{fw.totalControls}</DN> controls · <DN navigateTo="/identities?risk=critical,high">{fw.failedControls}</DN> failures
                    </div>
                  </div>
                </div>
                <ProgressBar value={fw.score} color={getScoreColor(fw.score)} height={4} />
                <div style={{ display: 'flex', gap: 6, marginTop: 10 }}>
                  <button onClick={() => handleExportSingle(fw)} style={{
                    flex: 1, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600,
                    background: 'transparent', color: COLORS.textSecondary, border: `1px solid ${COLORS.border}`,
                    cursor: 'pointer', fontFamily: FONT.ui,
                  }}>Export</button>
                  <button onClick={() => navigate(`/compliance?framework=${encodeURIComponent(fw.name)}`)} style={{
                    flex: 1, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 600,
                    background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                    cursor: 'pointer', fontFamily: FONT.ui,
                  }}>Details</button>
                </div>
              </CISOCard>
            ))}
          </div>
        </div>
      ))}

      {/* Bottom: Maturity + Progress */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        <CISOCard>
          <SectionTitle>Control Maturity</SectionTitle>
          {Object.entries(d.compliance.maturity).map(([key, val]) => (
            <div key={key} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: `1px solid ${COLORS.border}` }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>● {key.charAt(0).toUpperCase() + key.slice(1)}</span>
              <DN navigateTo="/compliance"><span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: COLORS.text }}>{val}</span></DN>
            </div>
          ))}
        </CISOCard>
        <CISOCard>
          <SectionTitle>Progress</SectionTitle>
          <div style={{ marginBottom: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>Remediation Progress</span>
              <DN navigateTo="/remediation"><span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{d.compliance.progress.remediation}%</span></DN>
            </div>
            <ProgressBar value={d.compliance.progress.remediation} color={COLORS.accent} />
          </div>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
              <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>IA Governance</span>
              <DN navigateTo="/service-accounts"><span style={{ fontSize: 11, fontFamily: FONT.mono, color: COLORS.text }}>{d.compliance.progress.iaGovernance}%</span></DN>
            </div>
            <ProgressBar value={d.compliance.progress.iaGovernance} color={COLORS.warning} />
          </div>
        </CISOCard>
      </div>
    </div>
  );
}
