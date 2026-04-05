import React, { useState, useCallback } from 'react';
import { useConnection } from '../../contexts/ConnectionContext';
import {
  TenantData, Nav,
  F, P,
  getRiskPerDay,
  Card, SectionTitle, SystemActionChip, AutomationBadge,
  RollbackBadge, DrillableNumber, ProductionBadge, MiniProgressBar,
} from './overview-shared';

export function ActionPlanTab({ d, nav }: { d: TenantData; nav: Nav }) {
  const identityRemediations = d.remediations.filter(r => r.type === 'identity-remediation' && r.gain > 0);
  const [scanTriggered, setScanTriggered] = useState(false);
  const { withConnection, selectedConnectionId } = useConnection();

  const triggerScan = useCallback(() => {
    if (scanTriggered) return;
    setScanTriggered(true);
    const payload: Record<string, unknown> = {};
    if (selectedConnectionId) payload.connection_id = selectedConnectionId;
    fetch(withConnection('/api/runs/trigger'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })
      .then(r => { if (!r.ok) throw new Error('Failed'); })
      .catch(() => setScanTriggered(false));
  }, [scanTriggered, withConnection, selectedConnectionId]);

  return (
    <div>
      {/* System Actions Bar */}
      {d.systemActions.length > 0 && (
        <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
          {d.systemActions.map(sa => (
            <SystemActionChip key={sa.id} action={sa}
              onTrigger={sa.id === 'run-scan' && !scanTriggered ? triggerScan : undefined} />
          ))}
        </div>
      )}

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <SectionTitle>Highest Impact Remediations</SectionTitle>
        <span style={{ fontFamily: F.data, fontSize: 13, color: '#22c55e', fontWeight: 700 }}>Potential Gain: +{d.riskScore.potentialGain} pts</span>
      </div>

      {/* Empty state when no identity remediations */}
      {!identityRemediations.length && (
        <Card style={{ textAlign: 'center', padding: 40 }}>
          <div style={{ fontSize: 32, marginBottom: 12, opacity: 0.3 }}>{'\uD83D\uDD0D'}</div>
          <div style={{ fontFamily: F.ui, fontSize: 15, color: P.textMuted, marginBottom: 8 }}>No identity remediation actions available</div>
          <div style={{ fontFamily: F.data, fontSize: 12, color: P.textDim, maxWidth: 400, margin: '0 auto', marginBottom: 16 }}>
            Capture a snapshot to analyze your identity estate and generate prioritized remediation recommendations.
          </div>
          <button
            onClick={triggerScan}
            disabled={scanTriggered}
            style={{
              fontFamily: F.data, fontSize: 12, fontWeight: 700, padding: '8px 24px', borderRadius: 8, border: 'none', cursor: scanTriggered ? 'default' : 'pointer',
              background: scanTriggered ? P.accentIndigoBg : P.btnGradient, color: 'white', opacity: scanTriggered ? 0.6 : 1,
            }}
          >{scanTriggered ? 'Capturing...' : 'Capture Snapshot'}</button>
        </Card>
      )}

      {identityRemediations.map((r, idx) => (
        <Card key={r.rank} style={{ marginBottom: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontFamily: F.data, fontSize: 22, fontWeight: 800, color: P.accentStrong }}>#{idx + 1}</span>
              <div>
                <div style={{ fontFamily: F.ui, fontSize: 14, color: P.textBright, fontWeight: 600 }}>{r.action}</div>
                <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted, marginTop: 2 }}>{r.description}</div>
              </div>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span style={{ fontFamily: F.data, fontSize: 22, fontWeight: 800, color: '#22c55e' }}>+{r.gain}</span>
              <span style={{
                fontFamily: F.data, fontSize: 10, fontWeight: 700, padding: '4px 10px', borderRadius: 4,
                background: r.complexity === 'LOW' ? 'rgba(34,197,94,0.1)' : r.complexity === 'MEDIUM' ? 'rgba(234,179,8,0.1)' : 'rgba(255,68,68,0.1)',
                color: r.complexity === 'LOW' ? '#22c55e' : r.complexity === 'MEDIUM' ? '#eab308' : '#ff4444',
              }}>{r.complexity}</span>
              <button style={{
                fontFamily: F.data, fontSize: 12, fontWeight: 700, padding: '6px 16px', borderRadius: 8, border: 'none', cursor: 'pointer',
                background: P.btnGradient, color: 'white',
              }}>Start Fix &rarr;</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
            {[
              { l: 'Confidence', v: r.confidence != null ? `${r.confidence}%` : '\u2014', drillUrl: null as string | null },
              { l: 'Est. Days', v: r.estimatedDays != null ? `~${r.estimatedDays}` : '\u2014', drillUrl: null as string | null },
              { l: 'Automation', v: null as string | null, comp: <AutomationBadge level={r.automation || 'manual'} />, drillUrl: null as string | null },
              { l: 'Blast Radius', v: null as string | null, drillUrl: '/identities', comp: <span><DrillableNumber value={r.blastRadius.identities} label="Affected identities" onClick={() => nav('/identities')} /> ids &middot; <DrillableNumber value={r.blastRadius.subscriptions} label="Affected subscriptions" onClick={() => nav('/subscriptions')} /> subs &middot; <DrillableNumber value={r.blastRadius.workloads} label="Affected workloads" onClick={() => nav('/workload-identities')} /> wklds</span> },
              { l: 'Rollback', v: null as string | null, comp: <RollbackBadge safety={r.rollbackSafety || 'requires-validation'} />, drillUrl: null as string | null },
              { l: 'Pts/Day', v: r.estimatedDays != null ? `${getRiskPerDay(r.gain, r.estimatedDays)} pts/day` : '\u2014', drillUrl: null as string | null },
            ].map((chip, i) => (
              <div key={i} style={{ padding: '6px 8px', background: P.bgHover, borderRadius: 6 }}>
                <div style={{ fontFamily: F.data, fontSize: 9, color: P.textFaint, textTransform: 'uppercase', marginBottom: 2 }}>{chip.l}</div>
                {chip.comp || <div style={{ fontFamily: F.data, fontSize: 11, color: P.textSub }}>{chip.v}</div>}
              </div>
            ))}
          </div>
          {r.impactsProduction && <ProductionBadge />}
        </Card>
      ))}
    </div>
  );
}
