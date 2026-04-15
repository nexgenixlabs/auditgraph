import React from 'react';
import { useNavigate } from 'react-router-dom';
import { COLORS, type Pillar } from '../../../constants/ciso';
import { FONT, CISOCard, SectionTitle, DN } from '../ciso-shared';
import { DIMENSIONS, getSeverityColor, MITRE_TECHNIQUE_LABELS, CIS_CONTROL_LABELS, NIST_FUNCTION_LABELS } from '../../../constants/riskScoring';
import { computeIdentityRisk, type IdentityRiskResult } from '../../../utils/identityRiskScore';

interface AGIRSBreakdownPanelProps {
  score: number;
  tier: string;
  pillars: Pillar[];
  previousScore: number | null;
  scoreAnalysis?: string;
  potentialScore?: number;
  dataCoverage?: Array<{ source: string; status: string; detail: string }>;
  /** Dangerous identities from AGIRS data — used to compute aggregate dimension scores */
  dangerousIdentities?: Record<string, any>[];
}

const PILLAR_COLORS: Record<string, string> = {
  'Usage Dormancy': '#f97316',
  'Ownership Governance': '#8b5cf6',
  'Effective Privilege': '#dc2626',
  'External Exposure': '#2563eb',
  'Credential Risk': '#f59e0b',
  'Trust & Federation': '#06b6d4',
  'Attack Path Exposure': '#e11d48',
};

const PILLAR_ICONS: Record<string, string> = {
  'Usage Dormancy': '\u23F0',       // clock
  'Ownership Governance': '\u2699', // gear
  'Effective Privilege': '\u26A0',  // warning
  'External Exposure': '\uD83C\uDF10', // globe
  'Credential Risk': '\uD83D\uDD11',   // key
  'Trust & Federation': '\uD83D\uDD17', // link
  'Attack Path Exposure': '\uD83D\uDEE1', // shield
};

const PILLAR_NAV: Record<string, string> = {
  'Usage Dormancy': '/identities?pillar=usage-dormancy',
  'Ownership Governance': '/identities?pillar=ownership-governance',
  'Effective Privilege': '/identities?pillar=effective-privilege',
  'External Exposure': '/identities?pillar=external-exposure',
  'Credential Risk': '/identities?pillar=credential-risk',
  'Trust & Federation': '/identities?pillar=trust-federation',
  'Attack Path Exposure': '/graph-findings',
};

const COVERAGE_ICONS: Record<string, string> = {
  active: '\u2713',    // checkmark
  partial: '\u25CB',   // circle
  inactive: '\u2717',  // x
};

/** Aggregate dimension scores across multiple identities — take max per dimension */
function aggregateDimensionScores(identities: Record<string, any>[]): IdentityRiskResult | null {
  if (!identities || identities.length === 0) return null;
  const results = identities.map(id => computeIdentityRisk(id));

  // For each dimension, take the max score across all identities
  const aggregated = DIMENSIONS.map((dim, i) => {
    let maxScore = 0;
    let maxResult = results[0].dimensions[i];
    for (const r of results) {
      if (r.dimensions[i].score > maxScore) {
        maxScore = r.dimensions[i].score;
        maxResult = r.dimensions[i];
      }
    }
    return maxResult;
  });

  const maxScore = Math.max(0, ...aggregated.map(d => d.score));
  const sevOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const maxSeverity = aggregated.reduce((best, d) =>
    (sevOrder[d.severity] ?? 0) > (sevOrder[best] ?? 0) ? d.severity : best, 'info');

  return {
    dimensions: aggregated,
    overall_severity: maxSeverity,
    overall_score: maxScore,
    critical_count: aggregated.filter(d => d.score >= 9.0).length,
    high_count: aggregated.filter(d => d.score >= 7.0).length,
  };
}

export function AGIRSBreakdownPanel({ score, tier, pillars, previousScore, scoreAnalysis, potentialScore, dataCoverage, dangerousIdentities }: AGIRSBreakdownPanelProps) {
  const navigate = useNavigate();

  // Use backend-computed score_impact (authoritative) — fall back to local calc if absent
  const penalties = pillars
    .map(p => {
      const penalty = p._scoreImpact != null ? Math.abs(p._scoreImpact) : Math.round(p.score * p.weight / 100 * 10) / 10;
      return {
        name: p.name,
        penalty,
        riskPct: p.score,                // risk_pct from backend
        weight: p.weight,
        identityCount: p.identityCount,
        severity: p._severity || (penalty > 10 ? 'critical' : penalty > 5 ? 'high' : penalty > 0 ? 'medium' : 'low'),
        color: PILLAR_COLORS[p.name] || COLORS.textDim,
        icon: PILLAR_ICONS[p.name] || '\u25CF',
        nav: PILLAR_NAV[p.name] || '/identities',
        detail: p.detail,
      };
    })
    .sort((a, b) => b.penalty - a.penalty);

  const totalPenalty = penalties.reduce((s, p) => s + p.penalty, 0);
  // Use backend potential score if provided, else compute locally (capped at 98)
  const displayPotential = potentialScore != null ? potentialScore : Math.min(98, Math.round((score + totalPenalty) * 10) / 10);
  const delta = previousScore != null ? Math.round((score - previousScore) * 10) / 10 : null;

  const SEVERITY_COLORS_MAP: Record<string, string> = {
    critical: COLORS.danger,
    high: COLORS.elevated,
    medium: COLORS.warning,
    low: COLORS.success,
  };

  // Compute v2.0 dimension scores from dangerous identities
  const riskResult = aggregateDimensionScores(dangerousIdentities || []);

  // Collect all standards references from active dimensions
  const activeDimensions = riskResult?.dimensions.filter(d => d.score > 0) || [];
  const allMitre = Array.from(new Set(activeDimensions.flatMap(d => d.mitre)));
  const allCis = Array.from(new Set(activeDimensions.flatMap(d => d.cis)));
  const allNist = Array.from(new Set(activeDimensions.flatMap(d => d.nist)));

  return (
    <CISOCard>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
        <SectionTitle>Risk Score Breakdown</SectionTitle>
        {delta != null && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui }}>Previous: {previousScore?.toFixed(1)}</span>
            <span style={{
              fontSize: 10, fontWeight: 700, fontFamily: FONT.mono,
              color: delta > 0 ? COLORS.success : delta < 0 ? COLORS.danger : COLORS.textMuted,
            }}>
              {delta > 0 ? '+' : ''}{delta.toFixed(1)}
            </span>
            <span style={{
              fontSize: 11, color: delta > 0 ? COLORS.success : delta < 0 ? COLORS.danger : COLORS.textMuted,
            }}>
              {delta > 0 ? '\u2191' : delta < 0 ? '\u2193' : '\u2192'}
            </span>
          </div>
        )}
      </div>

      {/* Current Score Display */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 16 }}>
        <div style={{
          width: 64, height: 64, borderRadius: '50%', flexShrink: 0,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: `conic-gradient(${score >= 80 ? COLORS.success : score >= 65 ? COLORS.warning : COLORS.danger} ${score * 3.6}deg, ${COLORS.border} 0deg)`,
        }}>
          <div style={{
            width: 52, height: 52, borderRadius: '50%', background: COLORS.surface,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text,
          }}>
            {score.toFixed(0)}
          </div>
        </div>
        <div style={{ flex: 1 }}>
          <div style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
            Posture Score: <span style={{ fontWeight: 700, color: COLORS.text }}>{score.toFixed(1)} / 100</span>
          </div>
          <div style={{ fontSize: 10, color: COLORS.textMuted, fontFamily: FONT.mono, marginTop: 2 }}>
            Score = 100 &minus; &Sigma;(risk_exposure &times; pillar_weight)
          </div>
        </div>
        <div style={{
          padding: '8px 14px', borderRadius: 8,
          background: `${COLORS.success}08`, border: `1px solid ${COLORS.success}30`,
          textAlign: 'center' as const,
        }}>
          <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Potential Score
          </div>
          <div style={{ fontSize: 20, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success }}>
            ~{displayPotential}
          </div>
          <div style={{ fontSize: 8, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
            if critical/high risks remediated
          </div>
        </div>
      </div>

      {/* ── Identity Risk Dimensions (v2.0) ── */}
      {riskResult && riskResult.dimensions.some(d => d.score > 0) && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <span style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              Identity Risk Dimensions
            </span>
            <span style={{
              fontSize: 8, padding: '1px 5px', borderRadius: 3,
              background: `${getSeverityColor(riskResult.overall_severity)}18`,
              color: getSeverityColor(riskResult.overall_severity),
              fontWeight: 600, fontFamily: FONT.mono, textTransform: 'uppercase',
            }}>
              {riskResult.overall_severity}
            </span>
          </div>
          <div style={{ fontSize: 9, color: COLORS.textMuted, letterSpacing: '0.5px', marginBottom: 10, fontFamily: FONT.mono }}>
            CVSS v3.1 · NIST SP 800-63B · SP 800-207 · CIS Controls v8
          </div>

          {/* 5 dimension bars */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {riskResult.dimensions.map((dim, i) => {
              const barPct = (dim.score / 10) * 100;
              const sevColor = getSeverityColor(dim.severity);
              const primaryMitre = dim.score > 0 && dim.mitre.length > 0 ? dim.mitre[0] : null;
              return (
                <div
                  key={dim.dimension}
                  style={{
                    display: 'flex', alignItems: 'center', gap: 8,
                    padding: '7px 10px',
                    borderBottom: i < riskResult.dimensions.length - 1 ? `1px solid ${COLORS.border}` : 'none',
                  }}
                >
                  <span style={{ fontSize: 13, width: 18, textAlign: 'center', flexShrink: 0 }}>{dim.icon}</span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
                      <span style={{ fontSize: 10, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{dim.name}</span>
                      {primaryMitre && (
                        <span style={{
                          fontSize: 7, padding: '1px 4px', borderRadius: 2,
                          background: `${COLORS.accent}18`, color: COLORS.accent,
                          fontWeight: 600, fontFamily: FONT.mono,
                        }}>
                          {primaryMitre}
                        </span>
                      )}
                    </div>
                    {/* Bar */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{
                        flex: 1, height: 5, borderRadius: 3,
                        background: COLORS.border, overflow: 'hidden',
                      }}>
                        <div style={{
                          width: `${barPct}%`, height: '100%', borderRadius: 3,
                          background: dim.score > 0 ? dim.color : COLORS.textDim,
                          transition: 'width 0.6s ease',
                        }} />
                      </div>
                      <span style={{
                        fontSize: 10, fontWeight: 700, fontFamily: FONT.mono,
                        color: dim.score > 0 ? sevColor : COLORS.textDim,
                        width: 28, textAlign: 'right', flexShrink: 0,
                      }}>
                        {dim.score.toFixed(1)}
                      </span>
                    </div>
                  </div>
                  <span style={{
                    fontSize: 7, fontWeight: 600, padding: '2px 5px', borderRadius: 3,
                    background: `${sevColor}18`, color: sevColor, fontFamily: FONT.mono,
                    textTransform: 'uppercase', flexShrink: 0,
                  }}>
                    {dim.severity}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Stacked Bar */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
          <span style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Risk Contribution by Pillar
          </span>
        </div>
        <div style={{
          display: 'flex', height: 20, borderRadius: 4, overflow: 'hidden',
          background: COLORS.success, border: `1px solid ${COLORS.border}`,
        }}>
          {/* Green portion = current score */}
          <div style={{ width: `${score}%`, background: COLORS.success, transition: 'width 0.8s ease' }} />
          {/* Each pillar's penalty */}
          {penalties.filter(p => p.penalty > 0).map(p => (
            <div
              key={p.name}
              style={{
                width: `${p.penalty}%`, background: p.color, transition: 'width 0.8s ease',
                cursor: 'pointer', position: 'relative',
              }}
              title={`${p.icon} ${p.name}: -${p.penalty.toFixed(1)} (${p.identityCount} identities, ${p.riskPct.toFixed(1)}% risk)`}
              onClick={() => navigate(p.nav)}
            >
              {p.penalty > 4 && (
                <span style={{
                  position: 'absolute', inset: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 8, fontWeight: 700, color: '#fff', fontFamily: FONT.mono,
                }}>
                  -{p.penalty.toFixed(0)}
                </span>
              )}
            </div>
          ))}
        </div>
        {/* Legend */}
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 8 }}>
          <span style={{ fontSize: 9, display: 'flex', alignItems: 'center', gap: 3, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
            <span style={{ width: 8, height: 8, borderRadius: 2, background: COLORS.success }} />
            Score: {score.toFixed(0)}
          </span>
          {penalties.filter(p => p.penalty > 0).map(p => (
            <span key={p.name} style={{
              fontSize: 9, display: 'flex', alignItems: 'center', gap: 3,
              color: COLORS.textSecondary, fontFamily: FONT.ui, cursor: 'pointer',
            }} onClick={() => navigate(p.nav)}>
              <span style={{ width: 8, height: 8, borderRadius: 2, background: p.color }} />
              {p.icon} {p.name}: -{p.penalty.toFixed(1)}
            </span>
          ))}
        </div>
      </div>

      {/* Pillar Detail Rows */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {penalties.map((p, i) => {
          const sevColor = SEVERITY_COLORS_MAP[p.severity] || COLORS.textDim;
          return (
            <div
              key={p.name}
              onClick={() => navigate(p.nav)}
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '8px 10px', cursor: 'pointer', transition: 'background 0.15s',
                borderBottom: i < penalties.length - 1 ? `1px solid ${COLORS.border}` : 'none',
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = COLORS.surfaceAlt; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
            >
              <span style={{ fontSize: 14, width: 20, textAlign: 'center' }}>{p.icon}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{p.name}</div>
                <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui }}>
                  Weight: {p.weight}% &middot; Risk: {p.riskPct.toFixed(1)}% &middot; {p.identityCount.toLocaleString()} {p.name === 'Attack Path Exposure' ? 'paths' : 'identities'}
                </div>
              </div>
              <DN navigateTo={p.nav}>
                <span style={{
                  fontSize: 14, fontWeight: 700, fontFamily: FONT.mono, color: sevColor,
                }}>
                  -{p.penalty.toFixed(1)}
                </span>
              </DN>
              <span style={{
                fontSize: 8, fontWeight: 600, padding: '2px 6px', borderRadius: 3,
                background: `${sevColor}18`, color: sevColor, fontFamily: FONT.mono,
                textTransform: 'uppercase',
              }}>
                {p.severity}
              </span>
            </div>
          );
        })}
      </div>

      {/* Standards Mapping (v2.0) — collected from active dimensions */}
      {(allMitre.length > 0 || allCis.length > 0 || allNist.length > 0) && (
        <div style={{ marginTop: 14, paddingTop: 12, borderTop: `1px solid ${COLORS.border}` }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 8 }}>Standards Mapping</div>

          {allMitre.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 9, fontWeight: 600, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                MITRE ATT&CK
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {allMitre.map(t => (
                  <span key={t} title={MITRE_TECHNIQUE_LABELS[t] || t} style={{
                    fontSize: 9, padding: '2px 6px', borderRadius: 3,
                    background: `${COLORS.danger}12`, color: COLORS.danger,
                    fontWeight: 600, fontFamily: FONT.mono,
                  }}>
                    {t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {allCis.length > 0 && (
            <div style={{ marginBottom: 8 }}>
              <div style={{ fontSize: 9, fontWeight: 600, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                CIS Controls v8
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {allCis.map(c => (
                  <span key={c} title={CIS_CONTROL_LABELS[c] || c} style={{
                    fontSize: 9, padding: '2px 6px', borderRadius: 3,
                    background: `${COLORS.accent}12`, color: COLORS.accent,
                    fontWeight: 600, fontFamily: FONT.mono,
                  }}>
                    CIS {c}
                  </span>
                ))}
              </div>
            </div>
          )}

          {allNist.length > 0 && (
            <div>
              <div style={{ fontSize: 9, fontWeight: 600, color: COLORS.textMuted, fontFamily: FONT.ui, textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>
                NIST CSF 2.0
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                {allNist.map(n => (
                  <span key={n} title={NIST_FUNCTION_LABELS[n] || n} style={{
                    fontSize: 9, padding: '2px 6px', borderRadius: 3,
                    background: `${COLORS.purple}12`, color: COLORS.purple,
                    fontWeight: 600, fontFamily: FONT.mono,
                  }}>
                    {n}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Score Analysis — per-pillar breakdown (distinct from AI Posture Analysis summary) */}
      <div style={{ marginTop: 14, paddingTop: 12, borderTop: `1px solid ${COLORS.border}` }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 6 }}>Pillar Impact Breakdown</div>
        <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.6 }}>
          {(() => {
            const impactful = [...pillars].filter(p => (p._scoreImpact ?? 0) < 0).sort((a, b) => (a._scoreImpact ?? 0) - (b._scoreImpact ?? 0));
            if (impactful.length === 0) return 'All pillars are within acceptable thresholds.';
            return impactful.map(p => (
              <div key={p.name} style={{ marginBottom: 4 }}>
                <span style={{ fontWeight: 600, color: COLORS.text }}>{PILLAR_ICONS[p.name] || '\u25CF'} {p.name}</span>
                {' \u2014 '}
                <span style={{ color: COLORS.danger, fontWeight: 600, fontFamily: FONT.mono }}>{p._scoreImpact?.toFixed(1)} impact</span>
                {p.identityCount ? ` (${p.identityCount} ${p.identityCount === 1 ? 'identity' : 'identities'} affected)` : ''}
                {p._severity ? <span style={{
                  marginLeft: 6, fontSize: 8, padding: '1px 4px', borderRadius: 3,
                  background: p._severity === 'critical' ? `${COLORS.danger}18` : p._severity === 'high' ? `${COLORS.elevated}18` : `${COLORS.warning}18`,
                  color: p._severity === 'critical' ? COLORS.danger : p._severity === 'high' ? COLORS.elevated : COLORS.warning,
                  fontWeight: 600, fontFamily: FONT.mono, textTransform: 'uppercase',
                }}>{p._severity}</span> : null}
              </div>
            ));
          })()}
        </div>
      </div>

      {/* Data Coverage for This Score */}
      {dataCoverage && dataCoverage.length > 0 && (
        <div style={{ marginTop: 14, paddingTop: 12, borderTop: `1px solid ${COLORS.border}` }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            Data Coverage for This Score
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {dataCoverage.map(item => {
              const statusColor = item.status === 'active' ? COLORS.success : item.status === 'partial' ? COLORS.warning : COLORS.textDim;
              return (
                <div key={item.source} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10 }}>
                  <span style={{ color: statusColor, fontWeight: 700, fontFamily: FONT.mono, width: 14, textAlign: 'center' }}>
                    {COVERAGE_ICONS[item.status] || '\u2717'}
                  </span>
                  <span style={{ color: COLORS.text, fontFamily: FONT.ui, flex: 1 }}>{item.source}</span>
                  <span style={{ color: COLORS.textMuted, fontFamily: FONT.ui, fontSize: 9 }}>({item.detail})</span>
                </div>
              );
            })}
          </div>
          <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 6, fontStyle: 'italic' }}>
            Pillars with incomplete data are scored conservatively.
          </div>
        </div>
      )}
    </CISOCard>
  );
}
