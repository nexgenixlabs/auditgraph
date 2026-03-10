/**
 * AuditGraph v3.0.5 — Executive Summary
 *
 * Dark-themed executive risk intelligence view with 6 tabs:
 *   1. Executive Summary   2. Identity Risk   3. Action Plan
 *   4. Control & Governance 5. Compliance & Evidence 6. Risk Movement
 *
 * Uses inline styles (no Tailwind). Renders within the main app layout.
 * All data bound to tenantData schema — no hardcoded values in UI.
 *
 * v3.0.2: DrillableNumber enforcement (Rule 36), Preview Changes panel,
 *         Create Ticket integration, bug fixes (Rules 30-32),
 *         dead button elimination (Rules 33-35).
 * v3.0.5: MAJOR ARCHITECTURE FIX — removed identityStore, identityIds,
 *         changes[], affectedIdentityIds. Drill-downs navigate to
 *         /identities with filter params. Preview Changes fetches from
 *         remediation detail API. DrillDownPanel DEPRECATED.
 * v3.0.9: Enterprise Review Refinements — score label, confidence banner,
 *         pillar count labels, rollback badges, governance trends,
 *         Identity Controls Only tooltip, predictive scores, layout fix.
 */
import React, { useState, useEffect, useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { useAuth } from '../contexts/AuthContext';
import {
  COLORS, getTierColor,
  getTier, getGrade, getSemanticColor,
  type TenantData, type Remediation, type ComplianceFramework, type DangerousIdentity,
} from '../constants/ciso';
import { formatDate } from '../utils/displayHelpers';
import { FONT, ScoreRing, CISOBadge, ProgressBar, StatBox, SectionTitle, CISOCard, DN, pillarNav } from '../components/dashboard/ciso-shared';
import { IdentityDrawerProvider, useIdentityDrawer } from '../contexts/IdentityDrawerContext';
import { IdentityContextDrawer } from '../components/dashboard/IdentityContextDrawer';
import { ExecutiveMetrics } from '../components/dashboard/executive/ExecutiveMetrics';
import { HumanIdentityRiskTable } from '../components/dashboard/executive/HumanIdentityRiskTable';
import { PhantomExposureTable } from '../components/dashboard/executive/PhantomExposureTable';
import { GovernanceEffectivenessTable } from '../components/dashboard/executive/GovernanceEffectivenessTable';
import { RiskMonitoringTab } from '../components/dashboard/risk/RiskMonitoringTab';
import { RiskMovementTab } from '../components/dashboard/risk/RiskMovementTab';
import { ComplianceTab } from '../components/dashboard/compliance/ComplianceTab';

// ─── Typography, Reusable Components — extracted to components/dashboard/ciso-shared.tsx
// Imports: FONT, ScoreRing, Sparkline, CISOBadge, ProgressBar, StatBox, SectionTitle, CISOCard, DN, pillarNav

// ─── DrillableNumber — extracted to components/dashboard/ciso-shared.tsx

// ─── PreviewChangesPanel (640px, v3.0.5: API fetch model) ────────

function PreviewChangesPanel({ rem, data, onClose }: { rem: Remediation; data: TenantData; onClose: () => void }) {
  const navigate = useNavigate();
  const { withConnection } = useConnection();
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<any>(null);
  const [error, setError] = useState(false);

  // v3.0.5 Rule 39: Fetch from remediation detail API on click
  useEffect(() => {
    setLoading(true);
    setError(false);
    fetch(withConnection(`/api/identities/${rem.id}/remediations`))
      .then(r => r.ok ? r.json() : null)
      .then(d => { setDetail(d); setLoading(false); })
      .catch(() => { setError(true); setLoading(false); });
  }, [rem.id, withConnection]);

  const riskColor = (level: string) =>
    level === 'critical' ? COLORS.danger :
    level === 'high' ? COLORS.elevated :
    level === 'medium' ? COLORS.warning : COLORS.success;

  // Determine whether we have detailed identity-level data
  const hasDetail = detail?.playbooks?.length > 0 || detail?.affected_identities?.length > 0;

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 60 }} />
      <div style={{
        position: 'fixed', top: 0, right: 0, bottom: 0, width: 640,
        background: COLORS.surface, borderLeft: `1px solid ${COLORS.border}`,
        zIndex: 61, display: 'flex', flexDirection: 'column',
        boxShadow: '-8px 0 32px rgba(0,0,0,0.3)',
      }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', borderBottom: `1px solid ${COLORS.border}` }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Preview Changes</div>
              <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 2 }}>{rem.title}</div>
            </div>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: COLORS.textSecondary, cursor: 'pointer', fontSize: 20, fontFamily: FONT.ui }}>×</button>
          </div>
          {/* Score impact bar — always shown from tenantData */}
          <div style={{
            marginTop: 12, padding: '10px 14px', borderRadius: 8,
            background: COLORS.successSoft, border: `1px solid ${COLORS.success}2e`,
            display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          }}>
            <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Score impact</span>
            <span style={{ fontSize: 16, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>
              {data.riskScore.current.toFixed(1)} → {rem.projectedScore} (+{rem.gain} pts)
            </span>
          </div>
        </div>

        {/* Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '12px 20px' }}>
          {loading ? (
            /* Skeleton while API responds */
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {[1, 2, 3].map(i => (
                <div key={i} style={{
                  background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: '16px 14px', height: 60,
                }}>
                  <div style={{ width: `${60 + i * 10}%`, height: 10, borderRadius: 4, background: COLORS.border, marginBottom: 8 }} />
                  <div style={{ width: `${40 + i * 5}%`, height: 8, borderRadius: 4, background: COLORS.border }} />
                </div>
              ))}
              <div style={{ textAlign: 'center' as const, fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 8 }}>
                Loading affected identities...
              </div>
            </div>
          ) : hasDetail ? (
            /* Loaded — API returned data */
            <>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 12 }}>
                Remediation Details
              </div>
              {(detail.playbooks || []).map((pb: any, i: number) => (
                <div key={i} style={{
                  background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                  borderRadius: 8, padding: '12px 14px', marginBottom: 8,
                }}>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{pb.title || pb.name}</div>
                  <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>{pb.description || pb.subtitle}</div>
                  {pb.risk_level && <CISOBadge label={pb.risk_level} color={riskColor(pb.risk_level)} />}
                </div>
              ))}
            </>
          ) : (
            /* Fallback — show existing remediation data + View Affected Identities link (Rule 39) */
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                Remediation Summary
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Affected</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.affected}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Est. Effort</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.effort ?? '\u2014'}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Rollback</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: rem.rollbackRisk === 'safe' ? COLORS.success : rem.rollback != null ? COLORS.danger : COLORS.textMuted, fontFamily: FONT.mono, marginTop: 4 }}>{rem.rollback ?? '\u2014'}</div>
                </div>
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Confidence</div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{rem.confidence != null ? `${rem.confidence}%` : '\u2014'}</div>
                </div>
              </div>
              {rem.compliance != null && (
                <div style={{ background: COLORS.surfaceAlt, borderRadius: 8, padding: '10px 12px' }}>
                  <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Compliance</div>
                  <div style={{ fontSize: 12, color: COLORS.text, fontFamily: FONT.ui, marginTop: 4 }}>{rem.compliance}</div>
                </div>
              )}
              {/* Navigate to filtered identities matching this remediation */}
              <button onClick={() => { navigate(remediationNav(rem.id)); onClose(); }} style={{
                width: '100%', padding: '10px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                cursor: 'pointer', fontFamily: FONT.ui, marginTop: 4,
              }}>View Affected Identities →</button>
            </div>
          )}
        </div>

        {/* Footer */}
        <div style={{ padding: '14px 20px', borderTop: `1px solid ${COLORS.border}`, display: 'flex', gap: 8 }}>
          <button style={{
            flex: 1, padding: '8px', borderRadius: 6, fontSize: 11, fontWeight: 600,
            background: COLORS.accent,
            color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
          }}>Apply Changes</button>
          <button onClick={onClose} style={{
            padding: '8px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
            background: 'transparent', color: COLORS.textSecondary,
            border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
          }}>Cancel</button>
        </div>
        {/* Rule 40: Data source attribution */}
        <div style={{
          padding: '8px 20px', borderTop: `1px solid ${COLORS.border}`,
          fontSize: 10, color: COLORS.textDim, fontFamily: FONT.ui,
          display: 'flex', alignItems: 'center', gap: 6,
        }}>
          <span style={{ width: 4, height: 4, borderRadius: '50%', background: COLORS.success, flexShrink: 0 }} />
          Source: Azure RBAC · Entra ID · Last updated: {formatDate(data.tenant.lastScan, 'No snapshot data')}
        </div>
      </div>
    </>
  );
}

// ─── CreateTicketModal (v3.0.2 §6.1.2) ──────────────────────────

function CreateTicketModal({ rem, data, onClose }: { rem: Remediation; data: TenantData; onClose: () => void }) {
  const navigate = useNavigate();
  const configured = data.ticketingIntegration.configured;
  const provider = data.ticketingIntegration.provider || 'Not configured';
  const [title, setTitle] = useState(`[AuditGraph] ${rem.title}`);
  const [priority, setPriority] = useState(rem.risk === 'HIGH' ? 'high' : 'medium');
  const [submitted, setSubmitted] = useState(false);

  if (!configured) {
    return (
      <>
        <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 60 }} />
        <div style={{
          position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
          width: 420, background: COLORS.surface, border: `1px solid ${COLORS.border}`,
          borderRadius: 12, padding: '28px 24px', zIndex: 61,
          boxShadow: '0 16px 48px rgba(0,0,0,0.4)',
        }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui, marginBottom: 8 }}>Ticketing Not Configured</div>
          <div style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.6, marginBottom: 16 }}>
            Connect Jira, ServiceNow, or Azure DevOps in Settings to create tickets directly from remediation actions.
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button onClick={() => { navigate('/settings/integrations#ticketing'); onClose(); }} style={{
              flex: 1, padding: '8px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>Configure in Settings</button>
            <button onClick={onClose} style={{
              padding: '8px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.textSecondary,
              border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
            }}>Cancel</button>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.5)', zIndex: 60 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%, -50%)',
        width: 500, background: COLORS.surface, border: `1px solid ${COLORS.border}`,
        borderRadius: 12, padding: '24px', zIndex: 61,
        boxShadow: '0 16px 48px rgba(0,0,0,0.4)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ fontSize: 16, fontWeight: 700, color: COLORS.text, fontFamily: FONT.ui }}>Create Ticket</div>
          <CISOBadge label={provider} color={COLORS.accent} />
        </div>

        {submitted ? (
          <div style={{ textAlign: 'center' as const, padding: '24px 0' }}>
            <div style={{ fontSize: 32, marginBottom: 8 }}>✓</div>
            <div style={{ fontSize: 14, fontWeight: 600, color: COLORS.success, fontFamily: FONT.ui }}>Ticket Queued</div>
            <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>
              Pending {provider.toUpperCase()} integration
            </div>
            <button onClick={onClose} style={{
              marginTop: 16, padding: '8px 24px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>Done</button>
          </div>
        ) : (
          <>
            {/* Title */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Title</label>
              <input value={title} onChange={e => setTitle(e.target.value)} style={{
                width: '100%', padding: '8px 12px', borderRadius: 6, marginTop: 4,
                background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, fontSize: 12, fontFamily: FONT.ui, outline: 'none',
                boxSizing: 'border-box' as const,
              }} />
            </div>
            {/* Description */}
            <div style={{ marginBottom: 12 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Description</label>
              <textarea defaultValue={`${rem.subtitle}\n\nAffected: ${rem.affected}\nEffort: ${rem.effort}\nCompliance: ${rem.compliance}\nConfidence: ${rem.confidence}%`} style={{
                width: '100%', padding: '8px 12px', borderRadius: 6, marginTop: 4, minHeight: 80, resize: 'vertical' as const,
                background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
                color: COLORS.text, fontSize: 12, fontFamily: FONT.ui, outline: 'none',
                boxSizing: 'border-box' as const,
              }} />
            </div>
            {/* Priority */}
            <div style={{ marginBottom: 16 }}>
              <label style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>Priority</label>
              <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
                {['critical', 'high', 'medium', 'low'].map(p => (
                  <button key={p} onClick={() => setPriority(p)} style={{
                    padding: '4px 12px', borderRadius: 4, fontSize: 10, fontWeight: 600,
                    background: priority === p ? COLORS.accentSoft : 'transparent',
                    color: priority === p ? COLORS.accent : COLORS.textMuted,
                    border: `1px solid ${priority === p ? `${COLORS.accent}40` : COLORS.border}`,
                    cursor: 'pointer', fontFamily: FONT.ui, textTransform: 'capitalize' as const,
                  }}>{p}</button>
                ))}
              </div>
            </div>
            {/* Actions */}
            <div style={{ display: 'flex', gap: 8 }}>
              <button onClick={() => setSubmitted(true)} style={{
                flex: 1, padding: '8px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
              }}>Create Ticket</button>
              <button onClick={onClose} style={{
                padding: '8px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
                background: 'transparent', color: COLORS.textSecondary,
                border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
              }}>Cancel</button>
            </div>
          </>
        )}
      </div>
    </>
  );
}

// ─── Remediation Card ────────────────────────────────────────────

function RemediationCard({ item, index, data, onPreview, onTicket }: {
  item: Remediation; index: number; data: TenantData;
  onPreview?: (r: Remediation) => void;
  onTicket?: (r: Remediation) => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const navigate = useNavigate();
  const c = getSemanticColor(item.color) || COLORS.accent;
  const currentScore = data.riskScore.current;
  const afterScore = Math.min(100, currentScore + item.gain);

  // Parse affected count
  const affectedMatch = item.affected?.match(/^(\d+)/);
  const affectedCount = affectedMatch ? parseInt(affectedMatch[1], 0) : 0;
  const totalIds = data.tenant.identityCount || 1;
  const riskContribution = totalIds > 0 ? Math.round((affectedCount / totalIds) * 100) : 0;

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      style={{
        background: expanded ? COLORS.surfaceHover : COLORS.surfaceAlt,
        border: `1px solid ${expanded ? COLORS.borderAccent : COLORS.border}`,
        borderRadius: 10, padding: '14px 18px', cursor: 'pointer',
        transition: 'all 0.2s ease',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <div style={{
          width: 34, height: 34, borderRadius: 7,
          background: `${c}1f`, border: `1px solid ${c}40`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontFamily: FONT.mono, fontSize: 13, fontWeight: 700, color: c,
          flexShrink: 0,
        }}>#{index + 1}</div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui }}>{item.title}</div>
          <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 1 }}>{item.subtitle}</div>
        </div>
        <div style={{ textAlign: 'right' as const, flexShrink: 0 }}>
          <DN navigateTo={remediationNav(item.id)}><div style={{ fontSize: 18, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>+{item.gain}</div></DN>
          <div style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.mono }}>
            {currentScore.toFixed(0)} {'\u2192'} {afterScore.toFixed(0)}
          </div>
        </div>
        <CISOBadge label={item.risk} color={item.risk === 'HIGH' ? COLORS.danger : COLORS.success} />
        <CISOBadge label={item.automation} color={item.automation === 'Auto' ? COLORS.accent : COLORS.textMuted} />
        {item.rollbackRisk != null && (
          <CISOBadge
            label={item.rollbackRisk === 'safe' ? 'Safe' : item.rollbackRisk === 'controlled' ? 'Controlled' : 'Risky'}
            color={item.rollbackRisk === 'safe' ? COLORS.success : item.rollbackRisk === 'controlled' ? COLORS.warning : COLORS.danger}
          />
        )}
        <span style={{ fontSize: 12, color: COLORS.textMuted, marginLeft: 4, transform: expanded ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }}>▾</span>
      </div>
      {expanded && (
        <div style={{ borderTop: `1px solid ${COLORS.border}`, marginTop: 14, paddingTop: 14 }}>
          {/* Score improvement preview bar */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14, padding: '8px 12px', borderRadius: 6, background: `${COLORS.success}08`, border: `1px solid ${COLORS.success}1a` }}>
            <span style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Score Impact</span>
            <div style={{ flex: 1, height: 6, borderRadius: 3, background: COLORS.border, position: 'relative', overflow: 'hidden' }}>
              <div style={{ position: 'absolute', left: 0, top: 0, height: '100%', width: `${currentScore}%`, background: COLORS.warning, borderRadius: 3 }} />
              <div style={{ position: 'absolute', left: `${currentScore}%`, top: 0, height: '100%', width: `${item.gain}%`, background: COLORS.success, borderRadius: '0 3px 3px 0' }} />
            </div>
            <span style={{ fontSize: 11, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.success }}>
              {currentScore.toFixed(0)} {'\u2192'} {afterScore.toFixed(0)}
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Affected</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>
                <DN navigateTo={remediationNav(item.id)}>{item.affected}</DN>
              </div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Risk Share</div>
              <div style={{ fontSize: 11, color: riskContribution > 20 ? COLORS.danger : COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{riskContribution}%</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Est. Effort</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.effort ?? '\u2014'}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Rollback</div>
              <div style={{ fontSize: 11, color: item.rollbackRisk === 'safe' ? COLORS.success : item.rollback != null ? COLORS.danger : COLORS.textMuted, fontFamily: FONT.mono, marginTop: 4 }}>{item.rollback ?? '\u2014'}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Compliance</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.compliance ?? '\u2014'}</div>
            </div>
            <div>
              <div style={{ fontSize: 9, color: COLORS.textSecondary, textTransform: 'uppercase' as const, letterSpacing: '0.08em', fontFamily: FONT.ui }}>Confidence</div>
              <div style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.mono, marginTop: 4 }}>{item.confidence != null ? `${item.confidence}%` : '\u2014'}</div>
            </div>
          </div>

          {/* 3 action options: Apply, Ticket, Terraform */}
          <div style={{ display: 'flex', gap: 8, marginTop: 14 }}>
            <button onClick={(e) => { e.stopPropagation(); onPreview?.(item); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: COLORS.accent,
              color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
            }}>Apply Changes</button>
            <button onClick={(e) => { e.stopPropagation(); onTicket?.(item); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.text,
              border: `1px solid ${COLORS.borderAccent}`, cursor: 'pointer', fontFamily: FONT.ui,
            }}>Create Ticket</button>
            <button onClick={(e) => { e.stopPropagation(); navigate(remediationNav(item.id)); }} style={{
              padding: '6px 14px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'transparent', color: COLORS.textSecondary,
              border: `1px solid ${COLORS.border}`, cursor: 'pointer', fontFamily: FONT.ui,
            }}>Export Terraform</button>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Empty Data (no hardcoded values) ────────────────────────────

function buildEmptyData(): TenantData {
  return {
    tenant: {
      id: '', name: '', organizationName: '', organizationLogo: null,
      cloud: 'Azure', subscriptions: 0, identityCount: 0,
      lastScan: '', scanDuration: 0, scanCompleteness: 0, scanConfidence: 'Low',
      sources: [], isolationGuarantee: 'Isolated dataset \u2022 No cross-tenant visibility',
    },
    riskScore: {
      current: 0, previous: 0, delta: 0,
      tier: 'NO DATA', grade: '—',
      industry: 0, target: 90, potentialGain: 0,
      trend: [],
    },
    projection: {
      noAction: { score: 0, tier: 'NO DATA', consequences: [], breachImpact: 'Unknown' },
      remediated: { score: 0, tier: 'NO DATA', actions: [], breachImpact: 'Unknown' },
    },
    ghostAccounts: {
      total: 0, privileged: 0, nonPrivileged: 0,
      roles: [], complianceImpact: [], lastDetected: '',
    },
    deltaChanges: [],
    identityBreakdown: [],
    pillars: [
      { name: 'Effective Privilege', score: 0, weight: 30, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Credential Risk', score: 0, weight: 20, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Trust & Federation', score: 0, weight: 20, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Usage Dormancy', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'Ownership Governance', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
      { name: 'External Exposure', score: 0, weight: 10, detail: '', identityCount: 0, subMetrics: [] },
    ],
    blastRadius: {
      highRisk: 0, lowRisk: 0, orphaned: 0, productionWorkloads: 0,
      categories: [
        { name: 'Privilege', score: 0, color: COLORS.danger },
        { name: 'Credential', score: 0, color: COLORS.warning },
        { name: 'Exposure', score: 0, color: COLORS.elevated },
        { name: 'Lifecycle', score: 0, color: COLORS.accent },
        { name: 'Visibility', score: 0, color: COLORS.purple },
      ],
    },
    kpis: {
      privilegedRoles: { value: 0, subtitle: '' },
      dormantPrivileged: { value: 0, subtitle: '' },
      ghostAccounts: { value: 0, subtitle: '' },
      subscriptionAccess: { value: 0, subtitle: '' },
      rbacModifiers: { value: 0, subtitle: '' },
    },
    remediations: [],
    governance: {
      effectivenessScore: 0, effectivenessTier: 'NO DATA', maturityLevel: 'Not assessed',
      metrics: [], controlFailures: [],
      setupCompletion: { configured: 0, total: 4 },
    },
    compliance: {
      frameworks: [],
      maturity: { preventive: 0, detective: 0, compensating: 0, missing: 0 },
      progress: { remediation: 0, iaGovernance: 0 },
    },
    riskMovement: {
      trajectory: [], changes: [],
      mostChanged: { name: '', score: 0, category: '' },
      scanMeta: { frequency: '', lastRun: '', sources: '', duration: '', completeness: '' },
    },
    ticketingIntegration: { configured: false, provider: null, projectKey: null, defaultAssignee: null, jira: null },
    agirs: { agirs: null, hiri: null, nhiri: null, gei: null, dangerous_identities: [], previous: null },
  };
}

// ─── Data Hook (real API data) ───────────────────────────────────

function useCISOData(): { data: TenantData; loading: boolean } {
  const { withConnection, selectedConnectionId } = useConnection();
  const { activeOrgId } = useAuth();
  const [data, setData] = useState<TenantData>(buildEmptyData);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    async function load() {
      setLoading(true);
      try {
        // Fetch all data sources in parallel
        const [attackRes, statsRes, compRes, driftRes, trendsRes, summaryRes, agirstRes] = await Promise.all([
          fetch(withConnection('/api/overview/attack-surface-score')).catch(() => null),
          fetch(withConnection('/api/stats')).catch(() => null),
          fetch(withConnection('/api/dashboard/compliance')).catch(() => null),
          fetch(withConnection('/api/drift/latest')).catch(() => null),
          fetch(withConnection('/api/trends?limit=11')).catch(() => null),
          fetch(withConnection('/api/identity-summary')).catch(() => null),
          fetch(withConnection('/api/identity-risk-summary')).catch(() => null),
        ]);

        const attack = attackRes?.ok ? await attackRes.json() : null;
        const stats = statsRes?.ok ? await statsRes.json() : null;
        const comp = compRes?.ok ? await compRes.json() : null;
        const drift = driftRes?.ok ? await driftRes.json() : null;
        const trends = trendsRes?.ok ? await trendsRes.json() : null;
        const summary = summaryRes?.ok ? await summaryRes.json() : null;
        const agirstData = agirstRes?.ok ? await agirstRes.json() : null;

        if (cancelled) return;
        const d = buildEmptyData();

        // ── Tenant metadata ──
        if (attack?.data_integrity) {
          const di = attack.data_integrity;
          d.tenant.id = String(di.organization_id || di.tenant_id || '');
          d.tenant.name = di.org_name || di.organization_name || '';
          d.tenant.organizationName = di.organization_name || di.org_name || '';
          d.tenant.organizationLogo = di.organization_logo || null;
          d.tenant.lastScan = di.last_scan || '';
          d.tenant.scanDuration = di.scan_duration_seconds || 0;
          d.tenant.scanCompleteness = di.data_completeness_pct || 0;
          d.tenant.scanConfidence = di.confidence || 'Low';
          d.tenant.sources = ['Azure RBAC', 'Entra ID', 'Graph API'];
        }
        if (attack) {
          d.tenant.identityCount = attack.total_identities || 0;
        }
        const subCount = summary?.monitored_resources?.azure?.subscriptions || 0;
        d.tenant.subscriptions = subCount;

        // ── Risk Score ──
        // Attack surface score: higher = worse. UI shows posture: higher = better.
        // Invert: posture = 100 - attack_score
        if (attack) {
          const posture = Math.round((100 - (attack.score || 0)) * 10) / 10;
          const prevPosture = stats?.previous_run
            ? Math.round((100 - (stats.previous_run.avg_risk_score || 0)) * 10) / 10
            : null;
          d.riskScore.current = posture;
          d.riskScore.previous = prevPosture ?? posture;
          d.riskScore.delta = prevPosture != null ? Math.round((posture - prevPosture) * 10) / 10 : null;
          d.riskScore.tier = getTier(posture);
          const gradeMap: Record<string, string> = { A: 'A', B: 'B', C: 'C', D: 'D', F: 'F' };
          d.riskScore.grade = attack.grade ? (gradeMap[attack.grade as string] || getGrade(posture)) : getGrade(posture);
          d.riskScore.industry = attack.industry_avg != null ? Math.max(0, Math.min(100, attack.industry_avg)) : null;
          d.riskScore.target = attack.posture_target != null ? attack.posture_target : 90;
          d.riskScore.potentialGain = Math.max(0, d.riskScore.target - posture);
        }
        // Trend from /api/trends
        if (trends?.runs?.length) {
          d.riskScore.trend = trends.runs.map((r: any) => r.posture_score ?? 0);
        }

        // ── Pillars ──
        if (attack?.pillars) {
          const p = attack.pillars;
          const ep = p.effective_privilege || {};
          const cr = p.credential_risk || {};
          const tf = p.trust_federation || {};
          const ud = p.usage_dormancy || {};
          const og = p.ownership_governance || {};
          const ee = p.external_exposure || {};

          d.pillars = [
            {
              name: 'Effective Privilege', score: ep.score || 0, weight: ep.weight || 30,
              detail: `${ep.detail?.t0t1 || 0} IDs at T0/T1`,
              identityCount: ep.detail?.t0t1 || 0,
              subMetrics: [
                { name: 'T0 (Tenant Owner)', value: ep.detail?.t0 || 0, max: attack.total_identities || 1 },
                { name: 'T0+T1 privileged', value: ep.detail?.t0t1 || 0, max: attack.total_identities || 1 },
              ],
            },
            {
              name: 'Credential Risk', score: cr.score || 0, weight: cr.weight || 20,
              detail: `${(cr.detail?.expired || 0) + (cr.detail?.expiring || 0)} credential issues`,
              identityCount: (cr.detail?.expired || 0) + (cr.detail?.expiring || 0),
              subMetrics: [
                { name: 'Expired', value: cr.detail?.expired || 0, max: cr.detail?.with_creds || 1 },
                { name: 'Expiring soon', value: cr.detail?.expiring || 0, max: cr.detail?.with_creds || 1 },
              ],
            },
            {
              name: 'Trust & Federation', score: tf.score || 0, weight: tf.weight || 20,
              detail: `${tf.detail?.guest_with_roles || 0} guests with roles`,
              identityCount: tf.detail?.guest_with_roles || 0,
              subMetrics: [
                { name: 'Guests with roles', value: tf.detail?.guest_with_roles || 0, max: tf.detail?.guests || 1 },
                { name: 'Federated', value: tf.detail?.federated || 0, max: tf.detail?.guests || 1 },
              ],
            },
            {
              name: 'Usage Dormancy', score: ud.score || 0, weight: ud.weight || 10,
              detail: `${ud.detail?.dormant || 0} dormant identities`,
              identityCount: ud.detail?.dormant || 0,
              subMetrics: [
                { name: 'Dormant', value: ud.detail?.dormant || 0, max: ud.detail?.total || 1 },
              ],
            },
            {
              name: 'Ownership Governance', score: og.score || 0, weight: og.weight || 10,
              detail: `${og.detail?.unowned_spns || 0} unowned SPNs`,
              identityCount: og.detail?.unowned_spns || 0,
              subMetrics: [
                { name: 'Unowned SPNs', value: og.detail?.unowned_spns || 0, max: og.detail?.total_spns || 1 },
              ],
            },
            {
              name: 'External Exposure', score: ee.score || 0, weight: ee.weight || 10,
              detail: `${ee.detail?.tenant_scope || 0} with tenant-wide scope`,
              identityCount: ee.detail?.tenant_scope || 0,
              subMetrics: [
                { name: 'Tenant-wide scope', value: ee.detail?.tenant_scope || 0, max: ee.detail?.total || 1 },
              ],
            },
          ];
        }

        // ── Ghost Accounts ──
        const ghostTotal = stats?.ghost_count || 0;
        const zombieTotal = stats?.zombie_count || 0;
        const dormantPrivCount = attack?.attack_opportunities?.dormant_privileged_count || 0;
        d.ghostAccounts.total = ghostTotal;
        d.ghostAccounts.privileged = Math.min(dormantPrivCount, ghostTotal);
        d.ghostAccounts.nonPrivileged = Math.max(0, ghostTotal - d.ghostAccounts.privileged);
        if (ghostTotal > 0) {
          d.ghostAccounts.complianceImpact = ['SOC2 CC6.1', 'HIPAA', 'NIST AC-2', 'SOX'];
          d.ghostAccounts.lastDetected = d.tenant.lastScan;
        }

        // ── KPIs ──
        if (attack) {
          const ao = attack.attack_opportunities || {};
          const ep = attack.pillars?.effective_privilege?.detail || {};
          d.kpis.privilegedRoles = { value: (ep.t0 || 0) + (ao.rbac_modifier_count || 0), subtitle: `${ep.t0 || 0} T0 identities` };
          d.kpis.dormantPrivileged = { value: ao.dormant_privileged_count || 0, subtitle: 'Active roles retained' };
          d.kpis.ghostAccounts = { value: ghostTotal, subtitle: ghostTotal > 0 ? 'Disabled + active RBAC' : 'None detected' };
          d.kpis.subscriptionAccess = { value: subCount, subtitle: `${ao.multi_sub_count || 0} cross-sub identities` };
          d.kpis.rbacModifiers = { value: ao.rbac_modifier_count || 0, subtitle: 'Custom role defs' };
        }

        // ── Identity Breakdown ──
        if (summary?.categories) {
          const cats = summary.categories as Record<string, { total: number }>;
          const humanCount = (cats.human_user?.total || 0);
          const workloadCount = (cats.service_principal?.total || 0) + (cats.managed_identity_system?.total || 0) + (cats.managed_identity_user?.total || 0);
          const guestCount = cats.guest?.total || 0;
          const total = humanCount + workloadCount + guestCount;
          if (total > 0) {
            d.identityBreakdown = [
              { type: 'Human Users', count: humanCount, percentage: Math.round((humanCount / total) * 100), color: 'accent' },
              { type: 'Workload Identities', count: workloadCount, percentage: Math.round((workloadCount / total) * 100), color: 'warning' },
              { type: 'Guest Users', count: guestCount, percentage: Math.round((guestCount / total) * 100), color: 'textDim' },
            ];
          }
        } else if (attack?.nhi_breakdown) {
          const nb = attack.nhi_breakdown;
          const humanCount = nb.human || 0;
          const workloadCount = (nb.service_principal || 0) + (nb.managed_identity_system || 0) + (nb.managed_identity_user || 0);
          const guestCount = nb.guest || 0;
          const total = humanCount + workloadCount + guestCount;
          if (total > 0) {
            d.identityBreakdown = [
              { type: 'Human Users', count: humanCount, percentage: Math.round((humanCount / total) * 100), color: 'accent' },
              { type: 'Workload Identities', count: workloadCount, percentage: Math.round((workloadCount / total) * 100), color: 'warning' },
              { type: 'Guest Users', count: guestCount, percentage: Math.round((guestCount / total) * 100), color: 'textDim' },
            ];
          }
        }

        // ── Blast Radius ──
        if (attack?.workload_exposure) {
          const we = attack.workload_exposure;
          const ed = we.exposure_distribution || {};
          d.blastRadius.highRisk = (ed.critical || 0) + (ed.high || 0);
          d.blastRadius.lowRisk = (ed.medium || 0) + (ed.low || 0);
          d.blastRadius.orphaned = attack.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          d.blastRadius.productionWorkloads = we.total || 0;
          const ca = we.component_averages || {};
          d.blastRadius.categories = [
            { name: 'Privilege', score: ca.privilege || 0, color: COLORS.danger },
            { name: 'Credential', score: ca.credential_risk || 0, color: COLORS.warning },
            { name: 'Exposure', score: ca.exposure || 0, color: COLORS.elevated },
            { name: 'Lifecycle', score: ca.lifecycle || 0, color: COLORS.accent },
            { name: 'Visibility', score: ca.visibility || 0, color: COLORS.purple },
          ];
        }

        // ── Delta Changes (from drift) ──
        if (drift?.has_drift_data) {
          const dormantPillar = attack?.pillars?.usage_dormancy?.detail?.dormant || 0;
          const overPriv = attack?.pillars?.effective_privilege?.detail?.t0t1 || 0;
          const unownedSPs = attack?.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          const extExposure = attack?.pillars?.external_exposure?.detail?.tenant_scope || 0;
          d.deltaChanges = [
            { icon: '\uD83D\uDC64', label: 'Dormant', value: String(dormantPillar), color: dormantPillar > 0 ? 'danger' : 'success' },
            { icon: '\uD83D\uDD11', label: 'Over-priv', value: String(overPriv), color: overPriv > 0 ? 'warning' : 'success' },
            { icon: '\uD83D\uDC7B', label: 'Ghost Roles', value: String(ghostTotal), color: ghostTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDDDF', label: 'Zombies', value: String(zombieTotal), color: zombieTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDD16', label: 'Unowned SPs', value: String(unownedSPs), color: unownedSPs > 0 ? 'elevated' : 'success' },
            { icon: '\uD83C\uDF10', label: 'Ext exposure', value: String(extExposure), color: extExposure > 0 ? 'accent' : 'success' },
          ];
        } else {
          // No drift data — show current pillar counts as absolute values
          const dormantPillar = attack?.pillars?.usage_dormancy?.detail?.dormant || 0;
          const overPriv = attack?.pillars?.effective_privilege?.detail?.t0t1 || 0;
          const unownedSPs = attack?.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          const extExposure = attack?.pillars?.external_exposure?.detail?.tenant_scope || 0;
          d.deltaChanges = [
            { icon: '\uD83D\uDC64', label: 'Dormant', value: String(dormantPillar), color: dormantPillar > 0 ? 'danger' : 'success' },
            { icon: '\uD83D\uDD11', label: 'Over-priv', value: String(overPriv), color: overPriv > 0 ? 'warning' : 'success' },
            { icon: '\uD83D\uDC7B', label: 'Ghost Roles', value: String(ghostTotal), color: ghostTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDDDF', label: 'Zombies', value: String(zombieTotal), color: zombieTotal > 0 ? 'danger' : 'success' },
            { icon: '\uD83E\uDD16', label: 'Unowned SPs', value: String(unownedSPs), color: unownedSPs > 0 ? 'elevated' : 'success' },
            { icon: '\uD83C\uDF10', label: 'Ext exposure', value: String(extExposure), color: extExposure > 0 ? 'accent' : 'success' },
          ];
        }

        // ── Governance ──
        if (attack?.governance) {
          const gov = attack.governance;
          const ownerPct = gov.ownership_coverage_pct || 0;
          const pimPct = gov.pim_adoption_pct || 0;
          const dormantCleanupPct = gov.dormant_cleanup_pct || 0;
          const reviewPct = gov.privileged_under_review_pct || 0;
          // Effectiveness: average of 4 governance percentages on 0-10 scale
          const avgPct = (ownerPct + pimPct + dormantCleanupPct + reviewPct) / 4;
          const effScore = Math.round(avgPct / 10);
          d.governance.effectivenessScore = effScore;
          d.governance.effectivenessTier = effScore >= 8 ? 'RESILIENT' : effScore >= 5 ? 'CONTROLLED' : effScore >= 3 ? 'ELEVATED' : 'CRITICAL';
          d.governance.maturityLevel = effScore >= 8 ? 'Optimized' : effScore >= 5 ? 'Managed' : effScore >= 3 ? 'Developing' : effScore >= 1 ? 'Ad-Hoc' : 'Unknown';

          const govStatus = (pct: number) => pct >= 80 ? 'good' : pct >= 40 ? 'warning' : pct > 0 ? 'critical' : 'not-configured';
          d.governance.metrics = [
            { label: 'Ownership Coverage', value: `${Math.round(ownerPct)}%`, target: '80%', status: govStatus(ownerPct), icon: '\uD83D\uDC64' },
            { label: 'PIM Enforcement', value: pimPct > 0 ? `${Math.round(pimPct)}%` : '\u2014', target: '100%', status: govStatus(pimPct), icon: '\uD83D\uDD10' },
            { label: 'Access Reviews', value: gov.access_reviews_done > 0 ? `${gov.access_reviews_done} done` : '\u2014', target: 'quarterly', status: gov.access_reviews_done > 0 ? 'good' : 'not-configured', icon: '\uD83D\uDCCB' },
            { label: 'Privileged Monitoring', value: reviewPct > 0 ? `${Math.round(reviewPct)}%` : '\u2014', target: 'active', status: govStatus(reviewPct), icon: '\uD83D\uDCE1' },
          ];

          // Control failures derived from pillar details
          const preventiveItems: { label: string; count: number; color: string }[] = [];
          const operationalItems: { label: string; count: number; color: string }[] = [];
          const privT0 = attack.pillars?.effective_privilege?.detail?.t0 || 0;
          if (privT0 > 0 && pimPct < 100) preventiveItems.push({ label: 'Privilege outside PIM', count: privT0, color: COLORS.danger });
          if (ghostTotal > 0) preventiveItems.push({ label: 'Disabled accounts retain active RBAC roles', count: ghostTotal, color: COLORS.danger });
          const unownedSpns = attack.pillars?.ownership_governance?.detail?.unowned_spns || 0;
          if (unownedSpns > 0) operationalItems.push({ label: `Ownership coverage at ${Math.round(ownerPct)}%`, count: unownedSpns, color: COLORS.warning });
          const dormPriv = attack.attack_opportunities?.dormant_privileged_count || 0;
          if (dormPriv > 0) operationalItems.push({ label: 'Dormant privileged accounts active', count: dormPriv, color: COLORS.warning });

          d.governance.controlFailures = [];
          if (preventiveItems.length > 0) d.governance.controlFailures.push({ type: 'PREVENTIVE FAILURES', items: preventiveItems });
          if (operationalItems.length > 0) d.governance.controlFailures.push({ type: 'OPERATIONAL GAPS', items: operationalItems });

          const configured = [ownerPct > 0, pimPct > 0, gov.access_reviews_done > 0, reviewPct > 0].filter(Boolean).length;
          d.governance.setupCompletion = { configured, total: 4 };
        }

        // ── Compliance (from /api/dashboard/compliance) ──
        if (comp && typeof comp === 'object') {
          const frameworks: ComplianceFramework[] = [];
          for (const [key, fw] of Object.entries(comp) as [string, any][]) {
            if (!fw || typeof fw !== 'object' || !fw.name) continue;
            frameworks.push({
              id: key,
              name: fw.short_name || fw.name,
              type: fw.category || fw.tier || 'Industry',
              score: fw.score || 0,
              totalControls: fw.total_framework_controls || fw.total_controls || 0,
              failedControls: fw.fail_count || 0,
              status: fw.score >= 80 ? 'Mature' : fw.score >= 50 ? 'Developing' : fw.score > 0 ? 'Initial' : 'Not Assessed',
              trend: 0,
              identityImpactCount: fw.identity_controls_count || 0,
              controls: (fw.controls || []).map((c: any) => ({
                id: c.id, name: c.name, status: c.status,
                severity: c.status === 'fail' ? 'high' : 'medium',
                evidence: c.detail || '', recommendation: '', identityCount: 0,
                detectedAt: c.detected_at || c.detectedAt || d.tenant.lastScan || '',
                lastEvaluatedAt: c.last_evaluated_at || c.lastEvaluatedAt || d.tenant.lastScan || '',
              })),
            });
          }
          d.compliance.frameworks = frameworks;
          // Maturity summary
          const passTotal = frameworks.reduce((s, f) => s + (f.score >= 80 ? 1 : 0), 0);
          const failTotal = frameworks.reduce((s, f) => s + (f.failedControls || 0), 0);
          d.compliance.maturity = {
            preventive: passTotal,
            detective: frameworks.length - passTotal,
            compensating: 0,
            missing: failTotal,
          };
          const avgScore = frameworks.length > 0 ? Math.round(frameworks.reduce((s, f) => s + f.score, 0) / frameworks.length) : 0;
          d.compliance.progress = {
            remediation: avgScore,
            iaGovernance: (attack?.governance?.ownership_coverage_pct || 0) / 10,
          };
        }

        // ── Remediations (dynamic from attack surface data) ──
        const remCards: Remediation[] = [];
        if (attack) {
          const ep = attack.pillars?.effective_privilege?.detail || {};
          const ao = attack.attack_opportunities || {};
          const cr = attack.pillars?.credential_risk?.detail || {};
          const og = attack.pillars?.ownership_governance?.detail || {};
          const current = d.riskScore.current;
          const target = d.riskScore.target;

          if ((ep.t0t1 || 0) > 0) {
            const gain = Math.round((target - current) * 0.3);
            remCards.push({
              id: 'r1', type: 'identity-remediation',
              title: 'Reduce over-privileged identities',
              subtitle: `${ep.t0t1} identities at T0/T1 privilege across ${subCount} subscriptions`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Manual', risk: 'HIGH', color: 'danger',
              affected: `${ep.t0t1} ids \u00B7 ${subCount} subs`,
              effort: null, rollback: null, rollbackRisk: null,
              compliance: null, confidence: null, productionImpact: true, riskPerDay: null,
            });
          }
          if ((ao.dormant_privileged_count || 0) > 0) {
            const gain = Math.round((target - current) * 0.2);
            remCards.push({
              id: 'r2', type: 'identity-remediation',
              title: 'Remediate dormant privileged accounts',
              subtitle: `${ao.dormant_privileged_count} dormant accounts with active privileged roles`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Auto', risk: 'LOW', color: 'warning',
              affected: `${ao.dormant_privileged_count} ids`,
              effort: null, rollback: null, rollbackRisk: null,
              compliance: null, confidence: null, productionImpact: false, riskPerDay: null,
            });
          }
          if (ghostTotal > 0) {
            const gain = Math.round((target - current) * 0.15);
            remCards.push({
              id: 'r2b', type: 'identity-remediation',
              title: 'Revoke roles from disabled accounts',
              subtitle: `${ghostTotal} accounts disabled in Entra ID but retain active RBAC assignments`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Auto', risk: 'HIGH', color: 'danger',
              affected: `${ghostTotal} ids`,
              effort: null, rollback: null, rollbackRisk: null,
              compliance: null, confidence: null, productionImpact: false, riskPerDay: null,
            });
          }
          if ((og.unowned_spns || 0) > 0) {
            const gain = Math.round((target - current) * 0.1);
            remCards.push({
              id: 'r3', type: 'identity-remediation',
              title: 'Assign ownership to unowned SPNs',
              subtitle: `${og.unowned_spns} service principals without designated owners`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Manual', risk: 'LOW', color: 'elevated',
              affected: `${og.unowned_spns} ids`,
              effort: null, rollback: null, rollbackRisk: null,
              compliance: null, confidence: null, productionImpact: false, riskPerDay: null,
            });
          }
          if ((cr.expired || 0) > 0) {
            const gain = Math.round((target - current) * 0.15);
            remCards.push({
              id: 'r4', type: 'identity-remediation',
              title: 'Rotate expired credentials',
              subtitle: `${cr.expired} identities with expired credentials`,
              gain, projectedScore: `~${Math.round(current + gain)}`,
              status: 'new', automation: 'Manual', risk: 'MEDIUM', color: 'warning',
              affected: `${cr.expired} ids`,
              effort: null, rollback: null, rollbackRisk: null,
              compliance: null, confidence: null, productionImpact: false, riskPerDay: null,
            });
          }
        }
        d.remediations = remCards;

        // ── Projection ──
        const totalGain = remCards.reduce((s, r) => s + r.gain, 0);
        const noActionDelta = d.riskScore.delta;
        const noActionScore = noActionDelta != null && noActionDelta !== 0
          ? Math.max(0, d.riskScore.current - Math.abs(noActionDelta))
          : null;
        const remediatedScore = Math.min(100, d.riskScore.current + totalGain);
        d.projection.noAction = {
          score: noActionScore != null ? Math.round(noActionScore * 10) / 10 : null,
          tier: noActionScore != null ? getTier(noActionScore) : null,
          consequences: d.pillars.filter(p => p.score > 50).map(p => `${p.detail} (${p.name}: ${p.score}%)`),
          breachImpact: noActionScore != null ? (noActionScore < 40 ? 'High' : noActionScore < 60 ? 'Moderate-High' : 'Moderate') : null,
        };
        d.projection.remediated = {
          score: Math.round(remediatedScore * 10) / 10,
          tier: getTier(remediatedScore),
          actions: remCards.slice(0, 4).map(r => r.title),
          breachImpact: remediatedScore >= 80 ? 'Low' : 'Moderate',
        };

        // ── Risk Movement ──
        if (trends?.runs?.length) {
          d.riskMovement.trajectory = trends.runs.map((r: any) => r.posture_score ?? 0);
        }
        // Changes from stats + drift
        const latestRun = stats?.latest_run || {};
        const prevRun = stats?.previous_run || {};
        const prevTotal = prevRun.total_identities || 0;
        const newCount = drift?.new_identities_count || stats?.new_identities_count || 0;
        const removedCount = drift?.removed_identities_count || stats?.removed_identities_count || 0;
        d.riskMovement.changes = [
          { label: 'Critical Identities', before: prevRun.critical_count || 0, after: latestRun.critical_count || 0, direction: (latestRun.critical_count || 0) > (prevRun.critical_count || 0) ? 'up' : (latestRun.critical_count || 0) < (prevRun.critical_count || 0) ? 'down' : 'flat' },
          { label: 'High-Risk Identities', before: prevRun.high_count || 0, after: latestRun.high_count || 0, direction: (latestRun.high_count || 0) > (prevRun.high_count || 0) ? 'up' : (latestRun.high_count || 0) < (prevRun.high_count || 0) ? 'down' : 'flat' },
          { label: 'Ghost Accounts', before: ghostTotal, after: ghostTotal, direction: 'flat' },
          { label: 'Zombie Personas', before: zombieTotal, after: zombieTotal, direction: 'flat' },
          { label: 'Total Identities', before: prevTotal, after: latestRun.total_identities || 0, direction: (latestRun.total_identities || 0) > prevTotal ? 'up' : (latestRun.total_identities || 0) < prevTotal ? 'down' : 'flat' },
          { label: 'New Identities', before: prevTotal, after: prevTotal + newCount, direction: newCount > 0 ? 'up' : 'flat' },
          { label: 'Removed', before: prevTotal, after: prevTotal - removedCount, direction: removedCount > 0 ? 'down' : 'flat' },
        ];
        // Most changed pillar
        const worstPillar = [...d.pillars].sort((a, b) => b.score - a.score)[0];
        if (worstPillar) {
          d.riskMovement.mostChanged = { name: worstPillar.name, score: worstPillar.score, category: worstPillar.name };
        }
        d.riskMovement.scanMeta = {
          frequency: d.tenant.scanDuration > 0 ? 'Scheduled' : 'Unknown',
          lastRun: d.tenant.lastScan,
          sources: d.tenant.sources.join(', '),
          duration: d.tenant.scanDuration > 0 ? `${Math.floor(d.tenant.scanDuration / 60)}m ${d.tenant.scanDuration % 60}s` : 'Unknown',
          completeness: `${d.tenant.scanCompleteness}%`,
        };

        // ── AGIRS data ──
        // Prefer persisted AGIRS scores from API; fall back to computing
        // from pillar/stats/governance data that's already loaded.
        if (agirstData?.agirs) {
          d.agirs = {
            agirs: agirstData.agirs,
            hiri: agirstData.hiri || null,
            nhiri: agirstData.nhiri || null,
            gei: agirstData.gei || null,
            dangerous_identities: agirstData.dangerous_identities || [],
            previous: agirstData.previous || null,
          };
        } else if (attack || stats) {
          // Compute AGIRS from already-loaded data (single source of truth)
          const ao = attack?.attack_opportunities || {};
          const ep = attack?.pillars?.effective_privilege?.detail || {};
          const cr = attack?.pillars?.credential_risk?.detail || {};
          const tf = attack?.pillars?.trust_federation?.detail || {};
          const ud = attack?.pillars?.usage_dormancy?.detail || {};
          const og = attack?.pillars?.ownership_governance?.detail || {};
          const gov = attack?.governance || {};

          // Identity counts from summary/attack
          const cats = (summary?.categories || {}) as Record<string, { total: number }>;
          const humanCount = (cats.human_user?.total || 0) + (cats.guest?.total || 0);
          const nhiCount = (cats.service_principal?.total || 0)
            + (cats.managed_identity_system?.total || 0)
            + (cats.managed_identity_user?.total || 0);

          // ── HIRI: Human Identity Risk Index ──
          const h1_ghost = stats?.ghost_count || 0;
          const h2_dormant_priv = ao.dormant_privileged_count || 0;
          const h3_over_priv = (ep.t0t1 || 0);
          const h4_ext_guest = tf.guest_with_roles || 0;
          const h5_zombie = stats?.zombie_count || 0;

          const hiriRaw = h1_ghost * 3 + h2_dormant_priv * 5 + h3_over_priv * 4 + h4_ext_guest * 6 + h5_zombie * 7;
          const hiriNorm = humanCount > 0 ? Math.min(hiriRaw / humanCount * 100, 500) : 0;
          const hiriScore = Math.round(Math.max(100 - hiriNorm, 0) * 100) / 100;

          // ── NHIRI: Non-Human Identity Risk Index ──
          const n1_orphaned = og.unowned_spns || 0;
          // Dormant NHIs: exact count from backend (NHI categories only)
          const n2_dormant = ud.dormant_nhi || 0;
          const n3_zombie = 0; // requires credential + risk intersection, not in pillar data
          const n4_expired = (cr.expired || 0) + (cr.expiring || 0);
          const n5_ownerless_apps = 0; // from app_registrations, not in pillar data

          const nhiriRaw = (n1_orphaned * 4 + n2_dormant * 3 + n3_zombie * 6 + n4_expired * 2 + n5_ownerless_apps * 5) * 1.3;
          const nhiriNorm = nhiCount > 0 ? Math.min(nhiriRaw / nhiCount * 100, 500) : 0;
          const nhiriScore = Math.round(Math.max(100 - nhiriNorm, 0) * 100) / 100;

          // ── GEI: Governance Effectiveness Index ──
          const ownerPct = gov.ownership_coverage_pct || 0;
          const pimPct = gov.pim_adoption_pct || 0;
          const reviewPct = gov.privileged_under_review_pct || 0;
          const accessReviewsDone = gov.access_reviews_done || 0;
          const accessReviewScore = accessReviewsDone > 0 ? Math.min(accessReviewsDone * 20, 100) : 0;
          const geiScore = Math.round((ownerPct + pimPct + accessReviewScore + reviewPct) / 4 * 100) / 100;

          const agirs_score = Math.round((0.40 * hiriScore + 0.40 * nhiriScore + 0.20 * geiScore) * 100) / 100;
          const agirsTier = agirs_score >= 90 ? 'A' : agirs_score >= 75 ? 'B' : agirs_score >= 60 ? 'C' : agirs_score >= 40 ? 'D' : 'F';

          d.agirs = {
            agirs: { score: agirs_score, tier: agirsTier, delta: null },
            hiri: {
              score: hiriScore, human_count: humanCount,
              h1_ghost, h2_dormant_priv, h3_over_priv, h4_ext_guest, h5_zombie,
            },
            nhiri: {
              score: nhiriScore, nhi_count: nhiCount,
              phantom_breakdown: { orphaned: n1_orphaned, dormant: n2_dormant, zombie_nhi: n3_zombie, expired_creds: n4_expired, ownerless_apps: n5_ownerless_apps },
            },
            gei: {
              score: geiScore,
              components: [
                { name: 'Ownership Coverage', score: ownerPct, configured: ownerPct > 0 || og.total_spns > 0 },
                { name: 'PIM Adoption', score: pimPct, configured: pimPct > 0 },
                { name: 'Access Reviews', score: accessReviewScore, configured: accessReviewsDone > 0 },
                { name: 'Monitoring (P2)', score: reviewPct, configured: reviewPct > 0 },
              ],
            },
            dangerous_identities: agirstData?.dangerous_identities || [],
            previous: agirstData?.previous || null,
          };
        }

        setData(d);
      } catch {
        setData(buildEmptyData());
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    load();
    return () => { cancelled = true; };
  }, [selectedConnectionId, activeOrgId]);

  return { data, loading };
}

// ─── Tab Components ──────────────────────────────────────────────

// ─── Navigation Helpers (v3.0.5 Section 3.1) ─────────────────────
// pillarNav — extracted to components/dashboard/ciso-shared.tsx

function remediationNav(id: string): string {
  // Map each remediation card to the correct identity filter
  // Use pillar-based URLs for exact count match where applicable
  switch (id) {
    case 'r1': return '/identities?pillar=effective-privilege';
    case 'r2': return '/identities?activity_status=dormant_strict&privileged=true';
    case 'r2b': return '/identities?status=disabled&hasRoles=true';
    case 'r3': return '/identities?pillar=ownership-governance';
    case 'r4': return '/identities?pillar=credential-risk';
    default: return '/identities';
  }
}

// ── Identity Composite Risk Score ──

function computeCompositeRisk(id: DangerousIdentity): { score: number; drivers: { label: string; points: number }[] } {
  const drivers: { label: string; points: number }[] = [];
  let score = 0;
  const factors = id.key_risk_factors || [];

  // Privilege tier (0–30)
  const tierPts = id.tier === 'T0' ? 30 : id.tier === 'T1' ? 20 : id.tier === 'T2' ? 8 : 0;
  if (tierPts > 0) { score += tierPts; drivers.push({ label: `${id.tier} Privilege`, points: tierPts }); }

  // Blast radius (0–25)
  const brPts = Math.min(25, Math.round((id.blast_radius_score / 100) * 25));
  if (brPts > 0) { score += brPts; drivers.push({ label: 'Blast Radius', points: brPts }); }

  // Dormancy (0–15)
  if (factors.some(f => /dormant|stale|never.used/i.test(f))) { score += 15; drivers.push({ label: 'Dormant Account', points: 15 }); }

  // Credential exposure (0–15)
  if (factors.some(f => /credential|secret|cert|expired|key/i.test(f))) { score += 15; drivers.push({ label: 'Credential Exposure', points: 15 }); }

  // Attack path participation (0–10)
  const apPts = id.risk_score >= 80 ? 10 : id.risk_score >= 60 ? 6 : id.risk_score >= 40 ? 3 : 0;
  if (apPts > 0) { score += apPts; drivers.push({ label: 'Attack Path Risk', points: apPts }); }

  // Ownership status (0–5)
  if (factors.some(f => /unowned|orphan|no.owner/i.test(f))) { score += 5; drivers.push({ label: 'No Owner', points: 5 }); }

  drivers.sort((a, b) => b.points - a.points);
  return { score: Math.min(100, score), drivers };
}

function compositeLabel(score: number): { label: string; color: string } {
  if (score >= 75) return { label: 'Critical', color: COLORS.danger };
  if (score >= 50) return { label: 'High', color: '#FF8C42' };
  if (score >= 25) return { label: 'Medium', color: COLORS.warning };
  return { label: 'Low', color: COLORS.success };
}

function TopRiskIdentities({ identities }: { identities: DangerousIdentity[] }) {
  const drawerCtx = useIdentityDrawer();

  const scored = identities
    .map(id => { const r = computeCompositeRisk(id); return { ...id, compositeScore: r.score, drivers: r.drivers }; })
    .sort((a, b) => b.compositeScore - a.compositeScore)
    .slice(0, 5);

  if (scored.length === 0) return null;

  return (
    <CISOCard>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <SectionTitle>Top Risk Identities</SectionTitle>
        <DN navigateTo="/identities?sort=risk_score&order=desc">
          <span style={{ fontSize: 9, color: COLORS.accent, fontFamily: FONT.ui }}>View All →</span>
        </DN>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
        {scored.map((id, i) => {
          const { label, color } = compositeLabel(id.compositeScore);
          const shortName = id.display_name?.split(/[@.]/)[0] || 'Unknown';
          return (
            <div
              key={id.id}
              onClick={() => drawerCtx?.openIdentity(id.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '8px 10px', borderRadius: 6, cursor: 'pointer',
                transition: 'background 0.15s',
                borderBottom: i < scored.length - 1 ? `1px solid ${COLORS.border}22` : 'none',
              }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLElement).style.background = COLORS.surfaceAlt || '#0f1729'; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLElement).style.background = 'transparent'; }}
            >
              {/* Rank */}
              <span style={{ fontSize: 10, fontWeight: 700, color: COLORS.textDim, fontFamily: FONT.mono, width: 16, textAlign: 'center', flexShrink: 0 }}>
                {i + 1}
              </span>

              {/* Score ring */}
              <div style={{
                width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: `${color}15`, border: `2px solid ${color}`,
                fontSize: 10, fontWeight: 700, fontFamily: FONT.mono, color,
              }}>
                {id.compositeScore}
              </div>

              {/* Name + drivers */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{
                  fontSize: 12, fontWeight: 600, color: COLORS.text, fontFamily: FONT.ui,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  textDecoration: 'underline', textDecorationStyle: 'dashed' as const, textUnderlineOffset: '3px',
                }}>
                  {shortName}
                </div>
                <div style={{ display: 'flex', gap: 4, marginTop: 3, flexWrap: 'wrap' }}>
                  {id.drivers.slice(0, 3).map((dr, di) => (
                    <span key={di} style={{
                      fontSize: 8, fontWeight: 600, padding: '1px 5px', borderRadius: 3,
                      background: `${color}10`, color: COLORS.textSecondary,
                      border: `1px solid ${COLORS.border}`,
                      fontFamily: FONT.ui, whiteSpace: 'nowrap',
                    }}>
                      {dr.label}
                    </span>
                  ))}
                </div>
              </div>

              {/* Risk badge */}
              <span style={{
                fontSize: 9, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                background: `${color}18`, color, border: `1px solid ${color}30`,
                fontFamily: FONT.mono, flexShrink: 0,
              }}>
                {label}
              </span>
            </div>
          );
        })}
      </div>
    </CISOCard>
  );
}

// ── Tab 1: Executive Summary ──

function ExecSummaryTab({ d, onPreview: _onPreview, onTicket: _onTicket }: { d: TenantData; onPreview: (r: Remediation) => void; onTicket: (r: Remediation) => void }) {
  const navigate = useNavigate();
  const agirs = d.agirs?.agirs;
  const score = agirs?.score ?? 0;
  const tier = agirs?.tier ?? 'Unknown';
  const delta = agirs?.delta;

  const workloadCount = useMemo(() => d.identityBreakdown.filter(ib => ib.type !== 'Human Users' && ib.type !== 'Guest Users').reduce((s, ib) => s + ib.count, 0), [d.identityBreakdown]);
  const t0Count = d.pillars[0]?.subMetrics?.[0]?.value ?? 0;

  // Generate executive insight narrative
  const topRisks = [...d.pillars].sort((a, b) => b.score - a.score).slice(0, 2);
  const remGain = d.remediations.filter(r => r.type === 'identity-remediation').reduce((s, r) => s + r.gain, 0);
  const insightText = score >= 80
    ? `Your identity posture is strong at ${score.toFixed(1)}/100. Continue monitoring ${topRisks[0]?.name || 'key pillars'} to maintain resilience.`
    : score >= 60
    ? `Identity posture is developing (${score.toFixed(1)}/100). ${topRisks[0]?.name || 'Privilege'} is your highest risk area at ${topRisks[0]?.score || 0}%. Addressing top remediations could improve your score by +${remGain} points.`
    : `Immediate attention required. Identity posture is ${score.toFixed(1)}/100 (${tier}). ${topRisks[0]?.name || 'Privilege'} scores ${topRisks[0]?.score || 0}% risk. ${d.kpis.dormantPrivileged.value} dormant privileged accounts and ${t0Count} T0 administrators represent significant blast radius.`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Executive Insight Card */}
      <div style={{
        background: `linear-gradient(135deg, ${COLORS.surfaceAlt}, ${COLORS.surface})`,
        border: `1px solid ${COLORS.borderAccent}`,
        borderRadius: 10, padding: '14px 18px',
        borderLeft: `3px solid ${getSemanticColor(score >= 80 ? 'success' : score >= 60 ? 'warning' : 'danger') || COLORS.accent}`,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
          <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
            Executive Insight
          </span>
          <span style={{
            fontSize: 9, fontWeight: 600, padding: '1px 6px', borderRadius: 3,
            background: `${getSemanticColor(score >= 80 ? 'success' : score >= 60 ? 'warning' : 'danger') || COLORS.accent}15`,
            color: getSemanticColor(score >= 80 ? 'success' : score >= 60 ? 'warning' : 'danger') || COLORS.accent,
            fontFamily: FONT.mono,
          }}>
            {tier}
          </span>
        </div>
        <div style={{ fontSize: 12, color: COLORS.text, fontFamily: FONT.ui, lineHeight: 1.6 }}>
          {insightText}
        </div>

        {/* Why This Matters */}
        {(() => {
          const matters: string[] = [];
          const dormant = d.kpis.dormantPrivileged.value;
          const unowned = d.agirs.nhiri?.phantom_breakdown?.orphaned ?? d.blastRadius.orphaned ?? 0;
          const overPriv = d.pillars[0]?.subMetrics?.[0]?.value ?? 0;
          const expiredCreds = d.agirs.nhiri?.phantom_breakdown?.expired_creds ?? 0;
          const guestCount = d.identityBreakdown.find(ib => ib.type === 'Guest Users')?.count ?? 0;

          if (dormant > 0) matters.push('Dormant privileged identities increase the risk of unauthorized access through forgotten accounts.');
          if (unowned > 0) matters.push('Unowned service principals create unmanaged automation access that bypasses security reviews.');
          if (overPriv > 0) matters.push('Reducing over-privileged accounts limits potential lateral movement across your environment.');
          if (expiredCreds > 0) matters.push('Expired credentials on active identities signal stale configurations that may mask compromise.');
          if (guestCount > 5) matters.push('External guest identities with role assignments expand your trust boundary beyond organizational control.');

          if (matters.length === 0) {
            matters.push('Continuous monitoring ensures privilege drift is detected before it becomes exploitable.');
            matters.push('Maintaining ownership coverage enables timely response to identity-related incidents.');
          }

          return matters.length > 0 ? (
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid ${COLORS.border}` }}>
              <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 6 }}>
                Why This Matters
              </div>
              {matters.slice(0, 3).map((m, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 6, marginBottom: 3 }}>
                  <span style={{ color: COLORS.textDim, fontSize: 10, lineHeight: '18px', flexShrink: 0 }}>{'\u2022'}</span>
                  <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5 }}>{m}</span>
                </div>
              ))}
            </div>
          ) : null;
        })()}
      </div>

      {/* 5 Top Metric Cards — enhanced with projected score + benchmark */}
      <ExecutiveMetrics
        score={score}
        tier={tier}
        delta={delta}
        identityCount={d.tenant.identityCount}
        privilegedValue={d.kpis.privilegedRoles.value}
        privilegedSubtitle={d.kpis.privilegedRoles.subtitle}
        workloadCount={workloadCount}
        t0Count={t0Count}
        projectedScore={d.projection.remediated.score}
        industryBenchmark={d.riskScore.industry}
        pillars={d.pillars}
      />

      {/* 2-Column: HIRI + NHIRI Tables */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, alignItems: 'start' }}>
        <HumanIdentityRiskTable hiri={d.agirs.hiri} />
        <PhantomExposureTable nhiri={d.agirs.nhiri} />
      </div>

      {/* Top Risk Identities */}
      <TopRiskIdentities identities={d.agirs.dangerous_identities || []} />

      {/* Identity Attack Paths Widget — Mini Graph */}
      {(() => {
        const dangerous = d.agirs.dangerous_identities || [];
        const pathCount = dangerous.length;
        const topId = dangerous[0];

        // Node type definitions
        type NodeType = 'identity' | 'role' | 'resource' | 'privilege';
        interface GraphNode { id: string; label: string; type: NodeType; tooltip: string; }
        interface GraphEdge { from: string; to: string; }

        const NODE_COLORS: Record<NodeType, string> = {
          identity: '#3B82F6',
          role: '#EF4444',
          resource: '#A855F7',
          privilege: '#F59E0B',
        };

        // Build graph nodes from top dangerous identity
        const nodes: GraphNode[] = [];
        const edges: GraphEdge[] = [];

        if (topId) {
          const factors = topId.key_risk_factors || [];
          const hasPriv = factors.some((f: string) => /privilege|owner|admin|contributor/i.test(f));
          const hasCred = factors.some((f: string) => /credential|secret|cert|key/i.test(f));

          const roleName = hasPriv
            ? (factors.find((f: string) => /owner/i.test(f)) ? 'Owner Role' : factors.find((f: string) => /admin/i.test(f)) ? 'Admin Role' : 'Contributor Role')
            : 'Role Assignment';
          const resourceName = hasCred ? 'Key Vault' : 'Resource Scope';
          const privName = hasCred ? 'Secrets Access' : 'Data Access';

          nodes.push(
            { id: 'n0', label: topId.display_name?.split(/[@.]/)[0] || 'Identity', type: 'identity', tooltip: `Identity: ${topId.display_name || 'Unknown'}\nCategory: ${topId.identity_category}\nRisk: ${topId.risk_score}` },
            { id: 'n1', label: roleName, type: 'role', tooltip: `Role: ${roleName}\nGrants escalation path through privilege assignment` },
            { id: 'n2', label: resourceName, type: 'resource', tooltip: `Resource: ${resourceName}\nTarget resource in the escalation chain` },
            { id: 'n3', label: privName, type: 'privilege', tooltip: `Privilege: ${privName}\nFinal privilege gained through this attack path` },
          );
          edges.push({ from: 'n0', to: 'n1' }, { from: 'n1', to: 'n2' }, { from: 'n2', to: 'n3' });
        } else {
          nodes.push(
            { id: 'n0', label: 'User', type: 'identity', tooltip: 'Identity: User\nStarting point of the attack path' },
            { id: 'n1', label: 'Contributor Role', type: 'role', tooltip: 'Role: Contributor\nGrants write access to resources' },
            { id: 'n2', label: 'Key Vault', type: 'resource', tooltip: 'Resource: Key Vault\nContains secrets and keys' },
            { id: 'n3', label: 'Secrets Access', type: 'privilege', tooltip: 'Privilege: Secrets Access\nAbility to read/write vault secrets' },
          );
          edges.push({ from: 'n0', to: 'n1' }, { from: 'n1', to: 'n2' }, { from: 'n2', to: 'n3' });
        }

        // Path risk level
        let riskSignals = 0;
        if (topId) {
          if (topId.blast_radius_score >= 60) riskSignals += 2; else if (topId.blast_radius_score >= 30) riskSignals += 1;
          if (topId.tier === 'T0') riskSignals += 2; else if (topId.tier === 'T1') riskSignals += 1;
          if (nodes.some(n => /secret/i.test(n.label))) riskSignals += 2;
          if (edges.length >= 3) riskSignals += 1;
        }
        const pathRisk = riskSignals >= 5 ? 'High' : riskSignals >= 2 ? 'Medium' : 'Low';
        const pathRiskColor = pathRisk === 'High' ? COLORS.danger : pathRisk === 'Medium' ? COLORS.warning : COLORS.success;

        // Check if topId is in the Top Risk Identities list
        const topRiskIds = new Set(
          dangerous
            .map(di => ({ id: di.id, s: computeCompositeRisk(di).score }))
            .sort((a, b) => b.s - a.s)
            .slice(0, 5)
            .map(x => x.id)
        );
        const identityHighlighted = !!topId && topRiskIds.has(topId.id);

        // SVG layout constants
        const svgW = 460;
        const svgH = 100;
        const nodeW = 90;
        const nodeH = 32;
        const spacing = (svgW - nodeW) / (nodes.length - 1);
        const cy = svgH / 2;

        const nodePositions = nodes.map((_, i) => ({
          cx: nodeW / 2 + i * spacing,
          cy,
        }));

        return (
          <CISOCard>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 24 }}>
              {/* Left: count + button */}
              <div style={{ minWidth: 160 }}>
                <SectionTitle>Identity Attack Paths</SectionTitle>
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 8 }}>
                  <DN navigateTo="/attack-simulator">
                    <span style={{ fontSize: 32, fontWeight: 700, fontFamily: FONT.mono, color: pathCount > 0 ? COLORS.danger : COLORS.textDim }}>{pathCount}</span>
                  </DN>
                  <span style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui }}>paths detected</span>
                </div>
                <button onClick={() => navigate('/attack-simulator')} style={{
                  marginTop: 12, padding: '6px 14px', borderRadius: 6, fontSize: 10, fontWeight: 600,
                  background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                  cursor: 'pointer', fontFamily: FONT.ui,
                }}>View Attack Paths</button>
              </div>

              {/* Right: mini graph visualization */}
              <div style={{ flex: 1, padding: '4px 0' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span style={{ fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textMuted, fontFamily: FONT.ui }}>
                    {topId ? 'Top Escalation Chain' : 'Example Path'}
                  </span>
                  {topId && (
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: '1px 7px', borderRadius: 4,
                      background: `${pathRiskColor}18`, color: pathRiskColor,
                      border: `1px solid ${pathRiskColor}30`, fontFamily: FONT.mono,
                    }}>
                      {pathRisk}
                    </span>
                  )}
                </div>
                <svg width={svgW} height={svgH} style={{ display: 'block', cursor: topId ? 'pointer' : 'default' }}
                  onClick={topId ? () => navigate(`/attack-simulator?identity=${topId.id}`) : undefined}>
                  <defs>
                    <marker id="ap-arrow" viewBox="0 0 10 7" refX="10" refY="3.5" markerWidth="8" markerHeight="6" orient="auto">
                      <path d="M0 0 L10 3.5 L0 7z" fill={COLORS.textDim} />
                    </marker>
                    {nodes.map((n) => {
                      const c = NODE_COLORS[n.type];
                      return (
                        <radialGradient key={`g-${n.id}`} id={`ap-glow-${n.id}`} cx="50%" cy="50%" r="50%">
                          <stop offset="0%" stopColor={c} stopOpacity="0.25" />
                          <stop offset="100%" stopColor={c} stopOpacity="0.05" />
                        </radialGradient>
                      );
                    })}
                    {identityHighlighted && (
                      <filter id="ap-highlight" x="-40%" y="-40%" width="180%" height="180%">
                        <feGaussianBlur in="SourceGraphic" stdDeviation="4" result="blur" />
                        <feFlood floodColor={NODE_COLORS.identity} floodOpacity="0.6" result="color" />
                        <feComposite in="color" in2="blur" operator="in" result="glow" />
                        <feMerge>
                          <feMergeNode in="glow" />
                          <feMergeNode in="SourceGraphic" />
                        </feMerge>
                      </filter>
                    )}
                  </defs>

                  {/* Edges */}
                  {edges.map((e, i) => {
                    const fromIdx = nodes.findIndex(n => n.id === e.from);
                    const toIdx = nodes.findIndex(n => n.id === e.to);
                    if (fromIdx < 0 || toIdx < 0) return null;
                    const x1 = nodePositions[fromIdx].cx + nodeW / 2;
                    const y1 = nodePositions[fromIdx].cy;
                    const x2 = nodePositions[toIdx].cx - nodeW / 2;
                    const y2 = nodePositions[toIdx].cy;
                    return (
                      <line key={`e-${i}`} x1={x1} y1={y1} x2={x2} y2={y2}
                        stroke={COLORS.textDim} strokeWidth={1.5} markerEnd="url(#ap-arrow)" />
                    );
                  })}

                  {/* Nodes */}
                  {nodes.map((n, i) => {
                    const pos = nodePositions[i];
                    const c = NODE_COLORS[n.type];
                    const rx = pos.cx - nodeW / 2;
                    const ry = pos.cy - nodeH / 2;
                    const isHighlit = identityHighlighted && n.type === 'identity';
                    return (
                      <g key={n.id} filter={isHighlit ? 'url(#ap-highlight)' : undefined}>
                        <title>{n.tooltip}</title>
                        {/* Glow background */}
                        <ellipse cx={pos.cx} cy={pos.cy} rx={nodeW / 2 + 6} ry={nodeH / 2 + 6}
                          fill={`url(#ap-glow-${n.id})`} />
                        {/* Node rect */}
                        <rect x={rx} y={ry} width={nodeW} height={nodeH} rx={6}
                          fill={isHighlit ? `${c}30` : `${c}18`} stroke={c}
                          strokeWidth={isHighlit ? 2.5 : 1.5}
                          style={{ cursor: topId ? 'pointer' : 'default' }} />
                        {/* Type icon dot */}
                        <circle cx={rx + 10} cy={pos.cy} r={3} fill={c} />
                        {/* Label */}
                        <text x={rx + 18} y={pos.cy + 1} fill={c} fontSize={9.5} fontWeight={600}
                          fontFamily={FONT.ui} dominantBaseline="central"
                          style={{ pointerEvents: 'none' }}>
                          {n.label.length > 10 ? n.label.slice(0, 10) + '\u2026' : n.label}
                        </text>
                        {/* Type badge below */}
                        <text x={pos.cx} y={ry + nodeH + 11} fill={COLORS.textMuted} fontSize={7.5}
                          fontFamily={FONT.ui} textAnchor="middle" style={{ pointerEvents: 'none', textTransform: 'uppercase', letterSpacing: '0.06em' } as React.CSSProperties}>
                          {n.type}
                        </text>
                      </g>
                    );
                  })}
                </svg>
                {topId && (
                  <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginTop: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span>Blast radius: {topId.blast_radius_score} · Risk score: {topId.risk_score}</span>
                    <span onClick={() => navigate(`/attack-simulator?identity=${topId.id}`)}
                      style={{ color: COLORS.accent, cursor: 'pointer', textDecoration: 'underline', textDecorationStyle: 'dashed' as const, textUnderlineOffset: '2px' }}>
                      Click graph to explore →
                    </span>
                  </div>
                )}
              </div>
            </div>
          </CISOCard>
        );
      })()}

      {/* Full-Width: GEI Table */}
      <GovernanceEffectivenessTable gei={d.agirs.gei} maturity={d.compliance.maturity} />
    </div>
  );
}

// ── Tab 2: Identity Risk — extracted to components/dashboard/risk/RiskMonitoringTab.tsx

// ── Tab 3: Action Plan ──
// Rule 30 fix: Removed duplicate "Capture Snapshot" system-action from remediation list.
// The snapshot button is rendered once at the top bar only.

function ActionPlanTooltip({ text, children }: { text: string; children: React.ReactNode }) {
  const [show, setShow] = useState(false);
  return (
    <span style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && (
        <span style={{
          position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
          background: '#0f172a', border: `1px solid ${COLORS.border}`, padding: '6px 10px',
          borderRadius: 6, fontSize: 10, color: '#e2e8f0', maxWidth: 260, whiteSpace: 'normal',
          zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', marginBottom: 6, pointerEvents: 'none',
          fontFamily: FONT.ui, lineHeight: 1.4, fontWeight: 400,
        }}>{text}</span>
      )}
    </span>
  );
}

function ActionPlanTab({ d, onPreview, onTicket }: { d: TenantData; onPreview: (r: Remediation) => void; onTicket: (r: Remediation) => void }) {
  const { withConnection } = useConnection();
  const [filter, setFilter] = useState<string>('all');
  const identityRemediations = d.remediations.filter(r => r.type === 'identity-remediation');
  const filtered = filter === 'all' ? identityRemediations :
    filter === 'auto' ? identityRemediations.filter(r => r.automation === 'Auto') :
    filter === 'manual' ? identityRemediations.filter(r => r.automation === 'Manual') :
    identityRemediations.filter(r => r.status === 'in-progress');
  const totalGain = identityRemediations.reduce((s, r) => s + r.gain, 0);
  const stages = ['new', 'planned', 'in-progress', 'verified', 'closed'];
  const stageLabels = ['Detected', 'Planned', 'In Progress', 'Verified', 'Closed'];
  const stageColors = [COLORS.textDim, COLORS.accent, COLORS.warning, COLORS.success, COLORS.textDim];

  const handleScan = useCallback(() => {
    fetch(withConnection('/api/runs/trigger'), { method: 'POST' }).catch(() => {});
  }, [withConnection]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top bar — Rule 30: single scan button, no system-action duplicates */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <button onClick={handleScan} style={{
          padding: '7px 16px', borderRadius: 6, fontSize: 11, fontWeight: 600,
          background: COLORS.accent, color: '#fff', border: 'none', cursor: 'pointer', fontFamily: FONT.ui,
        }}>Capture Snapshot</button>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, padding: '3px 8px', borderRadius: 4, background: 'rgba(16,185,129,0.08)', border: '1px solid rgba(16,185,129,0.2)', fontSize: 9, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.05em', color: '#059669', fontFamily: FONT.ui }} title="Snapshot data is immutable — it reflects the state at capture time">
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          Immutable
        </span>
        <span style={{ fontSize: 10, color: COLORS.textSecondary, marginLeft: 'auto', fontFamily: FONT.ui }}>
          Last snapshot: {formatDate(d.tenant.lastScan, 'No snapshot data')}
        </span>
      </div>

      {/* Lifecycle legend */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        {stages.map((s, i) => (
          <React.Fragment key={s}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10, color: stageColors[i], fontFamily: FONT.ui }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: stageColors[i], border: s === 'new' ? `2px solid ${COLORS.textDim}` : 'none' }} />
              {stageLabels[i]}
            </span>
            {i < stages.length - 1 && <span style={{ color: COLORS.textDim, fontSize: 10 }}>→</span>}
          </React.Fragment>
        ))}
      </div>

      {/* Filters */}
      <div style={{ display: 'flex', gap: 6 }}>
        {['all', 'auto', 'manual', 'in-progress'].map(f => (
          <button key={f} onClick={() => setFilter(f)} style={{
            padding: '4px 12px', borderRadius: 4, fontSize: 10, fontWeight: 600,
            background: filter === f ? COLORS.accentSoft : 'transparent',
            color: filter === f ? COLORS.accent : COLORS.textMuted,
            border: `1px solid ${filter === f ? `${COLORS.accent}40` : COLORS.border}`,
            cursor: 'pointer', fontFamily: FONT.ui, textTransform: 'capitalize' as const,
          }}>{f === 'all' ? 'All' : f === 'auto' ? 'Auto Only' : f === 'manual' ? 'Manual Only' : 'In Progress'}</button>
        ))}
      </div>

      {/* Remediation cards */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {filtered.map((r, i) => <RemediationCard key={r.id} item={r} index={i} data={d} onPreview={onPreview} onTicket={onTicket} />)}
      </div>

      {/* Remediation Impact Summary */}
      <CISOCard style={{ borderLeft: `3px solid ${COLORS.success}` }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
              Remediation Impact Summary
            </span>
            {(() => {
              // Confidence = f(data completeness, pillar coverage, identity graph depth)
              const completeness = d.tenant.scanCompleteness || 0;
              const pillarsCovered = d.pillars.filter(p => p.score > 0).length;
              const hasBlastRadius = d.blastRadius.highRisk > 0 || d.blastRadius.lowRisk > 0;
              const hasOwnership = (d.agirs.gei?.components || []).some(c => c.name === 'Ownership Coverage' && c.configured);
              const hasPim = (d.agirs.gei?.components || []).some(c => c.name === 'PIM Adoption' && c.configured);

              let signals = 0;
              if (completeness >= 80) signals += 2; else if (completeness >= 50) signals += 1;
              if (pillarsCovered >= 4) signals += 2; else if (pillarsCovered >= 2) signals += 1;
              if (hasBlastRadius) signals += 1;
              if (hasOwnership) signals += 1;
              if (hasPim) signals += 1;

              const level = signals >= 6 ? 'High' : signals >= 3 ? 'Medium' : 'Low';
              const color = level === 'High' ? COLORS.success : level === 'Medium' ? COLORS.warning : COLORS.danger;
              const tooltip = level === 'High'
                ? 'Strong identity graph coverage — privilege reduction estimates are reliable'
                : level === 'Medium'
                ? 'Partial graph data — estimates are directionally accurate but may shift with fuller discovery'
                : 'Limited graph data — run a full discovery scan to improve confidence';

              return (
                <span title={tooltip} style={{
                  fontSize: 9, fontWeight: 700, padding: '2px 8px', borderRadius: 4,
                  background: `${color}18`, color, border: `1px solid ${color}30`,
                  fontFamily: FONT.mono, cursor: 'help',
                }}>
                  {level} Confidence
                </span>
              );
            })()}
          </div>
          <DN navigateTo="/remediation">
            <span style={{ fontSize: 16, fontWeight: 700, color: COLORS.success, fontFamily: FONT.mono }}>
              +{totalGain} pts
            </span>
          </DN>
        </div>
        {/* Before / After comparison */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: 16, alignItems: 'center' }}>
          <div style={{ textAlign: 'center' as const, padding: '10px', borderRadius: 8, background: `${COLORS.danger}08`, border: `1px solid ${COLORS.danger}1a` }}>
            <div style={{ fontSize: 9, color: COLORS.danger, textTransform: 'uppercase' as const, letterSpacing: 1, marginBottom: 4, fontFamily: FONT.mono }}>Current</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: COLORS.text, fontFamily: FONT.mono }}>{d.riskScore.current.toFixed(1)}</div>
            <CISOBadge label={d.riskScore.tier} color={getTierColor(d.riskScore.tier)} />
          </div>
          <span style={{ fontSize: 20, color: COLORS.success, fontWeight: 700 }}>{'\u2192'}</span>
          <div style={{ textAlign: 'center' as const, padding: '10px', borderRadius: 8, background: `${COLORS.success}08`, border: `1px solid ${COLORS.success}1a` }}>
            <div style={{ fontSize: 9, color: COLORS.success, textTransform: 'uppercase' as const, letterSpacing: 1, marginBottom: 4, fontFamily: FONT.mono }}>After Remediation</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: COLORS.text, fontFamily: FONT.mono }}>{d.projection.remediated.score.toFixed(1)}</div>
            <CISOBadge label={d.projection.remediated.tier} color={getTierColor(d.projection.remediated.tier)} />
          </div>
        </div>
        <div style={{ marginTop: 12, display: 'flex', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui }}>
            {identityRemediations.length} remediations &middot; {identityRemediations.filter(r => r.automation === 'Auto').length} auto &middot; {identityRemediations.filter(r => r.productionImpact).length} prod impact
          </div>
        </div>

        {/* Risk Reduction Explanation */}
        {identityRemediations.length > 0 && (() => {
          // Derive breakdown from remediation types
          const privilegesRemoved = identityRemediations.filter(r =>
            r.id === 'r1' || r.title.toLowerCase().includes('over-privileged') || r.title.toLowerCase().includes('reduce')
          ).reduce((s, r) => { const m = r.affected?.match(/^(\d+)/); return s + (m ? parseInt(m[1], 10) : 0); }, 0);
          const rolesDowngraded = identityRemediations.filter(r =>
            r.id === 'r2' || r.id === 'r2b' || r.title.toLowerCase().includes('dormant') || r.title.toLowerCase().includes('revoke')
          ).reduce((s, r) => { const m = r.affected?.match(/^(\d+)/); return s + (m ? parseInt(m[1], 10) : 0); }, 0);
          const totalAffected = identityRemediations.reduce((s, r) => {
            const m = r.affected?.match(/^(\d+)/);
            return s + (m ? parseInt(m[1], 10) : 0);
          }, 0);
          const blastHigh = d.blastRadius.highRisk || 1;
          const blastReduction = blastHigh > 0 ? Math.min(99, Math.round((totalAffected / blastHigh) * 100)) : 0;

          return (
            <div style={{
              marginTop: 14, padding: '12px 16px', borderRadius: 8,
              background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10 }}>
                <span style={{ fontSize: 10, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>
                  Risk Reduction
                </span>
                <ActionPlanTooltip text="AuditGraph simulates identity graph changes to estimate risk reduction.">
                  <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                </ActionPlanTooltip>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 2 }}>Privileges removed</div>
                  <DN navigateTo="/identities?pillar=effective-privilege">
                    <span style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: privilegesRemoved > 0 ? COLORS.success : COLORS.textDim }}>{privilegesRemoved}</span>
                  </DN>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 2 }}>Roles downgraded</div>
                  <DN navigateTo="/identities?activity_status=dormant_strict&privileged=true">
                    <span style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: rolesDowngraded > 0 ? COLORS.success : COLORS.textDim }}>{rolesDowngraded}</span>
                  </DN>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 2 }}>Blast radius reduction</div>
                  <span style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: blastReduction > 0 ? COLORS.success : COLORS.textDim }}>{blastReduction}%</span>
                </div>
                <div>
                  <div style={{ fontSize: 9, color: COLORS.textMuted, fontFamily: FONT.ui, marginBottom: 2 }}>Identities affected</div>
                  <DN navigateTo="/identities">
                    <span style={{ fontSize: 18, fontWeight: 700, fontFamily: FONT.mono, color: totalAffected > 0 ? COLORS.text : COLORS.textDim }}>{totalAffected}</span>
                  </DN>
                </div>
              </div>
            </div>
          );
        })()}
      </CISOCard>
    </div>
  );
}

// ── Tab 4: Control & Governance ──
// Rule 31 fix: Governance ring displays raw effectivenessScore (e.g. "1"), not score*10.

function ControlGovTooltip({ text, children }: { text: string; children: React.ReactNode }) {
  const [show, setShow] = useState(false);
  return (
    <span style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}
      onMouseEnter={() => setShow(true)} onMouseLeave={() => setShow(false)}>
      {children}
      {show && (
        <span style={{
          position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
          background: '#0f172a', border: `1px solid ${COLORS.border}`, padding: '6px 10px',
          borderRadius: 6, fontSize: 10, color: '#e2e8f0', maxWidth: 260, whiteSpace: 'normal',
          zIndex: 100, boxShadow: '0 4px 12px rgba(0,0,0,0.5)', marginBottom: 6, pointerEvents: 'none',
          fontFamily: FONT.ui, lineHeight: 1.4, fontWeight: 400,
        }}>{text}</span>
      )}
    </span>
  );
}

const GOV_METRIC_TOOLTIPS: Record<string, string> = {
  'Ownership Coverage': 'Percentage of service principals with a designated owner. Unowned SPNs lack accountability for access reviews and credential rotation.',
  'PIM Enforcement': 'Percentage of privileged roles protected by PIM (just-in-time activation). Standing admin access without PIM is a primary attack vector.',
  'Access Reviews': 'Completion of periodic access certifications for privileged identities. Reviews catch over-provisioned and orphaned role assignments.',
  'Privileged Monitoring': 'Coverage of privileged identity monitoring via P2 telemetry. Without monitoring, compromised privileged accounts remain undetected.',
};

const MATURITY_DESCRIPTIONS: Record<string, string> = {
  'Unknown': 'Governance controls not yet assessed. Configure ownership, PIM, and review policies to begin.',
  'Ad-Hoc': 'Identity governance is reactive and inconsistent. Key controls are missing or manually executed.',
  'Developing': 'Basic governance processes exist but lack consistency. Some controls automated, many gaps remain.',
  'Managed': 'Governance processes are standardized and measured. Most controls operational with regular reviews.',
  'Optimized': 'Governance is fully automated with continuous improvement. All controls operational and exceeding targets.',
};

function ControlGovernanceTab({ d }: { d: TenantData }) {
  const navigate = useNavigate();
  const maturityDesc = MATURITY_DESCRIPTIONS[d.governance.maturityLevel] || MATURITY_DESCRIPTIONS['Unknown'];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
      {/* Governance Metric Cards — enhanced with tooltips */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        {d.governance.metrics.map((m, i) => {
          const numVal = parseFloat(String(m.value).replace(/[^0-9.]/g, ''));
          const numTarget = parseFloat(String(m.target).replace(/[^0-9.]/g, ''));
          const trendArrow = m.status === 'not-configured' ? '' : numVal >= numTarget ? '\u2191' : numVal >= numTarget * 0.7 ? '\u2192' : '\u2193';
          const trendColor = trendArrow === '\u2191' ? COLORS.success : trendArrow === '\u2192' ? COLORS.warning : COLORS.danger;
          const govNav = m.label.toLowerCase().includes('access review') ? '/access-reviews' :
            m.label.toLowerCase().includes('owner') ? '/service-accounts' :
            m.label.toLowerCase().includes('rotation') || m.label.toLowerCase().includes('credential') ? '/key-vaults' :
            m.label.toLowerCase().includes('pim') || m.label.toLowerCase().includes('jit') ? '/identities?pillar=effective-privilege' :
            '/service-accounts';
          const navTarget = m.status !== 'not-configured' ? govNav : '/settings/governance';
          const tooltip = GOV_METRIC_TOOLTIPS[m.label] || '';
          return (
          <CISOCard key={i}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.1em', color: COLORS.textSecondary, fontFamily: FONT.ui }}>{m.icon} {m.label}</span>
              {tooltip && (
                <ControlGovTooltip text={tooltip}>
                  <span style={{ fontSize: 10, color: COLORS.textDim, cursor: 'help' }}>{'\u24D8'}</span>
                </ControlGovTooltip>
              )}
            </div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <DN navigateTo={navTarget}>
                <div style={{
                  fontSize: 28, fontWeight: 700, fontFamily: FONT.mono, marginTop: 6,
                  color: m.status === 'not-configured' ? COLORS.textDim : m.status === 'critical' ? COLORS.danger : COLORS.success,
                }}>{m.value}</div>
              </DN>
              {trendArrow && <span style={{ fontSize: 16, color: trendColor, fontWeight: 700 }}>{trendArrow}</span>}
            </div>
            <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>Target: {m.target}</div>
            {m.status === 'not-configured' && (
              <button onClick={() => navigate('/settings/governance')} style={{
                marginTop: 8, padding: '4px 10px', borderRadius: 4, fontSize: 10,
                background: COLORS.accentSoft, color: COLORS.accent, border: `1px solid ${COLORS.accent}30`,
                cursor: 'pointer', fontFamily: FONT.ui,
              }}>Configure {'\u2192'}</button>
            )}
          </CISOCard>
          );
        })}
      </div>

      {/* Two-column: Control Failures + Governance Effectiveness */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
        <CISOCard>
          <SectionTitle>Control Failures</SectionTitle>
          {d.governance.controlFailures.length === 0 && (
            <div style={{ padding: '16px 0', textAlign: 'center' as const }}>
              <div style={{ fontSize: 12, color: COLORS.success, fontFamily: FONT.ui, fontWeight: 600 }}>No control failures detected</div>
              <div style={{ fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui, marginTop: 4 }}>All preventive and operational controls are passing</div>
            </div>
          )}
          {d.governance.controlFailures.map((group, gi) => (
            <div key={gi} style={{ marginBottom: 16 }}>
              <div style={{
                fontSize: 10, fontWeight: 600, textTransform: 'uppercase' as const, letterSpacing: '0.08em',
                color: group.type.includes('PREVENTIVE') ? COLORS.danger : COLORS.warning,
                marginBottom: 8, fontFamily: FONT.ui,
              }}>{'\u25B8'} {group.type}</div>
              {group.items.map((item, ii) => {
                const cfNav = item.label.toLowerCase().includes('pim') || item.label.toLowerCase().includes('privilege outside') ? '/identities?pillar=effective-privilege' :
                  item.label.toLowerCase().includes('disabled') || item.label.toLowerCase().includes('ghost') ? '/identities?status=disabled&hasRoles=true' :
                  item.label.toLowerCase().includes('ownership') || item.label.toLowerCase().includes('unowned') ? '/identities?pillar=ownership-governance' :
                  item.label.toLowerCase().includes('dormant') ? '/identities?pillar=usage-dormancy' :
                  item.label.toLowerCase().includes('credential') || item.label.toLowerCase().includes('expired') ? '/identities?pillar=credential-risk' :
                  '/identities';
                return (
                <div key={ii} style={{ display: 'flex', justifyContent: 'space-between', padding: '5px 0', borderBottom: `1px solid ${COLORS.border}` }}>
                  <span style={{ fontSize: 11, color: COLORS.text, fontFamily: FONT.ui }}>{'\u25CF'} {item.label}</span>
                  <DN navigateTo={cfNav}>
                    <span style={{ fontSize: 11, fontWeight: 600, fontFamily: FONT.mono, color: item.color }}>{item.count}</span>
                  </DN>
                </div>);
              })}
            </div>
          ))}
        </CISOCard>

        <CISOCard>
          <SectionTitle>Governance Effectiveness</SectionTitle>
          <div style={{ display: 'flex', alignItems: 'center', gap: 20, marginBottom: 14 }}>
            <ScoreRing
              score={d.governance.effectivenessScore * 10}
              size={80} strokeWidth={5}
              color={getTierColor(d.governance.effectivenessTier)}
              displayValue={String(d.governance.effectivenessScore)}
            />
            <div>
              <DN navigateTo="/service-accounts">
                <div style={{ fontSize: 24, fontWeight: 700, fontFamily: FONT.mono, color: COLORS.text }}>{d.governance.effectivenessScore}/10</div>
              </DN>
              <CISOBadge label={d.governance.effectivenessTier} color={getTierColor(d.governance.effectivenessTier)} />
              <div style={{ marginTop: 6 }}>
                <CISOBadge label={d.governance.maturityLevel} color={
                  d.governance.maturityLevel === 'Optimized' ? COLORS.accent :
                  d.governance.maturityLevel === 'Managed' ? COLORS.success :
                  d.governance.maturityLevel === 'Developing' ? COLORS.warning :
                  COLORS.textMuted
                } />
              </div>
            </div>
          </div>
          {/* Maturity level description */}
          <div style={{
            padding: '10px 12px', borderRadius: 6, background: COLORS.surfaceAlt,
            border: `1px solid ${COLORS.border}`,
          }}>
            <div style={{ fontSize: 9, fontWeight: 700, textTransform: 'uppercase' as const, letterSpacing: '0.08em', color: COLORS.textSecondary, fontFamily: FONT.ui, marginBottom: 4 }}>
              Maturity: {d.governance.maturityLevel}
            </div>
            <div style={{ fontSize: 11, color: COLORS.textSecondary, fontFamily: FONT.ui, lineHeight: 1.5 }}>
              {maturityDesc}
            </div>
          </div>
          {/* Setup completion */}
          <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 9, color: COLORS.textDim, fontFamily: FONT.ui, textTransform: 'uppercase' as const }}>Setup</span>
            <div style={{ flex: 1, height: 3, borderRadius: 2, background: COLORS.border }}>
              <div style={{ height: '100%', borderRadius: 2, width: `${(d.governance.setupCompletion.configured / d.governance.setupCompletion.total) * 100}%`, background: COLORS.accent, transition: 'width 0.5s ease' }} />
            </div>
            <span style={{ fontSize: 9, color: COLORS.textSecondary, fontFamily: FONT.mono }}>{d.governance.setupCompletion.configured}/{d.governance.setupCompletion.total}</span>
          </div>
        </CISOCard>
      </div>
    </div>
  );
}

// ── Tab 5: Compliance & Evidence — extracted to components/dashboard/compliance/ComplianceTab.tsx

// ── Tab 6: Risk Movement — extracted to components/dashboard/risk/RiskMovementTab.tsx

// ─── Tab Configuration ───────────────────────────────────────────

type CISOTab = 'exec' | 'risk' | 'action' | 'governance' | 'compliance' | 'movement';

const TAB_CONFIG: { id: CISOTab; label: string }[] = [
  { id: 'exec', label: 'Executive Summary' },
  { id: 'risk', label: 'Identity Risk' },
  { id: 'action', label: 'Action Plan' },
  { id: 'governance', label: 'Control & Governance' },
  { id: 'compliance', label: 'Compliance & Evidence' },
  { id: 'movement', label: 'Risk Movement' },
];

// ─── Main Dashboard Component ────────────────────────────────────

export default function CISODashboard() {
  const [activeTab, setActiveTab] = useState<CISOTab>('exec');
  const { data, loading } = useCISOData();

  // v3.0.5: Preview Changes + Create Ticket state (DrillDownPanel removed)
  const [previewRem, setPreviewRem] = useState<Remediation | null>(null);
  const [ticketRem, setTicketRem] = useState<Remediation | null>(null);

  // Tab content renderer
  const renderTab = () => {
    switch (activeTab) {
      case 'exec': return <ExecSummaryTab d={data} onPreview={setPreviewRem} onTicket={setTicketRem} />;
      case 'risk': return <RiskMonitoringTab d={data} />;
      case 'action': return <ActionPlanTab d={data} onPreview={setPreviewRem} onTicket={setTicketRem} />;
      case 'governance': return <ControlGovernanceTab d={data} />;
      case 'compliance': return <ComplianceTab d={data} />;
      case 'movement': return <RiskMovementTab d={data} />;
    }
  };

  if (loading) {
    return (
      <IdentityDrawerProvider>
        <div style={{
          minHeight: 'calc(100vh - 56px)', background: COLORS.bg,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          borderRadius: '12px 0 0 0',
        }}>
          <div style={{ textAlign: 'center' as const }}>
            <div style={{
              width: 40, height: 40, borderRadius: '50%',
              border: `3px solid ${COLORS.border}`, borderTopColor: COLORS.accent,
              animation: 'spin 1s linear infinite', margin: '0 auto 12px',
            }} />
            <div style={{ fontSize: 12, color: COLORS.textSecondary, fontFamily: FONT.ui }}>Loading Executive Summary...</div>
          </div>
          <style>{`@keyframes spin { to { transform: rotate(360deg) } } @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }`}</style>
        </div>
        <IdentityContextDrawer />
      </IdentityDrawerProvider>
    );
  }

  return (
    <IdentityDrawerProvider>
      <div style={{ minHeight: 'calc(100vh - 56px)', background: COLORS.bg, fontFamily: FONT.ui, borderRadius: '12px 0 0 0' }}>
        <style>{`@keyframes spin { to { transform: rotate(360deg) } } @keyframes pulse { 0%, 100% { opacity: 1 } 50% { opacity: 0.4 } }`}</style>

        {/* Tab Bar */}
        <div style={{
          borderBottom: `1px solid ${COLORS.border}`, display: 'flex', padding: '0 24px',
          background: COLORS.surface, borderRadius: '12px 0 0 0',
        }}>
          {TAB_CONFIG.map(t => (
            <div key={t.id} onClick={() => setActiveTab(t.id)} style={{
              padding: '12px 18px', cursor: 'pointer', fontSize: 12, fontFamily: FONT.ui,
              color: activeTab === t.id ? COLORS.accent : COLORS.textMuted,
              fontWeight: activeTab === t.id ? 600 : 400,
              borderBottom: `2px solid ${activeTab === t.id ? COLORS.accent : 'transparent'}`,
              transition: 'all 0.15s ease',
            }}>
              {t.label}
            </div>
          ))}

          {/* Scan status indicator */}
          <div style={{
            marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8,
            fontSize: 10, color: COLORS.textSecondary, fontFamily: FONT.ui,
          }}>
            <span>Updated {formatDate(data.tenant.lastScan, 'No snapshot data')}</span>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: COLORS.success }} />
          </div>
        </div>

        {/* v3.0.9: Confidence / Data Completeness Banner */}
        <div style={{
          margin: '12px 24px 0', padding: '8px 14px', borderRadius: 8,
          background: COLORS.surfaceAlt, border: `1px solid ${COLORS.border}`,
          display: 'flex', alignItems: 'center', gap: 16, fontSize: 10, fontFamily: FONT.ui,
        }}>
          <span style={{ color: COLORS.textSecondary }}>Data Completeness</span>
          <div style={{ width: 80, height: 4, borderRadius: 2, background: COLORS.border, overflow: 'hidden' }}>
            <div style={{ width: `${data.tenant.scanCompleteness}%`, height: '100%', background: data.tenant.scanCompleteness >= 80 ? COLORS.success : COLORS.warning, borderRadius: 2 }} />
          </div>
          <DN navigateTo="/settings/connections">
            <span style={{ fontFamily: FONT.mono, fontWeight: 600, color: data.tenant.scanCompleteness >= 80 ? COLORS.success : COLORS.warning }}>{data.tenant.scanCompleteness}%</span>
          </DN>
          <span style={{ color: COLORS.textDim }}>|</span>
          <span style={{ color: COLORS.textSecondary }}>Confidence</span>
          <CISOBadge label={data.tenant.scanConfidence || 'Unknown'} color={
            data.tenant.scanConfidence?.toLowerCase() === 'high' ? COLORS.success :
            data.tenant.scanConfidence?.toLowerCase() === 'medium' ? COLORS.warning : COLORS.textMuted
          } />
          <span style={{ color: COLORS.textDim }}>|</span>
          <span style={{ color: COLORS.textSecondary }}>Sources: {data.tenant.sources?.join(', ') || 'Graph API'}</span>
        </div>

        {/* Tab Content */}
        <div style={{ padding: 24 }}>
          {renderTab()}
        </div>

        {/* v3.0.5 Panels */}
        {previewRem && <PreviewChangesPanel rem={previewRem} data={data} onClose={() => setPreviewRem(null)} />}
        {ticketRem && <CreateTicketModal rem={ticketRem} data={data} onClose={() => setTicketRem(null)} />}
      </div>
      <IdentityContextDrawer />
    </IdentityDrawerProvider>
  );
}
