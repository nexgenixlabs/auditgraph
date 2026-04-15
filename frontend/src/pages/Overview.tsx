import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useConnection } from '../contexts/ConnectionContext';
import { formatDate } from '../utils/displayHelpers';
import {
  type TenantData, type Nav, type Framework, type FilterType, type DrillPanelState,
  F, P, FILTER_NAV,
  getTierColor, formatDelta,
  ScoreRing, RiskTierBadge, DataFreshnessBar, DrillableNumber, DrillDownPanel, ComplianceDetailPanel, ExportMenu,
} from '../components/overview/overview-shared';
import { fetchTenantData } from '../components/overview/overview-data';
import { ExecutiveSummaryTab } from '../components/overview/ExecutiveSummaryTab';
import { IdentityRiskTab } from '../components/overview/IdentityRiskTab';
import { ActionPlanTab } from '../components/overview/ActionPlanTab';
import { ControlGovernanceTab } from '../components/overview/ControlGovernanceTab';
import { ComplianceEvidenceTab } from '../components/overview/ComplianceEvidenceTab';
import { RiskMovementTab } from '../components/overview/RiskMovementTab';


const TABS = [
  { id: 'exec', label: 'Executive Summary' },
  { id: 'risk', label: 'Identity Risk' },
  { id: 'action', label: 'Action Plan' },
  { id: 'governance', label: 'Control & Governance' },
  { id: 'compliance', label: 'Compliance & Evidence' },
  { id: 'movement', label: 'Risk Movement' },
];

export default function Overview() {
  const navigate = useNavigate();
  const { withConnection, selectedConnectionId } = useConnection();
  const [data, setData] = useState<TenantData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState('exec');
  const [filter, setFilter] = useState<FilterType>('All');
  const [viewMode, setViewMode] = useState<'Detailed' | 'Executive'>('Detailed');
  const [drillPanel, setDrillPanel] = useState<DrillPanelState>({ open: false, title: '', filterUrl: '', identities: [], loading: false });
  const [compliancePanel, setCompliancePanel] = useState<{ open: boolean; framework: Framework | null }>({ open: false, framework: null });
  const [exportMenu, setExportMenu] = useState<{ open: boolean; framework: Framework | null; anchorRect: DOMRect | null }>({ open: false, framework: null, anchorRect: null });

  const nav: Nav = useCallback((path: string) => navigate(path), [navigate]);

  const openDrill = useCallback((title: string, filterUrl: string) => {
    setDrillPanel({ open: true, title, filterUrl, identities: [], loading: true });
    const apiUrl = filterUrl.replace(/^\/identities/, '/api/identities');
    const joiner = apiUrl.includes('?') ? '&' : '?';
    fetch(withConnection(`${apiUrl}${joiner}limit=20`))
      .then(r => r.ok ? r.json() : { identities: [] })
      .then(data => setDrillPanel(prev => ({ ...prev, identities: data.identities || [], loading: false })))
      .catch(() => setDrillPanel(prev => ({ ...prev, identities: [], loading: false })));
  }, [withConnection]);

  const openComplianceDetail = useCallback((fw: Framework) => { setCompliancePanel({ open: true, framework: fw }); }, []);
  const closeComplianceDetail = useCallback(() => { setCompliancePanel({ open: false, framework: null }); }, []);
  const openExportMenuCb = useCallback((fw: Framework, rect: DOMRect) => { setExportMenu({ open: true, framework: fw, anchorRect: rect }); }, []);
  const closeExportMenu = useCallback(() => { setExportMenu({ open: false, framework: null, anchorRect: null }); }, []);

  useEffect(() => {
    // Inject Google Fonts
    if (!document.getElementById('exec-fonts')) {
      const link = document.createElement('link');
      link.id = 'exec-fonts';
      link.rel = 'stylesheet';
      link.href = 'https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700;800&display=swap';
      document.head.appendChild(link);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    fetchTenantData(withConnection)
      .then(d => { setData(d); setLoading(false); })
      .catch(e => { setError(e.message); setLoading(false); });
  }, [selectedConnectionId, withConnection]);

  if (loading) {
    return (
      <div style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: P.bgPage,
        fontFamily: F.data, fontSize: 14, color: P.textMuted,
      }}>Loading...</div>
    );
  }

  if (error || !data) {
    return (
      <div style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: P.bgPage,
        fontFamily: F.ui, fontSize: 14, color: '#ff4444',
      }}>Failed to load dashboard data: {error}</div>
    );
  }

  const d = data;
  const tier = d.riskScore.tier;
  const tierColor = getTierColor(tier);

  // Identity count based on filter
  const identityCount = filter === 'All' ? d.identities.total
    : filter === 'Users' ? d.identities.byType.users
    : filter === 'SPNs' ? d.identities.byType.servicePrincipals
    : filter === 'Managed' ? d.identities.byType.managedIdentities
    : d.identities.byType.workloadIdentities;

  const renderTab = () => {
    switch (activeTab) {
      case 'exec': return <ExecutiveSummaryTab d={d} nav={nav} openDrill={openDrill} setActiveTab={setActiveTab} openComplianceDetail={openComplianceDetail} />;
      case 'risk': return <IdentityRiskTab d={d} nav={nav} />;
      case 'action': return <ActionPlanTab d={d} nav={nav} />;
      case 'governance': return <ControlGovernanceTab d={d} nav={nav} />;
      case 'compliance': return <ComplianceEvidenceTab d={d} nav={nav} openDrill={openDrill} setActiveTab={setActiveTab} openComplianceDetail={openComplianceDetail} openExportMenu={openExportMenuCb} />;
      case 'movement': return <RiskMovementTab d={d} nav={nav} />;
      default: return null;
    }
  };

  return (
    <div style={{
      minHeight: '100vh', fontFamily: F.ui, color: P.textBright,
      background: P.bgPage,
      padding: '24px 32px',
      animation: 'execFadeIn 0.5s ease',
    }}>
      <style>{`@keyframes execFadeIn { from { opacity: 0; } to { opacity: 1; } }`}</style>

      {/* ── DATA FRESHNESS BAR ── */}
      <DataFreshnessBar tenant={d.tenant} scoring={d.scoringMethodology} />

      {/* ── HEADER ── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 24, marginBottom: 24 }}>
        <ScoreRing score={d.riskScore.current} grade={d.riskScore.grade} size={80} />

        <div style={{ flex: 1 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {d.tenant.organizationLogo && (
              <img src={d.tenant.organizationLogo} alt="" style={{ height: 28, borderRadius: 4 }} />
            )}
            <div>
              <div style={{ fontFamily: F.ui, fontSize: 18, fontWeight: 700, color: P.textBright }}>{d.tenant.organizationName}</div>
              <div style={{ fontFamily: F.ui, fontSize: 12, color: P.textMuted }}>Identity Attack Surface Management</div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 12, marginTop: 6, alignItems: 'center' }}>
            <RiskTierBadge tier={tier} />
            {d.riskScore.delta30d != null ? (
              <span style={{ fontFamily: F.data, fontSize: 10, color: d.riskScore.delta30d >= 0 ? '#22c55e' : '#ff4444' }}>
                {formatDelta(d.riskScore.delta30d)} vs 30d
              </span>
            ) : (
              <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>No previous scan</span>
            )}
            <span style={{ fontFamily: F.data, fontSize: 10, color: P.textFaint }}>|</span>
            <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>Industry: {d.riskScore.industryAvg != null ? <DrillableNumber value={d.riskScore.industryAvg} label="Industry average posture" onClick={() => navigate('/identities')} /> : 'N/A'}</span>
            <span style={{ fontFamily: F.data, fontSize: 10, color: P.textDim }}>Target: <DrillableNumber value={d.riskScore.target} label="Posture target (configurable in Settings)" onClick={() => navigate('/settings')} /></span>
            <span style={{ fontFamily: F.data, fontSize: 10, color: '#22c55e' }}>Potential: <DrillableNumber value={`+${d.riskScore.potentialGain}`} label="Potential gain from remediations" onClick={() => setActiveTab('action')} /></span>
          </div>
          <div style={{ marginTop: 4, fontFamily: F.data, fontSize: 10, color: P.textFaint }}>
            {'\u2022'} {d.tenant.cloud} {'\u2022'} <DrillableNumber value={d.tenant.subscriptions} label="View subscriptions" onClick={() => navigate('/subscriptions')} /> subs {'\u2022'} {formatDate(d.tenant.lastScan, 'No snapshot data')}
          </div>
        </div>

        {/* Filters */}
        <div style={{ display: 'flex', gap: 4, padding: 4, background: P.bgSubtle, borderRadius: 8, border: `1px solid ${P.borderCard}` }}>
          {(['All', 'Users', 'SPNs', 'Managed', 'Workload'] as FilterType[]).map(f => (
            <button key={f} onClick={() => setFilter(f)} style={{
              fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '4px 10px', borderRadius: 6,
              border: 'none', cursor: 'pointer',
              background: filter === f ? P.accentIndigoBg : 'transparent',
              color: filter === f ? P.accentIndigo : P.textDim, transition: 'all 0.2s ease',
            }}>{f}</button>
          ))}
        </div>

        {/* Identity count — click opens drill-down panel */}
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontFamily: F.data, fontSize: 28, fontWeight: 800, color: P.textBright }}><DrillableNumber value={identityCount} label="Drill into identities" onClick={() => openDrill(`${filter} Identities`, FILTER_NAV[filter] || '/identities')} /></div>
          <div style={{ fontFamily: F.data, fontSize: 9, color: P.textDim, textTransform: 'uppercase' }}>Identities</div>
          <div style={{ display: 'flex', gap: 6, marginTop: 4 }}>
            {d.identities.critical > 0 && <span style={{ fontFamily: F.data, fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(255,68,68,0.15)', color: '#ff4444', cursor: 'pointer' }}><DrillableNumber value={`CRIT ${d.identities.critical}`} label="Critical identities" onClick={() => openDrill('Critical Identities', '/identities?risk_level=critical')} /></span>}
            {d.identities.high > 0 && <span style={{ fontFamily: F.data, fontSize: 9, padding: '1px 6px', borderRadius: 3, background: 'rgba(255,140,0,0.15)', color: '#ff8c00', cursor: 'pointer' }}><DrillableNumber value={`HIGH ${d.identities.high}`} label="High risk identities" onClick={() => openDrill('High Risk Identities', '/identities?risk_level=high')} /></span>}
          </div>
        </div>

        {/* View mode */}
        <div style={{ display: 'flex', gap: 4, padding: 4, background: P.bgSubtle, borderRadius: 8, border: `1px solid ${P.borderCard}` }}>
          {(['Detailed', 'Executive'] as const).map(v => (
            <button key={v} onClick={() => setViewMode(v)} style={{
              fontFamily: F.data, fontSize: 10, fontWeight: 600, padding: '4px 10px', borderRadius: 6,
              border: 'none', cursor: 'pointer',
              background: viewMode === v ? P.accentIndigoBg : 'transparent',
              color: viewMode === v ? P.accentIndigo : P.textDim, transition: 'all 0.2s ease',
            }}>{v}</button>
          ))}
        </div>
      </div>

      {/* ── TAB BAR ── */}
      <div style={{ display: 'flex', gap: 0, borderBottom: `1px solid ${P.borderCard}`, marginBottom: 24 }}>
        {TABS.map(tab => (
          <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
            fontFamily: F.ui, fontSize: 13, fontWeight: 500, padding: '10px 20px',
            border: 'none', cursor: 'pointer', background: 'transparent', transition: 'all 0.2s ease',
            color: activeTab === tab.id ? P.textLight : P.textDim,
            borderBottom: `2px solid ${activeTab === tab.id ? P.accentStrong : 'transparent'}`,
          }}>{tab.label}</button>
        ))}
      </div>

      {/* ── TAB CONTENT ── */}
      {renderTab()}

      {/* ── DRILL DOWN PANEL ── */}
      <DrillDownPanel
        state={drillPanel}
        onClose={() => setDrillPanel(prev => ({ ...prev, open: false }))}
        onViewAll={() => { setDrillPanel(prev => ({ ...prev, open: false })); nav(drillPanel.filterUrl); }}
      />

      {/* ── COMPLIANCE DETAIL PANEL ── */}
      <ComplianceDetailPanel
        state={compliancePanel}
        onClose={closeComplianceDetail}
        openDrill={openDrill}
        setDrillPanel={setDrillPanel}
      />

      {/* ── EXPORT MENU ── */}
      <ExportMenu state={exportMenu} onClose={closeExportMenu} />
    </div>
  );
}
