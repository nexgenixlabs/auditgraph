/**
 * AuditGraph Frontend Application Root
 *
 * Sets up:
 * - React Router routes
 * - Global navigation bar
 * - Front Page (Overview - Enterprise Risk Intelligence)
 *
 * Routes:
 *   /                  - Overview (global risk, cloud comparison, categories)
 *   /dashboard          - Dashboard (heat map, detailed analytics)
 *   /identities         - Identity list
 *   /identities/:id     - Identity detail (5-tab architecture)
 */
import React, { useEffect, useState } from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
} from 'react-router-dom';

import Dashboard from './pages/Dashboard';
import Identities from './pages/Identities';
import IdentityDetail from './pages/IdentityDetail';
import LifecycleJml from './pages/LifecycleJml';
import ConnectedApps from './pages/ConnectedApps';
import ShadowApps from './pages/ShadowApps';
import AIAttackPaths from './pages/AIAttackPaths';
import AIBoardScorecard from './pages/AIBoardScorecard';
import AILifecycle from './pages/AILifecycle';
import AIDataReachability from './pages/AIDataReachability';
import Argus from './pages/Argus';
import Reports from './pages/Reports';
import Settings from './pages/Settings';
import DriftHistory from './pages/DriftHistory';
import ActivityLog from './pages/ActivityLog';
import IdentityComparison from './pages/IdentityComparison';
import NotificationCenter from './pages/NotificationCenter';
import Compliance from './pages/Compliance';
import Exports from './pages/Exports';
import AccessReviews from './pages/AccessReviews';
import RoleMining from './pages/RoleMining';
import IdentityGroups from './pages/IdentityGroups';
import Login from './pages/Login';
import Signup from './pages/Signup';
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import LockedDashboard from './pages/LockedDashboard';
import CrossTenantAnalytics from './pages/CrossTenantAnalytics';
import OnboardingWizard from './pages/OnboardingWizard';
import DataSecurity from './pages/DataSecurity';
import AdminConsole from './pages/AdminConsole';
import SsoCallback from './pages/SsoCallback';
import ServiceAccountGovernance from './pages/ServiceAccountGovernance';
import SPNDashboard from './pages/SPNDashboard';
import AppRegistrations from './pages/AppRegistrations';
import IdentityCorrelation from './pages/IdentityCorrelation';
import WorkloadIdentities from './pages/WorkloadIdentities';
import AIAgents from './pages/AIAgents';
// 5-pillar AI Security IA per AG-161. The standalone AIIdentityGraph,
// AIAgentsStandalone, and AIPermissions pages are now wrapped inside these
// pillars; legacy URLs redirect (see Route declarations below).
import AIInventory from './pages/AIInventory';
import AIAccess from './pages/AIAccess';
import AIModelRegistry from './pages/AIModelRegistry';
import AIFindings from './pages/AIFindings';
import MultiHopXGraph from './pages/MultiHopXGraph';
import AISupplyChain from './pages/AISupplyChain';
import AIThreatConnectors from './pages/AIThreatConnectors';
import IdentityTrust from './pages/IdentityTrust';
import OwnershipCenter from './pages/OwnershipCenter';
import PeerBenchmarking from './pages/PeerBenchmarking';
import AIRuntime from './pages/AIRuntime';
import AgentActivityTimeline from './pages/AgentActivityTimeline';
import AIRisk from './pages/AIRisk';
import AIGovernance from './pages/AIGovernance';
import WorkloadIdentityDetail from './pages/WorkloadIdentityDetail';
import Subscriptions from './pages/Subscriptions';
import ClientBilling from './pages/ClientBilling';
import RbacHygiene from './pages/RbacHygiene';
import AccessGraph from './pages/AccessGraph';
import EffectiveAccessExplorer from './pages/EffectiveAccessExplorer';
import SensitiveDataAccess from './pages/SensitiveDataAccess';
import CISODashboard from './pages/CISODashboard';
import RemediationCenter from './pages/RemediationCenter';
import SecurityFindings from './pages/SecurityFindings';
import GraphFindings from './pages/GraphFindings';
import SecurityCommandCenter from './pages/SecurityCommandCenter';
import IdentityGraph from './pages/IdentityGraph';
import IdentityExplorer from './pages/IdentityExplorer';
import IdentityExposures from './pages/IdentityExposures';
import PrivilegeDrift from './pages/PrivilegeDrift';
import DriftAnalysis from './pages/DriftAnalysis';
import AttackSimulator from './pages/AttackSimulator';
import AttackPaths from './pages/AttackPaths';
import AttackPathDetailPage from './pages/AttackPathDetail';
import RemediationQueue from './pages/RemediationQueue';
import RemediationDetailPage from './pages/RemediationDetail';
import ComplianceDashboard from './pages/ComplianceDashboard';
import AcceptInvitation from './pages/AcceptInvitation';
import OrganizationUsers from './pages/OrganizationUsers';
import PrivacyPolicy from './pages/PrivacyPolicy';
import TermsOfService from './pages/TermsOfService';
import Trust from './pages/Trust';
import Documentation from './pages/Documentation';
import SearchModal from './components/SearchModal';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/ToastProvider';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import { TrialBanner } from './components/layout/TrialBanner';
import CopilotPanel from './components/CopilotPanel';

import { AuthProvider, useAuth } from './contexts/AuthContext';
import { OrganizationProvider, useOrganization } from './contexts/TenantContext';
import { ConnectionProvider } from './contexts/ConnectionContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { CopilotProvider, useCopilot } from './contexts/CopilotContext';
import { FeatureFlagProvider } from './contexts/FeatureFlagContext';
import { isAdminHost } from './utils/hostDetection';
// ConnectionSwitcher removed — scope selection now in TopBar

function ProtectedRoute({ children, requiredRole }: { children: React.ReactNode; requiredRole?: string }) {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 py-16 text-center">
        <div className="animate-spin h-8 w-8 border-2 border-blue-600 border-t-transparent rounded-full mx-auto" />
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  if (requiredRole === 'admin' && user.role !== 'admin') {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
}

function AppContent() {
  const { user, loading, isAdmin, isSuperAdmin, canManageConnections } = useAuth();
  const { loading: orgLoading, error: orgError } = useOrganization();
  const { state: copilotState, openCopilot, closeCopilot } = useCopilot();
  const location = useLocation();
  const [searchOpen, setSearchOpen] = useState(false);
  const [needsOnboarding, setNeedsOnboarding] = useState(false);
  const [orgStage, setTenantStage] = useState<string>('active');
  const [tenantPlan, setTenantPlan] = useState<string>('');
  const [trialExpiresAt, setTrialExpiresAt] = useState<string | null>(null);

  useEffect(() => {
    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        setSearchOpen(prev => !prev);
      }
    }
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, []);

  // Phase 48: Check if onboarding is needed (client portal admin only, not superadmins, not demo)
  // Re-check on path changes so navigating away from /onboarding picks up completion
  useEffect(() => {
    if (!user || loading || user.role !== 'admin' || user.is_superadmin || user.is_demo) return;
    if (location.pathname.startsWith('/admin') || location.pathname === '/onboarding') return;
    fetch('/api/onboarding/status')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && !data.onboarding_completed && !data.azure_configured) {
          setNeedsOnboarding(true);
        } else {
          setNeedsOnboarding(false);
        }
      })
      .catch(() => {});
  }, [user, loading, location.pathname]);

  // Phase 85: Fetch organization onboarding stage (client portal only, non-superadmin)
  // Re-fetch on route change so navigating away from Settings picks up stage updates
  // Also check discovery status — if a snapshot exists, treat as 'active' regardless of DB stage
  useEffect(() => {
    if (!user || loading || user.is_superadmin) return;
    if (location.pathname.startsWith('/admin')) return;
    Promise.all([
      fetch('/api/organization/stage').then(r => r.ok ? r.json().catch(() => null) : null),
      fetch('/api/discovery/status').then(r => r.ok ? r.json().catch(() => null) : null),
      fetch('/api/tenant/config').then(r => r.ok ? r.json().catch(() => null) : null),
    ])
      .then(([stageData, discData, configData]) => {
        const stage = stageData?.stage || 'active';
        const hasSnapshot = discData?.has_snapshot || false;
        // If discovery data exists, unlock the dashboard regardless of onboarding stage
        if (hasSnapshot || stage === 'active') {
          setTenantStage('active');
        } else {
          setTenantStage(stage);
        }
        // Trial/plan info for expiry banner
        if (configData) {
          setTenantPlan(configData.plan || '');
          setTrialExpiresAt(configData.trial_expires_at || null);
        }
      })
      .catch(() => {});
  }, [user, loading, location.pathname]);

  // Phase 53: Organization resolution loading
  if (orgLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-3 border-blue-600 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-sm text-gray-500">Resolving organization...</p>
        </div>
      </div>
    );
  }

  // Phase 53: Organization resolution error
  if (orgError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center max-w-md">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-red-100 text-red-600 text-2xl font-bold mb-4">!</div>
          <h1 className="text-xl font-bold text-gray-900 mb-2">Organization Not Found</h1>
          <p className="text-sm text-gray-500 mb-4">{orgError}</p>
          <p className="text-xs text-gray-400">
            Please check the URL or contact your administrator.
          </p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin h-10 w-10 border-3 border-blue-600 border-t-transparent rounded-full" />
      </div>
    );
  }

  // Phase 48: Auto-redirect to onboarding if needed (skip for admin portal)
  if (needsOnboarding && location.pathname !== '/onboarding' && location.pathname !== '/login'
      && !location.pathname.startsWith('/admin')) {
    return <Navigate to="/onboarding" replace />;
  }

  // Detect admin subdomain (admin.auditgraph.ai, dev.admin.auditgraph.ai) — render admin portal at root
  const isAdminSubdomain = isAdminHost();
  const isAdminAccessible = isAdminSubdomain
    || window.location.hostname === 'localhost'
    || window.location.hostname === '127.0.0.1';

  // Lock all non-settings routes when organization is not yet active
  const locked = orgStage !== 'active';

  return (
    <ToastProvider>
      <Routes>
        {/* Login route - no nav bar */}
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />
        <Route path="/signup" element={user ? <Navigate to="/onboarding" replace state={{ fromSignup: true }} /> : <Signup />} />

        {/* Phase 84: Password reset routes - public, no nav bar */}
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* Phase 54: SSO callback - no nav bar, no auth required */}
        <Route path="/sso-callback" element={<SsoCallback />} />

        {/* Phase 17: Accept invitation - public, no nav bar */}
        <Route path="/accept-invite" element={<AcceptInvitation />} />

        {/* Phase 5: Public legal & documentation pages */}
        <Route path="/privacy" element={<PrivacyPolicy />} />
        <Route path="/terms" element={<TermsOfService />} />
        <Route path="/trust" element={<Trust />} />
        <Route path="/docs" element={<Documentation />} />

        {/* Onboarding route - no nav bar, protected */}
        <Route path="/onboarding" element={
          <ProtectedRoute><OnboardingWizard /></ProtectedRoute>
        } />

        {/* Admin Console - standalone layout with own login, sidebar, topbar */}
        <Route path="/admin/*" element={
          isAdminAccessible
            ? <ErrorBoundary><AdminConsole /></ErrorBoundary>
            : <Navigate to="/login" replace />
        } />

        {/* Admin subdomain: render admin portal at root */}
        {isAdminSubdomain && (
          <Route path="/*" element={
            <ErrorBoundary><AdminConsole /></ErrorBoundary>
          } />
        )}

        {/* All other routes - with sidebar + topbar, protected */}
        <Route path="/*" element={
          <ProtectedRoute>
            <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-surface)' }}>
              {/* Top Bar */}
              <TopBar onSearchOpen={() => setSearchOpen(true)} onCopilotOpen={() => openCopilot()} />

              {/* Left Sidebar */}
              <Sidebar isAdmin={isAdmin} isSuperAdmin={isSuperAdmin} locked={orgStage !== 'active'} canManageConnections={canManageConnections} />

              {/* Global Search Modal */}
              <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />

              {/* AI Security Copilot Panel (Phase 79 + Investigation Enhancement) */}
              <CopilotPanel open={copilotState.open} onClose={closeCopilot} />

              {/* Trial Expiry Banner */}
              <TrialBanner plan={tenantPlan} trialExpiresAt={trialExpiresAt} />

              {/* Page Content */}
              <main className="min-h-screen w-full overflow-x-hidden" style={{ paddingLeft: 'var(--sidebar-width, 220px)', paddingTop: 'var(--header-height, 56px)' }}>
                <Routes>
                  <Route path="/" element={
                    orgStage !== 'active'
                      ? <ErrorBoundary><LockedDashboard /></ErrorBoundary>
                      : <ErrorBoundary><CISODashboard /></ErrorBoundary>
                  } />
                  <Route path="/dashboard" element={
                    orgStage !== 'active'
                      ? <Navigate to="/" replace />
                      : <ErrorBoundary><Dashboard /></ErrorBoundary>
                  } />
                  <Route path="/remediation" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><RemediationCenter /></ErrorBoundary>} />
                  <Route path="/security-findings" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><SecurityFindings /></ErrorBoundary>} />
                  <Route path="/graph-findings" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><GraphFindings /></ErrorBoundary>} />
                  <Route path="/command-center" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><SecurityCommandCenter /></ErrorBoundary>} />
                  {/* SecurityDashboard removed — consolidated into Executive Posture + Command Center */}
                  <Route path="/security-dashboard" element={<Navigate to="/command-center" replace />} />
                  <Route path="/identity-explorer" element={<Navigate to="/identity-explorer/humans" replace />} />
                  <Route path="/identity-explorer/:tab" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityExplorer /></ErrorBoundary>} />
                  <Route path="/identity-graph" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityGraph /></ErrorBoundary>} />
                  <Route path="/identity-exposures" element={<Navigate to="/security-findings" replace />} />
                  <Route path="/drift-analysis" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><DriftAnalysis /></ErrorBoundary>} />
                  <Route path="/privilege-drift" element={<Navigate to="/drift-analysis" replace />} />
                  <Route path="/attack-paths" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AttackPaths /></ErrorBoundary>} />
                  <Route path="/attack-paths/:pathId" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AttackPathDetailPage /></ErrorBoundary>} />
                  <Route path="/remediation-queue" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><RemediationQueue /></ErrorBoundary>} />
                  <Route path="/remediation-queue/:itemId" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><RemediationDetailPage /></ErrorBoundary>} />
                  <Route path="/attack-simulator" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AttackSimulator /></ErrorBoundary>} />
                  <Route path="/identities" element={<Navigate to="/identity-explorer/all" replace />} />
                  <Route path="/identities/compare" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityComparison /></ErrorBoundary>} />
                  <Route path="/identities/:id" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityDetail /></ErrorBoundary>} />
                  {/* AG-173 / AG-85 narrative pages — CISO tile drill-downs */}
                  <Route path="/lifecycle" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><LifecycleJml /></ErrorBoundary>} />
                  <Route path="/connected-apps" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ConnectedApps /></ErrorBoundary>} />
                  {/* AG-86: Shadow App registry & flagging */}
                  <Route path="/shadow-apps" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ShadowApps /></ErrorBoundary>} />
                  {/* AG-184: Argus 7-layer EPIC — Layer 3 (Investigate) + Layer 5 (Explain Why) live */}
                  <Route path="/argus" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Argus /></ErrorBoundary>} />
                  {/* AG-178: AI Identity Attack Paths (cinematic chain) */}
                  <Route path="/ai-risk/attack-paths" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIAttackPaths /></ErrorBoundary>} />
                  {/* AG-179: AI Board Scorecard */}
                  <Route path="/board-scorecard" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIBoardScorecard /></ErrorBoundary>} />
                  {/* AG-181: AI Agent Lifecycle (J/M/L) */}
                  <Route path="/ai-lifecycle" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AILifecycle /></ErrorBoundary>} />
                  {/* AG-161: 5-pillar AI Security IA. Legacy routes below redirect into new pillars. */}
                  <Route path="/ai-inventory" element={<Navigate to="/ai-inventory/graph" replace />} />
                  <Route path="/ai-inventory/:tab" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIInventory /></ErrorBoundary>} />
                  <Route path="/ai-access" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIAccess /></ErrorBoundary>} />
                  {/* AG-180: Per-agent data reachability (PHI/PCI/PII/Source/HR/Financial/Confidential) */}
                  <Route path="/ai-access/data-reachability" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIDataReachability /></ErrorBoundary>} />
                  <Route path="/ai-runtime" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIRuntime /></ErrorBoundary>} />
                  {/* AG-T2.2: Model Registry approval workflow */}
                  <Route path="/ai-runtime/model-registry" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIModelRegistry /></ErrorBoundary>} />
                  {/* AG-T2.3: AI Findings catalog */}
                  <Route path="/ai-findings" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIFindings /></ErrorBoundary>} />
                  {/* AG-T3.1: Multi-hop XGRAPH (agent-to-agent reachability) */}
                  <Route path="/ai-attack-paths/multi-hop" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><MultiHopXGraph /></ErrorBoundary>} />
                  {/* AG-T3.2: AI Supply Chain dependency graph */}
                  <Route path="/ai-runtime/supply-chain" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AISupplyChain /></ErrorBoundary>} />
                  {/* AG-T4: Threat-source partner connectors */}
                  <Route path="/ai-runtime/threat-connectors" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIThreatConnectors /></ErrorBoundary>} />
                  {/* AG-WK2: Identity Trust org rollup page */}
                  <Route path="/identity-trust" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityTrust /></ErrorBoundary>} />
                  {/* AG-WK3.1: Ownership Center */}
                  <Route path="/ownership" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><OwnershipCenter /></ErrorBoundary>} />
                  {/* AG-WK7.A: Peer Benchmarking */}
                  <Route path="/peer-benchmarking" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><PeerBenchmarking /></ErrorBoundary>} />
                  {/* AG-182: Per-agent forensic timeline + behavior baseline */}
                  <Route path="/ai-runtime/activity" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AgentActivityTimeline /></ErrorBoundary>} />
                  <Route path="/ai-risk" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIRisk /></ErrorBoundary>} />
                  <Route path="/ai-governance" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AIGovernance /></ErrorBoundary>} />
                  {/* Legacy redirects — preserve bookmarks from before AG-161 */}
                  <Route path="/ai-identity-graph" element={<Navigate to="/ai-inventory/graph" replace />} />
                  <Route path="/ai-agents" element={<Navigate to="/ai-inventory/agents" replace />} />
                  <Route path="/ai-permissions" element={<Navigate to="/ai-access" replace />} />
                  <Route path="/reports" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Reports /></ErrorBoundary>} />
                  <Route path="/compliance" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Compliance /></ErrorBoundary>} />
                  <Route path="/compliance-posture" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ComplianceDashboard /></ErrorBoundary>} />
                  <Route path="/drift" element={<Navigate to="/drift-analysis" replace />} />
                  <Route path="/exports" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Exports /></ErrorBoundary>} />
                  <Route path="/access-reviews" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AccessReviews /></ErrorBoundary>} />
                  <Route path="/role-mining" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><RoleMining /></ErrorBoundary>} />
                  <Route path="/groups" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityGroups /></ErrorBoundary>} />
                  <Route path="/identity-correlation" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityCorrelation /></ErrorBoundary>} />
                  <Route path="/service-accounts" element={<Navigate to="/identity-explorer/privileged" replace />} />
                  <Route path="/workload-identities" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><WorkloadIdentities /></ErrorBoundary>} />
                  <Route path="/workload-identities/:id" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><WorkloadIdentityDetail /></ErrorBoundary>} />
                  <Route path="/spns" element={<Navigate to="/workload-identities?type=spn" replace />} />
                  <Route path="/app-registrations" element={<Navigate to="/workload-identities?type=app_reg" replace />} />
                  {/* Phase 6: Access Explainability consolidated routes */}
                  <Route path="/access-graph" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AccessGraph /></ErrorBoundary>} />
                  <Route path="/effective-access" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><EffectiveAccessExplorer /></ErrorBoundary>} />
                  <Route path="/sensitive-access" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><SensitiveDataAccess /></ErrorBoundary>} />
                  {/* Legacy redirects for consolidated routes */}
                  <Route path="/rbac-hygiene" element={<Navigate to="/effective-access" replace />} />
                  <Route path="/data-security" element={<Navigate to="/sensitive-access" replace />} />
                  {/* Subscriptions must be accessible during onboarding (before first snapshot) */}
                  <Route path="/subscriptions" element={<ErrorBoundary><Subscriptions /></ErrorBoundary>} />
                  <Route path="/billing" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ClientBilling /></ErrorBoundary>} />
                  <Route path="/settings" element={
                    <ProtectedRoute requiredRole="admin">
                      <ErrorBoundary><Settings /></ErrorBoundary>
                    </ProtectedRoute>
                  } />
                  <Route path="/settings/:tab" element={
                    <ProtectedRoute requiredRole="admin">
                      <ErrorBoundary><Settings /></ErrorBoundary>
                    </ProtectedRoute>
                  } />
                  <Route path="/organization/users" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><OrganizationUsers /></ErrorBoundary>} />
                  <Route path="/activity" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ActivityLog /></ErrorBoundary>} />
                  <Route path="/notifications" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><NotificationCenter /></ErrorBoundary>} />
                  <Route path="/analytics" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><CrossTenantAnalytics /></ErrorBoundary>} />
                </Routes>
              </main>
            </div>
          </ProtectedRoute>
        } />
      </Routes>
    </ToastProvider>
  );
}

function App() {
  return (
    <ThemeProvider>
      <Router>
        <OrganizationProvider>
          <AuthProvider>
            <ConnectionProvider>
              <FeatureFlagProvider>
                <CopilotProvider>
                  <AppContent />
                </CopilotProvider>
              </FeatureFlagProvider>
            </ConnectionProvider>
          </AuthProvider>
        </OrganizationProvider>
      </Router>
    </ThemeProvider>
  );
}

export default App;
