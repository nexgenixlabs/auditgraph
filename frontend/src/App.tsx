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
import Resources from './pages/Resources';
import ResourceDetail from './pages/ResourceDetail';
import DataSecurity from './pages/DataSecurity';
import KeyVaultSecurity from './pages/KeyVaultSecurity';
import StorageSecurity from './pages/StorageSecurity';
import AdminConsole from './pages/AdminConsole';
import SsoCallback from './pages/SsoCallback';
import ServiceAccountGovernance from './pages/ServiceAccountGovernance';
import SPNDashboard from './pages/SPNDashboard';
import AppRegistrations from './pages/AppRegistrations';
import IdentityCorrelation from './pages/IdentityCorrelation';
import WorkloadIdentities from './pages/WorkloadIdentities';
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
import IdentityExposures from './pages/IdentityExposures';
import PrivilegeDrift from './pages/PrivilegeDrift';
import AttackSimulator from './pages/AttackSimulator';
import ComplianceDashboard from './pages/ComplianceDashboard';
import AcceptInvitation from './pages/AcceptInvitation';
import OrganizationUsers from './pages/OrganizationUsers';
import PrivacyPolicy from './pages/PrivacyPolicy';
import TermsOfService from './pages/TermsOfService';
import Documentation from './pages/Documentation';
import SearchModal from './components/SearchModal';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/ToastProvider';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import CopilotPanel from './components/CopilotPanel';
import DemoBanner from './components/DemoBanner';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { OrganizationProvider, useOrganization } from './contexts/TenantContext';
import { ConnectionProvider } from './contexts/ConnectionContext';
import { ThemeProvider } from './contexts/ThemeContext';
import { CopilotProvider, useCopilot } from './contexts/CopilotContext';
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
  useEffect(() => {
    if (!user || loading || user.role !== 'admin' || user.is_superadmin || user.is_demo) return;
    if (window.location.pathname.startsWith('/admin')) return;
    fetch('/api/onboarding/status')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && !data.onboarding_completed && !data.azure_configured) {
          setNeedsOnboarding(true);
        }
      })
      .catch(() => {});
  }, [user, loading]);

  // Phase 85: Fetch organization onboarding stage (client portal only, non-superadmin)
  // Re-fetch on route change so navigating away from Settings picks up stage updates
  // Also check discovery status — if a snapshot exists, treat as 'active' regardless of DB stage
  useEffect(() => {
    if (!user || loading || user.is_superadmin) return;
    if (location.pathname.startsWith('/admin')) return;
    Promise.all([
      fetch('/api/organization/stage').then(r => r.ok ? r.json().catch(() => null) : null),
      fetch('/api/discovery/status').then(r => r.ok ? r.json().catch(() => null) : null),
    ])
      .then(([stageData, discData]) => {
        const stage = stageData?.stage || 'active';
        const hasSnapshot = discData?.has_snapshot || false;
        // If discovery data exists, unlock the dashboard regardless of onboarding stage
        if (hasSnapshot || stage === 'active') {
          setTenantStage('active');
        } else {
          setTenantStage(stage);
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
        <Route path="/signup" element={user ? <Navigate to="/onboarding" replace /> : <Signup />} />

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
            <DemoBanner />
            <div className="min-h-screen" style={{ backgroundColor: 'var(--bg-surface)' }}>
              {/* Top Bar */}
              <TopBar onSearchOpen={() => setSearchOpen(true)} onCopilotOpen={() => openCopilot()} />

              {/* Left Sidebar */}
              <Sidebar isAdmin={isAdmin} isSuperAdmin={isSuperAdmin} locked={orgStage !== 'active'} canManageConnections={canManageConnections} />

              {/* Global Search Modal */}
              <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />

              {/* AI Security Copilot Panel (Phase 79 + Investigation Enhancement) */}
              <CopilotPanel open={copilotState.open} onClose={closeCopilot} />

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
                  <Route path="/identity-graph" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityGraph /></ErrorBoundary>} />
                  <Route path="/identity-exposures" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityExposures /></ErrorBoundary>} />
                  <Route path="/privilege-drift" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><PrivilegeDrift /></ErrorBoundary>} />
                  <Route path="/attack-simulator" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AttackSimulator /></ErrorBoundary>} />
                  <Route path="/identities" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Identities /></ErrorBoundary>} />
                  <Route path="/identities/compare" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityComparison /></ErrorBoundary>} />
                  <Route path="/identities/:id" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityDetail /></ErrorBoundary>} />
                  <Route path="/reports" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Reports /></ErrorBoundary>} />
                  <Route path="/compliance" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Compliance /></ErrorBoundary>} />
                  <Route path="/compliance-posture" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ComplianceDashboard /></ErrorBoundary>} />
                  <Route path="/drift" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><DriftHistory /></ErrorBoundary>} />
                  <Route path="/exports" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Exports /></ErrorBoundary>} />
                  <Route path="/access-reviews" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AccessReviews /></ErrorBoundary>} />
                  <Route path="/role-mining" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><RoleMining /></ErrorBoundary>} />
                  <Route path="/groups" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityGroups /></ErrorBoundary>} />
                  <Route path="/identity-correlation" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityCorrelation /></ErrorBoundary>} />
                  <Route path="/service-accounts" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ServiceAccountGovernance /></ErrorBoundary>} />
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
                  <Route path="/resources" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Resources /></ErrorBoundary>} />
                  <Route path="/resources/detail" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ResourceDetail /></ErrorBoundary>} />
                  <Route path="/key-vaults" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><KeyVaultSecurity /></ErrorBoundary>} />
                  <Route path="/storage-accounts" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><StorageSecurity /></ErrorBoundary>} />
                  <Route path="/subscriptions" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Subscriptions /></ErrorBoundary>} />
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
              <CopilotProvider>
                <AppContent />
              </CopilotProvider>
            </ConnectionProvider>
          </AuthProvider>
        </OrganizationProvider>
      </Router>
    </ThemeProvider>
  );
}

export default App;
