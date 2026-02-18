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
import ForgotPassword from './pages/ForgotPassword';
import ResetPassword from './pages/ResetPassword';
import LockedDashboard from './pages/LockedDashboard';
import CrossTenantAnalytics from './pages/CrossTenantAnalytics';
import OnboardingWizard from './pages/OnboardingWizard';
import Resources from './pages/Resources';
import ResourceDetail from './pages/ResourceDetail';
import AdminConsole from './pages/AdminConsole';
import SsoCallback from './pages/SsoCallback';
import ServiceAccountGovernance from './pages/ServiceAccountGovernance';
import SPNDashboard from './pages/SPNDashboard';
import AppRegistrations from './pages/AppRegistrations';
import Subscriptions from './pages/Subscriptions';
import RbacHygiene from './pages/RbacHygiene';
import Invoices from './pages/Invoices';
import Overview from './pages/Overview';
import SearchModal from './components/SearchModal';
import ErrorBoundary from './components/ErrorBoundary';
import { ToastProvider } from './components/ToastProvider';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import CopilotPanel from './components/CopilotPanel';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { TenantProvider, useTenant } from './contexts/TenantContext';
import { ConnectionProvider } from './contexts/ConnectionContext';
import { ThemeProvider } from './contexts/ThemeContext';
import ConnectionSwitcher from './components/ConnectionSwitcher';

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
  const { loading: tenantLoading, error: tenantError } = useTenant();
  const location = useLocation();
  const [searchOpen, setSearchOpen] = useState(false);
  const [copilotOpen, setCopilotOpen] = useState(false);
  const [needsOnboarding, setNeedsOnboarding] = useState(false);
  const [tenantStage, setTenantStage] = useState<string>('active');

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

  // Phase 48: Check if onboarding is needed (admin only)
  useEffect(() => {
    if (!user || loading || user.role !== 'admin') return;
    fetch('/api/onboarding/status')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data && !data.onboarding_completed && !data.azure_configured) {
          setNeedsOnboarding(true);
        }
      })
      .catch(() => {});
  }, [user, loading]);

  // Phase 85: Fetch tenant onboarding stage (non-superadmin only)
  // Re-fetch on route change so navigating away from Settings picks up stage updates
  useEffect(() => {
    if (!user || loading || user.is_superadmin) return;
    fetch('/api/tenant/stage')
      .then(r => r.ok ? r.json() : null)
      .then(data => {
        if (data?.stage) setTenantStage(data.stage);
      })
      .catch(() => {});
  }, [user, loading, location.pathname]);

  // Phase 53: Tenant resolution loading
  if (tenantLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin h-10 w-10 border-3 border-blue-600 border-t-transparent rounded-full mx-auto mb-4" />
          <p className="text-sm text-gray-500">Resolving organization...</p>
        </div>
      </div>
    );
  }

  // Phase 53: Tenant resolution error
  if (tenantError) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center max-w-md">
          <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-red-100 text-red-600 text-2xl font-bold mb-4">!</div>
          <h1 className="text-xl font-bold text-gray-900 mb-2">Organization Not Found</h1>
          <p className="text-sm text-gray-500 mb-4">{tenantError}</p>
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

  // Phase 48: Auto-redirect to onboarding if needed
  if (needsOnboarding && location.pathname !== '/onboarding' && location.pathname !== '/login') {
    return <Navigate to="/onboarding" replace />;
  }

  // Detect admin subdomain (admin.auditgraph.ai) — render admin portal at root
  const isAdminSubdomain = window.location.hostname.split('.')[0] === 'admin';
  const isAdminAccessible = isAdminSubdomain
    || window.location.hostname === 'localhost'
    || window.location.hostname === '127.0.0.1';

  // Lock all non-settings routes when tenant is not yet active
  const locked = tenantStage !== 'active';

  return (
    <ToastProvider>
      <Routes>
        {/* Login route - no nav bar */}
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />

        {/* Phase 84: Password reset routes - public, no nav bar */}
        <Route path="/forgot-password" element={<ForgotPassword />} />
        <Route path="/reset-password" element={<ResetPassword />} />

        {/* Phase 54: SSO callback - no nav bar, no auth required */}
        <Route path="/sso-callback" element={<SsoCallback />} />

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
            <div className="min-h-screen bg-gray-50 dark:bg-slate-950">
              {/* Top Bar */}
              <TopBar onSearchOpen={() => setSearchOpen(true)} onCopilotOpen={() => setCopilotOpen(true)} />

              {/* Left Sidebar */}
              <Sidebar isAdmin={isAdmin} isSuperAdmin={isSuperAdmin} locked={tenantStage !== 'active'} canManageConnections={canManageConnections} />

              {/* Global Search Modal */}
              <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />

              {/* AI Security Copilot Panel (Phase 79) */}
              <CopilotPanel open={copilotOpen} onClose={() => setCopilotOpen(false)} />

              {/* Page Content */}
              <main className="pl-60 pt-14 min-h-screen w-full overflow-x-hidden">
                {/* Connection Switcher (shows only with 2+ connections, in normal flow) */}
                <ConnectionSwitcher />
                <Routes>
                  <Route path="/" element={
                    tenantStage !== 'active'
                      ? <ErrorBoundary><LockedDashboard /></ErrorBoundary>
                      : <ErrorBoundary><Overview /></ErrorBoundary>
                  } />
                  <Route path="/dashboard" element={
                    tenantStage !== 'active'
                      ? <Navigate to="/" replace />
                      : <ErrorBoundary><Dashboard /></ErrorBoundary>
                  } />
                  <Route path="/identities" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Identities /></ErrorBoundary>} />
                  <Route path="/identities/compare" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityComparison /></ErrorBoundary>} />
                  <Route path="/identities/:id" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityDetail /></ErrorBoundary>} />
                  <Route path="/reports" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Reports /></ErrorBoundary>} />
                  <Route path="/compliance" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Compliance /></ErrorBoundary>} />
                  <Route path="/drift" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><DriftHistory /></ErrorBoundary>} />
                  <Route path="/exports" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Exports /></ErrorBoundary>} />
                  <Route path="/access-reviews" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AccessReviews /></ErrorBoundary>} />
                  <Route path="/role-mining" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><RoleMining /></ErrorBoundary>} />
                  <Route path="/groups" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><IdentityGroups /></ErrorBoundary>} />
                  <Route path="/service-accounts" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ServiceAccountGovernance /></ErrorBoundary>} />
                  <Route path="/spns" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><SPNDashboard /></ErrorBoundary>} />
                  <Route path="/app-registrations" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><AppRegistrations /></ErrorBoundary>} />
                  <Route path="/rbac-hygiene" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><RbacHygiene /></ErrorBoundary>} />
                  <Route path="/resources" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Resources /></ErrorBoundary>} />
                  <Route path="/resources/detail" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><ResourceDetail /></ErrorBoundary>} />
                  <Route path="/subscriptions" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Subscriptions /></ErrorBoundary>} />
                  <Route path="/invoices" element={locked ? <Navigate to="/" replace /> : <ErrorBoundary><Invoices /></ErrorBoundary>} />
                  <Route path="/settings" element={
                    <ProtectedRoute requiredRole="admin">
                      <ErrorBoundary><Settings /></ErrorBoundary>
                    </ProtectedRoute>
                  } />
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
        <TenantProvider>
          <AuthProvider>
            <ConnectionProvider>
              <AppContent />
            </ConnectionProvider>
          </AuthProvider>
        </TenantProvider>
      </Router>
    </ThemeProvider>
  );
}

export default App;
