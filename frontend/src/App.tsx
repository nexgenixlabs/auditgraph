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
import React, { useEffect, useState, useMemo } from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
  useNavigate,
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
import CrossTenantAnalytics from './pages/CrossTenantAnalytics';
import OnboardingWizard from './pages/OnboardingWizard';
import Resources from './pages/Resources';
import ResourceDetail from './pages/ResourceDetail';
import AdminConsole from './pages/AdminConsole';
import SsoCallback from './pages/SsoCallback';
import ServiceAccountGovernance from './pages/ServiceAccountGovernance';
import SPNDashboard from './pages/SPNDashboard';
import AppRegistrations from './pages/AppRegistrations';
import SystemHealth from './pages/SystemHealth';
import {
  GlobalRiskCards,
  CloudComparison,
  InsightsPanel,
} from './components/overview';
import SearchModal from './components/SearchModal';
import ErrorBoundary from './components/ErrorBoundary';
import StaleDataBanner from './components/StaleDataBanner';
import { ToastProvider } from './components/ToastProvider';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { TenantProvider, useTenant } from './contexts/TenantContext';
import { useTheme } from './hooks/useTheme';

// ============================================================
// Overview Page - Enterprise Risk Intelligence
// ============================================================

interface StatsResponse {
  total_discovery_runs: number;
  latest_run: {
    id: number;
    completed_at: string | null;
    total_identities: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
  } | null;
}

interface MonitoredResources {
  azure: { subscriptions: number; subscription_ids: string[] };
  aws: { accounts: number; account_ids: string[] };
  gcp: { projects: number; project_ids: string[] };
}

interface IdentitySummaryResponse {
  run_id: number;
  completed_at: string | null;
  categories: Record<
    string,
    { total: number; critical: number; high: number; medium: number; low: number; info: number }
  >;
  monitored_resources?: MonitoredResources;
}

const Overview: React.FC = () => {
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [summary, setSummary] = useState<IdentitySummaryResponse | null>(null);
  const [insights, setInsights] = useState<any>(null);
  const [trends, setTrends] = useState<any>(null);
  const [resourceStats, setResourceStats] = useState<{ storage_accounts: number; key_vaults: number } | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function load() {
      setLoading(true);
      setError(null);
      try {
        const [statsRes, summaryRes, insightsRes] = await Promise.all([
          fetch('/api/stats'),
          fetch('/api/identity-summary'),
          fetch('/api/overview/insights'),
        ]);

        if (!statsRes.ok) throw new Error(`Stats API error: ${statsRes.status}`);
        if (!summaryRes.ok) throw new Error(`Summary API error: ${summaryRes.status}`);

        const [statsJson, summaryJson] = await Promise.all([
          statsRes.json(),
          summaryRes.json(),
        ]);
        const insightsJson = insightsRes.ok ? await insightsRes.json() : null;

        // Fetch trend data for sparklines (non-blocking)
        let trendsJson = null;
        try {
          const trendsRes = await fetch('/api/trends');
          if (trendsRes.ok) trendsJson = await trendsRes.json();
        } catch { /* ignore */ }

        // Fetch resource stats (non-blocking)
        let resStats = null;
        try {
          const resRes = await fetch('/api/resources/stats');
          if (resRes.ok) resStats = await resRes.json();
        } catch { /* ignore */ }

        if (!cancelled) {
          setStats(statsJson);
          setSummary(summaryJson);
          setInsights(insightsJson);
          setTrends(trendsJson);
          setResourceStats(resStats);
        }
      } catch (e: any) {
        if (!cancelled) setError(e?.message || 'Failed to load overview data');
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    load();
    return () => { cancelled = true; };
  }, []);

  // Compute global risk counts from summary categories (real low/info split)
  const riskCounts = useMemo(() => {
    const cats = summary?.categories || {};
    let critical = 0, high = 0, medium = 0, low = 0, info = 0, total = 0;

    Object.values(cats).forEach((cat) => {
      critical += cat.critical;
      high += cat.high;
      medium += cat.medium;
      low += cat.low;
      info += cat.info;
      total += cat.total;
    });

    return { critical, high, medium, low, info, total };
  }, [summary]);

  // Compute trend arrays for sparklines
  const trendArrays = useMemo(() => {
    if (!trends?.runs || trends.runs.length < 2) return undefined;
    return {
      critical: trends.runs.map((r: any) => r.critical),
      high: trends.runs.map((r: any) => r.high),
      medium: trends.runs.map((r: any) => r.medium),
      low: trends.runs.map((r: any) => r.low),
      info: trends.runs.map((r: any) => r.total - r.critical - r.high - r.medium - r.low),
    };
  }, [trends]);

  // Compute cloud risk data (currently Azure only)
  const cloudData = useMemo(() => {
    const cats = summary?.categories || {};
    let total = 0, critical = 0, high = 0, medium = 0, low = 0;

    Object.values(cats).forEach((cat) => {
      total += cat.total;
      critical += cat.critical;
      high += cat.high;
      medium += cat.medium;
      low += cat.low + cat.info;
    });

    return [{
      cloud: 'azure' as const,
      total,
      critical,
      high,
      medium,
      low,
    }];
  }, [summary]);

  // Navigation handlers
  const handleRiskCardClick = (level: string) => {
    navigate(`/identities?risk_level=${level}`);
  };

  const handleCloudClick = (cloud: string) => {
    navigate(`/identities?cloud=${cloud}`);
  };

  const handleRiskClick = (cloud: string, riskLevel: string) => {
    navigate(`/identities?cloud=${cloud}&risk_level=${riskLevel}`);
  };

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="animate-pulse space-y-6">
          <div className="h-8 bg-gray-200 rounded w-64" />
          <div className="grid grid-cols-4 gap-4">
            {[1, 2, 3, 4].map((i) => <div key={i} className="h-24 bg-gray-100 rounded-xl" />)}
          </div>
          <div className="h-48 bg-gray-100 rounded-xl" />
          <div className="grid grid-cols-3 gap-4">
            {[1, 2, 3, 4, 5, 6].map((i) => <div key={i} className="h-40 bg-gray-100 rounded-xl" />)}
          </div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="bg-red-50 border border-red-200 rounded-xl p-6 text-red-700">
          <div className="font-semibold">Error loading overview</div>
          <div className="text-sm mt-1">{error}</div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h2 className="text-2xl font-bold text-gray-900">Identity Risk Overview</h2>
          <p className="text-sm text-gray-600 mt-1">
            Multi-cloud identity security posture at a glance
          </p>
        </div>
        <div className="text-xs text-gray-500">
          Last updated: {stats?.latest_run?.completed_at
            ? new Date(stats.latest_run.completed_at).toLocaleString()
            : 'Never'}
        </div>
      </div>

      {/* Stale Data Warning */}
      <StaleDataBanner completedAt={stats?.latest_run?.completed_at} />

      {/* Section 1: Global Risk Cards */}
      <div>
        <div className="text-sm font-semibold text-gray-700 mb-3">Global Risk Summary</div>
        <GlobalRiskCards counts={riskCounts} onCardClick={handleRiskCardClick} trends={trendArrays} />
      </div>

      {/* Section 2: Cloud Risk Comparison */}
      <CloudComparison data={cloudData} monitoredResources={summary?.monitored_resources} resourceStats={resourceStats} onCloudClick={handleCloudClick} onRiskClick={handleRiskClick} />

      {/* Section 3: Privilege Tiers + Action Items + Dormant/Unowned */}
      <InsightsPanel data={insights} loading={loading} />
    </div>
  );
};

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
  const { user, loading, isAdmin, isSuperAdmin } = useAuth();
  const { loading: tenantLoading, error: tenantError } = useTenant();
  const location = useLocation();
  const [searchOpen, setSearchOpen] = useState(false);
  const { dark, toggle: toggleTheme } = useTheme();
  const [needsOnboarding, setNeedsOnboarding] = useState(false);

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

  return (
    <ToastProvider>
      <Routes>
        {/* Login route - no nav bar */}
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />

        {/* Phase 54: SSO callback - no nav bar, no auth required */}
        <Route path="/sso-callback" element={<SsoCallback />} />

        {/* Onboarding route - no nav bar, protected */}
        <Route path="/onboarding" element={
          <ProtectedRoute><OnboardingWizard /></ProtectedRoute>
        } />

        {/* Admin Console - standalone layout with own login, sidebar, topbar */}
        <Route path="/admin/*" element={
          <ErrorBoundary><AdminConsole /></ErrorBoundary>
        } />

        {/* All other routes - with sidebar + topbar, protected */}
        <Route path="/*" element={
          <ProtectedRoute>
            <div className="min-h-screen bg-gray-50 dark:bg-slate-950">
              {/* Top Bar */}
              <TopBar dark={dark} onToggleTheme={toggleTheme} onSearchOpen={() => setSearchOpen(true)} />

              {/* Left Sidebar */}
              <Sidebar isAdmin={isAdmin} isSuperAdmin={isSuperAdmin} />

              {/* Global Search Modal */}
              <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />

              {/* Page Content */}
              <main className="pl-60 pt-14 min-h-screen w-full overflow-x-hidden">
                <Routes>
                  <Route path="/" element={<ErrorBoundary><Overview /></ErrorBoundary>} />
                  <Route path="/dashboard" element={<ErrorBoundary><Dashboard /></ErrorBoundary>} />
                  <Route path="/identities" element={<ErrorBoundary><Identities /></ErrorBoundary>} />
                  <Route path="/identities/compare" element={<ErrorBoundary><IdentityComparison /></ErrorBoundary>} />
                  <Route path="/identities/:id" element={<ErrorBoundary><IdentityDetail /></ErrorBoundary>} />
                  <Route path="/reports" element={<ErrorBoundary><Reports /></ErrorBoundary>} />
                  <Route path="/compliance" element={<ErrorBoundary><Compliance /></ErrorBoundary>} />
                  <Route path="/drift" element={<ErrorBoundary><DriftHistory /></ErrorBoundary>} />
                  <Route path="/exports" element={<ErrorBoundary><Exports /></ErrorBoundary>} />
                  <Route path="/access-reviews" element={<ErrorBoundary><AccessReviews /></ErrorBoundary>} />
                  <Route path="/role-mining" element={<ErrorBoundary><RoleMining /></ErrorBoundary>} />
                  <Route path="/groups" element={<ErrorBoundary><IdentityGroups /></ErrorBoundary>} />
                  <Route path="/service-accounts" element={<ErrorBoundary><ServiceAccountGovernance /></ErrorBoundary>} />
                  <Route path="/spns" element={<ErrorBoundary><SPNDashboard /></ErrorBoundary>} />
                  <Route path="/app-registrations" element={<ErrorBoundary><AppRegistrations /></ErrorBoundary>} />
                  <Route path="/system-health" element={
                    <ProtectedRoute requiredRole="admin">
                      <ErrorBoundary><SystemHealth /></ErrorBoundary>
                    </ProtectedRoute>
                  } />
                  <Route path="/resources" element={<ErrorBoundary><Resources /></ErrorBoundary>} />
                  <Route path="/resources/detail" element={<ErrorBoundary><ResourceDetail /></ErrorBoundary>} />
                  <Route path="/settings" element={
                    <ProtectedRoute requiredRole="admin">
                      <ErrorBoundary><Settings /></ErrorBoundary>
                    </ProtectedRoute>
                  } />
                  <Route path="/activity" element={<ErrorBoundary><ActivityLog /></ErrorBoundary>} />
                  <Route path="/notifications" element={<ErrorBoundary><NotificationCenter /></ErrorBoundary>} />
                  <Route path="/analytics" element={<ErrorBoundary><CrossTenantAnalytics /></ErrorBoundary>} />
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
    <Router>
      <TenantProvider>
        <AuthProvider>
          <AppContent />
        </AuthProvider>
      </TenantProvider>
    </Router>
  );
}

export default App;
