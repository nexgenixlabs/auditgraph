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
  Link,
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
import Login from './pages/Login';
import {
  GlobalRiskCards,
  CloudComparison,
  InsightsPanel,
} from './components/overview';
import SearchModal from './components/SearchModal';
import ErrorBoundary from './components/ErrorBoundary';
import StaleDataBanner from './components/StaleDataBanner';
import { ToastProvider } from './components/ToastProvider';
import { AuthProvider, useAuth } from './contexts/AuthContext';
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

        if (!cancelled) {
          setStats(statsJson);
          setSummary(summaryJson);
          setInsights(insightsJson);
          setTrends(trendsJson);
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
      <CloudComparison data={cloudData} monitoredResources={summary?.monitored_resources} onCloudClick={handleCloudClick} onRiskClick={handleRiskClick} />

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
  const { user, loading } = useAuth();
  const [searchOpen, setSearchOpen] = useState(false);
  const { dark, toggle: toggleTheme } = useTheme();

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

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin h-10 w-10 border-3 border-blue-600 border-t-transparent rounded-full" />
      </div>
    );
  }

  return (
    <ToastProvider>
      <Routes>
        {/* Login route - no nav bar */}
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <Login />} />

        {/* All other routes - with nav bar, protected */}
        <Route path="/*" element={
          <ProtectedRoute>
            <div className="App">
              {/* Navigation Bar */}
              <nav className="bg-white shadow-lg border-b-2 border-blue-600">
                <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                  <div className="flex items-center justify-between h-20">
                    <div className="flex items-center gap-8">
                      {/* Logo & Brand */}
                      <Link to="/" className="flex items-center gap-3 hover:opacity-80 transition">
                        <img
                          src="/auditgraph-logo.png"
                          alt="AuditGraph Logo"
                          className="h-16 w-auto"
                        />
                        <div>
                          <h1 className="text-2xl font-bold text-gray-900">AuditGraph</h1>
                          <p className="text-xs text-gray-500 font-medium">Map. Monitor. Secure.</p>
                        </div>
                      </Link>

                      {/* Navigation Links */}
                      <NavLinks onSearchOpen={() => setSearchOpen(true)} dark={dark} onToggleTheme={toggleTheme} />
                    </div>
                  </div>
                </div>
              </nav>

              {/* Global Search Modal */}
              <SearchModal isOpen={searchOpen} onClose={() => setSearchOpen(false)} />

              {/* Page Content */}
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
                <Route path="/settings" element={
                  <ProtectedRoute requiredRole="admin">
                    <ErrorBoundary><Settings /></ErrorBoundary>
                  </ProtectedRoute>
                } />
                <Route path="/activity" element={<ErrorBoundary><ActivityLog /></ErrorBoundary>} />
                <Route path="/notifications" element={<ErrorBoundary><NotificationCenter /></ErrorBoundary>} />
              </Routes>
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
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </Router>
  );
}

function NavLinks({ onSearchOpen, dark, onToggleTheme }: { onSearchOpen: () => void; dark: boolean; onToggleTheme: () => void }) {
  const location = useLocation();
  const navigate = useNavigate();
  const { user, logout, isAdmin } = useAuth();
  const [unreadCount, setUnreadCount] = useState(0);

  useEffect(() => {
    let mounted = true;
    async function fetchStats() {
      try {
        const res = await fetch('/api/notifications/stats');
        if (res.ok && mounted) {
          const data = await res.json();
          setUnreadCount(data.unread || 0);
        }
      } catch { /* ignore */ }
    }
    fetchStats();
    const interval = setInterval(fetchStats, 60000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  const isMac = typeof navigator !== 'undefined' && /Mac/.test(navigator.userAgent);

  const ROLE_COLORS: Record<string, string> = {
    admin: 'bg-red-50 text-red-700 dark:bg-red-900/30 dark:text-red-400',
    auditor: 'bg-blue-50 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400',
    viewer: 'bg-gray-100 text-gray-600 dark:bg-gray-700 dark:text-gray-300',
  };

  return (
    <div className="flex items-center space-x-1">
      <Link
        to="/"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/') && location.pathname === '/'
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Overview
      </Link>

      <Link
        to="/dashboard"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/dashboard')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Dashboard
      </Link>

      <Link
        to="/identities"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/identities')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Identities
      </Link>

      <Link
        to="/reports"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/reports')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Reports
      </Link>

      <Link
        to="/compliance"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/compliance')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Compliance
      </Link>

      <Link
        to="/drift"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/drift')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Drift
      </Link>

      <Link
        to="/exports"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/exports')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Exports
      </Link>

      <Link
        to="/access-reviews"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/access-reviews')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Reviews
      </Link>

      {isAdmin && (
        <Link
          to="/settings"
          className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
            isActive('/settings')
              ? 'bg-blue-600 text-white'
              : 'text-gray-700 hover:bg-gray-100'
          }`}
        >
          Settings
        </Link>
      )}

      <Link
        to="/activity"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/activity')
            ? 'bg-blue-600 text-white'
            : 'text-gray-700 hover:bg-gray-100'
        }`}
      >
        Activity
      </Link>

      <button
        onClick={onSearchOpen}
        className="ml-2 flex items-center gap-2 px-3 py-1.5 rounded-lg text-sm text-gray-500 bg-gray-100 hover:bg-gray-200 transition border border-gray-200"
      >
        <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
        </svg>
        <span className="hidden sm:inline text-xs text-gray-400">{isMac ? '\u2318' : 'Ctrl+'}K</span>
      </button>

      {/* Notification bell */}
      <button
        onClick={() => navigate('/notifications')}
        className={`ml-1 p-2 rounded-lg transition relative ${
          isActive('/notifications') ? 'bg-blue-100 text-blue-600' : 'text-gray-500 hover:bg-gray-100'
        }`}
        title="Notifications"
      >
        <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
        </svg>
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[10px] font-bold rounded-full min-w-[18px] h-[18px] flex items-center justify-center px-1">
            {unreadCount > 99 ? '99+' : unreadCount}
          </span>
        )}
      </button>

      {/* Dark mode toggle */}
      <button
        onClick={onToggleTheme}
        className="ml-1 p-2 rounded-lg text-gray-500 hover:bg-gray-100 transition"
        title={dark ? 'Switch to light mode' : 'Switch to dark mode'}
      >
        {dark ? (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
          </svg>
        ) : (
          <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
          </svg>
        )}
      </button>

      {/* User menu */}
      {user && (
        <div className="ml-2 flex items-center gap-2 pl-2 border-l border-gray-200 dark:border-gray-600">
          <span className="text-xs text-gray-500 dark:text-gray-400">
            {user.display_name}
            <span className={`ml-1 px-1.5 py-0.5 rounded text-[10px] font-medium uppercase ${ROLE_COLORS[user.role] || ROLE_COLORS.viewer}`}>
              {user.role}
            </span>
          </span>
          <button
            onClick={() => { logout(); navigate('/login'); }}
            className="p-1.5 rounded-lg text-gray-400 hover:text-red-500 hover:bg-gray-100 transition"
            title="Sign out"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
            </svg>
          </button>
        </div>
      )}
    </div>
  );
}

export default App;
