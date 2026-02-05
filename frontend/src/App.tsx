/**
 * AuditGraph Frontend Application Root
 *
 * Sets up:
 * - React Router routes
 * - Global navigation bar
 * - Front Page (Overview blocks)
 *
 * Routes:
 *   /                  - Overview (graphical blocks by identity type)
 *   /dashboard          - Existing Dashboard page (risk summary)
 *   /identities         - Identity list
 *   /identities/:id     - Identity detail
 */
import React from 'react';
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Link,
  useLocation,
  useNavigate,
} from 'react-router-dom';

import Dashboard from './pages/Dashboard';
import Identities from './pages/Identities';
import IdentityDetail from './pages/IdentityDetail';

/**
 * Front page: identity-type blocks.
 * This is intentionally “lightweight” for now:
 * - It routes users into /identities with query params
 * - Identities page can later read these query params and apply filters automatically
 */
const Overview: React.FC = () => {
  const navigate = useNavigate();

  const go = (identityType: string) => {
    // This is the contract we will implement in Identities.tsx next:
    // read identityType from query params and apply the filter.
    navigate(`/identities?identityType=${encodeURIComponent(identityType)}`);
  };

  const Block: React.FC<{
    title: string;
    subtitle: string;
    identityType: string;
    hint?: string;
  }> = ({ title, subtitle, identityType, hint }) => (
    <button
      onClick={() => go(identityType)}
      className="text-left bg-white border rounded-2xl shadow-sm hover:shadow-md transition p-5 w-full"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-lg font-semibold text-gray-900">{title}</div>
          <div className="text-sm text-gray-600 mt-1">{subtitle}</div>
          {hint ? (
            <div className="text-xs text-gray-500 mt-3">{hint}</div>
          ) : null}
        </div>
        <div className="text-xs font-semibold px-3 py-1 rounded-full bg-gray-100 text-gray-700">
          View
        </div>
      </div>
    </button>
  );

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      <div className="mb-6">
        <h2 className="text-2xl font-bold text-gray-900">Identity Overview</h2>
        <p className="text-sm text-gray-600 mt-1">
          Choose an identity category to view risks, roles, credentials, and activity evidence.
        </p>
      </div>

      {/* Blocks grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
        <Block
          title="Service Principals"
          subtitle="Enterprise apps, app registrations, workload identities"
          identityType="service_principal"
          hint="Includes app roles, Graph permissions, credential hygiene, exposed APIs"
        />
        <Block
          title="Managed Identity (System)"
          subtitle="System-assigned managed identities bound to Azure resources"
          identityType="managed_identity_system"
          hint="We will ensure these do NOT appear under Service Principals in UI"
        />
        <Block
          title="Managed Identity (User)"
          subtitle="User-assigned managed identities reusable across resources"
          identityType="managed_identity_user"
          hint="We will separate these cleanly from SPNs in backend + UI"
        />
        <Block
          title="Human Users"
          subtitle="Employees and standard members"
          identityType="human_user"
          hint="We’ll surface disabled users with privileged roles as critical"
        />
        <Block
          title="Guest Users"
          subtitle="B2B / external collaboration identities"
          identityType="guest"
          hint="Risk signals: dormant guests, privileged access, missing sponsor/owner"
        />
        <Block
          title="Microsoft Internal"
          subtitle="First-party / internal service principals"
          identityType="microsoft_internal"
          hint="We’ll keep visibility but tune risk scoring + reduce false positives"
        />
      </div>

      {/* Quick path */}
      <div className="mt-8 bg-white border rounded-2xl p-5">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <div>
            <div className="font-semibold text-gray-900">Want the full risk dashboard?</div>
            <div className="text-sm text-gray-600">
              Go to the risk posture view (existing dashboard).
            </div>
          </div>
          <Link
            to="/dashboard"
            className="inline-flex items-center justify-center px-4 py-2 rounded-lg bg-blue-600 text-white font-medium hover:bg-blue-700 transition"
          >
            Open Dashboard
          </Link>
        </div>
      </div>
    </div>
  );
};

function App() {
  return (
    <Router>
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
                <NavLinks />
              </div>
            </div>
          </div>
        </nav>

        {/* Page Content */}
        <Routes>
          {/* Front page blocks */}
          <Route path="/" element={<Overview />} />

          {/* Existing dashboard moved here */}
          <Route path="/dashboard" element={<Dashboard />} />

          {/* Existing identities pages */}
          <Route path="/identities" element={<Identities />} />
          <Route path="/identities/:id" element={<IdentityDetail />} />
        </Routes>
      </div>
    </Router>
  );
}

function NavLinks() {
  const location = useLocation();

  const isActive = (path: string) => {
    if (path === '/') return location.pathname === '/';
    return location.pathname.startsWith(path);
  };

  return (
    <div className="flex items-baseline space-x-1">
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
    </div>
  );
}

export default App;
