import React from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useLocation } from 'react-router-dom';
import Dashboard from './pages/Dashboard';
import Identities from './pages/Identities';

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
          <Route path="/" element={<Dashboard />} />
          <Route path="/identities" element={<Identities />} />
        </Routes>
      </div>
    </Router>
  );
}

function NavLinks() {
  const location = useLocation();
  
  const isActive = (path: string) => location.pathname === path;
  
  return (
    <div className="flex items-baseline space-x-1">
      <Link
        to="/"
        className={`px-4 py-2 rounded-lg text-sm font-medium transition ${
          isActive('/') 
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
