import React from 'react';
import Dashboard from './Dashboard';
import RiskMethodology from '../components/RiskMethodology';

export default function DashboardWithInfo() {
  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
      <RiskMethodology />
      <Dashboard />
    </div>
  );
}
