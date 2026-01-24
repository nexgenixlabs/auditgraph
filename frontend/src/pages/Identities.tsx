// src/pages/Identities.tsx
import React, { useEffect, useState } from 'react';
import { getIdentities } from '../services/api';
import { Identity } from '../types';

const Identities: React.FC = () => {
  const [identities, setIdentities] = useState<Identity[]>([]);
  const [filteredIdentities, setFilteredIdentities] = useState<Identity[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  
  // Filter states
  const [searchTerm, setSearchTerm] = useState('');
  const [riskFilter, setRiskFilter] = useState<string>('all');
  const [typeFilter, setTypeFilter] = useState<string>('all');
  const [sortField, setSortField] = useState<string>('risk_level');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');

  useEffect(() => {
    fetchIdentities();
  }, []);

  useEffect(() => {
    applyFilters();
  }, [identities, searchTerm, riskFilter, typeFilter, sortField, sortOrder]);

  const fetchIdentities = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getIdentities();
      setIdentities(data.identities || []);
    } catch (err: any) {
      console.error('Error fetching identities:', err);
      setError(err.message || 'Failed to load identities');
    } finally {
      setLoading(false);
    }
  };

  const applyFilters = () => {
    let filtered = [...identities];

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(identity =>
        identity.display_name.toLowerCase().includes(searchTerm.toLowerCase())
      );
    }

    // Risk level filter
    if (riskFilter !== 'all') {
      filtered = filtered.filter(identity =>
        identity.risk_level.toLowerCase() === riskFilter.toLowerCase()
      );
    }

    // Type filter
    if (typeFilter !== 'all') {
      filtered = filtered.filter(identity =>
        identity.identity_type.toLowerCase().includes(typeFilter.toLowerCase())
      );
    }

    // Sorting
    filtered.sort((a, b) => {
      let aValue: any;
      let bValue: any;

      switch (sortField) {
        case 'risk_level':
          const riskOrder = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
          aValue = riskOrder[a.risk_level.toLowerCase() as keyof typeof riskOrder] || 0;
          bValue = riskOrder[b.risk_level.toLowerCase() as keyof typeof riskOrder] || 0;
          break;
        case 'display_name':
          aValue = a.display_name.toLowerCase();
          bValue = b.display_name.toLowerCase();
          break;
        case 'identity_type':
          aValue = a.identity_type.toLowerCase();
          bValue = b.identity_type.toLowerCase();
          break;
        case 'role_count':
          aValue = a.role_count || 0;
          bValue = b.role_count || 0;
          break;
        default:
          return 0;
      }

      if (aValue < bValue) return sortOrder === 'asc' ? -1 : 1;
      if (aValue > bValue) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });

    setFilteredIdentities(filtered);
  };

  const handleSort = (field: string) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  const getRiskBadgeColor = (riskLevel: string) => {
    const level = riskLevel.toLowerCase();
    switch (level) {
      case 'critical':
        return 'bg-red-100 text-red-800 border-red-200';
      case 'high':
        return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'medium':
        return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'low':
        return 'bg-green-100 text-green-800 border-green-200';
      case 'info':
        return 'bg-blue-100 text-blue-800 border-blue-200';
      default:
        return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getActivityBadge = (activityStatus?: string) => {
    if (!activityStatus) return null;
    
    const status = activityStatus.toLowerCase();
    if (status.includes('active')) {
      return <span className="text-xs bg-green-100 text-green-700 px-2 py-1 rounded">Active</span>;
    } else if (status.includes('inactive')) {
      return <span className="text-xs bg-yellow-100 text-yellow-700 px-2 py-1 rounded">Inactive</span>;
    } else if (status.includes('dormant')) {
      return <span className="text-xs bg-red-100 text-red-700 px-2 py-1 rounded">Dormant</span>;
    }
    return <span className="text-xs bg-gray-100 text-gray-700 px-2 py-1 rounded">{activityStatus}</span>;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="text-xl text-gray-600">Loading identities...</div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-screen">
        <div className="bg-red-50 border border-red-200 rounded-lg p-6 max-w-md">
          <h2 className="text-red-600 font-bold text-lg mb-2">Error Loading Identities</h2>
          <p className="text-red-700">{error}</p>
          <button 
            onClick={fetchIdentities}
            className="mt-4 bg-red-600 text-white px-4 py-2 rounded hover:bg-red-700"
          >
            Retry
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50 p-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-4xl font-bold text-gray-800 mb-2">All Identities</h1>
        <p className="text-gray-600">
          Showing {filteredIdentities.length} of {identities.length} identities
        </p>
      </div>

      {/* Filters Section */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {/* Search */}
          <div className="md:col-span-2">
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Search by Name
            </label>
            <input
              type="text"
              placeholder="Search identities..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>

          {/* Risk Level Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Risk Level
            </label>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Levels</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>

          {/* Type Filter */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Identity Type
            </label>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            >
              <option value="all">All Types</option>
              <option value="service_principal">Service Principal</option>
              <option value="managed_identity">Managed Identity</option>
              <option value="user">User</option>
            </select>
          </div>
        </div>

        {/* Active Filters Summary */}
        {(searchTerm || riskFilter !== 'all' || typeFilter !== 'all') && (
          <div className="mt-4 flex items-center gap-2 flex-wrap">
            <span className="text-sm text-gray-600">Active filters:</span>
            {searchTerm && (
              <span className="inline-flex items-center gap-1 px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                Search: "{searchTerm}"
                <button onClick={() => setSearchTerm('')} className="hover:text-blue-900">×</button>
              </span>
            )}
            {riskFilter !== 'all' && (
              <span className="inline-flex items-center gap-1 px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                Risk: {riskFilter}
                <button onClick={() => setRiskFilter('all')} className="hover:text-blue-900">×</button>
              </span>
            )}
            {typeFilter !== 'all' && (
              <span className="inline-flex items-center gap-1 px-3 py-1 bg-blue-100 text-blue-800 rounded-full text-sm">
                Type: {typeFilter}
                <button onClick={() => setTypeFilter('all')} className="hover:text-blue-900">×</button>
              </span>
            )}
            <button
              onClick={() => {
                setSearchTerm('');
                setRiskFilter('all');
                setTypeFilter('all');
              }}
              className="text-sm text-blue-600 hover:text-blue-800 font-medium"
            >
              Clear all
            </button>
          </div>
        )}
      </div>

      {/* Identities Table */}
      <div className="bg-white rounded-lg shadow-md overflow-hidden">
        <div className="overflow-x-auto">
          <table className="min-w-full divide-y divide-gray-200">
            <thead className="bg-gray-50">
              <tr>
                <th 
                  onClick={() => handleSort('display_name')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center gap-1">
                    Identity Name
                    {sortField === 'display_name' && (
                      <span>{sortOrder === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('identity_type')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center gap-1">
                    Type
                    {sortField === 'identity_type' && (
                      <span>{sortOrder === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th 
                  onClick={() => handleSort('risk_level')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center gap-1">
                    Risk Level
                    {sortField === 'risk_level' && (
                      <span>{sortOrder === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Activity Status
                </th>
                <th 
                  onClick={() => handleSort('role_count')}
                  className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider cursor-pointer hover:bg-gray-100"
                >
                  <div className="flex items-center gap-1">
                    Roles
                    {sortField === 'role_count' && (
                      <span>{sortOrder === 'asc' ? '↑' : '↓'}</span>
                    )}
                  </div>
                </th>
                <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                  Credentials
                </th>
              </tr>
            </thead>
            <tbody className="bg-white divide-y divide-gray-200">
              {filteredIdentities.length > 0 ? (
                filteredIdentities.map((identity, index) => (
                  <tr key={index} className="hover:bg-gray-50 cursor-pointer">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="text-sm font-medium text-gray-900">
                        {identity.display_name}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {identity.identity_type}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`px-3 py-1 inline-flex text-xs leading-5 font-semibold rounded-full border ${getRiskBadgeColor(identity.risk_level)}`}>
                        {identity.risk_level.toUpperCase()}
                      </span>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      {getActivityBadge(identity.activity_status)}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                      {identity.role_count || 0} role{(identity.role_count || 0) !== 1 ? 's' : ''}
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <span className={`text-xs ${identity.credential_status === 'Valid' ? 'text-green-600' : 'text-red-600'}`}>
                        {identity.credential_status || 'Unknown'}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-gray-500">
                    No identities found matching your filters
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Results Summary */}
      {filteredIdentities.length > 0 && (
        <div className="mt-4 text-sm text-gray-600">
          Showing {filteredIdentities.length} identit{filteredIdentities.length !== 1 ? 'ies' : 'y'}
        </div>
      )}
    </div>
  );
};

export default Identities;
