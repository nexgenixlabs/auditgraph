// src/services/api.ts
import axios from 'axios';
import { 
  Identity, 
  DiscoveryRun, 
  StatsResponse,
  IdentitiesResponse,
  RisksResponse,
  RunsResponse,
  DriftReport 
} from '../types';

const API_BASE_URL = 'http://localhost:5001/api';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Health check
export const healthCheck = async () => {
  const response = await api.get('/health');
  return response.data;
};

// Get all identities
export const getIdentities = async (params?: {
  risk_level?: string;
}) => {
  const response = await api.get<IdentitiesResponse>('/identities', { params });
  return response.data;
};

// Get single identity
export const getIdentity = async (id: string) => {
  const response = await api.get<Identity>(`/identities/${id}`);
  return response.data;
};

// Get risks (critical and high only)
export const getRisks = async () => {
  const response = await api.get<RisksResponse>('/risks');
  return response.data;
};

// Get discovery runs
export const getDiscoveryRuns = async () => {
  const response = await api.get<RunsResponse>('/runs');
  return response.data;
};

// Get drift report
export const getDriftReport = async (runId: number) => {
  const response = await api.get<DriftReport>(`/drift/${runId}`);
  return response.data;
};

// Get stats
export const getStats = async () => {
  const response = await api.get<StatsResponse>('/stats');
  return response.data;
};

export default api;
