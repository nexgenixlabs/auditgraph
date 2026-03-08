import React, { useEffect, useState } from 'react';

interface DashboardSummary {
  total_identities: number;
  users: number;
  service_principals: number;
  managed_identities: number;
  guests: number;
  critical_findings: number;
  high_findings: number;
  medium_findings: number;
  low_findings: number;
  risk_score: number;
  secrets_without_expiry: number;
  secrets_older_than_180_days: number;
  unused_service_principals: number;
  identities_with_attack_paths: number;
  total_credentials: number;
  expired_credentials: number;
  expiring_soon_credentials: number;
}

interface Recommendation {
  id: string;
  recommendation_type: string;
  severity: string;
  description: string;
  recommended_action: string;
  identity_id: string | null;
  confidence_score: number;
  status: string;
}

interface RecommendationStats {
  total: number;
  open: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface AttackSimulation {
  id: string;
  identity_id: string;
  blast_radius: number;
  simulation_type: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

interface BenchmarkData {
  your_risk_score: number;
  industry_average: number;
  percentile: number;
  metrics: Record<string, {
    your_value: number | null;
    industry_average: number;
    percentile: number | null;
    sample_size: number;
  }>;
}

interface AdvisorReport {
  risk_score: number;
  benchmark_percentile: number;
  top_risks: Array<{
    type: string;
    severity: string;
    description: string;
    identity_id: string | null;
    impact_score: number;
  }>;
  recommended_actions: Array<{
    recommendation_id: string;
    recommendation_type: string;
    severity: string;
    description: string;
    recommended_action: string;
    priority_score: number;
  }>;
  risk_reduction_estimate: number;
}

interface RiskForecast {
  current_risk_score: number;
  predicted_risk_score: number;
  trend_direction: 'increasing' | 'stable' | 'decreasing';
  forecast_window_days: number;
  drivers: Array<{
    factor: string;
    description: string;
    impact: number;
    weight: number;
  }>;
}

interface GeneratedPolicy {
  identity_id: string;
  display_name: string;
  identity_category: string;
  cloud_provider: string;
  policy_type: string;
  current_roles: string[];
  suggested_roles: string[];
  removed_roles: string[];
  added_roles: string[];
  confidence_score: number;
  rationale: string;
  id?: string;
  status?: string;
}

interface PolicyStats {
  total: number;
  pending: number;
  applied: number;
  dismissed: number;
  avg_confidence: number;
}

interface ThreatEvent {
  id: string;
  identity_id: string;
  event_type: string;
  severity: string;
  description: string;
  metadata: Record<string, unknown>;
  status: string;
  created_at: string;
}

interface ThreatStats {
  total: number;
  open: number;
  critical: number;
  high: number;
  privilege_escalation: number;
  credential_creation: number;
  suspicious_login: number;
  policy_change: number;
}

interface ActivityEvent {
  id: string;
  identity_id: string;
  event_type: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

interface AttackIncident {
  id: string;
  identity_id: string;
  incident_type: string;
  severity: string;
  start_time: string;
  end_time: string;
  summary: string;
  status: string;
  created_at: string;
}

interface IncidentStats {
  total: number;
  open: number;
  investigating: number;
  resolved: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
}

interface ResponseAction {
  id: string;
  incident_id: string;
  identity_id: string;
  response_action: string;
  status: string;
  metadata: Record<string, unknown>;
  approved_by: string | null;
  created_at: string;
}

interface ResponseActionStats {
  total: number;
  pending: number;
  approved: number;
  executed: number;
  failed: number;
}

interface CopilotResponse {
  answer: string;
  intent: string;
  suggestions: string[];
}

interface AttackPrediction {
  id: string;
  identity_id: string;
  prediction_score: number;
  risk_level: string;
  risk_drivers: Array<{ driver: string; score: number; detail: string }>;
  recommended_actions: Array<{ action: string; priority: string }>;
  confidence: number;
  created_at: string;
}

interface PredictionStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  avg_score: number;
}

interface GraphInsight {
  id: string;
  identity_id: string;
  identity_name: string;
  identity_category: string;
  centrality_score: number;
  blast_radius: number;
  trust_chain_length: number;
  resource_reachability: number;
  privilege_concentration: number;
  risk_level: string;
  insight_summary: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

interface GraphInsightStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  avg_centrality: number;
  avg_blast_radius: number;
  max_centrality: number;
}

interface GovernanceAction {
  id: string;
  identity_id: string;
  identity_name: string;
  identity_category: string;
  governance_action: string;
  status: string;
  reason: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

interface GovernanceStats {
  total: number;
  pending: number;
  approved: number;
  executed: number;
  failed: number;
  by_action: {
    privilege_drift: number;
    unused_identity: number;
    stale_credential: number;
    guest_privilege: number;
  };
}

interface RiskSimulation {
  id: string;
  identity_id: string;
  identity_name: string;
  identity_category: string;
  simulation_type: string;
  exposed_resources: number;
  exposed_identities: number;
  escalation_paths: number;
  simulation_score: number;
  risk_level: string;
  impact_summary: string;
  metadata: Record<string, unknown>;
  created_at: string;
}

interface RiskSimulationStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  avg_score: number;
  avg_exposed_resources: number;
  max_score: number;
}

interface IntegrationEvent {
  id: string;
  event_type: string;
  destination: string;
  payload: Record<string, unknown>;
  status: string;
  error_message: string | null;
  created_at: string;
}

interface IntegrationStats {
  total: number;
  sent: number;
  failed: number;
  pending: number;
  by_destination: {
    slack: number;
    jira: number;
    servicenow: number;
    siem: number;
  };
}

interface GovernanceMetric {
  id: string;
  metric_type: string;
  metric_value: number;
  sample_size: number;
  affected_count: number;
  metadata: Record<string, unknown>;
  computed_at: string;
}

interface GovernanceMetricStats {
  total_metrics: number;
  by_type: Record<string, {
    value: number;
    sample_size: number;
    affected_count: number;
    computed_at: string | null;
  }>;
}

interface GovernanceTrend {
  id: string;
  metric_type: string;
  previous_value: number;
  current_value: number;
  change_pct: number;
  trend_direction: 'increasing' | 'stable' | 'decreasing';
  period_start: string;
  period_end: string;
  computed_at: string;
}

interface GovernanceTrendStats {
  total_trends: number;
  by_type: Record<string, {
    direction: string;
    change_pct: number;
    current_value: number;
    previous_value: number;
    computed_at: string | null;
  }>;
  increasing: number;
  stable: number;
  decreasing: number;
}

interface StrategyRecommendation {
  id: string;
  recommendation_type: string;
  risk_reduction_score: number;
  implementation_effort: string;
  priority: string;
  title: string;
  description: string;
  metadata: Record<string, unknown>;
  status: string;
  created_at: string;
}

interface StrategyStats {
  total: number;
  open: number;
  implemented: number;
  critical: number;
  high: number;
  avg_risk_reduction: number;
}

interface SecurityPosture {
  id: string;
  risk_score: number;
  incident_count: number;
  prediction_count: number;
  governance_violation_count: number;
  strategy_recommendation_count: number;
  threat_event_count: number;
  active_identity_count: number;
  metadata: {
    risk_label: string;
    incident_severity: Record<string, number>;
    prediction_avg_confidence: number;
    governance_by_action: Record<string, number>;
    strategy_by_priority: Record<string, number>;
  };
  created_at: string;
}

interface PostureStats {
  total_snapshots: number;
  avg_risk_score: number;
  max_risk_score: number;
  min_risk_score: number;
  total_incidents: number;
  total_predictions: number;
  total_violations: number;
  total_recommendations: number;
}

interface CloudProviderSummary {
  cloud: string;
  identity_count: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

const EVENT_TYPE_LABEL: Record<string, string> = {
  login: 'Login',
  role_assignment: 'Role Assignment',
  credential_change: 'Credential Change',
  policy_update: 'Policy Update',
  resource_access: 'Resource Access',
};

const EVENT_TYPE_COLOR: Record<string, string> = {
  login: 'bg-blue-500/20 text-blue-400',
  role_assignment: 'bg-purple-500/20 text-purple-400',
  credential_change: 'bg-amber-500/20 text-amber-400',
  policy_update: 'bg-cyan-500/20 text-cyan-400',
  resource_access: 'bg-emerald-500/20 text-emerald-400',
};

const CLOUD_COLOR: Record<string, string> = {
  azure: 'text-blue-400',
  aws: 'text-orange-400',
  gcp: 'text-emerald-400',
};

const CLOUD_BG: Record<string, string> = {
  azure: 'bg-blue-500/10 border-blue-500/30',
  aws: 'bg-orange-500/10 border-orange-500/30',
  gcp: 'bg-emerald-500/10 border-emerald-500/30',
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-yellow-400',
  low: 'text-blue-400',
};

const SecurityDashboard: React.FC = () => {
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [recommendations, setRecommendations] = useState<Recommendation[]>([]);
  const [recStats, setRecStats] = useState<RecommendationStats | null>(null);
  const [simulations, setSimulations] = useState<AttackSimulation[]>([]);
  const [benchmark, setBenchmark] = useState<BenchmarkData | null>(null);
  const [advisor, setAdvisor] = useState<AdvisorReport | null>(null);
  const [cloudSummary, setCloudSummary] = useState<CloudProviderSummary[]>([]);
  const [forecast, setForecast] = useState<RiskForecast | null>(null);
  const [generatedPolicies, setGeneratedPolicies] = useState<GeneratedPolicy[]>([]);
  const [policyStats, setPolicyStats] = useState<PolicyStats | null>(null);
  const [threatEvents, setThreatEvents] = useState<ThreatEvent[]>([]);
  const [threatStats, setThreatStats] = useState<ThreatStats | null>(null);
  const [activityEvents, setActivityEvents] = useState<ActivityEvent[]>([]);
  const [incidents, setIncidents] = useState<AttackIncident[]>([]);
  const [incidentStats, setIncidentStats] = useState<IncidentStats | null>(null);
  const [responseActions, setResponseActions] = useState<ResponseAction[]>([]);
  const [responseStats, setResponseStats] = useState<ResponseActionStats | null>(null);
  const [predictions, setPredictions] = useState<AttackPrediction[]>([]);
  const [predictionStats, setPredictionStats] = useState<PredictionStats | null>(null);
  const [graphInsights, setGraphInsights] = useState<GraphInsight[]>([]);
  const [graphInsightStats, setGraphInsightStats] = useState<GraphInsightStats | null>(null);
  const [governanceActions, setGovernanceActions] = useState<GovernanceAction[]>([]);
  const [governanceStats, setGovernanceStats] = useState<GovernanceStats | null>(null);
  const [riskSimulations, setRiskSimulations] = useState<RiskSimulation[]>([]);
  const [riskSimStats, setRiskSimStats] = useState<RiskSimulationStats | null>(null);
  const [integrationEvents, setIntegrationEvents] = useState<IntegrationEvent[]>([]);
  const [integrationStats, setIntegrationStats] = useState<IntegrationStats | null>(null);
  const [govMetrics, setGovMetrics] = useState<GovernanceMetric[]>([]);
  const [govMetricStats, setGovMetricStats] = useState<GovernanceMetricStats | null>(null);
  const [govTrends, setGovTrends] = useState<GovernanceTrend[]>([]);
  const [govTrendStats, setGovTrendStats] = useState<GovernanceTrendStats | null>(null);
  const [strategyRecs, setStrategyRecs] = useState<StrategyRecommendation[]>([]);
  const [strategyStats, setStrategyStats] = useState<StrategyStats | null>(null);
  const [securityPosture, setSecurityPosture] = useState<SecurityPosture | null>(null);
  const [postureStats, setPostureStats] = useState<PostureStats | null>(null);
  const [copilotQuery, setCopilotQuery] = useState('');
  const [copilotResponse, setCopilotResponse] = useState<CopilotResponse | null>(null);
  const [copilotLoading, setCopilotLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [executing, setExecuting] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      const [summaryRes, recsRes, simsRes, benchRes, advisorRes, cloudRes, forecastRes, policiesRes, threatsRes, activityRes, incidentsRes, responseRes, predictionsRes, graphInsightsRes, governanceRes, riskSimRes, integrationsRes, govMetricsRes, govTrendsRes, strategyRes, commandCenterRes] = await Promise.all([
        fetch('/api/dashboard/summary'),
        fetch('/api/security/recommendations?status=open'),
        fetch('/api/security/attack-simulations'),
        fetch('/api/security/benchmark'),
        fetch('/api/security/advisor'),
        fetch('/api/security/cloud-summary'),
        fetch('/api/security/risk-forecast'),
        fetch('/api/security/generated-policies?status=pending'),
        fetch('/api/security/threat-events?status=open'),
        fetch('/api/security/activity-events?limit=20'),
        fetch('/api/security/incidents?status=open'),
        fetch('/api/security/response-actions'),
        fetch('/api/security/attack-predictions'),
        fetch('/api/security/graph-insights'),
        fetch('/api/security/governance-actions'),
        fetch('/api/security/risk-simulations'),
        fetch('/api/security/integrations'),
        fetch('/api/security/governance-metrics'),
        fetch('/api/security/governance-trends'),
        fetch('/api/security/strategy-advisor'),
        fetch('/api/security/command-center'),
      ]);
      if (summaryRes.ok) {
        const data = await summaryRes.json();
        setSummary(data);
      }
      if (recsRes.ok) {
        const data = await recsRes.json();
        setRecommendations(data.recommendations || []);
        setRecStats(data.stats || null);
      }
      if (simsRes.ok) {
        const data = await simsRes.json();
        setSimulations(data.simulations || []);
      }
      if (benchRes.ok) {
        const data = await benchRes.json();
        if (!data.error) setBenchmark(data);
      }
      if (advisorRes.ok) {
        const data = await advisorRes.json();
        setAdvisor(data);
      }
      if (cloudRes.ok) {
        const data = await cloudRes.json();
        setCloudSummary(data.providers || []);
      }
      if (forecastRes.ok) {
        const data = await forecastRes.json();
        setForecast(data);
      }
      if (policiesRes.ok) {
        const data = await policiesRes.json();
        setGeneratedPolicies(data.policies || []);
        setPolicyStats(data.stats || null);
      }
      if (threatsRes.ok) {
        const data = await threatsRes.json();
        setThreatEvents(data.events || []);
        setThreatStats(data.stats || null);
      }
      if (activityRes.ok) {
        const data = await activityRes.json();
        setActivityEvents(data.events || []);
      }
      if (incidentsRes.ok) {
        const data = await incidentsRes.json();
        setIncidents(data.incidents || []);
        setIncidentStats(data.stats || null);
      }
      if (responseRes.ok) {
        const data = await responseRes.json();
        setResponseActions(data.actions || []);
        setResponseStats(data.stats || null);
      }
      if (predictionsRes.ok) {
        const data = await predictionsRes.json();
        setPredictions(data.predictions || []);
        setPredictionStats(data.stats || null);
      }
      if (graphInsightsRes.ok) {
        const data = await graphInsightsRes.json();
        setGraphInsights(data.insights || []);
        setGraphInsightStats(data.stats || null);
      }
      if (governanceRes.ok) {
        const data = await governanceRes.json();
        setGovernanceActions(data.actions || []);
        setGovernanceStats(data.stats || null);
      }
      if (riskSimRes.ok) {
        const data = await riskSimRes.json();
        setRiskSimulations(data.simulations || []);
        setRiskSimStats(data.stats || null);
      }
      if (integrationsRes.ok) {
        const data = await integrationsRes.json();
        setIntegrationEvents(data.events || []);
        setIntegrationStats(data.stats || null);
      }
      if (govMetricsRes.ok) {
        const data = await govMetricsRes.json();
        setGovMetrics(data.metrics || []);
        setGovMetricStats(data.stats || null);
      }
      if (govTrendsRes.ok) {
        const data = await govTrendsRes.json();
        setGovTrends(data.trends || []);
        setGovTrendStats(data.stats || null);
      }
      if (strategyRes.ok) {
        const data = await strategyRes.json();
        setStrategyRecs(data.recommendations || []);
        setStrategyStats(data.stats || null);
      }
      if (commandCenterRes.ok) {
        const data = await commandCenterRes.json();
        setSecurityPosture(data.posture || null);
        setPostureStats(data.stats || null);
      }
    } catch (err) {
      console.error('Failed to fetch dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchData(); }, []);

  const handleThreatAction = async (eventId: string, action: 'acknowledge' | 'resolve') => {
    try {
      const res = await fetch(`/api/security/threat-events/${eventId}/${action}`, { method: 'POST' });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(`Failed to ${action} threat event:`, err);
    }
  };

  const handleIncidentAction = async (incidentId: string, status: 'investigating' | 'resolved') => {
    try {
      const res = await fetch(`/api/security/incidents/${incidentId}/status`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(`Failed to update incident status:`, err);
    }
  };

  const handleResponseAction = async (actionId: string, action: 'approve' | 'execute') => {
    try {
      const res = await fetch(`/api/security/response-actions/${actionId}/${action}`, { method: 'POST' });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(`Failed to ${action} response action:`, err);
    }
  };

  const handleCopilotSubmit = async (queryText?: string) => {
    const q = queryText || copilotQuery;
    if (!q.trim()) return;
    setCopilotLoading(true);
    try {
      const res = await fetch('/api/security/copilot-query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: q }),
      });
      if (res.ok) {
        const data = await res.json();
        setCopilotResponse(data);
        setCopilotQuery('');
      }
    } catch (err) {
      console.error('Copilot query failed:', err);
    } finally {
      setCopilotLoading(false);
    }
  };

  const handlePolicyAction = async (policyId: string, action: 'apply' | 'dismiss') => {
    try {
      const res = await fetch(`/api/security/generated-policies/${policyId}/${action}`, { method: 'POST' });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error(`Failed to ${action} policy:`, err);
    }
  };

  const handleExecuteFix = async (recId: string) => {
    setExecuting(recId);
    try {
      const res = await fetch(`/api/security/remediation/${recId}/execute`, { method: 'POST' });
      if (res.ok) {
        fetchData();
      }
    } catch (err) {
      console.error('Failed to execute remediation:', err);
    } finally {
      setExecuting(null);
    }
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-400">Loading dashboard...</div>;
  }

  if (!summary) {
    return <div className="p-8 text-center text-slate-400">Failed to load dashboard data</div>;
  }

  const riskColor = summary.risk_score >= 100 ? 'text-red-400' :
                    summary.risk_score >= 50 ? 'text-orange-400' :
                    summary.risk_score >= 20 ? 'text-yellow-400' : 'text-emerald-400';

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Dashboard</h1>
          <p className="text-sm text-slate-400 mt-1">Executive view of IAM security posture</p>
        </div>
        <div className="text-right">
          <div className="text-xs text-slate-400 uppercase tracking-wider">Risk Score</div>
          <div className={`text-4xl font-bold ${riskColor}`}>{summary.risk_score}</div>
        </div>
      </div>

      {/* Cloud Provider Summary */}
      {cloudSummary.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Cloud Providers</h2>
          <div className={`grid grid-cols-${Math.min(cloudSummary.length, 3)} gap-4`}>
            {cloudSummary.map(provider => (
              <div key={provider.cloud} className={`border rounded-lg p-4 ${CLOUD_BG[provider.cloud] || 'bg-slate-800/50 border-slate-700/50'}`}>
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-sm font-semibold uppercase ${CLOUD_COLOR[provider.cloud] || 'text-slate-300'}`}>
                    {provider.cloud}
                  </span>
                  <span className="text-lg font-bold text-white">{provider.identity_count}</span>
                </div>
                <div className="flex items-center gap-3 text-xs">
                  {provider.critical > 0 && <span className="text-red-400">C: {provider.critical}</span>}
                  {provider.high > 0 && <span className="text-orange-400">H: {provider.high}</span>}
                  {provider.medium > 0 && <span className="text-yellow-400">M: {provider.medium}</span>}
                  {provider.low > 0 && <span className="text-blue-400">L: {provider.low}</span>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Identity Overview */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Overview</h2>
        <div className="grid grid-cols-5 gap-4">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400">Total Identities</div>
            <div className="text-2xl font-bold text-white mt-1">{summary.total_identities}</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400">Users</div>
            <div className="text-2xl font-bold text-blue-400 mt-1">{summary.users}</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400">Service Principals</div>
            <div className="text-2xl font-bold text-purple-400 mt-1">{summary.service_principals}</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400">Managed Identities</div>
            <div className="text-2xl font-bold text-cyan-400 mt-1">{summary.managed_identities}</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
            <div className="text-xs text-slate-400">Guests</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">{summary.guests}</div>
          </div>
        </div>
      </div>

      {/* Risk Findings */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Risk Findings</h2>
        <div className="grid grid-cols-4 gap-4">
          <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
            <div className="text-xs text-red-400">Critical</div>
            <div className="text-3xl font-bold text-red-400 mt-1">{summary.critical_findings}</div>
          </div>
          <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
            <div className="text-xs text-orange-400">High</div>
            <div className="text-3xl font-bold text-orange-400 mt-1">{summary.high_findings}</div>
          </div>
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
            <div className="text-xs text-yellow-400">Medium</div>
            <div className="text-3xl font-bold text-yellow-400 mt-1">{summary.medium_findings}</div>
          </div>
          <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
            <div className="text-xs text-blue-400">Low</div>
            <div className="text-3xl font-bold text-blue-400 mt-1">{summary.low_findings}</div>
          </div>
        </div>
      </div>

      {/* NHI Security + Privilege Escalation */}
      <div className="grid grid-cols-2 gap-6">
        {/* NHI Security */}
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">NHI Security</h2>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Secrets without expiry</span>
              <span className="text-lg font-bold text-red-400">{summary.secrets_without_expiry}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Secrets older than 180 days</span>
              <span className="text-lg font-bold text-orange-400">{summary.secrets_older_than_180_days}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Unused service principals</span>
              <span className="text-lg font-bold text-yellow-400">{summary.unused_service_principals}</span>
            </div>
          </div>
        </div>

        {/* Privilege Escalation */}
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Privilege Escalation</h2>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Identities with attack paths</span>
              <span className="text-lg font-bold text-red-400">{summary.identities_with_attack_paths}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Total credentials tracked</span>
              <span className="text-lg font-bold text-slate-300">{summary.total_credentials}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Expired credentials</span>
              <span className="text-lg font-bold text-red-400">{summary.expired_credentials}</span>
            </div>
            <div className="flex items-center justify-between px-4 py-3">
              <span className="text-sm text-slate-300">Expiring within 30 days</span>
              <span className="text-lg font-bold text-orange-400">{summary.expiring_soon_credentials}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Policy Recommendations */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Policy Recommendations</h2>
        {!!recStats && (
          <div className="grid grid-cols-4 gap-4 mb-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
              <div className="text-xs text-slate-400">Total Open</div>
              <div className="text-2xl font-bold text-white mt-1">{recStats.open}</div>
            </div>
            <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4">
              <div className="text-xs text-red-400">Critical</div>
              <div className="text-2xl font-bold text-red-400 mt-1">{recStats.critical}</div>
            </div>
            <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4">
              <div className="text-xs text-orange-400">High</div>
              <div className="text-2xl font-bold text-orange-400 mt-1">{recStats.high}</div>
            </div>
            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
              <div className="text-xs text-yellow-400">Medium</div>
              <div className="text-2xl font-bold text-yellow-400 mt-1">{recStats.medium}</div>
            </div>
          </div>
        )}
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
          {recommendations.length === 0 ? (
            <div className="px-4 py-6 text-center text-slate-400 text-sm">No open recommendations</div>
          ) : (
            recommendations.slice(0, 10).map(rec => (
              <div key={rec.id} className="px-4 py-3 flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-medium uppercase ${SEVERITY_COLOR[rec.severity] || 'text-slate-400'}`}>
                      {rec.severity}
                    </span>
                    <span className="text-sm text-white font-medium truncate">{rec.description}</span>
                  </div>
                  <div className="text-xs text-slate-400 mt-1">{rec.recommended_action}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {!!rec.identity_id && (
                    <span className="text-xs text-slate-500 font-mono">{rec.identity_id.slice(0, 12)}...</span>
                  )}
                  <button
                    onClick={() => handleExecuteFix(rec.id)}
                    disabled={executing === rec.id}
                    className="px-2 py-1 text-xs bg-emerald-500/20 text-emerald-400 rounded hover:bg-emerald-500/30 disabled:opacity-50"
                  >
                    {executing === rec.id ? 'Executing...' : 'Execute Fix'}
                  </button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>

      {/* Attack Simulation */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Attack Simulation</h2>
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
          {simulations.length === 0 ? (
            <div className="px-4 py-6 text-center text-slate-400 text-sm">No simulations run yet</div>
          ) : (
            simulations.slice(0, 5).map(sim => {
              const radiusColor = sim.blast_radius >= 20 ? 'text-red-400' :
                                  sim.blast_radius >= 10 ? 'text-orange-400' :
                                  sim.blast_radius >= 5 ? 'text-yellow-400' : 'text-emerald-400';
              return (
                <div key={sim.id} className="px-4 py-3 flex items-center justify-between">
                  <div>
                    <span className="text-sm text-white font-medium">{sim.identity_id}</span>
                    <span className="text-xs text-slate-500 ml-2">{sim.simulation_type.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="text-right">
                    <span className="text-xs text-slate-400">Blast Radius: </span>
                    <span className={`text-lg font-bold ${radiusColor}`}>{sim.blast_radius}</span>
                    <span className="text-xs text-slate-400 ml-1">resources</span>
                  </div>
                </div>
              );
            })
          )}
        </div>
      </div>

      {/* Security Benchmark */}
      {!!benchmark && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Security Benchmark</h2>
          <div className="grid grid-cols-3 gap-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
              <div className="text-xs text-slate-400">Your Risk Score</div>
              <div className="text-3xl font-bold text-white mt-1">{benchmark.your_risk_score}</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
              <div className="text-xs text-slate-400">Industry Average</div>
              <div className="text-3xl font-bold text-blue-400 mt-1">{benchmark.industry_average}</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
              <div className="text-xs text-slate-400">Percentile</div>
              <div className={`text-3xl font-bold mt-1 ${
                benchmark.percentile >= 75 ? 'text-red-400' :
                benchmark.percentile >= 50 ? 'text-orange-400' :
                benchmark.percentile >= 25 ? 'text-yellow-400' : 'text-emerald-400'
              }`}>
                Top {100 - benchmark.percentile}%
              </div>
            </div>
          </div>
        </div>
      )}

      {/* AI Security Advisor */}
      {!!advisor && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">AI Security Advisor</h2>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
              <div className="text-xs text-slate-400">Risk Score</div>
              <div className={`text-3xl font-bold mt-1 ${
                advisor.risk_score >= 100 ? 'text-red-400' :
                advisor.risk_score >= 50 ? 'text-orange-400' :
                advisor.risk_score >= 20 ? 'text-yellow-400' : 'text-emerald-400'
              }`}>{advisor.risk_score}</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
              <div className="text-xs text-slate-400">Benchmark Percentile</div>
              <div className="text-3xl font-bold text-blue-400 mt-1">Top {100 - advisor.benchmark_percentile}%</div>
            </div>
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-4 text-center">
              <div className="text-xs text-emerald-400">Potential Risk Reduction</div>
              <div className="text-3xl font-bold text-emerald-400 mt-1">{advisor.risk_reduction_estimate}%</div>
            </div>
          </div>

          {advisor.top_risks.length > 0 && (
            <div className="mb-4">
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Top Risks</h3>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
                {advisor.top_risks.slice(0, 5).map((risk, idx) => (
                  <div key={idx} className="px-4 py-3 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={`text-xs font-medium uppercase ${SEVERITY_COLOR[risk.severity] || 'text-slate-400'}`}>
                        {risk.severity}
                      </span>
                      <span className="text-sm text-white">{risk.description}</span>
                    </div>
                    <span className="text-xs text-slate-400">Impact: {risk.impact_score.toFixed(1)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {advisor.recommended_actions.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Prioritized Actions</h3>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
                {advisor.recommended_actions.slice(0, 5).map((action, idx) => (
                  <div key={idx} className="px-4 py-3 flex items-start justify-between gap-4">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className={`text-xs font-medium uppercase ${SEVERITY_COLOR[action.severity] || 'text-slate-400'}`}>
                          {action.severity}
                        </span>
                        <span className="text-sm text-white font-medium truncate">{action.description}</span>
                      </div>
                      <div className="text-xs text-slate-400 mt-1">{action.recommended_action}</div>
                    </div>
                    <div className="text-right shrink-0">
                      <div className="text-xs text-slate-400">Priority</div>
                      <div className="text-sm font-bold text-amber-400">{action.priority_score}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Risk Forecast */}
      {!!forecast && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Risk Forecast</h2>
          <div className="grid grid-cols-3 gap-4 mb-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
              <div className="text-xs text-slate-400">Current Risk Score</div>
              <div className={`text-3xl font-bold mt-1 ${
                forecast.current_risk_score >= 100 ? 'text-red-400' :
                forecast.current_risk_score >= 50 ? 'text-orange-400' :
                forecast.current_risk_score >= 20 ? 'text-yellow-400' : 'text-emerald-400'
              }`}>{forecast.current_risk_score}</div>
            </div>
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
              <div className="text-xs text-slate-400">Predicted ({forecast.forecast_window_days}d)</div>
              <div className={`text-3xl font-bold mt-1 ${
                forecast.predicted_risk_score >= 100 ? 'text-red-400' :
                forecast.predicted_risk_score >= 50 ? 'text-orange-400' :
                forecast.predicted_risk_score >= 20 ? 'text-yellow-400' : 'text-emerald-400'
              }`}>{forecast.predicted_risk_score}</div>
            </div>
            <div className={`border rounded-lg p-4 text-center ${
              forecast.trend_direction === 'increasing' ? 'bg-red-500/10 border-red-500/30' :
              forecast.trend_direction === 'decreasing' ? 'bg-emerald-500/10 border-emerald-500/30' :
              'bg-slate-800/50 border-slate-700/50'
            }`}>
              <div className="text-xs text-slate-400">Trend</div>
              <div className={`text-2xl font-bold mt-1 capitalize ${
                forecast.trend_direction === 'increasing' ? 'text-red-400' :
                forecast.trend_direction === 'decreasing' ? 'text-emerald-400' : 'text-slate-300'
              }`}>
                {forecast.trend_direction === 'increasing' ? '↑' :
                 forecast.trend_direction === 'decreasing' ? '↓' : '→'} {forecast.trend_direction}
              </div>
            </div>
          </div>

          {forecast.drivers.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">Risk Drivers</h3>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
                {forecast.drivers.map((driver, idx) => (
                  <div key={idx} className="px-4 py-3 flex items-center justify-between">
                    <div>
                      <span className="text-sm text-white">{driver.description}</span>
                      <span className="text-xs text-slate-500 ml-2">({driver.factor.replace(/_/g, ' ')})</span>
                    </div>
                    <div className="text-right">
                      <span className="text-xs text-slate-400">Impact: </span>
                      <span className={`text-sm font-bold ${
                        driver.impact >= 5 ? 'text-red-400' :
                        driver.impact >= 2 ? 'text-orange-400' : 'text-yellow-400'
                      }`}>{driver.impact}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Least-Privilege Recommendations */}
      {generatedPolicies.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Least-Privilege Recommendations</h2>
          {!!policyStats && (
            <div className="grid grid-cols-4 gap-4 mb-4">
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
                <div className="text-xs text-slate-400">Total Policies</div>
                <div className="text-2xl font-bold text-white mt-1">{policyStats.total}</div>
              </div>
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-lg p-4 text-center">
                <div className="text-xs text-amber-400">Pending</div>
                <div className="text-2xl font-bold text-amber-400 mt-1">{policyStats.pending}</div>
              </div>
              <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-lg p-4 text-center">
                <div className="text-xs text-emerald-400">Applied</div>
                <div className="text-2xl font-bold text-emerald-400 mt-1">{policyStats.applied}</div>
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
                <div className="text-xs text-slate-400">Avg Confidence</div>
                <div className="text-2xl font-bold text-blue-400 mt-1">{policyStats.avg_confidence ? `${Math.round(policyStats.avg_confidence * 100)}%` : '—'}</div>
              </div>
            </div>
          )}
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            {generatedPolicies.slice(0, 10).map((policy, idx) => (
              <div key={policy.id || idx} className="px-4 py-3">
                <div className="flex items-center justify-between mb-2">
                  <div>
                    <span className="text-sm text-white font-medium">{policy.display_name || policy.identity_id}</span>
                    <span className="text-xs text-slate-500 ml-2">{policy.identity_category}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      policy.confidence_score >= 0.8 ? 'bg-emerald-500/20 text-emerald-400' :
                      policy.confidence_score >= 0.5 ? 'bg-amber-500/20 text-amber-400' :
                      'bg-slate-700 text-slate-400'
                    }`}>
                      {Math.round(policy.confidence_score * 100)}% confidence
                    </span>
                    {!!policy.id && (
                      <>
                        <button
                          onClick={() => handlePolicyAction(policy.id!, 'apply')}
                          className="px-2 py-1 text-xs bg-emerald-500/20 text-emerald-400 rounded hover:bg-emerald-500/30"
                        >
                          Apply
                        </button>
                        <button
                          onClick={() => handlePolicyAction(policy.id!, 'dismiss')}
                          className="px-2 py-1 text-xs bg-slate-700 text-slate-400 rounded hover:bg-slate-600"
                        >
                          Dismiss
                        </button>
                      </>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs">
                  <div>
                    <span className="text-slate-400">Current: </span>
                    <span className="text-red-400">{policy.current_roles.join(', ')}</span>
                  </div>
                  <span className="text-slate-600">→</span>
                  <div>
                    <span className="text-slate-400">Suggested: </span>
                    <span className="text-emerald-400">{policy.suggested_roles.join(', ')}</span>
                  </div>
                </div>
                {!!policy.rationale && (
                  <div className="text-xs text-slate-500 mt-1">{policy.rationale}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Identity Threat Detection */}
      {threatEvents.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Threat Detection</h2>
          {!!threatStats && (
            <div className="grid grid-cols-4 gap-4 mb-4">
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
                <div className="text-xs text-slate-400">Total Events</div>
                <div className="text-2xl font-bold text-white mt-1">{threatStats.total}</div>
              </div>
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-center">
                <div className="text-xs text-red-400">Open</div>
                <div className="text-2xl font-bold text-red-400 mt-1">{threatStats.open}</div>
              </div>
              <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 text-center">
                <div className="text-xs text-red-400">Critical</div>
                <div className="text-2xl font-bold text-red-400 mt-1">{threatStats.critical}</div>
              </div>
              <div className="bg-orange-500/10 border border-orange-500/30 rounded-lg p-4 text-center">
                <div className="text-xs text-orange-400">High</div>
                <div className="text-2xl font-bold text-orange-400 mt-1">{threatStats.high}</div>
              </div>
            </div>
          )}
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            {threatEvents.slice(0, 10).map((event) => {
              const typeLabel = event.event_type.replace(/_/g, ' ');
              return (
                <div key={event.id} className="px-4 py-3 flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className={`text-xs font-medium uppercase ${SEVERITY_COLOR[event.severity] || 'text-slate-400'}`}>
                        {event.severity}
                      </span>
                      <span className="text-xs text-slate-500 capitalize">{typeLabel}</span>
                    </div>
                    <div className="text-sm text-white">{event.description}</div>
                    {!!event.identity_id && (
                      <div className="text-xs text-slate-500 mt-0.5 font-mono">{event.identity_id.slice(0, 24)}...</div>
                    )}
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => handleThreatAction(event.id, 'acknowledge')}
                      className="px-2 py-1 text-xs bg-amber-500/20 text-amber-400 rounded hover:bg-amber-500/30"
                    >
                      Ack
                    </button>
                    <button
                      onClick={() => handleThreatAction(event.id, 'resolve')}
                      className="px-2 py-1 text-xs bg-emerald-500/20 text-emerald-400 rounded hover:bg-emerald-500/30"
                    >
                      Resolve
                    </button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Identity Activity Timeline */}
      {activityEvents.length > 0 && (
        <div>
          <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Activity Timeline</h2>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            {activityEvents.slice(0, 15).map((event) => {
              const meta = event.metadata || {};
              return (
                <div key={event.id} className="px-4 py-3 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <span className={`text-xs px-2 py-0.5 rounded ${EVENT_TYPE_COLOR[event.event_type] || 'bg-slate-700 text-slate-400'}`}>
                      {EVENT_TYPE_LABEL[event.event_type] || event.event_type}
                    </span>
                    <div>
                      <span className="text-sm text-white">{(meta.display_name as string) || event.identity_id}</span>
                      {!!(meta.role_name) && (
                        <span className="text-xs text-slate-500 ml-2">→ {meta.role_name as string}</span>
                      )}
                    </div>
                  </div>
                  <span className="text-xs text-slate-500">
                    {new Date(event.created_at).toLocaleDateString()}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Identity Incident Replay */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Incident Replay</h2>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-white">{incidentStats?.total ?? 0}</div>
            <div className="text-xs text-slate-400">Total Incidents</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-red-400">{incidentStats?.open ?? 0}</div>
            <div className="text-xs text-slate-400">Open</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-yellow-400">{incidentStats?.investigating ?? 0}</div>
            <div className="text-xs text-slate-400">Investigating</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-green-400">{incidentStats?.resolved ?? 0}</div>
            <div className="text-xs text-slate-400">Resolved</div>
          </div>
        </div>
        {incidents.length > 0 ? (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            {incidents.slice(0, 10).map((inc) => (
              <div key={inc.id} className="px-4 py-3">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                      inc.severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                      inc.severity === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      inc.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-slate-700 text-slate-400'
                    }`}>{inc.severity}</span>
                    <span className="text-xs text-slate-500">{inc.incident_type.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      inc.status === 'open' ? 'bg-red-500/20 text-red-400' :
                      inc.status === 'investigating' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-green-500/20 text-green-400'
                    }`}>{inc.status}</span>
                    {inc.status === 'open' && (
                      <button onClick={() => handleIncidentAction(inc.id, 'investigating')} className="text-xs text-yellow-400 hover:text-yellow-300">Investigate</button>
                    )}
                    {inc.status !== 'resolved' && (
                      <button onClick={() => handleIncidentAction(inc.id, 'resolved')} className="text-xs text-green-400 hover:text-green-300">Resolve</button>
                    )}
                  </div>
                </div>
                <div className="text-sm text-white truncate">{inc.summary}</div>
                <div className="text-xs text-slate-500 mt-1">{inc.identity_id} &middot; {new Date(inc.created_at).toLocaleDateString()}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No incidents detected</div>
        )}
      </div>

      {/* Security Response Actions */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Security Response Actions</h2>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-white">{responseStats?.total ?? 0}</div>
            <div className="text-xs text-slate-400">Total Actions</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-yellow-400">{responseStats?.pending ?? 0}</div>
            <div className="text-xs text-slate-400">Pending</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-green-400">{responseStats?.executed ?? 0}</div>
            <div className="text-xs text-slate-400">Executed</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-red-400">{responseStats?.failed ?? 0}</div>
            <div className="text-xs text-slate-400">Failed</div>
          </div>
        </div>
        {responseActions.length > 0 ? (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            {responseActions.slice(0, 10).map((action) => (
              <div key={action.id} className="px-4 py-3">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                      action.response_action === 'disable_identity' ? 'bg-red-500/20 text-red-400' :
                      action.response_action === 'remove_privileged_role' ? 'bg-orange-500/20 text-orange-400' :
                      action.response_action === 'rotate_credential' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-blue-500/20 text-blue-400'
                    }`}>{action.response_action.replace(/_/g, ' ')}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded ${
                      action.status === 'pending' ? 'bg-yellow-500/20 text-yellow-400' :
                      action.status === 'approved' ? 'bg-blue-500/20 text-blue-400' :
                      action.status === 'executed' ? 'bg-green-500/20 text-green-400' :
                      action.status === 'failed' ? 'bg-red-500/20 text-red-400' :
                      'bg-slate-700 text-slate-400'
                    }`}>{action.status}</span>
                    {action.status === 'pending' && (
                      <button onClick={() => handleResponseAction(action.id, 'approve')} className="text-xs text-blue-400 hover:text-blue-300">Approve</button>
                    )}
                    {(action.status === 'pending' || action.status === 'approved') && (
                      <button onClick={() => handleResponseAction(action.id, 'execute')} className="text-xs text-green-400 hover:text-green-300">Execute</button>
                    )}
                  </div>
                </div>
                <div className="text-sm text-white">{(action.metadata?.description as string) || action.response_action}</div>
                <div className="text-xs text-slate-500 mt-1">{action.identity_id} &middot; {new Date(action.created_at).toLocaleDateString()}</div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No response actions</div>
        )}
      </div>

      {/* Predicted Identity Attacks */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Predicted Identity Attacks</h2>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-white">{predictionStats?.total ?? 0}</div>
            <div className="text-xs text-slate-400">Predictions</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-red-400">{predictionStats?.critical ?? 0}</div>
            <div className="text-xs text-slate-400">Critical</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-orange-400">{predictionStats?.high ?? 0}</div>
            <div className="text-xs text-slate-400">High</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-blue-400">{predictionStats?.avg_score ?? 0}</div>
            <div className="text-xs text-slate-400">Avg Score</div>
          </div>
        </div>
        {predictions.length > 0 ? (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg divide-y divide-slate-700/50">
            {predictions.slice(0, 10).map((pred) => (
              <div key={pred.id} className="px-4 py-3">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                      pred.risk_level === 'critical' ? 'bg-red-500/20 text-red-400' :
                      pred.risk_level === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      pred.risk_level === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-slate-700 text-slate-400'
                    }`}>{pred.risk_level}</span>
                    <span className="text-sm text-white">{pred.identity_id}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-slate-400">Score: {pred.prediction_score}</span>
                    <span className="text-xs text-slate-500">({Math.round(pred.confidence * 100)}% conf)</span>
                  </div>
                </div>
                {pred.risk_drivers.length > 0 && (
                  <div className="flex flex-wrap gap-1 mt-1">
                    {pred.risk_drivers.map((d, i) => (
                      <span key={i} className="text-xs px-1.5 py-0.5 bg-slate-700/50 text-slate-400 rounded">{d.driver.replace(/_/g, ' ')}</span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No attack predictions</div>
        )}
      </div>

      {/* Identity Graph Intelligence */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Graph Intelligence</h2>
        {graphInsightStats && (
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
              <div className="text-xs text-slate-500">Analyzed</div>
              <div className="text-xl font-bold text-white">{graphInsightStats.total}</div>
            </div>
            <div className="bg-slate-800/50 border border-red-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Critical Hubs</div>
              <div className="text-xl font-bold text-red-400">{graphInsightStats.critical}</div>
            </div>
            <div className="bg-slate-800/50 border border-orange-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Avg Centrality</div>
              <div className="text-xl font-bold text-orange-400">{graphInsightStats.avg_centrality.toFixed(3)}</div>
            </div>
            <div className="bg-slate-800/50 border border-yellow-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Avg Blast Radius</div>
              <div className="text-xl font-bold text-yellow-400">{graphInsightStats.avg_blast_radius.toFixed(1)}</div>
            </div>
          </div>
        )}
        {graphInsights.length > 0 ? (
          <div className="space-y-2">
            {graphInsights.slice(0, 10).map((insight) => (
              <div key={insight.id} className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 flex items-center justify-between">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                      insight.risk_level === 'critical' ? 'bg-red-900/50 text-red-300' :
                      insight.risk_level === 'high' ? 'bg-orange-900/50 text-orange-300' :
                      insight.risk_level === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                      'bg-green-900/50 text-green-300'
                    }`}>{insight.risk_level}</span>
                    <span className="text-sm font-medium text-white truncate">{insight.identity_name || insight.identity_id}</span>
                    <span className="text-xs text-slate-500">{insight.identity_category}</span>
                  </div>
                  <div className="flex gap-4 mt-1 text-xs text-slate-400">
                    <span>Centrality: <span className="text-slate-300">{insight.centrality_score.toFixed(2)}</span></span>
                    <span>Blast Radius: <span className="text-slate-300">{insight.blast_radius}</span></span>
                    <span>Trust Chain: <span className="text-slate-300">{insight.trust_chain_length}</span></span>
                    <span>Reachability: <span className="text-slate-300">{insight.resource_reachability}</span></span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No graph insights available</div>
        )}
      </div>

      {/* Identity Governance Actions */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Governance Actions</h2>
        {governanceStats && (
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
              <div className="text-xs text-slate-500">Total Actions</div>
              <div className="text-xl font-bold text-white">{governanceStats.total}</div>
            </div>
            <div className="bg-slate-800/50 border border-yellow-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Pending</div>
              <div className="text-xl font-bold text-yellow-400">{governanceStats.pending}</div>
            </div>
            <div className="bg-slate-800/50 border border-green-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Executed</div>
              <div className="text-xl font-bold text-green-400">{governanceStats.executed}</div>
            </div>
            <div className="bg-slate-800/50 border border-red-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Failed</div>
              <div className="text-xl font-bold text-red-400">{governanceStats.failed}</div>
            </div>
          </div>
        )}
        {governanceActions.length > 0 ? (
          <div className="space-y-2">
            {governanceActions.slice(0, 10).map((ga) => (
              <div key={ga.id} className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                    ga.status === 'pending' ? 'bg-yellow-900/50 text-yellow-300' :
                    ga.status === 'executed' ? 'bg-green-900/50 text-green-300' :
                    ga.status === 'failed' ? 'bg-red-900/50 text-red-300' :
                    'bg-blue-900/50 text-blue-300'
                  }`}>{ga.status}</span>
                  <span className="text-xs px-1.5 py-0.5 bg-slate-700/50 text-slate-400 rounded">
                    {ga.governance_action.replace(/_/g, ' ')}
                  </span>
                  <span className="text-sm font-medium text-white truncate">{ga.identity_name || ga.identity_id}</span>
                </div>
                <p className="text-xs text-slate-400 line-clamp-2">{ga.reason}</p>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No governance actions</div>
        )}
      </div>

      {/* Identity Risk Simulation */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Identity Risk Simulation</h2>
        {riskSimStats && (
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
              <div className="text-xs text-slate-500">Simulations</div>
              <div className="text-xl font-bold text-white">{riskSimStats.total}</div>
            </div>
            <div className="bg-slate-800/50 border border-red-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Critical Impact</div>
              <div className="text-xl font-bold text-red-400">{riskSimStats.critical}</div>
            </div>
            <div className="bg-slate-800/50 border border-orange-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Avg Score</div>
              <div className="text-xl font-bold text-orange-400">{riskSimStats.avg_score.toFixed(1)}</div>
            </div>
            <div className="bg-slate-800/50 border border-yellow-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Avg Resources Exposed</div>
              <div className="text-xl font-bold text-yellow-400">{riskSimStats.avg_exposed_resources.toFixed(0)}</div>
            </div>
          </div>
        )}
        {riskSimulations.length > 0 ? (
          <div className="space-y-2">
            {riskSimulations.slice(0, 8).map((sim) => (
              <div key={sim.id} className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                    sim.risk_level === 'critical' ? 'bg-red-900/50 text-red-300' :
                    sim.risk_level === 'high' ? 'bg-orange-900/50 text-orange-300' :
                    sim.risk_level === 'medium' ? 'bg-yellow-900/50 text-yellow-300' :
                    'bg-green-900/50 text-green-300'
                  }`}>{sim.risk_level}</span>
                  <span className="text-xs px-1.5 py-0.5 bg-slate-700/50 text-slate-400 rounded">
                    {sim.simulation_type.replace(/_/g, ' ')}
                  </span>
                  <span className="text-sm font-medium text-white truncate">{sim.identity_name || sim.identity_id}</span>
                </div>
                <div className="flex gap-4 mt-1 text-xs text-slate-400">
                  <span>Score: <span className="text-slate-300">{sim.simulation_score.toFixed(0)}</span></span>
                  <span>Resources: <span className="text-slate-300">{sim.exposed_resources}</span></span>
                  <span>Identities: <span className="text-slate-300">{sim.exposed_identities}</span></span>
                  <span>Escalation Paths: <span className="text-slate-300">{sim.escalation_paths}</span></span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No risk simulations yet</div>
        )}
      </div>

      {/* Enterprise Security Integrations */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Enterprise Integrations</h2>
        {integrationStats && (
          <div className="grid grid-cols-4 gap-3 mb-4">
            <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
              <div className="text-xs text-slate-500">Total Events</div>
              <div className="text-xl font-bold text-white">{integrationStats.total}</div>
            </div>
            <div className="bg-slate-800/50 border border-green-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Sent</div>
              <div className="text-xl font-bold text-green-400">{integrationStats.sent}</div>
            </div>
            <div className="bg-slate-800/50 border border-red-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Failed</div>
              <div className="text-xl font-bold text-red-400">{integrationStats.failed}</div>
            </div>
            <div className="bg-slate-800/50 border border-yellow-900/30 rounded-lg p-3">
              <div className="text-xs text-slate-500">Pending</div>
              <div className="text-xl font-bold text-yellow-400">{integrationStats.pending}</div>
            </div>
          </div>
        )}
        {integrationEvents.length > 0 ? (
          <div className="space-y-2">
            {integrationEvents.slice(0, 8).map((evt) => (
              <div key={evt.id} className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${
                    evt.status === 'sent' ? 'bg-green-900/50 text-green-300' :
                    evt.status === 'failed' ? 'bg-red-900/50 text-red-300' :
                    'bg-yellow-900/50 text-yellow-300'
                  }`}>{evt.status}</span>
                  <span className="text-xs px-1.5 py-0.5 bg-blue-900/50 text-blue-300 rounded">{evt.destination}</span>
                  <span className="text-sm text-white">{evt.event_type.replace(/_/g, ' ')}</span>
                </div>
                <span className="text-xs text-slate-500">{new Date(evt.created_at).toLocaleString()}</span>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No integration events</div>
        )}
      </div>

      {/* Security Command Center */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Security Command Center</h2>
        {securityPosture ? (
          <>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
                <div className={`text-3xl font-bold ${
                  securityPosture.risk_score >= 80 ? 'text-red-400' :
                  securityPosture.risk_score >= 60 ? 'text-orange-400' :
                  securityPosture.risk_score >= 40 ? 'text-yellow-400' :
                  securityPosture.risk_score >= 20 ? 'text-blue-400' :
                  'text-green-400'
                }`}>{securityPosture.risk_score}</div>
                <div className="text-xs text-slate-400 mt-1">Risk Score / 100</div>
                <div className={`text-xs mt-1 px-2 py-0.5 rounded inline-block ${
                  securityPosture.metadata?.risk_label === 'critical' ? 'bg-red-500/20 text-red-400' :
                  securityPosture.metadata?.risk_label === 'poor' ? 'bg-orange-500/20 text-orange-400' :
                  securityPosture.metadata?.risk_label === 'fair' ? 'bg-yellow-500/20 text-yellow-400' :
                  securityPosture.metadata?.risk_label === 'good' ? 'bg-blue-500/20 text-blue-400' :
                  'bg-green-500/20 text-green-400'
                }`}>{securityPosture.metadata?.risk_label?.toUpperCase() || 'N/A'}</div>
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-white">{securityPosture.active_identity_count}</div>
                <div className="text-xs text-slate-400 mt-1">Active Identities</div>
              </div>
            </div>
            <div className="grid grid-cols-4 gap-3">
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
                <div className="text-lg font-bold text-red-400">{securityPosture.incident_count}</div>
                <div className="text-xs text-slate-400">Incidents</div>
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
                <div className="text-lg font-bold text-orange-400">{securityPosture.prediction_count}</div>
                <div className="text-xs text-slate-400">Predictions</div>
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
                <div className="text-lg font-bold text-yellow-400">{securityPosture.governance_violation_count}</div>
                <div className="text-xs text-slate-400">Violations</div>
              </div>
              <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
                <div className="text-lg font-bold text-blue-400">{securityPosture.strategy_recommendation_count}</div>
                <div className="text-xs text-slate-400">Recommendations</div>
              </div>
            </div>
          </>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No security posture data</div>
        )}
      </div>

      {/* Security Strategy Advisor */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Security Strategy Advisor</h2>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-white">{strategyStats?.open ?? 0}</div>
            <div className="text-xs text-slate-400">Open</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-red-400">{strategyStats?.critical ?? 0}</div>
            <div className="text-xs text-slate-400">Critical</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-orange-400">{strategyStats?.high ?? 0}</div>
            <div className="text-xs text-slate-400">High</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-green-400">{strategyStats?.avg_risk_reduction ?? 0}%</div>
            <div className="text-xs text-slate-400">Avg Risk Reduction</div>
          </div>
        </div>
        {strategyRecs.length > 0 ? (
          <div className="space-y-2">
            {strategyRecs.slice(0, 6).map((rec) => (
              <div key={rec.id} className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3">
                <div className="flex items-center justify-between mb-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium ${
                      rec.priority === 'critical' ? 'bg-red-500/20 text-red-400' :
                      rec.priority === 'high' ? 'bg-orange-500/20 text-orange-400' :
                      rec.priority === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                      'bg-slate-500/20 text-slate-400'
                    }`}>{rec.priority}</span>
                    <span className="text-sm font-medium text-white">{rec.title}</span>
                  </div>
                  <span className="text-sm font-bold text-green-400">-{rec.risk_reduction_score}%</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-slate-400">
                  <span>Effort: {rec.implementation_effort}</span>
                  <span>Type: {rec.recommendation_type.replace(/_/g, ' ')}</span>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No strategy recommendations</div>
        )}
      </div>

      {/* Governance Posture */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Governance Posture</h2>
        <div className="grid grid-cols-4 gap-3 mb-4">
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-white">{govMetricStats?.total_metrics ?? 0}</div>
            <div className="text-xs text-slate-400">Metrics Tracked</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-red-400">{govTrendStats?.increasing ?? 0}</div>
            <div className="text-xs text-slate-400">Increasing</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-green-400">{govTrendStats?.decreasing ?? 0}</div>
            <div className="text-xs text-slate-400">Decreasing</div>
          </div>
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 text-center">
            <div className="text-lg font-bold text-yellow-400">{govTrendStats?.stable ?? 0}</div>
            <div className="text-xs text-slate-400">Stable</div>
          </div>
        </div>
        {govMetrics.length > 0 ? (
          <div className="space-y-2">
            {govMetrics.slice(0, 8).map((m) => (
              <div key={m.id} className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-3 flex items-center justify-between">
                <div>
                  <span className="text-sm font-medium text-white">{m.metric_type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase())}</span>
                  <span className="ml-2 text-xs text-slate-400">{m.affected_count}/{m.sample_size} affected</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className={`text-sm font-bold ${m.metric_value > 0.3 ? 'text-red-400' : m.metric_value > 0.15 ? 'text-yellow-400' : 'text-green-400'}`}>
                    {(m.metric_value * 100).toFixed(1)}%
                  </span>
                  {(() => {
                    const trend = govTrendStats?.by_type?.[m.metric_type];
                    if (!trend) return null;
                    const arrow = trend.direction === 'increasing' ? '\u2191' : trend.direction === 'decreasing' ? '\u2193' : '\u2192';
                    const color = trend.direction === 'increasing' ? 'text-red-400' : trend.direction === 'decreasing' ? 'text-green-400' : 'text-yellow-400';
                    return <span className={`text-xs ${color}`}>{arrow} {Math.abs(trend.change_pct).toFixed(1)}%</span>;
                  })()}
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4 text-center text-sm text-slate-500">No governance metrics</div>
        )}
      </div>

      {/* Security Copilot */}
      <div>
        <h2 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">Security Copilot</h2>
        <div className="bg-slate-800/50 border border-slate-700/50 rounded-lg p-4">
          <div className="flex gap-2 mb-4">
            <input
              type="text"
              value={copilotQuery}
              onChange={(e) => setCopilotQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleCopilotSubmit()}
              placeholder="Ask about your security posture..."
              className="flex-1 bg-slate-900/50 border border-slate-600 rounded px-3 py-2 text-sm text-white placeholder-slate-500 focus:outline-none focus:border-blue-500"
            />
            <button
              onClick={() => handleCopilotSubmit()}
              disabled={copilotLoading || !copilotQuery.trim()}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 disabled:bg-slate-700 disabled:text-slate-500 text-white text-sm rounded transition-colors"
            >
              {copilotLoading ? 'Thinking...' : 'Ask'}
            </button>
          </div>
          {copilotResponse ? (
            <div>
              <div className="bg-slate-900/50 rounded p-3 mb-3">
                <pre className="text-sm text-slate-200 whitespace-pre-wrap font-sans">{copilotResponse.answer}</pre>
              </div>
              {copilotResponse.suggestions.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {copilotResponse.suggestions.map((s, i) => (
                    <button
                      key={i}
                      onClick={() => { setCopilotQuery(s); handleCopilotSubmit(s); }}
                      className="text-xs px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-full transition-colors"
                    >
                      {s}
                    </button>
                  ))}
                </div>
              )}
            </div>
          ) : (
            <div className="text-center text-sm text-slate-500">
              <p>Ask questions like:</p>
              <div className="flex flex-wrap gap-2 justify-center mt-2">
                {['Which identities are most dangerous?', 'Show open incidents', 'What is the security posture trend?'].map((s, i) => (
                  <button
                    key={i}
                    onClick={() => { setCopilotQuery(s); handleCopilotSubmit(s); }}
                    className="text-xs px-3 py-1 bg-slate-700 hover:bg-slate-600 text-slate-300 rounded-full transition-colors"
                  >
                    {s}
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default SecurityDashboard;
