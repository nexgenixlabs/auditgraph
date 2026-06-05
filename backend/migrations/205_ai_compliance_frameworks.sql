-- AG-T1.2: AI-specific compliance frameworks.
--
-- Adds NIST AI RMF 1.0, ISO/IEC 42001:2023, EU AI Act (Reg 2024/1689)
-- to the existing compliance_frameworks catalog. Each framework gets
-- a tightly curated set of controls mapped to REAL AuditGraph signals
-- (added to _compute_compliance_metrics() in handlers.py).
--
-- Design rules
-- ────────────
-- 1. Real clause IDs only (GV-1.1, A.5.1, Article 9) — sourced from
--    public catalogs. No invented control numbers.
-- 2. Every control's `metric` field maps to a key in the metrics dict
--    returned by _compute_compliance_metrics(). Bad metric name = the
--    engine returns 0 = false pass; we don't want that.
-- 3. Pillar field groups controls semantically (governance / data /
--    risk / transparency / oversight) so the UI can collapse them.
-- 4. Drilldown URLs point at REAL pages in the app — Identity Explorer
--    with filters, AI Inventory views, Data Reachability.
-- 5. Idempotent: ON CONFLICT DO UPDATE so repeated runs are safe.

\set ON_ERROR_STOP on

BEGIN;

-- ============================================================
-- 1. FRAMEWORKS — register the 3 new catalogs
-- ============================================================
INSERT INTO compliance_frameworks
    (key, name, short_name, description, version, enabled, display_order,
     tier, category, identity_controls_count, total_framework_controls, scope_label)
VALUES
    ('nist_ai_rmf', 'NIST AI Risk Management Framework', 'NIST AI RMF',
     'NIST AI RMF 1.0 — voluntary framework for managing risks to individuals, organizations, and society from AI systems. Four functions: Govern, Map, Measure, Manage.',
     '1.0 (2023)', TRUE, 80, 'ai', 'AI Governance', 10, 72,
     'AI agent governance, ownership, and risk controls'),

    ('iso_42001', 'ISO/IEC 42001:2023', 'ISO 42001',
     'International standard for AI Management Systems (AIMS). Defines requirements for establishing, implementing, maintaining, and continually improving an AIMS within an organization.',
     '2023', TRUE, 85, 'ai', 'AI Governance', 10, 38,
     'AI agent governance, ownership, and risk controls'),

    ('eu_ai_act', 'EU AI Act', 'EU AI Act',
     'Regulation (EU) 2024/1689 — risk-based regulation of AI systems in the European Union. High-risk AI systems must meet requirements for risk management, data governance, transparency, human oversight, and robustness.',
     'Regulation (EU) 2024/1689', TRUE, 90, 'ai', 'AI Governance', 10, 25,
     'AI agent governance, ownership, and risk controls')
ON CONFLICT (key) DO UPDATE SET
    name = EXCLUDED.name,
    short_name = EXCLUDED.short_name,
    description = EXCLUDED.description,
    version = EXCLUDED.version,
    enabled = TRUE,
    display_order = EXCLUDED.display_order,
    tier = EXCLUDED.tier,
    category = EXCLUDED.category,
    identity_controls_count = EXCLUDED.identity_controls_count,
    total_framework_controls = EXCLUDED.total_framework_controls,
    scope_label = EXCLUDED.scope_label;

-- ============================================================
-- 2. CONTROLS — 10 per framework, mapped to real AuditGraph metrics
-- ============================================================

-- ─── NIST AI RMF 1.0 ─────────────────────────────────────────────
-- Functions: GOVERN, MAP, MEASURE, MANAGE
WITH fw AS (SELECT id FROM compliance_frameworks WHERE key = 'nist_ai_rmf')
INSERT INTO compliance_controls
    (framework_id, control_id, name, description, metric,
     pass_operator, pass_value, warn_operator, warn_value,
     drilldown_url, display_order, severity, weight, cloud, pillar)
SELECT fw.id, c.control_id, c.name, c.description, c.metric,
       c.pass_op, c.pass_val, c.warn_op, c.warn_val,
       c.drill, c.disp, c.sev, c.wt, 'azure', c.pillar
FROM fw, (VALUES
    ('GV-1.1', 'AI Agent Ownership Accountability',
     'Legal and regulatory requirements involving AI are understood, managed, and documented. Every autonomous AI agent must have a documented human owner accountable for its behavior.',
     'ai_agents_no_owner', '==', 0, '<=', 1,
     '/ai-inventory/graph?filter=no_owner', 10, 'high', 8, 'governance'),

    ('GV-3.2', 'AI Agent Inventory Completeness',
     'Decision-making related to AI risks is informed by an inventory of all AI systems including ownership, purpose, and risk classification. AuditGraph maintains the inventory automatically.',
     'ai_agents_total', '>=', 1, NULL, NULL,
     '/ai-inventory/graph', 20, 'medium', 5, 'governance'),

    ('MP-2.3', 'AI Agent Scope of Deployment',
     'Scientific integrity and TEVV considerations are documented. Production AI agents should not hold subscription-wide Owner or Contributor — scope must be least-privilege per intended use.',
     'ai_agents_with_subscription_owner', '==', 0, '<=', 1,
     '/ai-attack-paths?type=sub_owner_ai', 30, 'critical', 9, 'privilege'),

    ('MP-5.1', 'AI Agent Data Reachability — Sensitive Data',
     'Likely impacts of AI systems on individuals and groups are characterized. AI agents reaching PHI must be documented and access reviewed.',
     'ai_agents_reaching_phi', '==', 0, '<=', 2,
     '/ai-access/data-reachability?class=PHI', 40, 'critical', 9, 'data'),

    ('MS-2.1', 'AI Agent Risk Measurement',
     'Risks and benefits from AI are identified and measured. Track count of high/critical-risk AI agents.',
     'ai_high_risk_agents', '<=', 1, '<=', 3,
     '/ai-inventory/graph?risk=critical,high', 50, 'high', 7, 'risk'),

    ('MS-2.7', 'AI Agent Secrets Access — Privilege Containment',
     'Security and resilience of AI systems are measured. AI agents with KV Administrator role can exfiltrate entire secret stores under prompt-injection compromise.',
     'ai_agents_with_kv_admin', '==', 0, '<=', 1,
     '/ai-attack-paths?type=ai_agent_secret_exfil', 60, 'critical', 9, 'privilege'),

    ('MS-3.3', 'AI Agent Data Write Containment',
     'Pre-deployment testing is performed. AI agents holding Storage Blob Data Owner can write to data planes — material risk under compromise.',
     'ai_agents_with_blob_owner', '==', 0, '<=', 1,
     '/ai-attack-paths?type=ai_agent_data_exfil', 70, 'critical', 9, 'data'),

    ('MG-1.2', 'AI Agent Lifecycle Drift Resolution',
     'AI risks are tracked and managed over time. Privilege escalations and ownership changes must be triaged.',
     'ai_lifecycle_events_unresolved', '==', 0, '<=', 3,
     '/ai-lifecycle?resolved=false', 80, 'high', 7, 'governance'),

    ('MG-3.1', 'AI Agent Observability',
     'AI risk management activities are documented and tracked. Agents with zero recent telemetry cannot be monitored for drift.',
     'ai_agents_no_telemetry', '<=', 0, '<=', 2,
     '/ai-runtime/activity?filter=no_telemetry', 90, 'medium', 5, 'oversight'),

    ('MG-4.3', 'AI Model Provenance Verification',
     'Risks of third-party AI components are managed. Custom or fine-tuned models must be approved before deployment to production.',
     'ai_models_unverified', '==', 0, '<=', 2,
     '/ai-runtime', 100, 'medium', 6, 'supply_chain')
) AS c(control_id, name, description, metric, pass_op, pass_val, warn_op, warn_val, drill, disp, sev, wt, pillar)
ON CONFLICT (framework_id, control_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    metric = EXCLUDED.metric,
    pass_operator = EXCLUDED.pass_operator,
    pass_value = EXCLUDED.pass_value,
    warn_operator = EXCLUDED.warn_operator,
    warn_value = EXCLUDED.warn_value,
    drilldown_url = EXCLUDED.drilldown_url,
    display_order = EXCLUDED.display_order,
    severity = EXCLUDED.severity,
    weight = EXCLUDED.weight,
    pillar = EXCLUDED.pillar;


-- ─── ISO/IEC 42001:2023 ──────────────────────────────────────────
WITH fw AS (SELECT id FROM compliance_frameworks WHERE key = 'iso_42001')
INSERT INTO compliance_controls
    (framework_id, control_id, name, description, metric,
     pass_operator, pass_value, warn_operator, warn_value,
     drilldown_url, display_order, severity, weight, cloud, pillar)
SELECT fw.id, c.control_id, c.name, c.description, c.metric,
       c.pass_op, c.pass_val, c.warn_op, c.warn_val,
       c.drill, c.disp, c.sev, c.wt, 'azure', c.pillar
FROM fw, (VALUES
    ('5.3', 'Roles, Responsibilities, and Authorities',
     'Top management shall ensure that responsibilities and authorities for relevant roles related to AI are assigned and communicated. Every AI agent requires a designated owner.',
     'ai_agents_no_owner', '==', 0, '<=', 1,
     '/ai-inventory/graph?filter=no_owner', 10, 'high', 8, 'governance'),

    ('6.1.2', 'AI Risk Assessment',
     'The organization shall define and apply an AI risk assessment process. High/critical risk AI agents must be triaged.',
     'ai_high_risk_agents', '<=', 1, '<=', 3,
     '/ai-inventory/graph?risk=critical,high', 20, 'high', 7, 'risk'),

    ('8.3', 'AI Risk Treatment',
     'The organization shall implement controls necessary to mitigate identified AI risks. Privilege containment is the primary identity-side control.',
     'ai_agents_with_subscription_owner', '==', 0, '<=', 1,
     '/ai-attack-paths?type=sub_owner_ai', 30, 'critical', 9, 'privilege'),

    ('A.5.1', 'AI Use Case Inventory',
     'Information about each AI system shall be documented. AuditGraph auto-inventories Azure-resident AI agents.',
     'ai_agents_total', '>=', 1, NULL, NULL,
     '/ai-inventory/graph', 40, 'medium', 5, 'governance'),

    ('A.6.2.3', 'Access to AI Resources',
     'Access to AI systems shall be controlled. AI agents with KV Administrator scope violate least-privilege.',
     'ai_agents_with_kv_admin', '==', 0, '<=', 1,
     '/ai-attack-paths?type=ai_agent_secret_exfil', 50, 'critical', 9, 'privilege'),

    ('A.7.2', 'Data Quality and Provenance',
     'Data used by the AI system shall meet quality requirements. AI agents reaching PHI must be documented and access reviewed.',
     'ai_agents_reaching_phi', '==', 0, '<=', 2,
     '/ai-access/data-reachability?class=PHI', 60, 'critical', 9, 'data'),

    ('A.7.3', 'Sensitive Data Containment',
     'AI processing of personal data shall be controlled. PII reachability requires DPIA + lawful basis documentation.',
     'ai_agents_reaching_pii', '<=', 1, '<=', 3,
     '/ai-access/data-reachability?class=PII', 70, 'high', 7, 'data'),

    ('A.8.4', 'AI System Performance Monitoring',
     'AI system performance shall be monitored. Agents with no observed runtime activity cannot be monitored.',
     'ai_agents_no_telemetry', '<=', 0, '<=', 2,
     '/ai-runtime/activity?filter=no_telemetry', 80, 'medium', 5, 'oversight'),

    ('A.9.2', 'Third-Party AI Component Management',
     'Risks of using third-party AI components shall be managed. Custom and fine-tuned models must be approved.',
     'ai_models_unverified', '==', 0, '<=', 2,
     '/ai-runtime', 90, 'medium', 6, 'supply_chain'),

    ('A.10.3', 'AI System Change Management',
     'Changes to AI systems shall be controlled and documented. Privilege escalations must be reviewed.',
     'ai_lifecycle_events_unresolved', '==', 0, '<=', 3,
     '/ai-lifecycle?resolved=false', 100, 'high', 7, 'governance')
) AS c(control_id, name, description, metric, pass_op, pass_val, warn_op, warn_val, drill, disp, sev, wt, pillar)
ON CONFLICT (framework_id, control_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    metric = EXCLUDED.metric,
    pass_operator = EXCLUDED.pass_operator,
    pass_value = EXCLUDED.pass_value,
    warn_operator = EXCLUDED.warn_operator,
    warn_value = EXCLUDED.warn_value,
    drilldown_url = EXCLUDED.drilldown_url,
    display_order = EXCLUDED.display_order,
    severity = EXCLUDED.severity,
    weight = EXCLUDED.weight,
    pillar = EXCLUDED.pillar;


-- ─── EU AI Act (Regulation 2024/1689) ────────────────────────────
WITH fw AS (SELECT id FROM compliance_frameworks WHERE key = 'eu_ai_act')
INSERT INTO compliance_controls
    (framework_id, control_id, name, description, metric,
     pass_operator, pass_value, warn_operator, warn_value,
     drilldown_url, display_order, severity, weight, cloud, pillar)
SELECT fw.id, c.control_id, c.name, c.description, c.metric,
       c.pass_op, c.pass_val, c.warn_op, c.warn_val,
       c.drill, c.disp, c.sev, c.wt, 'azure', c.pillar
FROM fw, (VALUES
    ('Art 9.1', 'Risk Management System',
     'Providers of high-risk AI systems shall establish, implement, document, and maintain a risk management system. Track high/critical risk AI agents.',
     'ai_high_risk_agents', '<=', 1, '<=', 3,
     '/ai-inventory/graph?risk=critical,high', 10, 'critical', 9, 'risk'),

    ('Art 10.2', 'Data Governance — Training & Validation',
     'Training, validation, and testing data sets shall be relevant, representative, free of errors, and complete. Reachability to PHI must be controlled.',
     'ai_agents_reaching_phi', '==', 0, '<=', 1,
     '/ai-access/data-reachability?class=PHI', 20, 'critical', 9, 'data'),

    ('Art 10.5', 'Personal Data Processing',
     'Processing of special categories of personal data shall be subject to appropriate safeguards. PII reachability is a primary signal.',
     'ai_agents_reaching_pii', '<=', 1, '<=', 3,
     '/ai-access/data-reachability?class=PII', 30, 'high', 8, 'data'),

    ('Art 12.1', 'Record-keeping',
     'High-risk AI systems shall be designed with capabilities for automatic recording of events (logs). Agents with zero telemetry breach this requirement.',
     'ai_agents_no_telemetry', '<=', 0, '<=', 2,
     '/ai-runtime/activity?filter=no_telemetry', 40, 'high', 7, 'oversight'),

    ('Art 14.1', 'Human Oversight',
     'High-risk AI systems shall be designed to be effectively overseen by natural persons. Every AI agent requires a designated human owner.',
     'ai_agents_no_owner', '==', 0, '<=', 1,
     '/ai-inventory/graph?filter=no_owner', 50, 'critical', 9, 'oversight'),

    ('Art 15.1', 'Accuracy, Robustness, and Cybersecurity',
     'High-risk AI systems shall achieve an appropriate level of accuracy, robustness, and cybersecurity. Containment of secret-store access is a primary cyber control.',
     'ai_agents_with_kv_admin', '==', 0, '<=', 1,
     '/ai-attack-paths?type=ai_agent_secret_exfil', 60, 'critical', 9, 'privilege'),

    ('Art 15.4', 'Public Network Exposure',
     'AI systems shall be designed with cybersecurity controls including resilience to attempts to alter use, behavior, or performance. Public network endpoints expand the attack surface.',
     'ai_agents_public_endpoint', '==', 0, '<=', 1,
     '/ai-runtime?network=public', 70, 'high', 8, 'network'),

    ('Art 17.1', 'Quality Management System — AI Operations',
     'Providers shall put a quality management system in place. Unresolved drift events break the QMS audit trail.',
     'ai_lifecycle_events_unresolved', '==', 0, '<=', 3,
     '/ai-lifecycle?resolved=false', 80, 'high', 7, 'governance'),

    ('Art 25', 'AI Provider Obligations — Inventory',
     'AI providers shall maintain documentation enabling competent authorities to assess conformity. AuditGraph maintains the inventory.',
     'ai_agents_total', '>=', 1, NULL, NULL,
     '/ai-inventory/graph', 90, 'medium', 5, 'governance'),

    ('Art 26.5', 'Deployer Obligations — Containment',
     'Deployers shall implement appropriate technical and organizational measures. Subscription-wide AI agent access violates these.',
     'ai_agents_with_subscription_owner', '==', 0, '<=', 1,
     '/ai-attack-paths?type=sub_owner_ai', 100, 'critical', 9, 'privilege')
) AS c(control_id, name, description, metric, pass_op, pass_val, warn_op, warn_val, drill, disp, sev, wt, pillar)
ON CONFLICT (framework_id, control_id) DO UPDATE SET
    name = EXCLUDED.name,
    description = EXCLUDED.description,
    metric = EXCLUDED.metric,
    pass_operator = EXCLUDED.pass_operator,
    pass_value = EXCLUDED.pass_value,
    warn_operator = EXCLUDED.warn_operator,
    warn_value = EXCLUDED.warn_value,
    drilldown_url = EXCLUDED.drilldown_url,
    display_order = EXCLUDED.display_order,
    severity = EXCLUDED.severity,
    weight = EXCLUDED.weight,
    pillar = EXCLUDED.pillar;

COMMIT;

\echo ''
\echo '=== AI frameworks loaded ==='
SELECT key, name, version, enabled,
       (SELECT count(*) FROM compliance_controls WHERE framework_id = compliance_frameworks.id) AS controls
FROM compliance_frameworks
WHERE key IN ('nist_ai_rmf', 'iso_42001', 'eu_ai_act')
ORDER BY display_order;
