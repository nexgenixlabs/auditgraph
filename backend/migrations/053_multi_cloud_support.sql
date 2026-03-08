-- Migration 053: Multi-Cloud Identity Support
-- Phase 17: Extend graph model for AWS/GCP + add cloud-specific risk rules

-- Extend graph_nodes to support multi-cloud node types
ALTER TABLE graph_nodes DROP CONSTRAINT IF EXISTS graph_nodes_node_type_check;
ALTER TABLE graph_nodes ADD CONSTRAINT graph_nodes_node_type_check
    CHECK (node_type IN (
        'identity', 'role', 'resource', 'subscription',
        'aws_user', 'aws_role', 'gcp_service_account', 'gcp_project'
    ));

-- Extend graph_edges to support multi-cloud edge types
ALTER TABLE graph_edges DROP CONSTRAINT IF EXISTS graph_edges_edge_type_check;
ALTER TABLE graph_edges ADD CONSTRAINT graph_edges_edge_type_check
    CHECK (edge_type IN (
        'assigned_role', 'grants_access', 'contains_resource',
        'escalation_path', 'policy_attachment', 'role_binding'
    ));

-- Seed 4 cloud-specific risk rules
INSERT INTO risk_rules (rule_key, rule_name, description, severity, rule_type) VALUES
    ('aws_access_key_stale', 'AWS Access Key Older Than 90 Days', 'AWS IAM user with access key older than 90 days', 'high', 'credential'),
    ('aws_user_admin_policy', 'AWS IAM User with Admin Policy', 'AWS IAM user with AdministratorAccess or equivalent attached', 'critical', 'access'),
    ('gcp_sa_key_exposure', 'GCP Service Account Key Exposure', 'GCP service account with user-managed keys (potential key exposure)', 'high', 'credential'),
    ('gcp_owner_on_project', 'GCP Owner Role on Project', 'Identity with Owner role binding on a GCP project', 'critical', 'access')
ON CONFLICT (rule_key) DO NOTHING;
