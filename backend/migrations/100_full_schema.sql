-- Auto-generated comprehensive schema (from localhost dump)
-- All statements use IF NOT EXISTS — safe to run on every startup.

CREATE TABLE IF NOT EXISTS access_review_campaigns (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    scope_filters jsonb DEFAULT '{}'::jsonb NOT NULL,
    deadline timestamp with time zone,
    created_by integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    organization_id integer,
    campaign_type character varying(100) DEFAULT 'general'::character varying,
    scope_clouds text[],
    scope_description character varying(500),
    risk_focus character varying(100)
);

CREATE TABLE IF NOT EXISTS access_reviews (
    id integer NOT NULL,
    review_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer NOT NULL,
    title text NOT NULL,
    description text,
    review_type character varying(30) DEFAULT 'manual'::character varying NOT NULL,
    scope character varying(30) DEFAULT 'privileged'::character varying NOT NULL,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    created_by character varying(100),
    created_by_user_id integer,
    total_assignments integer DEFAULT 0 NOT NULL,
    completed_assignments integer DEFAULT 0 NOT NULL,
    approved_count integer DEFAULT 0 NOT NULL,
    revoked_count integer DEFAULT 0 NOT NULL,
    flagged_count integer DEFAULT 0 NOT NULL,
    due_date timestamp with time zone,
    completed_at timestamp with time zone,
    completed_by character varying(100),
    compliance_frameworks jsonb DEFAULT '[]'::jsonb,
    settings jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    review_outcome text,
    review_duration_hours integer
);

CREATE TABLE IF NOT EXISTS activity_log (
    id integer NOT NULL,
    action_type character varying(50) NOT NULL,
    description text NOT NULL,
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    user_id integer,
    organization_id integer,
    integrity_hash character varying(64)
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
    id integer NOT NULL,
    admin_user_id integer,
    action text NOT NULL,
    target_user_id integer,
    target_organization_id integer,
    details jsonb DEFAULT '{}'::jsonb,
    ip_address text,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS agirs_scores (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    run_id integer,
    agirs_score numeric(5,2),
    hiri_score numeric(5,2),
    nhiri_score numeric(5,2),
    gei_score numeric(5,2),
    hiri_breakdown jsonb,
    nhiri_breakdown jsonb,
    gei_breakdown jsonb,
    dangerous_identities jsonb,
    human_count integer,
    nhi_count integer,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS anomalies (
    id integer NOT NULL,
    discovery_run_id integer,
    anomaly_type character varying(50) NOT NULL,
    severity character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    identity_id text,
    identity_name character varying(255),
    title character varying(255) NOT NULL,
    description text NOT NULL,
    details jsonb,
    resolved boolean DEFAULT false,
    resolved_at timestamp with time zone,
    resolved_by character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS api_keys (
    id integer NOT NULL,
    key_prefix character varying(12) NOT NULL,
    key_hash character varying(64) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    role character varying(20) DEFAULT 'viewer'::character varying NOT NULL,
    enabled boolean DEFAULT true,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    last_used_at timestamp with time zone,
    expires_at timestamp with time zone,
    usage_count integer DEFAULT 0 NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS app_reg_exposure_findings (
    id integer NOT NULL,
    app_reg_id bigint NOT NULL,
    discovery_run_id bigint,
    finding_type character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    title text NOT NULL,
    description text,
    evidence jsonb DEFAULT '{}'::jsonb,
    remediation text,
    component character varying(30),
    score_impact integer DEFAULT 0,
    organization_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS app_registrations (
    id integer NOT NULL,
    discovery_run_id integer NOT NULL,
    app_object_id text NOT NULL,
    app_id text NOT NULL,
    display_name text NOT NULL,
    created_datetime timestamp with time zone,
    sign_in_audience text,
    publisher_domain text,
    app_owner_organization_id text,
    is_third_party boolean DEFAULT false,
    required_permissions jsonb DEFAULT '[]'::jsonb,
    permission_count integer DEFAULT 0,
    application_permission_count integer DEFAULT 0,
    delegated_permission_count integer DEFAULT 0,
    high_risk_permissions text[] DEFAULT '{}'::text[],
    secret_count integer DEFAULT 0,
    certificate_count integer DEFAULT 0,
    credential_details jsonb DEFAULT '[]'::jsonb,
    next_expiry timestamp with time zone,
    has_expired_credential boolean DEFAULT false,
    has_expiring_soon boolean DEFAULT false,
    owner_count integer DEFAULT 0,
    owners jsonb DEFAULT '[]'::jsonb,
    primary_owner text,
    has_service_principal boolean DEFAULT false,
    linked_spn_id integer,
    spn_last_sign_in timestamp with time zone,
    spn_activity_status text,
    redirect_uris jsonb DEFAULT '[]'::jsonb,
    redirect_uri_count integer DEFAULT 0,
    has_localhost_redirect boolean DEFAULT false,
    has_http_redirect boolean DEFAULT false,
    risk_level text DEFAULT 'info'::text,
    risk_score integer DEFAULT 0,
    risk_reasons jsonb DEFAULT '[]'::jsonb,
    approval_status text DEFAULT 'unknown'::text,
    organization_id integer,
    created_at timestamp with time zone DEFAULT now(),
    exposure_score integer DEFAULT 0,
    exposure_components jsonb DEFAULT '{}'::jsonb,
    privilege_score integer DEFAULT 0,
    credential_risk_score integer DEFAULT 0,
    exposure_subscore integer DEFAULT 0,
    lifecycle_score integer DEFAULT 0,
    visibility_score integer DEFAULT 0,
    activity_confidence integer DEFAULT 0,
    lifecycle_state character varying(20) DEFAULT 'blind'::character varying,
    can_escalate boolean DEFAULT false,
    effective_scope_flag character varying(30) DEFAULT 'resource'::character varying,
    credential_age_days integer DEFAULT 0,
    owner_status character varying(20) DEFAULT 'unknown'::character varying,
    federated_trust boolean DEFAULT false,
    cross_subscription boolean DEFAULT false,
    exposure_computed_at timestamp without time zone,
    critical_exposure_overrides jsonb DEFAULT '[]'::jsonb
);

CREATE TABLE IF NOT EXISTS attack_paths (
    id integer NOT NULL,
    path_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer NOT NULL,
    discovery_run_id integer,
    source_entity_id text NOT NULL,
    source_entity_name text,
    source_entity_type character varying(30),
    path_type character varying(60) NOT NULL,
    risk_score integer DEFAULT 0 NOT NULL,
    severity character varying(20) DEFAULT 'medium'::character varying NOT NULL,
    path_nodes jsonb DEFAULT '[]'::jsonb NOT NULL,
    description text NOT NULL,
    narrative text,
    impact text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    path_fingerprint text,
    first_detected_at timestamp with time zone DEFAULT now() NOT NULL,
    last_detected_at timestamp with time zone DEFAULT now() NOT NULL,
    occurrence_count integer DEFAULT 1 NOT NULL,
    last_seen_run_id integer,
    affected_resource_count integer DEFAULT 0 NOT NULL
);

CREATE TABLE IF NOT EXISTS azure_key_vaults (
    id integer NOT NULL,
    discovery_run_id integer NOT NULL,
    resource_id text NOT NULL,
    name text NOT NULL,
    location text,
    resource_group text,
    subscription_id text,
    subscription_name text,
    sku text,
    soft_delete_enabled boolean DEFAULT false,
    soft_delete_retention_days integer DEFAULT 0,
    purge_protection boolean DEFAULT false,
    enable_rbac_authorization boolean DEFAULT false,
    public_network_access text DEFAULT 'Enabled'::text,
    default_network_action text DEFAULT 'Allow'::text,
    ip_rules_count integer DEFAULT 0,
    vnet_rules_count integer DEFAULT 0,
    private_endpoint_count integer DEFAULT 0,
    network_rules jsonb DEFAULT '{}'::jsonb,
    secrets_total integer DEFAULT 0,
    secrets_expired integer DEFAULT 0,
    secrets_expiring_soon integer DEFAULT 0,
    keys_total integer DEFAULT 0,
    keys_expired integer DEFAULT 0,
    keys_expiring_soon integer DEFAULT 0,
    certs_total integer DEFAULT 0,
    certs_expired integer DEFAULT 0,
    certs_expiring_soon integer DEFAULT 0,
    access_policy_count integer DEFAULT 0,
    access_policies jsonb DEFAULT '[]'::jsonb,
    secrets_detail jsonb DEFAULT '[]'::jsonb,
    keys_detail jsonb DEFAULT '[]'::jsonb,
    certs_detail jsonb DEFAULT '[]'::jsonb,
    risk_level text DEFAULT 'info'::text,
    risk_score integer DEFAULT 0,
    risk_reasons jsonb DEFAULT '[]'::jsonb,
    tags jsonb DEFAULT '{}'::jsonb,
    organization_id integer,
    created_at timestamp with time zone DEFAULT now(),
    risk_components jsonb DEFAULT '{}'::jsonb,
    blast_radius_score integer DEFAULT 0,
    critical_overrides jsonb DEFAULT '[]'::jsonb,
    data_classification character varying(20),
    classification_source character varying(20),
    classification_confidence character varying(10),
    classified_by character varying(100),
    classified_at timestamp with time zone,
    classification_notes text
);

CREATE TABLE IF NOT EXISTS azure_storage_accounts (
    id integer NOT NULL,
    discovery_run_id integer NOT NULL,
    resource_id text NOT NULL,
    name text NOT NULL,
    location text,
    resource_group text,
    subscription_id text,
    subscription_name text,
    sku text,
    kind text,
    access_tier text,
    public_blob_access boolean DEFAULT false,
    https_only boolean DEFAULT true,
    minimum_tls_version text DEFAULT 'TLS1_2'::text,
    shared_key_access boolean DEFAULT true,
    allow_cross_tenant_replication boolean DEFAULT false,
    default_network_action text DEFAULT 'Allow'::text,
    ip_rules_count integer DEFAULT 0,
    vnet_rules_count integer DEFAULT 0,
    private_endpoint_count integer DEFAULT 0,
    bypass_settings text,
    network_rules jsonb DEFAULT '{}'::jsonb,
    infrastructure_encryption boolean DEFAULT false,
    customer_managed_keys boolean DEFAULT false,
    key_vault_uri text,
    encryption_details jsonb DEFAULT '{}'::jsonb,
    key1_created_at timestamp with time zone,
    key2_created_at timestamp with time zone,
    key_rotation_stale boolean DEFAULT false,
    sas_policy_enabled boolean,
    sas_expiration_period text,
    risk_level text DEFAULT 'info'::text,
    risk_score integer DEFAULT 0,
    risk_reasons jsonb DEFAULT '[]'::jsonb,
    tags jsonb DEFAULT '{}'::jsonb,
    organization_id integer,
    created_at timestamp with time zone DEFAULT now(),
    diagnostic_logging_enabled boolean,
    logging_destinations jsonb DEFAULT '[]'::jsonb,
    risk_components jsonb DEFAULT '{}'::jsonb,
    blast_radius_score integer DEFAULT 0,
    critical_overrides jsonb DEFAULT '[]'::jsonb,
    data_classification character varying(20),
    classification_source character varying(20),
    classification_confidence character varying(10),
    classified_by character varying(100),
    classified_at timestamp with time zone,
    classification_notes text
);

CREATE TABLE IF NOT EXISTS billing_audit_log (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    action character varying(50) NOT NULL,
    actor_id integer,
    details jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS billing_events (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    event_type character varying(50) NOT NULL,
    field_changed character varying(50),
    old_value text,
    new_value text,
    changed_by integer,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS blast_radius_results (
    id integer NOT NULL,
    result_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer NOT NULL,
    identity_id integer NOT NULL,
    identity_name text,
    identity_type text,
    discovery_run_id integer,
    reachable_resource_count integer DEFAULT 0 NOT NULL,
    reachable_subscription_count integer DEFAULT 0 NOT NULL,
    reachable_resource_group_count integer DEFAULT 0 NOT NULL,
    sensitive_resource_count integer DEFAULT 0 NOT NULL,
    sensitive_data_types jsonb DEFAULT '[]'::jsonb,
    resource_breakdown jsonb DEFAULT '{}'::jsonb,
    privilege_escalation_paths integer DEFAULT 0 NOT NULL,
    risk_domain text DEFAULT 'identity'::text NOT NULL,
    identity_exposure_level text DEFAULT 'LOW'::text NOT NULL,
    blast_radius_reduction integer DEFAULT 0 NOT NULL,
    remediation_confidence text,
    risk_score integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS ca_identity_coverage (
    id integer NOT NULL,
    identity_db_id integer NOT NULL,
    coverage_status text NOT NULL,
    mfa_enforced boolean DEFAULT false,
    applicable_policy_count integer DEFAULT 0,
    excluded_from_count integer DEFAULT 0,
    risk_flags jsonb DEFAULT '[]'::jsonb,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS ca_policies (
    id integer NOT NULL,
    discovery_run_id integer NOT NULL,
    policy_id text NOT NULL,
    display_name text NOT NULL,
    state text NOT NULL,
    include_users jsonb DEFAULT '[]'::jsonb,
    exclude_users jsonb DEFAULT '[]'::jsonb,
    include_applications jsonb DEFAULT '[]'::jsonb,
    client_app_types jsonb DEFAULT '[]'::jsonb,
    grant_controls jsonb DEFAULT '{}'::jsonb,
    session_controls jsonb DEFAULT '{}'::jsonb,
    requires_mfa boolean DEFAULT false,
    targets_all_users boolean DEFAULT false,
    has_exclusions boolean DEFAULT false,
    allows_legacy_auth boolean DEFAULT false,
    modified_datetime timestamp with time zone,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS campaign_audit_log (
    id integer NOT NULL,
    campaign_id integer NOT NULL,
    review_id integer,
    action character varying(100) NOT NULL,
    actor_id integer,
    old_value text,
    new_value text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS campaign_reviews (
    id integer NOT NULL,
    campaign_id integer NOT NULL,
    identity_id text NOT NULL,
    identity_display_name text,
    identity_risk_level character varying(20),
    identity_category character varying(100),
    reviewer_id integer,
    decision character varying(20),
    notes text,
    decided_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    identity_db_id integer,
    identity_type character varying(100),
    access_role character varying(255),
    access_scope character varying(500),
    cloud_provider character varying(50),
    risk_score integer,
    risk_factors jsonb DEFAULT '[]'::jsonb,
    last_used_date timestamp with time zone,
    last_used_days integer,
    privilege_level character varying(50),
    credential_risk character varying(255),
    credential_risk_level character varying(50),
    ai_recommendation character varying(100),
    ai_recommendation_reason text,
    decision_by integer,
    review_due_date timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS cloud_connections (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    cloud character varying(20) DEFAULT 'azure'::character varying NOT NULL,
    connection_type character varying(30) DEFAULT 'entra'::character varying NOT NULL,
    label character varying(255) NOT NULL,
    azure_directory_id character varying(100),
    client_id character varying(100),
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    display_order integer DEFAULT 0 NOT NULL,
    last_test_at timestamp with time zone,
    last_test_status character varying(20),
    last_discovery_at timestamp with time zone,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    external_id character varying(500),
    discovered_count integer DEFAULT 0
);

CREATE TABLE IF NOT EXISTS cloud_subscriptions (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    cloud character varying(20) NOT NULL,
    account_id character varying(255) NOT NULL,
    account_name character varying(500),
    status character varying(20) DEFAULT 'discovered'::character varying,
    monitored boolean DEFAULT false,
    activated_at timestamp with time zone,
    activated_by integer,
    created_at timestamp with time zone DEFAULT now(),
    rate_cents integer DEFAULT 6900 NOT NULL,
    discovered_at timestamp with time zone DEFAULT now(),
    cloud_connection_id integer NOT NULL,
    deleted boolean DEFAULT false,
    deleted_at timestamp with time zone,
    stripe_subscription_item_id character varying(100)
);

CREATE TABLE IF NOT EXISTS compliance_controls (
    id integer NOT NULL,
    framework_id integer NOT NULL,
    control_id character varying(50) NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    metric character varying(50) NOT NULL,
    pass_operator character varying(10) NOT NULL,
    pass_value numeric NOT NULL,
    warn_operator character varying(10),
    warn_value numeric,
    drilldown_url character varying(255),
    display_order integer DEFAULT 100,
    severity character varying(20) DEFAULT 'medium'::character varying,
    weight integer DEFAULT 5,
    cloud character varying(20) DEFAULT 'azure'::character varying,
    pillar character varying(50),
    root_cause_id integer
);

CREATE TABLE IF NOT EXISTS compliance_frameworks (
    id integer NOT NULL,
    key character varying(50) NOT NULL,
    name character varying(100) NOT NULL,
    description text,
    version character varying(50),
    enabled boolean DEFAULT true,
    display_order integer DEFAULT 100,
    created_at timestamp with time zone DEFAULT now(),
    tier character varying(20) DEFAULT 'core'::character varying,
    category character varying(50),
    short_name character varying(30),
    identity_controls_count integer DEFAULT 0,
    total_framework_controls integer DEFAULT 0,
    scope_label character varying(255) DEFAULT 'Identity, access, and privilege controls'::character varying
);

CREATE TABLE IF NOT EXISTS compliance_root_causes (
    id integer NOT NULL,
    code character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    description text,
    category character varying(50),
    recommendation text,
    display_order integer DEFAULT 100
);

CREATE TABLE IF NOT EXISTS compliance_snapshots (
    id integer NOT NULL,
    run_id integer NOT NULL,
    framework_key character varying(50) NOT NULL,
    framework_name character varying(100) NOT NULL,
    score integer NOT NULL,
    pass_count integer DEFAULT 0 NOT NULL,
    warn_count integer DEFAULT 0 NOT NULL,
    fail_count integer DEFAULT 0 NOT NULL,
    total_controls integer DEFAULT 0 NOT NULL,
    metrics jsonb,
    created_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS copilot_conversations (
    id integer NOT NULL,
    user_id integer,
    organization_id integer,
    title text,
    messages jsonb DEFAULT '[]'::jsonb,
    created_at timestamp without time zone DEFAULT now(),
    updated_at timestamp without time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS credentials (
    id bigint NOT NULL,
    identity_db_id bigint NOT NULL,
    credential_type text NOT NULL,
    key_id text NOT NULL,
    display_name text,
    start_datetime timestamp with time zone,
    end_datetime timestamp with time zone,
    thumbprint text,
    issuer text,
    subject text,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS custom_risk_rules (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    conditions jsonb NOT NULL,
    action_type character varying(20) DEFAULT 'adjust_points'::character varying NOT NULL,
    points_adjustment integer DEFAULT 0,
    force_level character varying(20),
    reason_text text,
    enabled boolean DEFAULT true,
    priority integer DEFAULT 100,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS dashboard_preferences (
    id integer NOT NULL,
    user_id integer NOT NULL,
    preferences jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS discovery_integrity_metrics (
    id integer NOT NULL,
    metric_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer NOT NULL,
    discovery_run_id integer,
    identities_count integer DEFAULT 0,
    resources_count integer DEFAULT 0,
    role_assignments_count integer DEFAULT 0,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS discovery_runs (
    id bigint NOT NULL,
    subscription_id text NOT NULL,
    subscription_name text,
    started_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone,
    status text NOT NULL,
    total_identities integer,
    critical_count integer,
    high_count integer,
    medium_count integer,
    low_count integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer,
    cloud_connection_id integer NOT NULL,
    snapshot_hash character varying(64),
    snapshot_signature character varying(64)
);

CREATE TABLE IF NOT EXISTS drift_reports (
    id integer NOT NULL,
    current_run_id integer NOT NULL,
    previous_run_id integer NOT NULL,
    new_identities_count integer DEFAULT 0 NOT NULL,
    removed_identities_count integer DEFAULT 0 NOT NULL,
    permission_changes_count integer DEFAULT 0 NOT NULL,
    risk_changes_count integer DEFAULT 0 NOT NULL,
    credential_changes_count integer DEFAULT 0 NOT NULL,
    total_changes integer DEFAULT 0 NOT NULL,
    changes jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    events jsonb DEFAULT '[]'::jsonb,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS entra_role_assignments (
    id bigint NOT NULL,
    identity_db_id bigint,
    role_name text NOT NULL,
    role_definition_id text,
    directory_scope text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer,
    usage_status text DEFAULT 'unknown'::text,
    assigned_on timestamp with time zone,
    days_since_assigned integer,
    redundant_with text,
    role_type text DEFAULT 'entra'::text,
    risk_level text,
    why_critical text
);

CREATE TABLE IF NOT EXISTS fix_recommendations (
    id integer NOT NULL,
    recommendation_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer NOT NULL,
    discovery_run_id integer,
    entity_id text NOT NULL,
    entity_type character varying(30) NOT NULL,
    entity_name text,
    fix_type character varying(60) NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    fix_category character varying(40) NOT NULL,
    priority_score integer DEFAULT 0 NOT NULL,
    effort character varying(10) DEFAULT 'medium'::character varying NOT NULL,
    steps jsonb DEFAULT '[]'::jsonb NOT NULL,
    azure_cli_commands text,
    compliance_refs jsonb DEFAULT '{}'::jsonb,
    linked_finding_types jsonb DEFAULT '[]'::jsonb,
    linked_path_types jsonb DEFAULT '[]'::jsonb,
    linked_finding_count integer DEFAULT 0 NOT NULL,
    linked_path_count integer DEFAULT 0 NOT NULL,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    status_changed_by character varying(100),
    status_changed_at timestamp with time zone,
    assigned_to character varying(100),
    recommendation_fingerprint text,
    first_detected_at timestamp with time zone DEFAULT now() NOT NULL,
    last_detected_at timestamp with time zone DEFAULT now() NOT NULL,
    occurrence_count integer DEFAULT 1 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    risk_reduction_score integer DEFAULT 0,
    finding_id integer,
    attack_path_id integer
);

CREATE TABLE IF NOT EXISTS governance_decisions (
    id integer NOT NULL,
    identity_db_id integer NOT NULL,
    identity_id text NOT NULL,
    decision character varying(50) NOT NULL,
    reason text,
    risk_score_snapshot integer,
    risk_band_snapshot character varying(20),
    risk_factors_snapshot jsonb DEFAULT '[]'::jsonb,
    access_snapshot jsonb DEFAULT '[]'::jsonb,
    decided_by integer NOT NULL,
    exception_expiry timestamp with time zone,
    organization_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS graph_api_permissions (
    id bigint NOT NULL,
    identity_db_id bigint NOT NULL,
    permission_name text NOT NULL,
    permission_description text,
    resource_name text DEFAULT 'Microsoft Graph'::text,
    risk_level text,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS human_identities (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    display_name character varying(500),
    employee_id character varying(255),
    department character varying(255),
    manager_id character varying(255),
    employment_status character varying(50) DEFAULT 'active'::character varying,
    status_determined_at timestamp with time zone,
    status_source character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS identities (
    id bigint NOT NULL,
    discovery_run_id bigint,
    identity_id text NOT NULL,
    display_name text NOT NULL,
    source text DEFAULT 'azure'::text NOT NULL,
    identity_type text NOT NULL,
    identity_category text DEFAULT 'service_principal'::text NOT NULL,
    app_id text,
    object_id text,
    entra_object_type text,
    service_principal_type text,
    publisher_name text,
    app_owner_organization_id text,
    alternative_names jsonb,
    created_datetime timestamp with time zone,
    enabled boolean DEFAULT true,
    is_microsoft_system boolean DEFAULT false,
    risk_level text,
    risk_reasons text[],
    credential_expiration timestamp with time zone,
    credential_status text,
    last_sign_in timestamp with time zone,
    activity_status text,
    tags jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    primary_subscription_id text,
    additional_subscription_count integer DEFAULT 0,
    app_owner_org_id text,
    permission_plane character varying(50),
    deleted_at timestamp with time zone,
    exposure_score integer DEFAULT 0,
    exposure_components jsonb DEFAULT '{}'::jsonb,
    privilege_score integer DEFAULT 0,
    credential_risk_score integer DEFAULT 0,
    exposure_subscore integer DEFAULT 0,
    lifecycle_score integer DEFAULT 0,
    visibility_score integer DEFAULT 0,
    activity_confidence integer DEFAULT 0,
    lifecycle_state character varying(20) DEFAULT 'blind'::character varying,
    can_escalate boolean DEFAULT false,
    effective_scope_flag character varying(30) DEFAULT 'resource'::character varying,
    credential_age_days integer DEFAULT 0,
    owner_status character varying(20) DEFAULT 'unknown'::character varying,
    federated_trust boolean DEFAULT false,
    cross_subscription boolean DEFAULT false,
    exposure_computed_at timestamp without time zone,
    critical_exposure_overrides jsonb DEFAULT '[]'::jsonb,
    organization_id integer,
    risk_factors jsonb DEFAULT '[]'::jsonb,
    upn character varying(500),
    employee_id_entra character varying(255),
    department character varying(255),
    manager_id character varying(255),
    manager_upn character varying(500),
    job_title character varying(255),
    account_category character varying(50),
    credential_count integer DEFAULT 0,
    next_expiry timestamp with time zone,
    credential_risk text,
    cloud text DEFAULT 'azure'::text,
    identity_type_normalized text,
    canonical_name text,
    principal_id text,
    tenant_or_org_id text,
    source_normalized text,
    is_federated boolean DEFAULT false,
    status text DEFAULT 'active'::text,
    last_seen_auth timestamp with time zone,
    owner_display_name text,
    owner_count integer DEFAULT 0,
    risk_score integer DEFAULT 0,
    api_permission_count integer DEFAULT 0,
    app_role_count integer DEFAULT 0,
    days_since_last_use integer,
    last_activity_source text,
    pim_eligible_count integer DEFAULT 0,
    pim_active_count integer DEFAULT 0,
    has_permanent_assignment boolean DEFAULT false,
    ca_coverage_status text,
    ca_mfa_enforced boolean,
    blast_radius_score integer,
    privilege_tier character varying(20)
);

CREATE TABLE IF NOT EXISTS identity_graph_edges (
    id SERIAL PRIMARY KEY,
    connection_id INT NOT NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    edge_type TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_graph_conn ON identity_graph_edges(connection_id);
CREATE INDEX IF NOT EXISTS idx_graph_source ON identity_graph_edges(source_id);
CREATE INDEX IF NOT EXISTS idx_graph_target ON identity_graph_edges(target_id);
CREATE INDEX IF NOT EXISTS idx_graph_edge_type ON identity_graph_edges(edge_type);

CREATE TABLE IF NOT EXISTS identity_group_members (
    id integer NOT NULL,
    group_id integer NOT NULL,
    identity_id text NOT NULL,
    added_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS identity_groups (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    color character varying(20) DEFAULT '#3B82F6'::character varying,
    group_type character varying(10) DEFAULT 'custom'::character varying NOT NULL,
    auto_criteria jsonb,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS identity_links (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    human_identity_id integer NOT NULL,
    identity_db_id integer,
    account_type character varying(50) NOT NULL,
    account_upn character varying(500),
    account_object_id character varying(255),
    account_enabled boolean DEFAULT true,
    link_method character varying(50) DEFAULT 'naming_convention'::character varying NOT NULL,
    link_confidence numeric(5,2) DEFAULT 0,
    linked_at timestamp with time zone DEFAULT now() NOT NULL,
    linked_by character varying(255),
    verified boolean DEFAULT false,
    verified_at timestamp with time zone,
    verified_by character varying(255)
);

CREATE TABLE IF NOT EXISTS identity_roles (
    id bigint NOT NULL,
    identity_db_id bigint NOT NULL,
    role_name text NOT NULL,
    role_type text NOT NULL,
    scope text,
    inherited boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS identity_subscription_access (
    id bigint NOT NULL,
    identity_db_id bigint NOT NULL,
    identity_id text NOT NULL,
    subscription_id text NOT NULL,
    subscription_name text,
    rbac_role text NOT NULL,
    scope text,
    scope_type text,
    risk_level text,
    last_activity timestamp with time zone,
    discovered_at timestamp with time zone DEFAULT now(),
    discovery_run_id bigint,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS identity_security_posture (
    id SERIAL PRIMARY KEY,
    connection_id INT,
    risk_score INT,
    findings_count INT,
    high_severity INT,
    medium_severity INT,
    low_severity INT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS invoice_documents (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    invoice_id integer,
    snapshot_id integer,
    document_type character varying(20) DEFAULT 'invoice'::character varying NOT NULL,
    file_name character varying(255) NOT NULL,
    content_type character varying(100) DEFAULT 'application/pdf'::character varying NOT NULL,
    file_data bytea,
    file_size integer,
    generated_by integer,
    generated_at timestamp with time zone DEFAULT now() NOT NULL,
    immutable boolean DEFAULT true NOT NULL
);

CREATE TABLE IF NOT EXISTS invoices (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    invoice_number character varying(50) NOT NULL,
    status character varying(20) DEFAULT 'draft'::character varying NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    subtotal_cents integer DEFAULT 0 NOT NULL,
    tax_label character varying(50),
    tax_rate numeric(5,2) DEFAULT 0 NOT NULL,
    tax_amount_cents integer DEFAULT 0 NOT NULL,
    discount_cents integer DEFAULT 0 NOT NULL,
    total_cents integer DEFAULT 0 NOT NULL,
    line_items jsonb DEFAULT '[]'::jsonb NOT NULL,
    seller_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    buyer_snapshot jsonb DEFAULT '{}'::jsonb NOT NULL,
    issued_at timestamp with time zone,
    due_at timestamp with time zone,
    paid_at timestamp with time zone,
    voided_at timestamp with time zone,
    notes text,
    payment_terms integer DEFAULT 30 NOT NULL,
    created_by integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    content_hash character varying(64)
);

CREATE TABLE IF NOT EXISTS job_runs (
    id integer NOT NULL,
    job_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer,
    job_type text NOT NULL,
    status text DEFAULT 'queued'::text NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_ms integer,
    error_message text,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS msp_relationships (
    id integer NOT NULL,
    msp_organization_id integer NOT NULL,
    client_organization_id integer NOT NULL,
    margin_pct numeric(5,2) DEFAULT 0 NOT NULL,
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id integer NOT NULL,
    event_type character varying(50) NOT NULL,
    category character varying(30) NOT NULL,
    severity character varying(20) DEFAULT 'info'::character varying NOT NULL,
    title character varying(255) NOT NULL,
    description text NOT NULL,
    payload jsonb,
    related_identity_id text,
    related_identity_name character varying(255),
    related_run_id integer,
    read boolean DEFAULT false,
    read_at timestamp with time zone,
    actioned boolean DEFAULT false,
    action_type character varying(50),
    action_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS organization_billing_snapshots (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    plan character varying(20) NOT NULL,
    platform_fee_cents integer DEFAULT 0 NOT NULL,
    subscription_total_cents integer DEFAULT 0 NOT NULL,
    gross_cents integer DEFAULT 0 NOT NULL,
    discount_pct numeric(5,2) DEFAULT 0 NOT NULL,
    discount_cents integer DEFAULT 0 NOT NULL,
    net_cents integer DEFAULT 0 NOT NULL,
    tax_rate numeric(5,2) DEFAULT 0 NOT NULL,
    tax_cents integer DEFAULT 0 NOT NULL,
    total_cents integer DEFAULT 0 NOT NULL,
    active_subscriptions integer DEFAULT 0 NOT NULL,
    breakdown jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    pricing_version character varying(20),
    unit_prices jsonb DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS organization_entitlements (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    feature_key character varying(100) NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    granted_by integer,
    granted_at timestamp with time zone DEFAULT now() NOT NULL,
    expires_at timestamp with time zone,
    reason text
);

CREATE TABLE IF NOT EXISTS organization_usage (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    resource_type character varying(50) NOT NULL,
    resource_id character varying(255),
    action character varying(20) NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS organization_usage_counters (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    resource_type character varying(50) NOT NULL,
    current_count integer DEFAULT 0 NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS organizations (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(100) NOT NULL,
    plan character varying(20) DEFAULT 'free'::character varying NOT NULL,
    settings jsonb DEFAULT '{}'::jsonb NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    license_activated_at timestamp with time zone,
    license_expires_at timestamp with time zone,
    logo_url text,
    subscription_term integer DEFAULT 0 NOT NULL,
    primary_cloud character varying(20),
    industry character varying(100),
    compliance_framework character varying(100),
    status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    onboarding_stage character varying(20) DEFAULT 'active'::character varying NOT NULL,
    platform_fee_cents integer DEFAULT 20000 NOT NULL,
    discount_pct numeric(5,2) DEFAULT 0 NOT NULL,
    trial_expires_at timestamp with time zone,
    billing_status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    tax_label character varying(50) DEFAULT 'Tax'::character varying NOT NULL,
    tax_rate numeric(5,2) DEFAULT 0 NOT NULL,
    tax_id character varying(100),
    tax_exempt boolean DEFAULT false NOT NULL,
    tax_notes text,
    payment_terms integer DEFAULT 30 NOT NULL,
    billing_company character varying(255),
    billing_address_line1 character varying(255),
    billing_address_line2 character varying(255),
    billing_city character varying(100),
    billing_state character varying(100),
    billing_postal_code character varying(20),
    billing_country character varying(100),
    billing_email character varying(255),
    stripe_customer_id character varying(100),
    stripe_subscription_id character varying(100),
    plan_type character varying(20) DEFAULT 'self_serve'::character varying NOT NULL,
    plan_status character varying(20) DEFAULT 'active'::character varying NOT NULL,
    subscription_limit integer,
    enforcement_mode character varying(20) DEFAULT 'strict'::character varying NOT NULL,
    trial_started_at timestamp with time zone,
    is_demo boolean DEFAULT false
);

CREATE TABLE IF NOT EXISTS orphaned_privileged_findings (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    discovery_run_id integer,
    human_identity_id integer,
    regular_link_id integer,
    privileged_link_id integer,
    regular_upn character varying(500),
    regular_object_id character varying(255),
    privileged_upn character varying(500),
    privileged_object_id character varying(255),
    severity character varying(20) DEFAULT 'high'::character varying NOT NULL,
    azure_roles text[],
    role_count integer DEFAULT 0,
    highest_role_privilege character varying(100),
    subscription_count integer DEFAULT 0,
    has_activity_after_disable boolean DEFAULT false,
    days_since_regular_disabled integer,
    status character varying(50) DEFAULT 'open'::character varying NOT NULL,
    acknowledged_at timestamp with time zone,
    acknowledged_by character varying(255),
    remediated_at timestamp with time zone,
    remediated_by character varying(255),
    remediation_action text,
    suppressed_at timestamp with time zone,
    suppressed_by character varying(255),
    suppression_reason text,
    compliance_reference character varying(255) DEFAULT 'HIPAA §164.312(a)(2)(iii)'::character varying,
    days_out_of_compliance integer DEFAULT 0,
    remediation_commands jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS pim_activations (
    id integer NOT NULL,
    identity_db_id integer NOT NULL,
    role_name text NOT NULL,
    role_definition_id text,
    directory_scope text DEFAULT '/'::text,
    status text,
    activation_start timestamp with time zone,
    activation_end timestamp with time zone,
    justification text,
    ticket_number text,
    ticket_system text,
    is_approval_required boolean DEFAULT false,
    created_datetime timestamp with time zone,
    discovered_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pim_eligible_assignments (
    id integer NOT NULL,
    identity_db_id integer NOT NULL,
    role_name text NOT NULL,
    role_definition_id text,
    directory_scope text DEFAULT '/'::text,
    assignment_type text DEFAULT 'eligible'::text,
    start_datetime timestamp with time zone,
    end_datetime timestamp with time zone,
    member_type text,
    discovered_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS plans (
    id character varying(20) NOT NULL,
    name character varying(100) NOT NULL,
    platform_fee_cents integer DEFAULT 0 NOT NULL,
    default_sub_rate_cents integer DEFAULT 6900 NOT NULL,
    max_subscriptions integer,
    max_identities integer,
    ai_features boolean DEFAULT false NOT NULL,
    trial_days integer,
    enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS platform_settings (
    key character varying(100) NOT NULL,
    value text,
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS rbac_hygiene_scans (
    id integer NOT NULL,
    score integer DEFAULT 0 NOT NULL,
    grade character varying(2) DEFAULT 'F'::character varying NOT NULL,
    total_assignments integer DEFAULT 0 NOT NULL,
    total_findings integer DEFAULT 0 NOT NULL,
    summary jsonb DEFAULT '{}'::jsonb NOT NULL,
    findings jsonb DEFAULT '[]'::jsonb NOT NULL,
    discovery_run_id bigint,
    organization_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    id integer NOT NULL,
    user_id integer NOT NULL,
    token_hash character varying(255) NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    revoked boolean DEFAULT false,
    portal character varying(10) DEFAULT 'client'::character varying
);

CREATE TABLE IF NOT EXISTS remediation_actions (
    id integer NOT NULL,
    identity_id text NOT NULL,
    playbook_id integer NOT NULL,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    notes text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    execution_status character varying(20) DEFAULT NULL::character varying,
    execution_log jsonb,
    executed_at timestamp with time zone,
    executed_by integer,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS remediation_playbooks (
    id integer NOT NULL,
    risk_pattern character varying(255) NOT NULL,
    pattern_type character varying(20) DEFAULT 'contains'::character varying,
    title character varying(255) NOT NULL,
    description text,
    steps jsonb NOT NULL,
    impact character varying(10) DEFAULT 'high'::character varying,
    effort character varying(10) DEFAULT 'medium'::character varying,
    priority_score integer DEFAULT 50,
    compliance_refs jsonb,
    category character varying(50),
    created_at timestamp without time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS report_outputs (
    id integer NOT NULL,
    output_id uuid DEFAULT gen_random_uuid() NOT NULL,
    run_id integer NOT NULL,
    organization_id integer NOT NULL,
    format text DEFAULT 'json'::text NOT NULL,
    storage_path text,
    file_size_bytes integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS report_runs (
    id integer NOT NULL,
    run_id uuid DEFAULT gen_random_uuid() NOT NULL,
    report_id integer NOT NULL,
    organization_id integer NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    record_count integer DEFAULT 0,
    error_message text,
    started_at timestamp with time zone,
    generated_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    generation_duration_ms integer,
    parameters jsonb DEFAULT '{}'::jsonb,
    expires_at timestamp with time zone
);

CREATE TABLE IF NOT EXISTS reports (
    id integer NOT NULL,
    report_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer NOT NULL,
    report_type text NOT NULL,
    title text,
    parameters jsonb DEFAULT '{}'::jsonb,
    created_by integer,
    created_by_username character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_findings (
    id integer NOT NULL,
    discovery_run_id integer NOT NULL,
    resource_id text NOT NULL,
    resource_type character varying(30) NOT NULL,
    component character varying(50) NOT NULL,
    finding_key character varying(200) NOT NULL,
    finding_title text NOT NULL,
    points integer DEFAULT 0 NOT NULL,
    severity character varying(20) DEFAULT 'low'::character varying NOT NULL,
    is_critical_override boolean DEFAULT false NOT NULL,
    metadata jsonb DEFAULT '{}'::jsonb,
    organization_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS resource_risk_history (
    id integer NOT NULL,
    discovery_run_id integer NOT NULL,
    resource_id text NOT NULL,
    resource_type character varying(30) NOT NULL,
    risk_score integer DEFAULT 0 NOT NULL,
    risk_level character varying(20) DEFAULT 'info'::character varying NOT NULL,
    risk_components jsonb DEFAULT '{}'::jsonb,
    critical_overrides jsonb DEFAULT '[]'::jsonb,
    blast_radius_score integer DEFAULT 0,
    privileged_identity_count integer DEFAULT 0,
    dependency_count integer DEFAULT 0,
    network_exposure_score integer DEFAULT 0,
    organization_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS review_assignments (
    id integer NOT NULL,
    assignment_id uuid DEFAULT gen_random_uuid() NOT NULL,
    review_id integer NOT NULL,
    organization_id integer NOT NULL,
    identity_id integer NOT NULL,
    identity_name text,
    identity_type character varying(30),
    role_name text NOT NULL,
    role_type character varying(20) DEFAULT 'rbac'::character varying NOT NULL,
    scope text,
    risk_level character varying(20),
    risk_score integer DEFAULT 0,
    blast_radius_score integer DEFAULT 0,
    attack_path_count integer DEFAULT 0,
    finding_count integer DEFAULT 0,
    reviewer character varying(100),
    reviewer_user_id integer,
    decision character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    decision_reason text,
    decision_at timestamp with time zone,
    due_date timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    risk_snapshot jsonb
);

CREATE TABLE IF NOT EXISTS review_evidence (
    id integer NOT NULL,
    evidence_id uuid DEFAULT gen_random_uuid() NOT NULL,
    assignment_id integer NOT NULL,
    organization_id integer NOT NULL,
    evidence_type character varying(30) NOT NULL,
    source_id text,
    title text NOT NULL,
    detail jsonb DEFAULT '{}'::jsonb,
    added_by character varying(100),
    added_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS role_activity_log (
    id bigint NOT NULL,
    identity_db_id bigint NOT NULL,
    role_name text NOT NULL,
    last_activity_date timestamp with time zone,
    days_since_last_use integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS role_assignments (
    id bigint NOT NULL,
    identity_db_id bigint,
    role_name text NOT NULL,
    scope text NOT NULL,
    scope_type text NOT NULL,
    principal_id text NOT NULL,
    assignment_id text,
    created_on timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer,
    scope_exists boolean DEFAULT true,
    usage_status text DEFAULT 'unknown'::text,
    days_since_assigned integer,
    redundant_with text,
    role_type text DEFAULT 'azure'::text,
    risk_level text,
    why_critical text,
    resource_type text,
    resource_name text
);

CREATE TABLE IF NOT EXISTS role_attack_patterns (
    id bigint NOT NULL,
    role_name text NOT NULL,
    attack_scenario text NOT NULL,
    real_world_example text,
    company_affected text,
    breach_year integer,
    estimated_cost_usd bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS role_hipaa_mappings (
    id bigint NOT NULL,
    role_name text NOT NULL,
    hipaa_section text NOT NULL,
    violation_explanation text,
    violation_risk text,
    typical_penalty_min bigint,
    typical_penalty_max bigint,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS role_permissions (
    id bigint NOT NULL,
    role_name text NOT NULL,
    role_type text NOT NULL,
    privileged boolean DEFAULT false,
    risk_level text,
    description text,
    why_critical text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS sa_attestations (
    id integer NOT NULL,
    identity_db_id integer NOT NULL,
    identity_id text NOT NULL,
    attested_by integer NOT NULL,
    status character varying(30) NOT NULL,
    justification text,
    attested_at timestamp with time zone DEFAULT now() NOT NULL,
    next_due timestamp with time zone,
    organization_id integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS saved_views (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    filters jsonb DEFAULT '{}'::jsonb NOT NULL,
    sort_field character varying(50),
    sort_direction character varying(10) DEFAULT 'desc'::character varying,
    is_default boolean DEFAULT false,
    is_shared boolean DEFAULT false,
    user_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS scan_schedules (
    id integer NOT NULL,
    organization_id integer NOT NULL,
    connection_id integer,
    label character varying(100),
    frequency character varying(20) DEFAULT 'daily'::character varying NOT NULL,
    cron_expression character varying(100) DEFAULT '0 2 * * *'::character varying,
    next_run_at timestamp with time zone,
    last_run_at timestamp with time zone,
    last_run_status character varying(20),
    enabled boolean DEFAULT true,
    created_by integer,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    version text NOT NULL,
    description text DEFAULT ''::text NOT NULL,
    applied_at timestamp with time zone DEFAULT now() NOT NULL,
    checksum text
);

CREATE TABLE IF NOT EXISTS security_findings (
    id integer NOT NULL,
    finding_id uuid DEFAULT gen_random_uuid() NOT NULL,
    organization_id integer NOT NULL,
    entity_type character varying(30) NOT NULL,
    entity_id text NOT NULL,
    finding_type character varying(60) NOT NULL,
    severity character varying(20) NOT NULL,
    risk_score integer DEFAULT 0 NOT NULL,
    title text NOT NULL,
    description text NOT NULL,
    recommended_fix text,
    status character varying(20) DEFAULT 'open'::character varying NOT NULL,
    status_changed_by character varying(100),
    status_changed_at timestamp with time zone,
    discovery_run_id integer,
    metadata jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    finding_fingerprint text,
    first_detected_at timestamp with time zone DEFAULT now() NOT NULL,
    last_detected_at timestamp with time zone DEFAULT now() NOT NULL,
    occurrence_count integer DEFAULT 1 NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    id integer NOT NULL,
    key character varying(255) NOT NULL,
    value text,
    organization_id integer NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS soar_actions (
    id integer NOT NULL,
    playbook_id integer,
    identity_id text,
    anomaly_id integer,
    trigger_event jsonb,
    action_type character varying(30) NOT NULL,
    integration character varying(30) NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying,
    result jsonb,
    executed_at timestamp with time zone,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS soar_playbooks (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    enabled boolean DEFAULT true,
    trigger_type character varying(30) NOT NULL,
    trigger_conditions jsonb DEFAULT '{}'::jsonb NOT NULL,
    action_type character varying(30) NOT NULL,
    action_config jsonb DEFAULT '{}'::jsonb NOT NULL,
    integration character varying(30) DEFAULT 'internal'::character varying NOT NULL,
    cooldown_minutes integer DEFAULT 60,
    created_by character varying(100),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    last_triggered_at timestamp with time zone,
    trigger_count integer DEFAULT 0,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS sp_app_roles (
    id bigint NOT NULL,
    identity_db_id bigint NOT NULL,
    app_role_id text NOT NULL,
    resource_id text NOT NULL,
    resource_display_name text,
    principal_display_name text,
    created_date_time timestamp with time zone,
    risk_level text,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS sp_ownership (
    id bigint NOT NULL,
    identity_db_id bigint NOT NULL,
    owner_object_id text NOT NULL,
    owner_display_name text,
    owner_upn text,
    owner_type text DEFAULT 'user'::text,
    ownership_type text DEFAULT 'application'::text,
    is_primary_owner boolean DEFAULT false,
    discovered_at timestamp with time zone DEFAULT now() NOT NULL,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS spn_exposure_findings (
    id integer NOT NULL,
    identity_db_id bigint NOT NULL,
    discovery_run_id bigint,
    finding_type character varying(50) NOT NULL,
    severity character varying(20) NOT NULL,
    title text NOT NULL,
    description text,
    evidence jsonb DEFAULT '{}'::jsonb,
    remediation text,
    component character varying(30),
    score_impact integer DEFAULT 0,
    organization_id integer NOT NULL,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sso_auth_codes (
    id integer NOT NULL,
    code character varying(128) NOT NULL,
    user_id integer NOT NULL,
    organization_id integer,
    used boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL
);

CREATE TABLE IF NOT EXISTS system_health_metrics (
    id integer NOT NULL,
    metric_id uuid DEFAULT gen_random_uuid() NOT NULL,
    metric_name text NOT NULL,
    metric_value double precision NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS tenant_health (
    organization_id integer NOT NULL,
    last_discovery_run timestamp with time zone,
    snapshot_age_hours integer DEFAULT 0,
    findings_count integer DEFAULT 0,
    critical_risks integer DEFAULT 0,
    blast_radius_critical integer DEFAULT 0,
    integrity_warning boolean DEFAULT false,
    status text DEFAULT 'stale'::text NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id integer NOT NULL,
    username character varying(100) NOT NULL,
    password_hash character varying(255) NOT NULL,
    display_name character varying(255) NOT NULL,
    role character varying(20) DEFAULT 'viewer'::character varying NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now(),
    last_login_at timestamp with time zone,
    created_by integer,
    organization_id integer,
    is_superadmin boolean DEFAULT false,
    auth_provider character varying(20) DEFAULT 'local'::character varying,
    external_id character varying(500),
    force_password_change boolean DEFAULT false,
    is_root_user boolean DEFAULT false,
    password_reset_token text,
    password_reset_expires timestamp with time zone,
    failed_login_attempts integer DEFAULT 0,
    locked_until timestamp with time zone,
    portal_role character varying(20),
    email character varying(255),
    phone character varying(50)
);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id integer NOT NULL,
    webhook_id integer,
    event_type character varying(50) NOT NULL,
    payload jsonb NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying,
    http_status integer,
    response_body text,
    attempts integer DEFAULT 0,
    next_retry_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    delivered_at timestamp with time zone,
    organization_id integer
);

CREATE TABLE IF NOT EXISTS webhooks (
    id integer NOT NULL,
    name character varying(255) NOT NULL,
    url text NOT NULL,
    secret character varying(255),
    event_types text[] DEFAULT '{}'::text[] NOT NULL,
    headers jsonb,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    organization_id integer
);

CREATE TABLE IF NOT EXISTS workload_activity_stats (
    id bigint NOT NULL,
    organization_id integer NOT NULL,
    identity_db_id bigint,
    identity_id text NOT NULL,
    period_start date NOT NULL,
    period_end date NOT NULL,
    total_sign_ins integer DEFAULT 0,
    successful_sign_ins integer DEFAULT 0,
    failed_sign_ins integer DEFAULT 0,
    unique_resources integer DEFAULT 0,
    unique_ips integer DEFAULT 0,
    unique_locations integer DEFAULT 0,
    peak_hour integer,
    off_hours_pct real DEFAULT 0,
    avg_daily_sign_ins real DEFAULT 0,
    risk_sign_ins integer DEFAULT 0,
    ca_failures integer DEFAULT 0,
    discovery_run_id bigint,
    computed_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workload_anomaly_events (
    id bigint NOT NULL,
    organization_id integer NOT NULL,
    identity_db_id bigint,
    identity_id text NOT NULL,
    anomaly_type text NOT NULL,
    severity text NOT NULL,
    title text NOT NULL,
    description text,
    evidence jsonb DEFAULT '{}'::jsonb,
    baseline jsonb DEFAULT '{}'::jsonb,
    detected_value jsonb DEFAULT '{}'::jsonb,
    resolved boolean DEFAULT false,
    resolved_at timestamp with time zone,
    resolved_by text,
    discovery_run_id bigint,
    created_at timestamp with time zone DEFAULT now()
);

CREATE TABLE IF NOT EXISTS workload_signin_events (
    id bigint NOT NULL,
    organization_id integer NOT NULL,
    identity_db_id bigint,
    identity_id text NOT NULL,
    sign_in_id text,
    created_datetime timestamp with time zone NOT NULL,
    status text NOT NULL,
    error_code integer,
    failure_reason text,
    resource_display_name text,
    resource_id text,
    ip_address text,
    location_city text,
    location_country text,
    app_display_name text,
    client_app_type text,
    is_interactive boolean DEFAULT false,
    risk_level text,
    risk_detail text,
    conditional_access_status text,
    discovery_run_id bigint,
    ingested_at timestamp with time zone DEFAULT now()
);
