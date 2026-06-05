-- AG-T4: Threat-source partner connector framework.
--
-- AuditGraph doesn't detect prompt injection / jailbreaks / content
-- abuse — that's vendor territory (Azure Content Filter, Bedrock
-- Guardrails, Lakera, NeMo). This table normalizes signals from ANY
-- partner into our internal shape so they feed the Findings catalog
-- + Abuse Scenarios + Trust Score.
--
-- Each row: one signal that some partner observed against some agent.

\set ON_ERROR_STOP on

BEGIN;

CREATE TABLE IF NOT EXISTS threat_signals (
    id                  BIGSERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL,

    identity_db_id      BIGINT,            -- nullable: signal may pre-date identity discovery
    identity_id         TEXT,

    vendor              TEXT NOT NULL
        CHECK (vendor IN ('azure_content_filter','bedrock_guardrails','lakera_guard',
                          'openai_moderation','nemo_guardrails','custom')),
    signal_type         TEXT NOT NULL
        CHECK (signal_type IN ('prompt_injection','jailbreak','data_leakage','toxic_content',
                                'pii_in_output','hallucination','off_topic','custom')),
    severity            TEXT NOT NULL DEFAULT 'medium'
        CHECK (severity IN ('critical','high','medium','low','info')),

    score               NUMERIC(5,4),        -- vendor's 0-1 confidence
    title               TEXT NOT NULL,
    description         TEXT,
    evidence            JSONB NOT NULL DEFAULT '{}'::jsonb,

    external_id         TEXT,                -- vendor's incident id for dedup
    received_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    occurred_at         TIMESTAMPTZ,         -- vendor-reported event time

    status              TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open','acknowledged','resolved','suppressed')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Dedup: same vendor + external_id wins
    CONSTRAINT threat_signals_vendor_external_unique
        UNIQUE (organization_id, vendor, external_id)
);

CREATE INDEX IF NOT EXISTS idx_threat_signals_org_received
    ON threat_signals (organization_id, received_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_signals_identity
    ON threat_signals (identity_db_id, received_at DESC)
    WHERE identity_db_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_threat_signals_vendor
    ON threat_signals (organization_id, vendor, received_at DESC);

-- Connector configuration: which vendors are wired, with what settings
CREATE TABLE IF NOT EXISTS threat_connectors (
    id                  SERIAL PRIMARY KEY,
    organization_id     INTEGER NOT NULL,
    vendor              TEXT NOT NULL
        CHECK (vendor IN ('azure_content_filter','bedrock_guardrails','lakera_guard',
                          'openai_moderation','nemo_guardrails','custom')),
    display_name        TEXT NOT NULL,
    is_enabled          BOOLEAN NOT NULL DEFAULT TRUE,

    -- Webhook secret for incoming partner posts (no actual API keys; partners
    -- HMAC-sign their webhooks). NULL for read-only ingest paths.
    webhook_secret      TEXT,

    config              JSONB NOT NULL DEFAULT '{}'::jsonb,

    last_signal_at      TIMESTAMPTZ,
    total_signals       INTEGER NOT NULL DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT threat_connectors_vendor_unique
        UNIQUE (organization_id, vendor)
);

CREATE INDEX IF NOT EXISTS idx_threat_connectors_org
    ON threat_connectors (organization_id);

-- Bump connectors.total_signals + last_signal_at whenever a signal lands
CREATE OR REPLACE FUNCTION _threat_signal_bump_connector()
RETURNS TRIGGER AS $$
BEGIN
    UPDATE threat_connectors
       SET total_signals = total_signals + 1,
           last_signal_at = COALESCE(NEW.received_at, NOW()),
           updated_at = NOW()
     WHERE organization_id = NEW.organization_id
       AND vendor = NEW.vendor;
    RETURN NEW;
END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_threat_signal_bump_connector ON threat_signals;
CREATE TRIGGER trg_threat_signal_bump_connector
    AFTER INSERT ON threat_signals
    FOR EACH ROW EXECUTE FUNCTION _threat_signal_bump_connector();

-- Connector updated_at
CREATE OR REPLACE FUNCTION _threat_connectors_touch()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END $$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_threat_connectors_touch ON threat_connectors;
CREATE TRIGGER trg_threat_connectors_touch
    BEFORE UPDATE ON threat_connectors
    FOR EACH ROW EXECUTE FUNCTION _threat_connectors_touch();

-- Grants
DO $$ BEGIN
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON threat_signals TO auditgraph_app';
    EXECUTE 'GRANT SELECT, INSERT, UPDATE ON threat_connectors TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE threat_signals_id_seq TO auditgraph_app';
    EXECUTE 'GRANT USAGE, SELECT ON SEQUENCE threat_connectors_id_seq TO auditgraph_app';
EXCEPTION WHEN undefined_object THEN NULL; END $$;
DO $$ BEGIN
    EXECUTE 'GRANT ALL ON threat_signals TO auditgraph_admin';
    EXECUTE 'GRANT ALL ON threat_connectors TO auditgraph_admin';
EXCEPTION WHEN undefined_object THEN NULL; END $$;

COMMIT;
