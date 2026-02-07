-- Migration 010: PIM (Privileged Identity Management) tables
-- Tracks eligible role assignments, active activations, and overuse patterns

CREATE TABLE IF NOT EXISTS pim_eligible_assignments (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    role_definition_id TEXT,
    directory_scope TEXT DEFAULT '/',
    assignment_type TEXT DEFAULT 'eligible',        -- permanent_eligible | time_bound_eligible
    start_datetime TIMESTAMPTZ,
    end_datetime TIMESTAMPTZ,                       -- NULL = permanent eligible
    member_type TEXT,                                -- Direct | Group
    discovered_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(identity_db_id, role_definition_id, directory_scope)
);

CREATE TABLE IF NOT EXISTS pim_activations (
    id SERIAL PRIMARY KEY,
    identity_db_id INTEGER NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    role_name TEXT NOT NULL,
    role_definition_id TEXT,
    directory_scope TEXT DEFAULT '/',
    status TEXT,                                     -- Active | Expired | Revoked
    activation_start TIMESTAMPTZ,
    activation_end TIMESTAMPTZ,
    justification TEXT,
    ticket_number TEXT,
    ticket_system TEXT,
    is_approval_required BOOLEAN DEFAULT FALSE,
    created_datetime TIMESTAMPTZ,
    discovered_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE identities ADD COLUMN IF NOT EXISTS pim_eligible_count INTEGER DEFAULT 0;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS pim_active_count INTEGER DEFAULT 0;
ALTER TABLE identities ADD COLUMN IF NOT EXISTS has_permanent_assignment BOOLEAN DEFAULT FALSE;
