-- Phase 3 skeleton writer expects identity_list.is_microsoft_system but no
-- migration adds it. Backfill the column so phase3_skeleton_writer can populate
-- the list and the /identities API returns rows.

ALTER TABLE identity_list
    ADD COLUMN IF NOT EXISTS is_microsoft_system BOOLEAN NOT NULL DEFAULT FALSE;

CREATE INDEX IF NOT EXISTS idx_identity_list_microsoft_system
    ON identity_list(is_microsoft_system);
