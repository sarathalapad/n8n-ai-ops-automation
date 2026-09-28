-- Runs once, on first start of the Postgres container.
-- n8n keeps its own tables in the default database; incident data lives in
-- a separate "ops" database so it can have its own retention and access.
CREATE DATABASE ops;

\connect ops

CREATE TABLE IF NOT EXISTS incidents (
    id            BIGSERIAL PRIMARY KEY,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    service       TEXT,
    environment   TEXT,
    -- title/description are stored AFTER PII redaction
    title         TEXT NOT NULL,
    description   TEXT,
    category      TEXT,
    priority      TEXT CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
    team          TEXT,
    summary       TEXT,
    confidence    NUMERIC(3, 2),
    status        TEXT NOT NULL CHECK (status IN ('triaged', 'manual_triage', 'resolved')),
    triage_errors JSONB
);

CREATE INDEX IF NOT EXISTS incidents_created_at_idx ON incidents (created_at);
