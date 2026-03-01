-- AIBBP Initial Schema
-- =====================

-- Enable extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ── Enum types ───────────────────────────────────────────────────────

CREATE TYPE scan_status AS ENUM (
    'pending', 'running', 'completed', 'failed', 'cancelled'
);

CREATE TYPE vuln_status AS ENUM (
    'raw', 'validated', 'false_positive', 'reported', 'duplicate'
);

CREATE TYPE severity_level AS ENUM (
    'info', 'low', 'medium', 'high', 'critical'
);

-- ── Programs ─────────────────────────────────────────────────────────

CREATE TABLE programs (
    id           UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    platform     TEXT NOT NULL,
    handle       TEXT NOT NULL,
    name         TEXT NOT NULL,
    policy_url   TEXT,
    scope_raw    JSONB NOT NULL DEFAULT '{}',
    max_severity severity_level NOT NULL DEFAULT 'critical',
    status       TEXT NOT NULL DEFAULT 'active',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (platform, handle)
);

CREATE INDEX idx_programs_status ON programs (status);
CREATE INDEX idx_programs_platform ON programs (platform);

-- ── Root Domains ─────────────────────────────────────────────────────

CREATE TABLE root_domains (
    id         UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    domain     TEXT NOT NULL,
    wildcard   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (program_id, domain)
);

CREATE INDEX idx_root_domains_program ON root_domains (program_id);
CREATE INDEX idx_root_domains_domain ON root_domains (domain);

-- ── Subdomains ───────────────────────────────────────────────────────

CREATE TABLE subdomains (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    root_domain_id  UUID NOT NULL REFERENCES root_domains(id) ON DELETE CASCADE,
    program_id      UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    hostname        TEXT NOT NULL,
    ip_addresses    TEXT[] DEFAULT '{}',
    cnames          TEXT[] DEFAULT '{}',
    is_alive        BOOLEAN DEFAULT FALSE,
    http_status     INTEGER,
    title           TEXT,
    technologies    JSONB DEFAULT '[]',
    priority        INTEGER DEFAULT 5 CHECK (priority BETWEEN 1 AND 10),
    source          TEXT NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (program_id, hostname)
);

CREATE INDEX idx_subdomains_program ON subdomains (program_id);
CREATE INDEX idx_subdomains_root_domain ON subdomains (root_domain_id);
CREATE INDEX idx_subdomains_hostname ON subdomains USING gin (hostname gin_trgm_ops);
CREATE INDEX idx_subdomains_alive ON subdomains (program_id, is_alive) WHERE is_alive = TRUE;
CREATE INDEX idx_subdomains_priority ON subdomains (program_id, priority DESC);

-- ── Open Ports ───────────────────────────────────────────────────────

CREATE TABLE open_ports (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subdomain_id  UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    port          INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
    protocol      TEXT NOT NULL DEFAULT 'tcp',
    service       TEXT,
    version       TEXT,
    banner        TEXT,
    source        TEXT NOT NULL,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (subdomain_id, port, protocol)
);

CREATE INDEX idx_open_ports_subdomain ON open_ports (subdomain_id);
CREATE INDEX idx_open_ports_service ON open_ports (service);

-- ── URLs / Endpoints ─────────────────────────────────────────────────

CREATE TABLE urls (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subdomain_id   UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    program_id     UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    url            TEXT NOT NULL,
    method         TEXT DEFAULT 'GET',
    status_code    INTEGER,
    content_type   TEXT,
    content_length BIGINT,
    title          TEXT,
    parameters     JSONB DEFAULT '{}',
    headers        JSONB DEFAULT '{}',
    source         TEXT NOT NULL,
    discovered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (program_id, url, method)
);

CREATE INDEX idx_urls_program ON urls (program_id);
CREATE INDEX idx_urls_subdomain ON urls (subdomain_id);
CREATE INDEX idx_urls_status ON urls (status_code);
CREATE INDEX idx_urls_url ON urls USING gin (url gin_trgm_ops);

-- ── Technologies ─────────────────────────────────────────────────────

CREATE TABLE technologies (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subdomain_id  UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    version       TEXT,
    category      TEXT,
    confidence    INTEGER DEFAULT 50 CHECK (confidence BETWEEN 0 AND 100),
    source        TEXT NOT NULL,
    UNIQUE (subdomain_id, name)
);

CREATE INDEX idx_technologies_name ON technologies (name);
CREATE INDEX idx_technologies_subdomain ON technologies (subdomain_id);

-- ── JavaScript Files ─────────────────────────────────────────────────

CREATE TABLE js_files (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    subdomain_id  UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    url           TEXT NOT NULL,
    hash          TEXT NOT NULL,
    size          BIGINT,
    endpoints     JSONB DEFAULT '[]',
    secrets       JSONB DEFAULT '[]',
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (subdomain_id, hash)
);

CREATE INDEX idx_js_files_subdomain ON js_files (subdomain_id);
CREATE INDEX idx_js_files_hash ON js_files (hash);

-- ── Vulnerabilities ──────────────────────────────────────────────────

CREATE TABLE vulnerabilities (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id    UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    subdomain_id  UUID NOT NULL REFERENCES subdomains(id) ON DELETE CASCADE,
    url_id        UUID REFERENCES urls(id) ON DELETE SET NULL,
    type          TEXT NOT NULL,
    severity      severity_level NOT NULL,
    status        vuln_status NOT NULL DEFAULT 'raw',
    title         TEXT NOT NULL,
    description   TEXT,
    evidence      JSONB DEFAULT '{}',
    confidence    INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    cvss_score    NUMERIC(3,1) DEFAULT 0.0,
    cvss_vector   TEXT,
    endpoint      TEXT,
    parameter     TEXT,
    payload       TEXT,
    impact        TEXT,
    remediation   TEXT,
    source        TEXT NOT NULL,
    dedup_hash    TEXT NOT NULL,
    report_url    TEXT,
    discovered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    validated_at  TIMESTAMPTZ,
    reported_at   TIMESTAMPTZ
);

CREATE INDEX idx_vulns_program ON vulnerabilities (program_id);
CREATE INDEX idx_vulns_subdomain ON vulnerabilities (subdomain_id);
CREATE INDEX idx_vulns_type ON vulnerabilities (type);
CREATE INDEX idx_vulns_severity ON vulnerabilities (severity);
CREATE INDEX idx_vulns_status ON vulnerabilities (status);
CREATE INDEX idx_vulns_dedup ON vulnerabilities (dedup_hash);
CREATE INDEX idx_vulns_program_status ON vulnerabilities (program_id, status);
CREATE INDEX idx_vulns_confidence ON vulnerabilities (confidence DESC);

-- ── Scans ────────────────────────────────────────────────────────────

CREATE TABLE scans (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id    UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scanner_type  TEXT NOT NULL,
    target        TEXT NOT NULL,
    status        scan_status NOT NULL DEFAULT 'pending',
    config        JSONB DEFAULT '{}',
    result_raw    JSONB,
    result_count  INTEGER DEFAULT 0,
    error_msg     TEXT,
    duration_ms   BIGINT,
    started_at    TIMESTAMPTZ,
    completed_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_program ON scans (program_id);
CREATE INDEX idx_scans_status ON scans (status);
CREATE INDEX idx_scans_type ON scans (scanner_type);
CREATE INDEX idx_scans_program_status ON scans (program_id, status);

-- ── Vulnerability Chains ─────────────────────────────────────────────

CREATE TABLE vuln_chains (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id  UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    description TEXT,
    vuln_ids    UUID[] NOT NULL,
    steps       JSONB NOT NULL DEFAULT '[]',
    severity    severity_level NOT NULL,
    cvss_score  NUMERIC(3,1) DEFAULT 0.0,
    impact      TEXT,
    confidence  INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_vuln_chains_program ON vuln_chains (program_id);

-- ── Monitor Deltas ───────────────────────────────────────────────────

CREATE TABLE monitor_deltas (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id    UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    subdomain_id  UUID REFERENCES subdomains(id) ON DELETE SET NULL,
    delta_type    TEXT NOT NULL,
    before_data   JSONB,
    after_data    JSONB,
    detected_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_monitor_deltas_program ON monitor_deltas (program_id);
CREATE INDEX idx_monitor_deltas_type ON monitor_deltas (delta_type);
CREATE INDEX idx_monitor_deltas_time ON monitor_deltas (detected_at DESC);

-- ── Cost Tracking ────────────────────────────────────────────────────

CREATE TABLE cost_tracking (
    id                   UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    program_id           UUID NOT NULL REFERENCES programs(id) ON DELETE CASCADE,
    scan_id              UUID,
    phase                TEXT NOT NULL,
    model                TEXT NOT NULL,
    input_tokens         INTEGER NOT NULL DEFAULT 0,
    output_tokens        INTEGER NOT NULL DEFAULT 0,
    cache_read_tokens    INTEGER NOT NULL DEFAULT 0,
    cache_creation_tokens INTEGER NOT NULL DEFAULT 0,
    cost_dollars         NUMERIC(10,6) NOT NULL DEFAULT 0.0,
    prompt_type          TEXT,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_cost_tracking_program ON cost_tracking (program_id);
CREATE INDEX idx_cost_tracking_phase ON cost_tracking (phase);
CREATE INDEX idx_cost_tracking_model ON cost_tracking (model);
CREATE INDEX idx_cost_tracking_time ON cost_tracking (created_at DESC);

-- ── Materialized View: Asset Statistics ──────────────────────────────

CREATE VIEW v_asset_stats AS
SELECT
    p.id AS program_id,
    p.name AS program_name,
    (SELECT COUNT(*) FROM root_domains rd WHERE rd.program_id = p.id) AS root_domain_count,
    (SELECT COUNT(*) FROM subdomains s WHERE s.program_id = p.id) AS subdomain_count,
    (SELECT COUNT(*) FROM subdomains s WHERE s.program_id = p.id AND s.is_alive = TRUE) AS alive_subdomain_count,
    (SELECT COUNT(*) FROM urls u WHERE u.program_id = p.id) AS url_count,
    (SELECT COUNT(*) FROM vulnerabilities v WHERE v.program_id = p.id) AS vuln_count,
    (SELECT COUNT(*) FROM vulnerabilities v WHERE v.program_id = p.id AND v.status = 'validated') AS validated_vuln_count,
    (SELECT COALESCE(SUM(ct.cost_dollars), 0) FROM cost_tracking ct WHERE ct.program_id = p.id) AS total_cost
FROM programs p;

-- ── Updated_at trigger ───────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_programs_updated_at
    BEFORE UPDATE ON programs
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
