-- Active testing engine tables.
-- Stores sessions, accounts, HTTP traffic, findings, steps, and screenshots.

CREATE TABLE active_test_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID REFERENCES scans(id),
    target_url TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    config JSONB NOT NULL DEFAULT '{}',
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    budget_spent NUMERIC(10,4) DEFAULT 0,
    budget_limit NUMERIC(10,4) DEFAULT 0,
    findings_count INT DEFAULT 0,
    total_requests INT DEFAULT 0,
    total_api_calls INT DEFAULT 0,
    errors JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_active_sessions_scan ON active_test_sessions(scan_id);
CREATE INDEX idx_active_sessions_status ON active_test_sessions(status);

CREATE TABLE test_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES active_test_sessions(id) ON DELETE CASCADE,
    username TEXT NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT DEFAULT 'user',
    cookies JSONB DEFAULT '{}',
    session_token TEXT,
    auth_level TEXT DEFAULT 'unauthenticated',
    context_name TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_test_accounts_session ON test_accounts(session_id);

CREATE TABLE http_traffic_log (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID REFERENCES active_test_sessions(id) ON DELETE CASCADE,
    request_method TEXT NOT NULL,
    request_url TEXT NOT NULL,
    request_headers JSONB,
    request_body TEXT,
    request_content_type TEXT DEFAULT '',
    response_status INT,
    response_headers JSONB,
    response_body TEXT,
    response_content_type TEXT DEFAULT '',
    duration_ms INT,
    tags TEXT[] DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_traffic_session ON http_traffic_log(session_id);
CREATE INDEX idx_traffic_url ON http_traffic_log(request_url);
CREATE INDEX idx_traffic_tags ON http_traffic_log USING GIN(tags);

CREATE TABLE active_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    session_id UUID REFERENCES active_test_sessions(id) ON DELETE CASCADE,
    vuln_type TEXT NOT NULL,
    severity severity_level NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    endpoint TEXT,
    parameter TEXT,
    evidence JSONB,
    poc_code TEXT,
    poc_type TEXT,
    reproduction_steps JSONB,
    remediation TEXT,
    verified BOOLEAN DEFAULT false,
    confidence INT DEFAULT 0,
    cvss_score NUMERIC(3,1) DEFAULT 0,
    cvss_vector TEXT DEFAULT '',
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_active_findings_session ON active_findings(session_id);
CREATE INDEX idx_active_findings_severity ON active_findings(severity);
CREATE INDEX idx_active_findings_type ON active_findings(vuln_type);

CREATE TABLE active_test_steps (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID REFERENCES active_test_sessions(id) ON DELETE CASCADE,
    step_number INT NOT NULL,
    agent_type TEXT NOT NULL,
    action TEXT NOT NULL,
    input_data JSONB,
    output_data JSONB,
    duration_ms INT,
    tokens_used INT DEFAULT 0,
    error TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_active_steps_session ON active_test_steps(session_id);

CREATE TABLE browser_screenshots (
    id BIGSERIAL PRIMARY KEY,
    session_id UUID REFERENCES active_test_sessions(id) ON DELETE CASCADE,
    step_id BIGINT REFERENCES active_test_steps(id),
    page_url TEXT NOT NULL,
    screenshot_path TEXT NOT NULL,
    dom_snapshot TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX idx_screenshots_session ON browser_screenshots(session_id);
