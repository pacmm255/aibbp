"""Pydantic schemas for the active testing engine.

Models cover browser interactions, HTTP traffic capture, account management,
vulnerability findings from active testing, test planning, and reporting.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from ai_brain.schemas import AIOutput, VulnFinding


# ── Browser Interaction ──────────────────────────────────────────────


class BrowserAction(BaseModel):
    """A single browser action to execute."""

    action_type: Literal[
        "navigate", "click", "fill", "select", "screenshot",
        "extract", "execute_js", "wait", "scroll", "submit",
    ]
    selector: str = ""
    value: str = ""
    url: str = ""
    timeout: int = 30000  # milliseconds


class BrowserActionResult(BaseModel):
    """Result of executing a browser action."""

    success: bool
    page_url: str = ""
    page_title: str = ""
    screenshot_b64: str = ""
    extracted_text: str = ""
    extracted_data: dict[str, Any] = Field(default_factory=dict)
    network_requests: list[dict[str, Any]] = Field(default_factory=list)
    error: str = ""
    duration_ms: int = 0


# ── HTTP Traffic ─────────────────────────────────────────────────────


class HTTPRequest(BaseModel):
    """Captured HTTP request."""

    method: str
    url: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    content_type: str = ""


class HTTPResponse(BaseModel):
    """Captured HTTP response."""

    status: int
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = ""
    content_type: str = ""


class HTTPTrafficEntry(BaseModel):
    """A captured HTTP request/response pair."""

    request: HTTPRequest
    response: HTTPResponse
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: int = 0
    tags: list[str] = Field(default_factory=list)


# ── Account Management ───────────────────────────────────────────────


class TestAccount(BaseModel):
    """A test account created during active testing."""

    username: str
    email: str
    password: str
    role: str = "user"
    cookies: dict[str, str] = Field(default_factory=dict)
    session_token: str = ""
    auth_level: Literal[
        "unauthenticated", "basic_user", "premium_user",
        "moderator", "admin", "super_admin",
    ] = "unauthenticated"
    context_name: str = ""  # Browser context this account is logged into
    created_at: datetime = Field(default_factory=datetime.utcnow)


# ── Interaction Points ───────────────────────────────────────────────


class FormField(BaseModel):
    """A form field discovered during recon."""

    name: str
    field_type: str = "text"  # text, password, email, hidden, file, select, etc.
    required: bool = False
    value: str = ""
    options: list[str] = Field(default_factory=list)


class InteractionPoint(BaseModel):
    """A testable interaction point in the application."""

    url: str
    method: str = "GET"
    params: list[str] = Field(default_factory=list)
    param_type: Literal[
        "query", "body", "path", "header", "cookie", "json", "multipart",
    ] = "query"
    auth_required: bool = False
    form_fields: list[FormField] = Field(default_factory=list)
    content_type: str = ""
    priority: int = Field(default=5, description="Priority 1-10")
    notes: str = ""


# ── Active Recon Results ─────────────────────────────────────────────


class SitemapEntry(BaseModel):
    """A page discovered during active recon."""

    url: str
    title: str = ""
    depth: int = 0
    links_count: int = 0
    forms_count: int = 0
    requires_auth: bool = False


class ActiveReconResult(AIOutput):
    """Output from active reconnaissance."""

    sitemap: list[SitemapEntry] = Field(default_factory=list)
    forms: list[InteractionPoint] = Field(default_factory=list)
    api_endpoints: list[InteractionPoint] = Field(default_factory=list)
    auth_endpoints: list[str] = Field(default_factory=list)
    file_upload_points: list[str] = Field(default_factory=list)
    interesting_features: list[str] = Field(default_factory=list)
    technology_stack: list[str] = Field(default_factory=list)
    total_pages_crawled: int = 0

    @field_validator("technology_stack", "interesting_features",
                     "auth_endpoints", "file_upload_points", mode="before")
    @classmethod
    def _coerce_str_list(cls, v: Any) -> list[str]:
        """Coerce dict/mixed to list[str] — Haiku sometimes returns dicts."""
        if isinstance(v, dict):
            parts: list[str] = []
            for key, val in v.items():
                if isinstance(val, str):
                    parts.append(f"{key}: {val}")
                elif isinstance(val, list):
                    parts.extend(str(x) for x in val)
                else:
                    parts.append(f"{key}: {val}")
            return parts
        if isinstance(v, list):
            return [str(x) if not isinstance(x, str) else x for x in v]
        return []

    @field_validator("api_endpoints", "forms", mode="before")
    @classmethod
    def _coerce_interaction_list(cls, v: Any) -> list:
        """Skip non-list values — Haiku sometimes returns a summary dict."""
        if isinstance(v, dict):
            return []
        if isinstance(v, list):
            return v
        return []


# ── Auth Flow Results ────────────────────────────────────────────────


class AuthFlowResult(AIOutput):
    """Output from auth flow analysis and account setup."""

    accounts_created: list[TestAccount] = Field(default_factory=list)
    login_method: str = ""  # form, api, oauth, sso
    session_mechanism: str = ""  # cookie, jwt, bearer_token, api_key
    mfa_type: str = ""  # none, email, sms, totp, hardware
    auth_tokens: list[dict[str, str]] = Field(default_factory=list)
    registration_url: str = ""
    login_url: str = ""
    password_reset_url: str = ""
    auth_observations: list[str] = Field(default_factory=list)


# ── Injection Testing Results ────────────────────────────────────────


class InjectionTestResult(AIOutput):
    """Output from injection testing (SQLi, XSS, command injection, etc.)."""

    endpoint: str
    parameter: str
    vuln_type: str = ""  # sqli, xss, command_injection, ssti, ssrf
    payload_used: str = ""
    evidence: str = ""
    tool_used: str = ""  # sqlmap, dalfox, commix, manual
    tool_output: str = ""
    is_blind: bool = False
    confirmed: bool = False


# ── Business Logic Testing Results ───────────────────────────────────


class WorkflowStep(BaseModel):
    """A step in an application workflow."""

    step_number: int
    action: str
    url: str = ""
    method: str = ""
    expected_state: str = ""
    actual_state: str = ""


class BusinessLogicTestResult(AIOutput):
    """Output from business logic testing."""

    workflow: str  # checkout, registration, password_reset, etc.
    pattern_tested: str = ""  # price_manipulation, step_skip, race_condition, etc.
    steps_tested: list[WorkflowStep] = Field(default_factory=list)
    anomaly_type: str = ""
    evidence: str = ""
    impact: str = ""
    accounts_used: list[str] = Field(default_factory=list)
    is_exploitable: bool = False


# ── Active Validation Results ────────────────────────────────────────


class ActiveValidationResult(AIOutput):
    """Output from active finding validation."""

    finding_id: str
    verified: bool = False
    vuln_type: str = ""
    endpoint: str = ""
    method: str = ""
    tool_used: str = ""
    poc_code: str = ""
    poc_type: str = ""  # python_script, curl, html_page, js_snippet, burp_request
    reproduction_steps: list[str] = Field(default_factory=list)
    verification_method: str = ""  # browser_replay, request_replay, tool_confirm
    original_evidence: str = ""
    verification_evidence: str = ""

    # Shannon-inspired structured verdict
    verdict: Literal[
        "EXPLOITED", "BLOCKED_BY_SECURITY", "OUT_OF_SCOPE", "FALSE_POSITIVE",
    ] = "FALSE_POSITIVE"
    blocked_by: str = ""  # e.g. "Cloudflare WAF", "Rate limiter"
    severity_modifier: float = 1.0  # 1.0 for EXPLOITED, 0.5 for BLOCKED_BY_SECURITY

    @model_validator(mode="after")
    def _sync_verdict_verified(self) -> "ActiveValidationResult":
        """Auto-sync verified flag from verdict."""
        if self.verdict in ("EXPLOITED", "BLOCKED_BY_SECURITY"):
            self.verified = True
        if self.verdict == "EXPLOITED":
            self.severity_modifier = 1.0
        elif self.verdict == "BLOCKED_BY_SECURITY":
            self.severity_modifier = 0.5
        return self


# ── Active Test Reports ──────────────────────────────────────────────


class ActiveTestReport(AIOutput):
    """HackerOne-ready report from active testing."""

    title: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    vuln_type: str
    weakness_cwe: str = ""
    asset: str = ""
    description: str
    impact: str
    steps_to_reproduce: list[str] = Field(default_factory=list)
    poc_code: str = ""
    poc_type: str = ""
    remediation: str = ""
    cvss_score: float = Field(default=0.0, description="CVSS score 0-10")
    cvss_vector: str = ""
    supporting_evidence: list[str] = Field(default_factory=list)


# ── Test Planning ────────────────────────────────────────────────────


class TestPhase(BaseModel):
    """A phase in the active test plan."""

    phase_name: str
    description: str
    priority: int = Field(default=5, description="Priority 1-10")
    estimated_api_calls: int = 0
    estimated_duration_minutes: int = 0
    requires_auth: bool = False
    vuln_classes: list[str] = Field(default_factory=list)


class ActiveTestPlan(AIOutput):
    """Test plan generated by the orchestrator."""

    target_url: str
    phases: list[TestPhase] = Field(default_factory=list)
    estimated_total_api_calls: int = 0
    priority_areas: list[str] = Field(default_factory=list)
    technology_assumptions: list[str] = Field(default_factory=list)
    risk_assessment: str = ""


class ActiveStepDecision(AIOutput):
    """Decision about what to do next during active testing."""

    next_action: Literal[
        "injection_testing", "business_logic_testing",
        "hexstrike_testing",
        "validate_findings", "generate_reports",
        "continue_recon", "continue_current", "cleanup",
    ]
    reasoning: str = ""  # inherited from AIOutput but reused with specific meaning
    fallback_action: str = ""
    areas_exhausted: list[str] = Field(default_factory=list)
    areas_remaining: list[str] = Field(default_factory=list)
    findings_summary: str = ""
    budget_status: str = ""


# ── Session State ────────────────────────────────────────────────────


class ActiveTestSession(BaseModel):
    """Top-level state for an active testing session."""

    session_id: str = ""
    target_url: str
    status: Literal[
        "pending", "running", "paused", "completed", "killed", "failed",
    ] = "pending"
    config: dict[str, Any] = Field(default_factory=dict)
    accounts: list[TestAccount] = Field(default_factory=list)
    findings: list[ActiveTestReport] = Field(default_factory=list)
    started_at: datetime | None = None
    completed_at: datetime | None = None
    budget_spent: float = 0.0
    budget_limit: float = 0.0
    total_requests: int = 0
    total_api_calls: int = 0
    errors: list[str] = Field(default_factory=list)
