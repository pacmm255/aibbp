"""Pydantic output schemas for all Claude API structured outputs.

Every schema includes:
- confidence (0-100): How confident the AI is in the finding
- reasoning: Explanation of the analysis
- uncertainties: List of things the AI is unsure about
"""

from __future__ import annotations

from typing import Literal
from pydantic import BaseModel, Field


# ── Base Schemas ──────────────────────────────────────────────────────


class AIOutput(BaseModel):
    """Base for all AI brain outputs."""

    confidence: int = Field(default=50, description="Confidence score 0-100")
    reasoning: str = Field(default="", description="Explanation of analysis reasoning")
    uncertainties: list[str] = Field(
        default_factory=list, description="Things the AI is unsure about"
    )


class VulnFinding(AIOutput):
    """Base for all vulnerability findings."""

    vuln_type: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str
    endpoint: str = ""
    parameter: str = ""
    evidence: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    cvss_estimate: float = Field(default=0.0, description="CVSS estimate 0-10")
    false_positive_indicators: list[str] = Field(default_factory=list)


# ── Phase 0: Program Analysis ────────────────────────────────────────


class ScopeAsset(BaseModel):
    """A single scoped asset."""

    domain: str
    wildcard: bool = False
    asset_type: str = "web"  # web, api, mobile, etc.
    notes: str = ""


class ScopeAnalysis(AIOutput):
    """Output from 0.1 Program Scope Analysis."""

    program_name: str
    platform: str
    in_scope_assets: list[ScopeAsset]
    out_of_scope_assets: list[str]
    bounty_range: str = ""
    special_rules: list[str] = Field(default_factory=list)
    response_targets: list[str] = Field(default_factory=list)
    focus_areas: list[str] = Field(default_factory=list)


class TargetPriority(BaseModel):
    """Priority ranking for a single target."""

    domain: str
    priority: int = Field(default=5, description="Priority 1-10")
    attack_surface_estimate: str  # small, medium, large, massive
    technology_hints: list[str] = Field(default_factory=list)
    rationale: str = ""


class TargetPrioritizationResult(AIOutput):
    """Output from 0.2 Target Prioritization."""

    targets: list[TargetPriority]
    recommended_scan_order: list[str]
    estimated_total_time_hours: float = 0


# ── Phase 1: Reconnaissance ──────────────────────────────────────────


class SubdomainClassification(BaseModel):
    """Classification of a single subdomain."""

    hostname: str
    category: str  # production, staging, dev, admin, api, cdn, internal
    interest_level: int = Field(default=5, description="Interest level 1-10")
    technologies: list[str] = Field(default_factory=list)
    notes: str = ""


class SubdomainClassificationResult(AIOutput):
    """Output from 1.1 Subdomain Classification."""

    classifications: list[SubdomainClassification]
    high_value_targets: list[str]
    potential_admin_panels: list[str] = Field(default_factory=list)
    api_endpoints: list[str] = Field(default_factory=list)


class JSEndpoint(BaseModel):
    """An API endpoint extracted from JavaScript."""

    url: str
    method: str = "GET"
    parameters: list[str] = Field(default_factory=list)
    auth_required: bool = False
    notes: str = ""


class JSSecret(BaseModel):
    """A potential secret found in JavaScript."""

    type: str  # api_key, aws_key, token, password, etc.
    value_preview: str  # First/last chars only
    file_url: str
    line_hint: str = ""
    is_likely_real: bool = False


class JSAnalysisResult(AIOutput):
    """Output from 1.3 JS Analysis."""

    endpoints: list[JSEndpoint]
    secrets: list[JSSecret]
    frameworks_detected: list[str] = Field(default_factory=list)
    interesting_patterns: list[str] = Field(default_factory=list)


class APISwaggerResult(AIOutput):
    """Output from 1.4 API/Swagger Analysis."""

    base_url: str = ""
    auth_scheme: str = ""  # bearer, api_key, oauth2, basic, none
    endpoints: list[JSEndpoint]
    rate_limited: bool = False
    versioned: bool = False
    interesting_params: list[str] = Field(default_factory=list)


class ReconCorrelation(AIOutput):
    """Output from 1.5 Recon Correlation."""

    attack_surface_summary: str
    high_value_targets: list[str]
    technology_stack: dict[str, list[str]] = Field(default_factory=dict)
    shared_infrastructure: list[str] = Field(default_factory=list)
    recommended_test_areas: list[str] = Field(default_factory=list)
    potential_vuln_classes: list[str] = Field(default_factory=list)


class CustomWordlist(AIOutput):
    """Output from 1.6 Custom Wordlist Generation."""

    words: list[str]
    categories: dict[str, list[str]] = Field(default_factory=dict)
    generation_rationale: str = ""


# ── Phase 2: Vulnerability Detection ─────────────────────────────────


class IDORCandidate(BaseModel):
    """A single IDOR/BOLA candidate."""

    endpoint: str
    parameter: str
    id_type: str  # sequential, uuid, encoded
    access_pattern: str  # direct, indirect
    evidence: str


class IDORScanResult(AIOutput):
    """Output from 2.1 IDOR Detection."""

    candidates: list[IDORCandidate]
    findings: list[VulnFinding] = Field(default_factory=list)
    tested_endpoints: int = 0


class AuthBypassFinding(VulnFinding):
    """Output from 2.2 Auth Flow Analysis."""

    vuln_type: str = "auth_bypass"
    bypass_technique: str = ""  # token_manipulation, path_traversal, role_escalation
    auth_mechanism: str = ""  # jwt, session, oauth
    affected_roles: list[str] = Field(default_factory=list)


class BusinessLogicFinding(VulnFinding):
    """Output from 2.3 Business Logic Detection."""

    vuln_type: str = "business_logic"
    workflow: str = ""  # checkout, registration, password_reset, etc.
    exploit_steps: list[str] = Field(default_factory=list)
    business_impact: str = ""


class CORSFinding(VulnFinding):
    """Output from 2.4 CORS Detection."""

    vuln_type: str = "cors_misconfiguration"
    origin_tested: str = ""
    acao_header: str = ""  # Access-Control-Allow-Origin value
    acac_header: bool = False  # Access-Control-Allow-Credentials
    cors_type: str = ""  # wildcard, null_origin, reflected, subdomain


class GraphQLFinding(VulnFinding):
    """Output from 2.5 GraphQL Detection."""

    vuln_type: str = "graphql"
    query_type: str = ""  # introspection, batching, depth_limit, injection
    schema_exposed: bool = False
    interesting_types: list[str] = Field(default_factory=list)
    interesting_mutations: list[str] = Field(default_factory=list)


class MassAssignmentFinding(VulnFinding):
    """Output from 2.6 Mass Assignment Detection."""

    vuln_type: str = "mass_assignment"
    writable_fields: list[str] = Field(default_factory=list)
    protected_fields_bypassed: list[str] = Field(default_factory=list)
    request_method: str = ""


class SSRFFinding(VulnFinding):
    """Output from 2.7 SSRF Detection."""

    vuln_type: str = "ssrf"
    ssrf_type: str = ""  # full, blind, partial
    injection_point: str = ""  # url_param, header, body, file_upload
    protocols_tested: list[str] = Field(default_factory=list)
    internal_access: bool = False


class JWTOAuthFinding(VulnFinding):
    """Output from 2.8 JWT/OAuth Detection."""

    vuln_type: str = "jwt_oauth"
    token_type: str = ""  # jwt, oauth2, api_key
    weakness: str = ""  # none_alg, weak_secret, missing_validation, token_leak
    algorithm: str = ""
    claims_analyzed: list[str] = Field(default_factory=list)


class ErrorMessageFinding(VulnFinding):
    """Output from 2.9 Error Message Analysis."""

    vuln_type: str = "information_disclosure"
    error_type: str = ""  # stack_trace, debug_info, version_leak, path_disclosure
    information_leaked: list[str] = Field(default_factory=list)
    exploitability: str = ""  # direct, indirect, informational


# ── Phase 3: Validation ──────────────────────────────────────────────


class FPVulnAssessment(BaseModel):
    """Assessment of a single finding for false positives."""

    vuln_id: str
    is_false_positive: bool
    fp_reason: str = ""
    adjusted_confidence: int = Field(default=50, description="Adjusted confidence 0-100")
    additional_evidence_needed: list[str] = Field(default_factory=list)


class FalsePositiveFilterResult(AIOutput):
    """Output from 3.1 False Positive Filter."""

    assessments: list[FPVulnAssessment]
    total_reviewed: int = 0
    false_positives_found: int = 0
    true_positives_found: int = 0


class DifferentialAnalysis(AIOutput):
    """Output from 3.2 Differential Analysis."""

    baseline_behavior: str
    attack_behavior: str
    meaningful_differences: list[str]
    is_vulnerable: bool = False
    evidence_quality: str = ""  # strong, moderate, weak, inconclusive


class ExploitabilityAssessment(AIOutput):
    """Output from 3.3 Exploitability Assessment."""

    vuln_id: str
    is_exploitable: bool
    exploit_complexity: str = ""  # low, medium, high
    prerequisites: list[str] = Field(default_factory=list)
    real_world_impact: str = ""
    proof_of_concept_steps: list[str] = Field(default_factory=list)


# ── Phase 4: Attack Chaining ─────────────────────────────────────────


class ChainStep(BaseModel):
    """A single step in an attack chain."""

    step_number: int
    vuln_id: str
    action: str
    result: str
    prerequisites: list[str] = Field(default_factory=list)


class AttackChain(BaseModel):
    """A chain of vulnerabilities for higher impact."""

    title: str
    description: str
    steps: list[ChainStep]
    combined_severity: Literal["medium", "high", "critical"]
    combined_cvss: float = Field(default=0.0, description="Combined CVSS 0-10")
    business_impact: str
    likelihood: str  # likely, possible, theoretical


class AttackChainResult(AIOutput):
    """Output from 4.1 Attack Chain Discovery."""

    chains: list[AttackChain]
    unchainable_vulns: list[str] = Field(default_factory=list)


# ── Phase 5: Reporting ────────────────────────────────────────────────


class CVSSMetric(BaseModel):
    """CVSS v3.1 metric values."""

    attack_vector: str  # N, A, L, P
    attack_complexity: str  # L, H
    privileges_required: str  # N, L, H
    user_interaction: str  # N, R
    scope: str  # U, C
    confidentiality: str  # N, L, H
    integrity: str  # N, L, H
    availability: str  # N, L, H


class CVSSScore(AIOutput):
    """Output from 5.2 CVSS Scoring."""

    score: float = Field(default=0.0, description="CVSS score 0-10")
    vector_string: str
    severity: Literal["none", "low", "medium", "high", "critical"]
    metrics: CVSSMetric
    justification: str


class VulnReport(AIOutput):
    """Output from 5.1 Report Generation - HackerOne-ready report."""

    title: str
    severity: Literal["low", "medium", "high", "critical"]
    weakness_type: str  # CWE identifier
    asset: str  # Affected domain/URL
    summary: str
    description: str
    steps_to_reproduce: list[str]
    impact_statement: str
    remediation: str
    supporting_material: list[str] = Field(default_factory=list)
    cvss: CVSSScore | None = None


# ── Phase 6: Strategy ────────────────────────────────────────────────


class StrategyDecision(AIOutput):
    """Output from 6.1 Continue vs Move On."""

    decision: Literal["continue", "pivot", "move_on"]
    current_target: str
    next_action: str
    rationale: str
    findings_so_far: int = 0
    time_spent_minutes: float = 0
    estimated_remaining_value: str = ""  # high, medium, low, exhausted
    suggested_next_target: str = ""
