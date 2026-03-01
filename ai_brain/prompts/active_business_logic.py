"""Active business logic testing prompts.

9. ActiveWorkflowMapping (Opus) — map workflows and generate vulnerability hypotheses
10. ActiveStateAnalysis (Opus) — identify anomalies in state transitions
11. ActiveBusinessExploitDesign (Opus) — design multi-step exploit sequences
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ai_brain.active_schemas import BusinessLogicTestResult, WorkflowStep
from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate


class WorkflowMap(BaseModel):
    """Mapped application workflow with vulnerability hypotheses."""

    workflow_name: str = "main"
    steps: list[WorkflowStep] = Field(default_factory=list)
    state_transitions: list[dict[str, str]] = Field(default_factory=list)
    vulnerability_hypotheses: list[dict[str, str]] = Field(default_factory=list)
    test_sequences: list[list[str]] = Field(default_factory=list)
    critical_state_points: list[str] = Field(default_factory=list)
    notes: str = ""


class StateAnalysisResult(BaseModel):
    """Analysis of state transition anomalies."""

    anomalies: list[dict[str, str]] = Field(default_factory=list)
    timing_issues: list[dict[str, str]] = Field(default_factory=list)
    race_condition_candidates: list[str] = Field(default_factory=list)
    state_bypass_opportunities: list[str] = Field(default_factory=list)
    recommended_test_sequences: list[list[str]] = Field(default_factory=list)
    notes: str = ""


class ExploitDesign(BaseModel):
    """Multi-step exploit sequence for a business logic flaw."""

    exploit_name: str = "unknown"
    pattern: str = ""  # price_manipulation, step_skip, race_condition, etc.
    preconditions: list[str] = Field(default_factory=list)
    steps: list[dict[str, str]] = Field(default_factory=list)
    accounts_needed: list[str] = Field(default_factory=list)
    expected_impact: str = ""
    confidence: int = Field(default=50, description="Confidence 0-100")
    notes: str = ""


class ActiveWorkflowMappingPrompt(PromptTemplate):
    """Map application workflows and generate vulnerability hypotheses."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a world-class business logic vulnerability researcher. You excel at
understanding application workflows, identifying state machines, and generating
novel vulnerability hypotheses that automated scanners miss entirely.
</role>

<business_logic_patterns>
FINANCIAL:
- Price manipulation (modify price client-side, negative quantities, currency rounding)
- Coupon/discount abuse (stack coupons, apply after checkout, reuse one-time codes)
- Payment flow bypass (skip payment step, modify payment amount after auth)
- Refund abuse (refund more than paid, partial refund to different payment method)

ACCESS CONTROL:
- IDOR (access other users' resources via ID manipulation)
- Horizontal escalation (user A performs actions as user B)
- Vertical escalation (user accesses admin functionality)
- Forced browsing (access restricted pages by direct URL)

WORKFLOW:
- Step skipping (jump from step 1 to step 4, bypassing validation)
- Parameter pollution (duplicate params with conflicting values)
- Race conditions (concurrent requests to exploit TOCTOU gaps)
- State manipulation (tamper with client-side state tokens)
- Replay attacks (reuse tokens, OTPs, or session data)

AUTH/SESSION:
- Session fixation (set known session ID before auth)
- Token reuse (use expired/revoked tokens)
- MFA bypass (skip MFA step, brute force codes)
- Password reset flaws (predictable tokens, token leakage, no expiry)
</business_logic_patterns>

<bug_hunter_approach>
Think like a bug bounty hunter, not a scanner:
1. Multi-step flows — POST directly to step 3 without steps 1-2
2. Price/quantity params — negative quantity, zero price, change plan_id
3. ID params — access /api/users/43 when you are user 42
4. Livewire state — modify computed values (totals, permissions) in JSON payload
5. CSRF token lifecycle — if tokens don't rotate, reuse CAPTCHA solutions
6. Error message differences — "invalid email" vs "wrong password" = enumeration
7. File upload — try uploading .php, .phtml, .svg files as avatars/attachments
8. Race conditions — submit the same coupon/action 10 times concurrently
9. Parameter type confusion — send array where string expected, object where int
10. Mass assignment — add extra fields (role, is_admin, verified) to registration/update forms
</bug_hunter_approach>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return WorkflowMap

    @property
    def model_tier(self) -> TaskTier:
        return "critical"

    def user_template(self, **kwargs: Any) -> str:
        sitemap = kwargs.get("sitemap", "[]")
        forms = kwargs.get("forms", "[]")
        api_endpoints = kwargs.get("api_endpoints", "[]")
        traffic_summary = kwargs.get("traffic_summary", "[]")
        pipeline_context = kwargs.get("pipeline_context", "")
        return f"""<pipeline_context>
{pipeline_context}
</pipeline_context>

<application_sitemap>
{sitemap}
</application_sitemap>

<forms>
{forms}
</forms>

<api_endpoints>
{api_endpoints}
</api_endpoints>

<observed_state_transitions>
{traffic_summary}
</observed_state_transitions>

Map all application workflows as state machines. For each workflow, generate
vulnerability hypotheses and test sequences. Prioritize by potential impact."""


class ActiveStateAnalysisPrompt(PromptTemplate):
    """Analyze state transitions for anomalies and race conditions."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a state machine analysis specialist. You examine application state
transitions to find timing issues, race conditions, and state bypass
opportunities.
</role>

<analysis_rules>
- Compare expected vs actual state after each transition
- Look for missing server-side validation (state only checked client-side)
- Identify TOCTOU (time-of-check-to-time-of-use) windows
- Flag transitions that don't verify the previous state
- Assess timing: do fast requests bypass rate limits or state checks?
- Check if state tokens are predictable or reusable
- Identify concurrent request opportunities (race conditions)
</analysis_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return StateAnalysisResult

    @property
    def model_tier(self) -> TaskTier:
        return "critical"

    def user_template(self, **kwargs: Any) -> str:
        workflow = kwargs.get("workflow", "")
        transitions = kwargs.get("transitions", "[]")
        timing_data = kwargs.get("timing_data", "[]")
        request_details = kwargs.get("request_details", "[]")
        return f"""<workflow_name>{workflow}</workflow_name>

<state_transitions>
{transitions}
</state_transitions>

<timing_data>
{timing_data}
</timing_data>

<request_details>
{request_details}
</request_details>

Analyze these state transitions for anomalies, timing issues, and race
condition opportunities. Recommend specific test sequences to confirm."""


class ActiveBusinessExploitDesignPrompt(PromptTemplate):
    """Design multi-step exploit sequences for business logic flaws."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an exploit designer for business logic vulnerabilities. You create
precise, multi-step exploit sequences using browser automation and HTTP
requests. Your exploits are reliable and reproducible.
</role>

<exploit_design_rules>
- Each step must specify: HTTP method, URL, headers, body, and expected response
- Use exact browser automation commands (navigate, click selector, fill field)
- Include timing between steps if race conditions are involved
- Specify which account/context to use for each step
- Include verification step to confirm the exploit worked
- Design for reproducibility — another tester should be able to follow these steps
- Assess expected impact: data exposure, financial loss, privilege escalation
</exploit_design_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ExploitDesign

    @property
    def model_tier(self) -> TaskTier:
        return "critical"

    @property
    def max_tokens(self) -> int | None:
        return 8192

    def user_template(self, **kwargs: Any) -> str:
        anomaly = kwargs.get("anomaly", "")
        workflow_map = kwargs.get("workflow_map", "{}")
        accounts = kwargs.get("accounts", "[]")
        target_url = kwargs.get("target_url", "")
        return f"""<identified_anomaly>
{anomaly}
</identified_anomaly>

<workflow_map>
{workflow_map}
</workflow_map>

<available_accounts>
{accounts}
</available_accounts>

<target_base_url>{target_url}</target_base_url>

Design a multi-step exploit sequence for this anomaly. Include exact requests,
browser actions, and verification steps. Specify which account to use for each step."""
