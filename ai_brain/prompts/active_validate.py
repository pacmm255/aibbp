"""Active validation prompts.

12. ActiveFindingVerification (Sonnet) — re-verify findings independently
13. ActivePoCGeneration (Sonnet) — generate PoC code for verified findings
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ai_brain.active_schemas import ActiveValidationResult
from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate


class PoCCode(BaseModel):
    """Generated proof-of-concept code."""

    code: str
    language: str = "python"  # python, bash, curl, html, javascript
    description: str = ""
    setup_steps: list[str] = Field(default_factory=list)
    expected_output: str = ""
    cleanup_steps: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)


class ActiveFindingVerificationPrompt(PromptTemplate):
    """Re-verify a finding independently to confirm it's real."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a vulnerability verification specialist. You independently re-test
findings to confirm they are real vulnerabilities, not false positives.
Your verification must be rigorous — only mark as verified if you can
independently reproduce the issue.
</role>

<verification_rules>
- Re-execute the finding using a different method than the original discovery
- For XSS: navigate to URL with payload, verify JS execution (check DOM changes)
- For SQLi: send a single confirming request (not full sqlmap re-scan)
- For IDOR: verify with a fresh account that shouldn't have access
- For SSRF: replay request, check for internal content, cloud metadata, timing differentials
- For business logic: replay exact sequence, confirm same anomalous result
- For command injection: verify with a time-based payload (sleep)
- Record exact verification evidence (response content, status codes, timing)
</verification_rules>

<verdict_classification>
You MUST set the "verdict" field to one of these four values:
- EXPLOITED: Active exploitation succeeded with concrete evidence (response data,
  status code changes, timing proof). This is the strongest signal.
- BLOCKED_BY_SECURITY: The vulnerability exists in the code but a security control
  (WAF, rate limiter, CSP, input filter) prevented exploitation. Set "blocked_by"
  to the control name (e.g. "Cloudflare WAF", "CSP header", "Rate limiter").
- OUT_OF_SCOPE: Technically correct finding but not security-relevant for a bug
  bounty (self-XSS, CSRF on logout, missing headers on non-sensitive pages,
  clickjacking on login form).
- FALSE_POSITIVE: The vulnerability does not actually exist. The original detection
  was wrong, or the behavior is intended/expected.

The "verified" field is auto-set: EXPLOITED and BLOCKED_BY_SECURITY → verified=true.
</verdict_classification>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ActiveValidationResult

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        finding = kwargs.get("finding", "{}")
        evidence = kwargs.get("evidence", "")
        target_url = kwargs.get("target_url", "")
        accounts = kwargs.get("accounts", "[]")
        waf_info = kwargs.get("waf_info", "None detected")
        pipeline_context = kwargs.get("pipeline_context", "")
        return f"""<finding_to_verify>
{finding}
</finding_to_verify>

<original_evidence>
{evidence}
</original_evidence>

<target_url>{target_url}</target_url>

<waf_info>{waf_info}</waf_info>

<available_accounts>
{accounts}
</available_accounts>

<pipeline_context>
{pipeline_context}
</pipeline_context>

Independently verify this finding. Set the verdict field to EXPLOITED,
BLOCKED_BY_SECURITY, OUT_OF_SCOPE, or FALSE_POSITIVE based on your analysis."""


class ActivePoCGenerationPrompt(PromptTemplate):
    """Generate proof-of-concept code for a verified finding."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a security researcher who writes clean, reliable proof-of-concept
code. Your PoCs are designed to demonstrate vulnerabilities without causing
damage, and they are clear enough for another engineer to understand and
reproduce.
</role>

<poc_rules>
- Generate a self-contained PoC that demonstrates the vulnerability
- Prefer Python with requests library for HTTP-based PoCs
- For XSS: generate an HTML page that triggers the payload
- For SQLi: generate a Python script using requests
- For IDOR: generate a script that accesses another user's resource
- For business logic: generate a step-by-step script
- Include comments explaining each step
- Include a verification check (assert or print confirmation)
- Do NOT include destructive operations (DROP TABLE, rm -rf, etc.)
- Include setup instructions (pip install, environment variables)
- Make the PoC idempotent — running it twice should produce the same result
- Sanitize credentials — use placeholder values with instructions to replace
</poc_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return PoCCode

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        finding = kwargs.get("finding", "{}")
        target_url = kwargs.get("target_url", "")
        evidence = kwargs.get("evidence", "")
        poc_type = kwargs.get("poc_type", "python")
        return f"""<verified_finding>
{finding}
</verified_finding>

<target_url>{target_url}</target_url>

<evidence>
{evidence}
</evidence>

<poc_type>{poc_type}</poc_type>

Generate a clean, self-contained PoC that demonstrates this vulnerability.
Include setup instructions and a verification check."""
