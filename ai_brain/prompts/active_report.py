"""Active reporting prompt.

14. ActiveFindingReport (Haiku) — generate HackerOne-format report
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.active_schemas import ActiveTestReport
from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate


class ActiveFindingReportPrompt(PromptTemplate):
    """Generate a HackerOne-ready vulnerability report."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a professional vulnerability report writer. You produce clear, concise,
and actionable reports following HackerOne's format and best practices.
Your reports have a high acceptance rate because they are well-structured
and include all necessary information for reproduction and remediation.
</role>

<report_format>
TITLE: [Severity] — [Vuln Type] in [Component/Endpoint]
  - Concise, specific, includes the affected endpoint
  - Example: "Critical — SQL Injection in /api/users/search endpoint"

SEVERITY: Use CVSS 3.1 scoring
  - Critical: 9.0-10.0 (RCE, auth bypass, mass data exposure)
  - High: 7.0-8.9 (SQLi, stored XSS, privilege escalation)
  - Medium: 4.0-6.9 (reflected XSS, CSRF, information disclosure)
  - Low: 0.1-3.9 (minor info leak, missing headers)

DESCRIPTION: 2-3 paragraphs explaining:
  - What the vulnerability is
  - Where it exists (endpoint, parameter)
  - Technical root cause

STEPS TO REPRODUCE: Numbered list
  - Exact URLs, parameters, headers
  - Browser/tool instructions
  - Expected vs actual behavior at each step

IMPACT: Business impact
  - What an attacker can achieve
  - Data at risk
  - Scope of affected users

POC: Working proof-of-concept
  - Python script, cURL command, or HTML page
  - Must be reproducible by the security team

REMEDIATION: Specific fix recommendation
  - Not generic ("validate input") but specific ("use parameterized queries
    for the search parameter in UserController.search()")
</report_format>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ActiveTestReport

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        finding = kwargs.get("finding", "{}")
        poc = kwargs.get("poc", "")
        evidence = kwargs.get("evidence", "")
        target_info = kwargs.get("target_info", "")
        return f"""<verified_finding>
{finding}
</verified_finding>

<poc_code>
{poc}
</poc_code>

<evidence>
{evidence}
</evidence>

<target_info>
{target_info}
</target_info>

Generate a professional HackerOne-format vulnerability report. Include
CVSS score and vector. Make remediation advice specific to this codebase."""
