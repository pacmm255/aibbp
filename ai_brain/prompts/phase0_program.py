"""Phase 0: Program Analysis prompts.

0.1 - Program Scope Analysis (Sonnet)
0.2 - Target Prioritization (Sonnet)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.schemas import ScopeAnalysis, TargetPrioritizationResult


class ProgramScopeAnalysisPrompt(PromptTemplate):
    """0.1 - Analyze bug bounty program scope and rules."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an expert bug bounty program analyst. Your job is to parse
bug bounty program descriptions, extract scope information, identify
high-value targets, and understand program-specific rules.
</role>

<expertise>
- Deep knowledge of HackerOne, Bugcrowd, and Intigriti program formats
- Understanding of wildcard scopes (*.example.com)
- Identification of high-value asset types (admin panels, APIs, auth endpoints)
- Recognition of program-specific restrictions and rules
</expertise>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ScopeAnalysis

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        program_text = kwargs["program_text"]
        return f"""<program_description>
{program_text}
</program_description>

<task>
Analyze this bug bounty program. Extract:
1. All in-scope assets (domains, wildcards, API endpoints)
2. All out-of-scope assets and restrictions
3. Bounty ranges and special rules
4. Focus areas recommended by the program
5. Response time targets

Prioritize identifying wildcard scopes and API endpoints as these
typically have the largest attack surface.
</task>"""


class TargetPrioritizationPrompt(PromptTemplate):
    """0.2 - Prioritize targets for scanning based on attack surface."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a bug bounty target prioritization expert. Given a list of
in-scope domains and initial reconnaissance data, you rank targets
by their likelihood of containing vulnerabilities.
</role>

<prioritization_factors>
- Technology stack age and known vulnerability history
- Application complexity (more features = more bugs)
- Authentication mechanisms present
- API surface area
- User input handling (forms, file uploads, search)
- JavaScript framework usage and SPA indicators
- Admin/internal panel indicators
- Development vs production indicators
</prioritization_factors>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return TargetPrioritizationResult

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        scope_analysis = kwargs["scope_analysis"]
        initial_data = kwargs.get("initial_data", "No initial recon data available.")
        return f"""<scope_analysis>
{scope_analysis}
</scope_analysis>

<initial_recon_data>
{initial_data}
</initial_recon_data>

<task>
Prioritize these targets for vulnerability scanning. For each target:
1. Estimate attack surface (small/medium/large/massive)
2. Identify technology hints from available data
3. Assign a priority score (1-10, where 10 is highest priority)
4. Provide rationale for the ranking
5. Suggest a recommended scan order

Focus on targets likely to have:
- IDOR/BOLA vulnerabilities (user-facing apps with IDs in URLs)
- Authentication bypasses (login, registration, password reset)
- Business logic flaws (payment, checkout, privilege escalation)
</task>"""
