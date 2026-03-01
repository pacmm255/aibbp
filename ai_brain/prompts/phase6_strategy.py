"""Phase 6: Strategy prompts.

6.1 - Continue vs Move On (Sonnet)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.schemas import StrategyDecision


class ContinueVsMoveOnPrompt(PromptTemplate):
    """6.1 - Decide whether to continue testing current target or move on."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a bug bounty strategy advisor. You make resource allocation
decisions: should we keep testing the current target, pivot to a
different approach, or move to the next target?
</role>

<decision_framework>
CONTINUE if:
- High-value findings are emerging (rate > 1 finding per 20 minutes)
- Untested vulnerability classes remain for this target
- Evidence suggests deeper bugs exist (e.g., found IDOR, likely more)
- Budget utilization for this target is below 50%

PIVOT if:
- Current approach is stalling but target still has potential
- Switch from automated scanning to manual-style testing
- Try a different vulnerability class on the same target
- Explore a different endpoint or feature area

MOVE ON if:
- Finding rate has dropped below 1 per 60 minutes
- Target budget is nearly exhausted
- All major vulnerability classes have been tested
- Target appears well-secured based on evidence
- Estimated remaining value is "low" or "exhausted"

ALWAYS MOVE ON if:
- Total budget is in emergency (< 15% remaining)
- Time limit is approaching
- No findings after 30+ minutes of testing
</decision_framework>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return StrategyDecision

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        current_target = kwargs["current_target"]
        findings_summary = kwargs.get("findings_summary", "")
        budget_status = kwargs.get("budget_status", "")
        time_spent = kwargs.get("time_spent", "")
        remaining_targets = kwargs.get("remaining_targets", "")
        context = kwargs.get("context", "")
        return f"""<current_state>
<current_target>{current_target}</current_target>

<findings_summary>
{findings_summary}
</findings_summary>

<budget_status>
{budget_status}
</budget_status>

<time_spent>{time_spent}</time_spent>

<remaining_targets>
{remaining_targets}
</remaining_targets>

<breadcrumb_context>
{context}
</breadcrumb_context>
</current_state>

<task>
Make a strategic decision:
1. Evaluate the current target's remaining potential
2. Assess finding rate and trend
3. Check budget and time constraints
4. Compare current target value vs remaining targets
5. Decide: continue, pivot, or move_on

Provide:
- decision: continue/pivot/move_on
- next_action: What to do next
- rationale: Why this decision
- estimated_remaining_value: high/medium/low/exhausted
- suggested_next_target: If moving on, which target next
</task>"""
