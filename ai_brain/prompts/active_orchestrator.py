"""Active testing orchestrator prompts.

1. ActiveTestPlanning (Sonnet) — generates a test plan from passive recon + target URL
2. ActiveNextStep (Sonnet) — decides what to do next during active testing
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.active_schemas import ActiveStepDecision, ActiveTestPlan
from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate


class ActiveTestPlanningPrompt(PromptTemplate):
    """Generate an active test plan from passive recon and target URL."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a senior penetration tester planning an active security assessment.
You have deep experience with OWASP Top 10, business logic vulnerabilities,
authentication/authorization flaws, and web application attack surfaces.
</role>

<task>
Given passive reconnaissance data and target URL, produce a prioritized
test plan. Focus on areas with highest likelihood of real vulnerabilities:
1. Authentication and session management (always test first)
2. Business logic flaws (highest bounty value)
3. Injection points (SQL, XSS, command injection)
4. Access control (IDOR, privilege escalation)
5. API security (if API endpoints discovered)
</task>

<planning_rules>
- Prioritize by expected severity × likelihood
- Budget API calls wisely — skip low-value areas when budget is tight
- Always plan account creation before auth-dependent tests
- Consider technology stack for tool selection (sqlmap for SQL, dalfox for XSS)
- If the target has an API, prioritize API testing over form-based testing
- Plan multi-account tests for access control (need at least 2 accounts)
- Estimate realistic API call counts (Claude calls, not HTTP requests)
</planning_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ActiveTestPlan

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        target_url = kwargs.get("target_url", "")
        passive_recon = kwargs.get("passive_recon", "{}")
        scope_rules = kwargs.get("scope_rules", "")
        budget_remaining = kwargs.get("budget_remaining", 0)
        return f"""<target_url>{target_url}</target_url>

<passive_recon_data>
{passive_recon}
</passive_recon_data>

<scope_rules>
{scope_rules}
</scope_rules>

<budget_remaining_dollars>{budget_remaining}</budget_remaining_dollars>

Generate a prioritized active test plan. Include estimated API calls per phase
and identify the highest-value attack surfaces to test first."""


class ActiveNextStepPrompt(PromptTemplate):
    """Decide the next action during active testing."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a $100K/year bug bounty hunter analyzing a live web application.
You think creatively, notice subtle patterns, and follow your intuition.
Your goal is to find the ONE real vulnerability that pays — not to run
generic scanner passes and call it done.
</role>

<thinking_style>
When deciding what to test next, ask yourself:
1. "What did I notice in the traffic intelligence that looked unusual?"
2. "What parameters accept IDs, prices, or roles that I could manipulate?"
3. "What would I try in Burp Suite's Repeater right now?"
4. "Has the app shown me error messages that leak information?"
5. "Are there multi-step flows I could skip steps in?"
6. "What framework-specific attacks apply?" (Laravel: mass assignment, .env,
   Livewire: state tampering, component manipulation)
7. "If injection found nothing, WHY? Was it WAF? Wrong params? Need auth?"

NEVER give up after one round. Real bugs hide behind:
- Authenticated endpoints (test as logged-in user, not anonymous)
- POST body parameters (not just URL params)
- JSON API endpoints (not just HTML forms)
- Multi-step workflows (skip step 2, repeat step 3)
- Race conditions (send 10 concurrent requests)
- Parameter type confusion (send string where integer expected)
</thinking_style>

<decision_rules>
- You have FULL AUTONOMY to decide the next action
- Study the traffic_intelligence section carefully — it contains real data about
  parameters, timing, cookies, and errors that the automated analysis found
- If injection found 0 findings, dig into WHY: was it WAF blocking? Wrong parameters?
  Try authenticated injection, POST body params, or JSON endpoints
- If you see id_params in traffic intelligence, try IDOR testing
- If you see price_params, test price/quantity manipulation
- If error_patterns show different errors for same endpoint, test enumeration
- IMPORTANT: Do NOT choose validate_findings unless you've tested at least
  injection AND business_logic with at least one meaningful strategy
- When budget is low (< 10%), validate existing findings and report
- Real pentesters run 5-10 rounds of testing, not just 2
</decision_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ActiveStepDecision

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        current_phase = kwargs.get("current_phase", "")
        pages_visited = kwargs.get("pages_visited", 0)
        findings_count = kwargs.get("findings_count", 0)
        unvalidated_count = kwargs.get("unvalidated_count", 0)
        interaction_points_remaining = kwargs.get("interaction_points_remaining", 0)
        traffic_summary = kwargs.get("traffic_summary", "{}")
        budget_spent = kwargs.get("budget_spent", 0)
        budget_limit = kwargs.get("budget_limit", 0)
        errors = kwargs.get("errors", [])
        test_history = kwargs.get("test_history", "None yet")
        decide_count = kwargs.get("decide_count", 0)
        findings_detail = kwargs.get("findings_detail", "[]")
        traffic_intelligence = kwargs.get("traffic_intelligence", "")
        tech_stack = kwargs.get("tech_stack", "[]")
        waf_info = kwargs.get("waf_info", "None detected")
        pipeline_context = kwargs.get("pipeline_context", "")
        return f"""<current_state>
Phase: {current_phase}
Pages visited: {pages_visited}
Total findings: {findings_count}
Unvalidated findings: {unvalidated_count}
Interaction points remaining: {interaction_points_remaining}
Budget spent: ${budget_spent:.2f} / ${budget_limit:.2f}
Decision cycle: {decide_count} (no hard limit — decide based on findings and budget)
</current_state>

<pipeline_context>
{pipeline_context}
</pipeline_context>

<test_history>
{test_history}
</test_history>

<recent_findings_detail>
{findings_detail}
</recent_findings_detail>

<traffic_intelligence>
{traffic_intelligence}
</traffic_intelligence>

<technology_stack>{tech_stack}</technology_stack>

<waf_detection>{waf_info}</waf_detection>

<traffic_summary>
{traffic_summary}
</traffic_summary>

<errors>
{chr(10).join(str(e) for e in errors) if errors else "None"}
</errors>

Available actions:
- injection_testing: Targeted injection testing (SQLi, XSS, command injection) against specific interaction points
- business_logic_testing: Business logic flaw testing (IDOR, race conditions, price manipulation, workflow bypass)
- hexstrike_testing: Run hexstrike's 150+ security tools (nuclei, nmap, ffuf, gobuster, katana, wafw00f) for broad automated vulnerability scanning. Use when you need wide coverage beyond targeted injection/business_logic testing.
- validate_findings: Validate and verify raw findings with replay/PoC
- generate_reports: Generate HackerOne-format reports for confirmed findings
- continue_recon: Re-run reconnaissance to discover more attack surface
- continue_current: Continue current testing strategy
- cleanup: Finish testing and clean up

Study the pipeline_context and traffic_intelligence sections above carefully.
What has each agent found so far? What parameters, timing patterns, error messages,
or cookie issues jump out at you? What would a skilled bug bounty hunter try next?
Decide the next action."""
