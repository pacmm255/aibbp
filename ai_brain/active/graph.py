"""LangGraph subgraph for active testing.

Defines ActiveTestState and 10 graph nodes that drive the active testing
lifecycle: plan → recon → auth → {injection, business_logic} → validate →
report → cleanup. Conditional edges handle budget exhaustion, kill switch,
and AI-driven next-step decisions.
"""

from __future__ import annotations

import asyncio
import copy
import json
import operator
import os
import time
from typing import Annotated, Any, TypedDict
from urllib.parse import urlparse

import structlog
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph

from ai_brain.active.agents import create_active_agent
from ai_brain.errors import BudgetExhausted
from ai_brain.active_schemas import (
    ActiveReconResult,
    ActiveStepDecision,
    ActiveTestPlan,
    ActiveTestReport,
    ActiveValidationResult,
    InteractionPoint,
    TestAccount,
)
from ai_brain.prompts.active_orchestrator import (
    ActiveNextStepPrompt,
    ActiveTestPlanningPrompt,
)

logger = structlog.get_logger()

# Path for incremental findings persistence (survives graph crashes)
_INCREMENTAL_FINDINGS_PATH = "/tmp/aibbp_incremental_findings.json"


def _save_incremental(state: ActiveTestState) -> None:
    """Persist current findings to disk incrementally.

    Called after validate_findings and generate_reports so that even
    if the graph crashes later, findings are not lost.
    """
    try:
        data = {
            "target_url": state.get("target_url", ""),
            "session_id": state.get("session_id", ""),
            "budget_spent": state.get("budget_spent", 0),
            "budget_limit": state.get("budget_limit", 0),
            "raw_findings": _serialize(state.get("raw_findings", [])),
            "validated_findings": _serialize(state.get("validated_findings", [])),
            "reports": _serialize(state.get("reports", [])),
            "errors": list(state.get("errors", []))[-50:],
            "phase": state.get("phase", ""),
        }
        with open(_INCREMENTAL_FINDINGS_PATH, "w") as f:
            json.dump(data, f, indent=2, default=str)
        logger.info("incremental_save", path=_INCREMENTAL_FINDINGS_PATH,
                     raw=len(state.get("raw_findings", [])),
                     validated=len(state.get("validated_findings", [])),
                     reports=len(state.get("reports", [])))
    except Exception as e:
        logger.warning("incremental_save_failed", error=str(e))


def _save_report_files(state: ActiveTestState) -> str:
    """Save each report as a separate markdown file.

    Returns the reports directory path.
    """
    reports = state.get("reports", [])
    if not reports:
        return ""

    target_url = state.get("target_url", "unknown")
    ts = time.strftime("%Y%m%d_%H%M%S")
    reports_dir = f"/tmp/aibbp_reports_{ts}"
    os.makedirs(reports_dir, exist_ok=True)

    for i, report in enumerate(reports, 1):
        r = report.model_dump() if hasattr(report, "model_dump") else report if isinstance(report, dict) else {"raw": str(report)}
        title = r.get("title", f"Finding {i}")
        severity = r.get("severity", "unknown")
        vuln_type = r.get("vuln_type", "unknown")
        cwe = r.get("weakness_cwe", "")
        asset = r.get("asset", target_url)
        description = r.get("description", "")
        impact = r.get("impact", "")
        steps = r.get("steps_to_reproduce", [])
        poc_code = r.get("poc_code", "")
        poc_type = r.get("poc_type", "python")
        remediation = r.get("remediation", "")
        cvss_score = r.get("cvss_score", 0)
        cvss_vector = r.get("cvss_vector", "")
        evidence = r.get("supporting_evidence", [])

        # Build markdown
        md_lines = [
            f"# {title}",
            "",
            f"**Severity:** {severity.upper()}",
            f"**Vulnerability Type:** {vuln_type}",
        ]
        if cwe:
            md_lines.append(f"**CWE:** {cwe}")
        if cvss_score:
            md_lines.append(f"**CVSS Score:** {cvss_score}")
        if cvss_vector:
            md_lines.append(f"**CVSS Vector:** {cvss_vector}")
        md_lines.append(f"**Asset:** {asset}")
        md_lines.append("")

        md_lines.append("## Description")
        md_lines.append("")
        md_lines.append(description)
        md_lines.append("")

        if impact:
            md_lines.append("## Impact")
            md_lines.append("")
            md_lines.append(impact)
            md_lines.append("")

        if steps:
            md_lines.append("## Steps to Reproduce")
            md_lines.append("")
            for j, step in enumerate(steps, 1):
                md_lines.append(f"{j}. {step}")
            md_lines.append("")

        if poc_code:
            md_lines.append("## Proof of Concept")
            md_lines.append("")
            md_lines.append(f"```{poc_type}")
            md_lines.append(poc_code)
            md_lines.append("```")
            md_lines.append("")

        if evidence:
            md_lines.append("## Supporting Evidence")
            md_lines.append("")
            for ev in evidence:
                md_lines.append(f"- {ev}")
            md_lines.append("")

        if remediation:
            md_lines.append("## Remediation")
            md_lines.append("")
            md_lines.append(remediation)
            md_lines.append("")

        # Write file — use sanitized title for filename
        safe_title = "".join(c if c.isalnum() or c in " -_" else "" for c in title)[:60].strip().replace(" ", "_")
        filename = f"{i:02d}_{severity}_{safe_title}.md"
        filepath = os.path.join(reports_dir, filename)
        try:
            with open(filepath, "w") as f:
                f.write("\n".join(md_lines))
            logger.info("report_file_saved", path=filepath)
        except Exception as e:
            logger.warning("report_file_save_failed", error=str(e))

    return reports_dir


# ── State Definition ─────────────────────────────────────────────────


class ActiveTestState(TypedDict, total=False):
    """State for the active testing subgraph."""

    # Input
    target_url: str
    session_id: str
    passive_recon: dict[str, Any]
    config: dict[str, Any]

    # Planning
    test_plan: dict[str, Any]

    # Recon
    recon_result: dict[str, Any]
    interaction_points: Annotated[list[Any], operator.add]

    # Auth
    accounts: Annotated[list[Any], operator.add]
    auth_flow_result: dict[str, Any]

    # Findings
    raw_findings: Annotated[list[dict[str, Any]], operator.add]
    validated_findings: Annotated[list[Any], operator.add]
    reports: Annotated[list[Any], operator.add]

    # Traffic
    traffic_summary: dict[str, Any]
    traffic_intelligence: dict[str, Any]

    # Control flow
    phase: str
    next_action: str
    budget_spent: float
    budget_limit: float
    kill_switch_active: bool

    # Error tracking
    errors: Annotated[list[str], operator.add]

    # Timing
    start_time: float
    steps: Annotated[list[dict[str, Any]], operator.add]

    # Loop control
    decide_count: int

    # Shannon-inspired: parallel pipeline tracking + cascading intelligence
    first_round_done: bool
    pipeline_context: Annotated[list[str], operator.add]


# ── Helper ───────────────────────────────────────────────────────────


def _get_deps(config: RunnableConfig) -> dict[str, Any]:
    """Extract agent dependencies from RunnableConfig."""
    c = config["configurable"]
    return {
        "client": c["client"],
        "scope_guard": c["scope_guard"],
        "browser": c["browser"],
        "proxy": c["proxy"],
        "email_mgr": c["email_mgr"],
        "tool_runner": c["tool_runner"],
        "budget": c["budget"],
        "kill_switch_checker": c.get("kill_switch_checker"),
    }


def _is_budget_critical(state: ActiveTestState, config: RunnableConfig | None = None) -> bool:
    """Check if budget is below 5% remaining.

    Checks the actual BudgetManager if available (via config), falls back
    to state values. Threshold lowered to 5% to allow the AI more freedom
    to decide when to stop testing.
    """
    if config:
        budget = config["configurable"].get("budget")
        if budget:
            phase_spend = budget.phases.get("active_testing")
            if phase_spend and phase_spend.allocated > 0:
                return phase_spend.remaining < phase_spend.allocated * 0.05

    limit = state.get("budget_limit", 0)
    spent = state.get("budget_spent", 0)
    if limit <= 0:
        return False
    return spent > limit * 0.95


# ── Node Functions ───────────────────────────────────────────────────


async def plan_active_test(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 1: Generate test plan from passive recon + target URL."""
    deps = _get_deps(config)
    client = deps["client"]

    prompt = ActiveTestPlanningPrompt()
    system_blocks = prompt.build_system_blocks()
    user_message = prompt.user_template(
        target_url=state["target_url"],
        passive_recon=str(state.get("passive_recon", {}))[:8000],
        scope_rules="",
        budget_remaining=state.get("budget_limit", 0) - state.get("budget_spent", 0),
    )

    result = await client.call(
        phase="active_testing",
        task_tier=prompt.model_tier,
        system_blocks=system_blocks,
        user_message=user_message,
        output_schema=prompt.output_schema,
        target=state["target_url"],
    )

    plan = result.parsed.model_dump() if result.parsed else {}

    logger.info(
        "active_test_plan_created",
        target=state["target_url"],
        phases=len(plan.get("phases", [])),
    )

    phases_count = len(plan.get("phases", []))
    priority = ", ".join(plan.get("priority_areas", [])[:3]) or "standard"
    return {
        "test_plan": plan,
        "phase": "recon",
        "start_time": time.time(),
        "pipeline_context": [f"[plan] {phases_count} phases planned. Priority: {priority}"],
    }


async def active_recon(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 2: Run active recon agent to map attack surface."""
    deps = _get_deps(config)
    agent = create_active_agent("recon", **deps)
    try:
        result = await agent.execute(state)
    except Exception as e:
        logger.error("active_recon_failed", error=str(e))
        return {
            "recon_result": {},
            "interaction_points": [],
            "errors": [f"recon_failed: {e}"],
            "phase": "auth_setup",
        }

    recon = result.get("recon_result")
    recon_dict = recon.model_dump() if hasattr(recon, "model_dump") else recon or {}
    pages = len(recon_dict.get("sitemap", []))
    points = len(result.get("interaction_points", []))
    tech = ", ".join(recon_dict.get("technology_stack", [])[:5]) or "unknown"
    return {
        "recon_result": recon_dict,
        "interaction_points": result.get("interaction_points", []),
        "phase": "auth_setup",
        "steps": [{"action": "active_recon", "output_data": {
            "pages_crawled": pages,
            "interaction_points": points,
        }}],
        "pipeline_context": [f"[recon] Crawled {pages} pages, found {points} interaction points. Tech: {tech}"],
    }


async def auth_setup(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 3: Create test accounts and analyze auth flow."""
    deps = _get_deps(config)
    agent = create_active_agent("auth", **deps)
    try:
        result = await agent.execute(state)
    except Exception as e:
        logger.error("auth_setup_failed", error=str(e))
        return {
            "errors": [f"auth_setup_failed: {e}"],
            "phase": "testing",
        }

    auth_findings = result.get("raw_findings", [])
    accounts_created = result.get("accounts", [])
    auth_flow = result.get("auth_flow_result", {})
    login_method = auth_flow.get("login_method", "unknown") if isinstance(auth_flow, dict) else getattr(auth_flow, "login_method", "unknown")
    return_dict: dict[str, Any] = {
        "accounts": accounts_created,
        "auth_flow_result": auth_flow,
        "errors": result.get("errors", []),
        "phase": "testing",
        "pipeline_context": [
            f"[auth] Created {len(accounts_created)} account(s). "
            f"Login: {login_method}. Auth findings: {len(auth_findings)}"
        ],
    }
    if auth_findings:
        return_dict["raw_findings"] = auth_findings
        # Incremental save — auth findings survive crashes
        merged_state = {**state}
        merged_state["raw_findings"] = copy.deepcopy(state.get("raw_findings", [])) + copy.deepcopy(auth_findings)
        _save_incremental(merged_state)
    return return_dict


async def auth_recon(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 3b: Re-crawl with authenticated session to discover auth-only pages.

    Only runs if auth_setup created at least one logged-in account.
    Uses that account's browser context to find new endpoints.
    """
    accounts = state.get("accounts", [])
    if not accounts:
        return {}

    # Find first account with cookies (logged in)
    auth_account = None
    for acc in accounts:
        if hasattr(acc, "cookies") and acc.cookies:
            auth_account = acc
            break
        elif isinstance(acc, dict) and acc.get("cookies"):
            auth_account = acc
            break

    if not auth_account:
        logger.info("auth_recon_skip", reason="no_logged_in_accounts")
        return {}

    deps = _get_deps(config)
    target_url = state["target_url"]
    context_name = auth_account.context_name if hasattr(auth_account, "context_name") else auth_account.get("context_name", "user1")
    browser = deps["browser"]

    logger.info("auth_recon_start", context=context_name)

    # BFS authenticated crawl — discover pages only visible after login
    new_pages: list[dict[str, Any]] = []
    visited_before = set()
    recon_result = state.get("recon_result", {})
    if isinstance(recon_result, dict):
        for page in recon_result.get("sitemap", []):
            if isinstance(page, dict):
                visited_before.add(page.get("url", ""))
            elif isinstance(page, str):
                visited_before.add(page)

    visited_auth: set[str] = set()
    queue: list[str] = [target_url]
    max_auth_pages = 50

    try:
        while queue and len(visited_auth) < max_auth_pages:
            url = queue.pop(0)

            # Normalize for dedup
            normalized = url.split("#")[0].rstrip("/") or "/"
            if normalized in visited_auth:
                continue
            visited_auth.add(normalized)

            try:
                result = await browser.navigate(context_name, url=url)
                if not result.success:
                    continue

                page_info = await browser.extract_page_info(context_name)

                # Check if this page is new (not seen in unauthenticated crawl)
                page_url = page_info.get("url", url)
                page_norm = page_url.split("#")[0].rstrip("/") or "/"
                if page_norm not in visited_before:
                    new_pages.append({
                        "url": page_url,
                        "title": page_info.get("title", ""),
                        "forms": page_info.get("forms", []),
                        "text_content": page_info.get("text_content", "")[:1000],
                    })

                # BFS: queue all same-origin links we haven't visited
                for link in page_info.get("links", []):
                    href = link.get("href", "")
                    if not href:
                        continue
                    href_norm = href.split("#")[0].rstrip("/") or "/"
                    if href_norm in visited_auth:
                        continue
                    parsed = urlparse(href)
                    target_parsed = urlparse(target_url)
                    if parsed.netloc == target_parsed.netloc:
                        queue.append(href)

            except Exception:
                continue

    except Exception as e:
        logger.warning("auth_recon_error", error=str(e))

    if new_pages:
        logger.info("auth_recon_found_pages", count=len(new_pages),
                     urls=[p["url"] for p in new_pages[:5]])

        # Add new interaction points from authenticated pages
        from ai_brain.active_schemas import InteractionPoint
        new_points = []
        for page in new_pages:
            for form in page.get("forms", []):
                fields = form.get("fields", [])
                if fields:
                    new_points.append(InteractionPoint(
                        url=page["url"],
                        method=form.get("method", "POST").upper(),
                        params=[f.get("name", "") for f in fields if f.get("name")],
                        auth_required=True,
                        notes=f"Authenticated page: {page.get('title', '')}",
                    ))

        return {
            "interaction_points": new_points,
            "steps": [{"action": "auth_recon", "output_data": {
                "new_pages": len(new_pages),
                "new_interaction_points": len(new_points),
            }}],
        }

    return {
        "steps": [{"action": "auth_recon", "output_data": {"new_pages": 0}}],
    }


async def injection_testing(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 4: Run injection tests on interaction points."""
    deps = _get_deps(config)
    agent = create_active_agent("injection", **deps)
    try:
        result = await agent.execute(state)
    except BudgetExhausted:
        logger.warning("injection_budget_exhausted")
        return {
            "raw_findings": [],
            "errors": ["injection_budget_exhausted"],
            "steps": [{"action": "injection_testing", "output_data": {"findings": 0}, "error": "budget_exhausted"}],
        }
    except Exception as e:
        logger.error("injection_testing_failed", error=str(e))
        return {
            "raw_findings": [],
            "errors": [f"injection_testing_failed: {e}"],
            "steps": [{"action": "injection_testing", "output_data": {"findings": 0}, "error": str(e)}],
        }

    findings_count = len(result.get("raw_findings", []))
    update: dict[str, Any] = {
        "raw_findings": result.get("raw_findings", []),
        "errors": result.get("errors", []),
        "steps": [{"action": "injection_testing", "output_data": {"findings": findings_count}}],
        "pipeline_context": [f"[injection] Found {findings_count} raw finding(s)"],
    }

    # Incremental save after injection — raw findings survive crashes
    if update["raw_findings"]:
        merged_state = {**state}
        merged_state["raw_findings"] = copy.deepcopy(state.get("raw_findings", [])) + copy.deepcopy(update["raw_findings"])
        _save_incremental(merged_state)

    return update


async def business_logic_testing(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 5: Run business logic tests."""
    deps = _get_deps(config)
    agent = create_active_agent("business_logic", **deps)
    try:
        result = await agent.execute(state)
    except BudgetExhausted:
        logger.warning("business_logic_budget_exhausted")
        return {
            "raw_findings": [],
            "errors": ["business_logic_budget_exhausted"],
            "steps": [{"action": "business_logic_testing", "output_data": {"findings": 0}, "error": "budget_exhausted"}],
        }
    except Exception as e:
        logger.error("business_logic_testing_failed", error=str(e))
        return {
            "raw_findings": [],
            "errors": [f"business_logic_failed: {e}"],
            "steps": [{"action": "business_logic_testing", "output_data": {"findings": 0}, "error": str(e)}],
        }

    findings_count = len(result.get("raw_findings", []))
    update: dict[str, Any] = {
        "raw_findings": result.get("raw_findings", []),
        "errors": result.get("errors", []),
        "steps": [{"action": "business_logic_testing", "output_data": {"findings": findings_count}}],
        "pipeline_context": [f"[business_logic] Found {findings_count} raw finding(s)"],
    }

    # Incremental save after business logic — raw findings survive crashes
    if update["raw_findings"]:
        merged_state = {**state}
        merged_state["raw_findings"] = copy.deepcopy(state.get("raw_findings", [])) + copy.deepcopy(update["raw_findings"])
        _save_incremental(merged_state)

    return update


async def hexstrike_testing(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node: Run hexstrike-ai's broad automated scanning tools."""
    hexstrike_client = config["configurable"].get("hexstrike_client")
    if hexstrike_client is None:
        logger.info("hexstrike_testing_skip", reason="no_client")
        return {
            "raw_findings": [],
            "errors": ["hexstrike_not_available"],
            "steps": [{"action": "hexstrike_testing", "output_data": {"findings": 0}, "error": "not_available"}],
            "pipeline_context": ["[hexstrike] Skipped — server not available"],
        }

    deps = _get_deps(config)
    from ai_brain.active.agents.hexstrike import HexstrikeAgent
    agent = HexstrikeAgent(hexstrike_client=hexstrike_client, **deps)

    try:
        result = await agent.execute(state)
    except BudgetExhausted:
        logger.warning("hexstrike_budget_exhausted")
        return {
            "raw_findings": [],
            "errors": ["hexstrike_budget_exhausted"],
            "steps": [{"action": "hexstrike_testing", "output_data": {"findings": 0}, "error": "budget_exhausted"}],
        }
    except Exception as e:
        logger.error("hexstrike_testing_failed", error=str(e))
        return {
            "raw_findings": [],
            "errors": [f"hexstrike_testing_failed: {e}"],
            "steps": [{"action": "hexstrike_testing", "output_data": {"findings": 0}, "error": str(e)}],
        }

    findings_count = len(result.get("raw_findings", []))
    update: dict[str, Any] = {
        "raw_findings": result.get("raw_findings", []),
        "errors": result.get("errors", []),
        "steps": [{"action": "hexstrike_testing", "output_data": {"findings": findings_count}}],
        "pipeline_context": [f"[hexstrike] Found {findings_count} raw finding(s)"],
    }

    if update["raw_findings"]:
        merged_state = {**state}
        merged_state["raw_findings"] = copy.deepcopy(state.get("raw_findings", [])) + copy.deepcopy(update["raw_findings"])
        _save_incremental(merged_state)

    return update


async def parallel_testing(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node: Run injection + business logic + hexstrike testing in parallel (first round).

    Shannon-inspired: running all pipelines concurrently saves ~40% time
    on the first round. Subsequent rounds are AI-driven sequential.
    """
    logger.info("parallel_testing_start")

    injection_task = asyncio.create_task(injection_testing(state, config))
    bl_task = asyncio.create_task(business_logic_testing(state, config))
    hex_task = asyncio.create_task(hexstrike_testing(state, config))

    results = await asyncio.gather(injection_task, bl_task, hex_task, return_exceptions=True)

    merged: dict[str, Any] = {
        "raw_findings": [],
        "errors": [],
        "steps": [],
        "first_round_done": True,
        "pipeline_context": [],
    }

    labels = ["injection", "business_logic", "hexstrike"]
    findings_by_label: dict[str, int] = {}

    for i, result in enumerate(results):
        label = labels[i]
        if isinstance(result, Exception):
            logger.error(f"parallel_{label}_failed", error=str(result))
            merged["errors"].append(f"parallel_{label}_failed: {result}")
            findings_by_label[label] = 0
        elif isinstance(result, dict):
            merged["raw_findings"].extend(result.get("raw_findings", []))
            merged["errors"].extend(result.get("errors", []))
            merged["steps"].extend(result.get("steps", []))
            merged["pipeline_context"].extend(result.get("pipeline_context", []))
            findings_by_label[label] = len(result.get("raw_findings", []))
        else:
            findings_by_label[label] = 0

    summary_parts = [f"{k}: {v} finding(s)" for k, v in findings_by_label.items()]
    merged["pipeline_context"].append(f"[parallel] {', '.join(summary_parts)}")

    # Incremental save
    if merged["raw_findings"]:
        save_state = {**state}
        save_state["raw_findings"] = copy.deepcopy(state.get("raw_findings", [])) + copy.deepcopy(merged["raw_findings"])
        _save_incremental(save_state)

    logger.info("parallel_testing_done", **{f"{k}_findings": v for k, v in findings_by_label.items()})
    return merged


async def validate_findings(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 6: Validate raw findings."""
    deps = _get_deps(config)
    agent = create_active_agent("validator", **deps)
    try:
        result = await agent.execute(state)
    except BudgetExhausted:
        logger.warning("validate_budget_exhausted")
        return {
            "validated_findings": [],
            "errors": ["validate_budget_exhausted"],
            "phase": "validation",
        }
    except Exception as e:
        logger.error("validate_findings_failed", error=str(e))
        return {
            "validated_findings": [],
            "errors": [f"validate_findings_failed: {e}"],
            "phase": "validation",
        }

    validated_list = result.get("validated_findings", [])

    # Build verdict summary for pipeline context
    verdict_counts: dict[str, int] = {}
    for v in validated_list:
        vd = getattr(v, "verdict", "UNKNOWN") if hasattr(v, "verdict") else v.get("verdict", "UNKNOWN") if isinstance(v, dict) else "UNKNOWN"
        verdict_counts[vd] = verdict_counts.get(vd, 0) + 1
    verdict_str = ", ".join(f"{k}: {v}" for k, v in verdict_counts.items()) if verdict_counts else "none"

    update: dict[str, Any] = {
        "validated_findings": validated_list,
        "errors": result.get("errors", []),
        "phase": "validation",
        "pipeline_context": [f"[validator] Validated {len(validated_list)} finding(s). Verdicts: {{{verdict_str}}}"],
    }

    # Incremental save — merge new validated findings into state snapshot
    merged_state = {**state, **update}
    merged_state["validated_findings"] = copy.deepcopy(state.get("validated_findings", [])) + copy.deepcopy(update["validated_findings"])
    _save_incremental(merged_state)

    return update


async def generate_reports(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 7: Generate reports for verified findings."""
    deps = _get_deps(config)
    agent = create_active_agent("reporter", **deps)
    try:
        result = await agent.execute(state)
    except BudgetExhausted:
        logger.warning("reports_budget_exhausted")
        return {"reports": [], "errors": ["reports_budget_exhausted"], "phase": "reporting"}
    except Exception as e:
        logger.error("generate_reports_failed", error=str(e))
        return {"reports": [], "errors": [f"generate_reports_failed: {e}"], "phase": "reporting"}

    reports_list = result.get("reports", [])
    update: dict[str, Any] = {
        "reports": reports_list,
        "errors": result.get("errors", []),
        "phase": "reporting",
        "pipeline_context": [f"[reporter] Generated {len(reports_list)} report(s)"],
    }

    # Incremental save + write individual report files
    merged_state = {**state, **update}
    merged_state["reports"] = copy.deepcopy(state.get("reports", [])) + copy.deepcopy(update["reports"])
    _save_incremental(merged_state)
    reports_dir = _save_report_files(merged_state)
    if reports_dir:
        logger.info("report_files_saved", directory=reports_dir, count=len(reports_list))

    return update


async def analyze_traffic(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node: Analyze captured proxy traffic into actionable intelligence.

    Pure Python analysis — zero API cost. Runs after auth_recon and
    before decide_next. Re-runs automatically if traffic has grown
    significantly since last analysis.
    """
    deps = _get_deps(config)
    proxy = deps["proxy"]
    scope_guard = deps["scope_guard"]

    from ai_brain.active.http_attacker import TrafficIntelligence

    traffic = proxy.get_traffic(limit=500)
    if not traffic:
        return {"traffic_intelligence": {}}

    # Check if we need to re-analyze (skip if traffic hasn't grown much)
    prev_intel = state.get("traffic_intelligence", {})
    prev_count = prev_intel.get("_traffic_count", 0)
    if prev_count > 0 and len(traffic) - prev_count < 50:
        return {}  # No significant new traffic, keep existing intelligence

    analyzer = TrafficIntelligence(scope_guard)
    report = analyzer.analyze(traffic)

    return {"traffic_intelligence": {
        "prompt_text": report.to_prompt_text(),
        "waf_type": report.waf_type,
        "waf_detected": report.waf_detected,
        "timing_anomalies": report.timing_anomalies,
        "id_params": report.id_params,
        "price_params": report.price_params,
        "role_params": report.role_params,
        "observations": report.observations,
        "tech_signals": report.tech_signals,
        "cookie_issues": report.cookie_issues,
        "error_patterns": report.error_patterns,
        "csrf_analysis": report.csrf_analysis,
        "_traffic_count": len(traffic),
    }}


async def decide_next(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 8: AI decides next action based on current state."""
    if _is_budget_critical(state, config):
        logger.info("decide_budget_critical", action="validate_findings")
        return {"next_action": "validate_findings", "phase": "wrapping_up"}

    deps = _get_deps(config)
    client = deps["client"]
    count = state.get("decide_count", 0) + 1

    # Build test history from steps to show what was already tried
    steps = state.get("steps", [])
    test_history = []
    for step in steps:
        action = step.get("action", "")
        output = step.get("output_data", {})
        findings = output.get("findings", output.get("findings_count", 0))
        test_history.append(f"  - {action}: findings={findings}")
    history_text = "\n".join(test_history[-10:]) if test_history else "None yet"

    # If injection found 0 findings twice in a row, force business_logic next
    injection_runs = [s for s in steps if "injection" in s.get("action", "")]
    biz_logic_runs = [s for s in steps if "business_logic" in s.get("action", "")]

    # Gather traffic intelligence + pipeline context
    intel = state.get("traffic_intelligence", {})
    pipeline_ctx = state.get("pipeline_context", [])
    pipeline_text = "\n".join(pipeline_ctx[-15:]) if pipeline_ctx else "No previous context"

    prompt = ActiveNextStepPrompt()
    system_blocks = prompt.build_system_blocks()
    user_message = prompt.user_template(
        current_phase=state.get("phase", ""),
        pages_visited=len(state.get("recon_result", {}).get("sitemap", [])),
        findings_count=len(state.get("raw_findings", [])),
        unvalidated_count=len([
            f for f in state.get("raw_findings", [])
            if not any(
                v.finding_id == f"finding_{i}"
                for i, _ in enumerate(state.get("raw_findings", []))
                for v in state.get("validated_findings", [])
                if hasattr(v, "finding_id")
            )
        ]),
        interaction_points_remaining=len(state.get("interaction_points", [])),
        traffic_summary=str(state.get("traffic_summary", {}))[:3000],
        budget_spent=state.get("budget_spent", 0),
        budget_limit=state.get("budget_limit", 0),
        errors=state.get("errors", [])[-5:],
        test_history=history_text,
        decide_count=count,
        findings_detail=json.dumps(state.get("raw_findings", [])[-10:], default=str)[:4000],
        traffic_intelligence=intel.get("prompt_text", ""),
        tech_stack=json.dumps(state.get("recon_result", {}).get("technology_stack", [])),
        waf_info=intel.get("waf_type", "None detected"),
        pipeline_context=pipeline_text,
    )

    try:
        result = await client.call(
            phase="active_testing",
            task_tier=prompt.model_tier,
            system_blocks=system_blocks,
            user_message=user_message,
            output_schema=prompt.output_schema,
            target=state.get("target_url", ""),
        )
    except BudgetExhausted:
        logger.info("decide_budget_exhausted", action="validate_findings")
        raw = state.get("raw_findings", [])
        if raw:
            return {"next_action": "validate_findings", "decide_count": count}
        return {"next_action": "cleanup", "decide_count": count}

    next_action = "cleanup"
    if result.parsed:
        next_action = result.parsed.next_action

    # AI has full autonomy — no programmatic overrides on test type selection.
    # The AI can retry injection or business_logic with different strategies.

    # Soft safety: force wrap-up after 15 decision loops to prevent infinite loops
    if count >= 15:
        logger.info("decide_loop_limit_reached", count=count)
        next_action = "validate_findings"

    return {"next_action": next_action, "decide_count": count}


async def kill_switch_check(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 9: Check kill switch status."""
    checker = config["configurable"].get("kill_switch_checker")
    if checker and checker():
        return {"kill_switch_active": True, "phase": "killed"}
    return {"kill_switch_active": False}


def _serialize(obj: Any) -> Any:
    """Recursively serialize Pydantic models and other objects to dicts."""
    if hasattr(obj, "model_dump"):
        return obj.model_dump()
    if isinstance(obj, dict):
        return {k: _serialize(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_serialize(item) for item in obj]
    if isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    return str(obj)


async def cleanup(
    state: ActiveTestState, config: RunnableConfig
) -> dict[str, Any]:
    """Node 10: Clean up browser, proxy, save session, and persist findings."""
    deps = _get_deps(config)

    try:
        await deps["browser"].stop()
    except Exception:
        pass

    try:
        await deps["proxy"].stop()
    except Exception:
        pass

    try:
        await deps["email_mgr"].stop()
    except Exception:
        pass

    elapsed = time.time() - state.get("start_time", time.time())
    raw_findings = state.get("raw_findings", [])
    validated_findings = state.get("validated_findings", [])
    reports = state.get("reports", [])
    errors = state.get("errors", [])

    logger.info(
        "active_test_complete",
        target=state.get("target_url", ""),
        elapsed_seconds=int(elapsed),
        findings=len(validated_findings),
        reports=len(reports),
    )

    # Persist all findings and reports to JSON
    output_path = state.get("config", {}).get("output_path", "")
    if not output_path:
        ts = time.strftime("%Y%m%d_%H%M%S")
        output_path = f"/tmp/aibbp_findings_{ts}.json"

    try:
        output_data = {
            "target_url": state.get("target_url", ""),
            "session_id": state.get("session_id", ""),
            "elapsed_seconds": int(elapsed),
            "budget_spent": state.get("budget_spent", 0),
            "budget_limit": state.get("budget_limit", 0),
            "raw_findings": _serialize(raw_findings),
            "validated_findings": _serialize(validated_findings),
            "reports": _serialize(reports),
            "errors": errors[-50:],
            "summary": {
                "total_raw_findings": len(raw_findings),
                "total_validated": len(validated_findings),
                "confirmed": sum(
                    1 for v in validated_findings
                    if (
                        (getattr(v, "verdict", None) in ("EXPLOITED", "BLOCKED_BY_SECURITY"))
                        if hasattr(v, "verdict")
                        else (v.get("verdict") in ("EXPLOITED", "BLOCKED_BY_SECURITY"))
                        if isinstance(v, dict) and "verdict" in v
                        else (v.verified if hasattr(v, "verified") else v.get("verified", False))
                    )
                ),
                "reports_generated": len(reports),
            },
        }
        with open(output_path, "w") as f:
            json.dump(output_data, f, indent=2, default=str)
        logger.info("findings_persisted", path=output_path)
    except Exception as e:
        logger.warning("findings_persist_failed", error=str(e))

    # Save individual report markdown files
    reports_dir = _save_report_files(state)
    if reports_dir:
        print(f"\nReports saved to: {reports_dir}")

    return {
        "phase": "completed",
    }


# ── Routing Functions ────────────────────────────────────────────────


def route_after_auth(state: ActiveTestState) -> str:
    """After auth setup, re-crawl if authenticated, else go to decide."""
    accounts = state.get("accounts", [])
    has_auth = False
    for acc in accounts:
        if hasattr(acc, "cookies") and acc.cookies:
            has_auth = True
            break
        elif isinstance(acc, dict) and acc.get("cookies"):
            has_auth = True
            break
    if has_auth:
        return "auth_recon"
    return "analyze_traffic"


def route_after_decide(state: ActiveTestState) -> str:
    """Route based on AI decision."""
    if state.get("kill_switch_active"):
        return "cleanup"

    action = state.get("next_action", "cleanup")

    valid_actions = {
        "injection_testing",
        "business_logic_testing",
        "hexstrike_testing",
        "validate_findings",
        "generate_reports",
        "continue_recon",
        "continue_current",
        "cleanup",
    }

    if action not in valid_actions:
        return "cleanup"

    # Conditional skip: don't waste budget validating empty findings
    if action == "validate_findings" and not state.get("raw_findings"):
        logger.info("skip_validation_no_findings")
        return "cleanup"

    # Conditional skip: don't waste budget reporting with nothing reportable
    if action == "generate_reports":
        validated = state.get("validated_findings", [])
        reportable = [
            v for v in validated
            if (getattr(v, "verdict", None) in ("EXPLOITED", "BLOCKED_BY_SECURITY"))
            or (getattr(v, "verdict", None) is None and getattr(v, "verified", False))
            or (isinstance(v, dict) and v.get("verdict") in ("EXPLOITED", "BLOCKED_BY_SECURITY"))
            or (isinstance(v, dict) and "verdict" not in v and v.get("verified", False))
        ]
        if not reportable:
            logger.info("skip_reports_no_reportable_findings")
            return "cleanup"

    if action == "continue_recon":
        return "active_recon"
    if action == "continue_current":
        return "injection_testing"

    return action


def route_after_analyze(state: ActiveTestState) -> str:
    """After traffic analysis, run parallel testing if first round, else decide."""
    if not state.get("first_round_done", False):
        return "parallel_testing"
    return "decide_next"


def route_after_testing(state: ActiveTestState) -> str:
    """After injection or business logic testing, re-analyze traffic then decide."""
    return "analyze_traffic"


def route_after_validate(state: ActiveTestState) -> str:
    """After validation, go back to decide_next for more testing, or generate reports if done."""
    # Check if we have anything reportable before going to reports
    validated = state.get("validated_findings", [])
    has_reportable = any(
        (getattr(v, "verdict", None) in ("EXPLOITED", "BLOCKED_BY_SECURITY"))
        or (getattr(v, "verdict", None) is None and getattr(v, "verified", False))
        or (isinstance(v, dict) and v.get("verdict") in ("EXPLOITED", "BLOCKED_BY_SECURITY"))
        or (isinstance(v, dict) and "verdict" not in v and v.get("verified", False))
        for v in validated
    )

    # If budget is critical, go to reports if we have something to report, else cleanup
    limit = state.get("budget_limit", 0)
    spent = state.get("budget_spent", 0)
    if limit > 0 and spent > limit * 0.95:
        return "generate_reports" if has_reportable else "cleanup"

    # If we've done many decide loops already, wrap up
    if state.get("decide_count", 0) >= 15:
        return "generate_reports" if has_reportable else "cleanup"

    # Otherwise, go back to analyze_traffic → decide_next — the AI can choose to test more or report
    return "analyze_traffic"


def route_after_reports(state: ActiveTestState) -> str:
    """After reports, clean up."""
    return "cleanup"


# ── Graph Builder ────────────────────────────────────────────────────


def build_active_subgraph() -> StateGraph:
    """Build and return the active testing LangGraph subgraph.

    Returns:
        Compiled StateGraph ready to invoke.
    """
    graph = StateGraph(ActiveTestState)

    # Add nodes
    graph.add_node("plan_active_test", plan_active_test)
    graph.add_node("active_recon", active_recon)
    graph.add_node("auth_setup", auth_setup)
    graph.add_node("auth_recon", auth_recon)
    graph.add_node("injection_testing", injection_testing)
    graph.add_node("business_logic_testing", business_logic_testing)
    graph.add_node("hexstrike_testing", hexstrike_testing)
    graph.add_node("parallel_testing", parallel_testing)
    graph.add_node("validate_findings", validate_findings)
    graph.add_node("generate_reports", generate_reports)
    graph.add_node("analyze_traffic", analyze_traffic)
    graph.add_node("decide_next", decide_next)
    graph.add_node("kill_switch_check", kill_switch_check)
    graph.add_node("cleanup", cleanup)

    # Set entry point
    graph.set_entry_point("plan_active_test")

    # Linear flow: plan → recon → auth → (auth_recon if logged in) → decide
    graph.add_edge("plan_active_test", "active_recon")
    graph.add_edge("active_recon", "auth_setup")
    graph.add_conditional_edges("auth_setup", route_after_auth, {
        "auth_recon": "auth_recon",
        "analyze_traffic": "analyze_traffic",
    })
    graph.add_edge("auth_recon", "analyze_traffic")
    graph.add_conditional_edges("analyze_traffic", route_after_analyze, {
        "parallel_testing": "parallel_testing",
        "decide_next": "decide_next",
    })
    graph.add_conditional_edges("parallel_testing", route_after_testing, {
        "analyze_traffic": "analyze_traffic",
    })

    # Decide routes to multiple possible next nodes
    graph.add_conditional_edges("decide_next", route_after_decide, {
        "injection_testing": "injection_testing",
        "business_logic_testing": "business_logic_testing",
        "hexstrike_testing": "hexstrike_testing",
        "validate_findings": "validate_findings",
        "generate_reports": "generate_reports",
        "active_recon": "active_recon",
        "cleanup": "cleanup",
    })

    # After testing, re-analyze traffic then decide
    graph.add_conditional_edges("injection_testing", route_after_testing, {
        "analyze_traffic": "analyze_traffic",
    })
    graph.add_conditional_edges("business_logic_testing", route_after_testing, {
        "analyze_traffic": "analyze_traffic",
    })
    graph.add_conditional_edges("hexstrike_testing", route_after_testing, {
        "analyze_traffic": "analyze_traffic",
    })

    # Validate → either back to analyze_traffic → decide (for more testing) or to reports
    graph.add_conditional_edges("validate_findings", route_after_validate, {
        "generate_reports": "generate_reports",
        "analyze_traffic": "analyze_traffic",
        "cleanup": "cleanup",
    })
    graph.add_conditional_edges("generate_reports", route_after_reports, {
        "cleanup": "cleanup",
    })

    # Cleanup ends the graph
    graph.add_edge("cleanup", END)

    return graph.compile()
