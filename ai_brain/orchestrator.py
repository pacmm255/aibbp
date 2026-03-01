"""LangGraph state machine orchestrator for the scanning pipeline.

Drives the full scan lifecycle through these nodes:
1. program_analysis → Parse scope, prioritize targets
2. recon → Run recon solvers per target
3. recon_correlate → Synthesize recon intelligence
4. vuln_detection → Run vuln detection solvers per target
5. validation → Validate findings (non-AI + AI)
6. chain_discovery → Find attack chains
7. reporting → Generate HackerOne-ready reports
8. strategy → Decide continue/pivot/move_on

Conditional edges:
- vuln_detection → {continue_vuln, validate, strategy}
- strategy → {recon (next target), chain_discovery (done)}
- Emergency: any state → reporting when budget < 15%

PostgreSQL checkpointing for crash recovery via AsyncPostgresSaver.
"""

from __future__ import annotations

import json
import operator
import time
from typing import Annotated, Any, Literal, TypedDict

import structlog
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph

from ai_brain.budget import BudgetManager
from ai_brain.config import AIBrainConfig
from ai_brain.context import ContextManager
from ai_brain.coordinator import CoordinatorAgent
from ai_brain.errors import BudgetExhausted, CircuitBreaker, IdempotencyTracker
from ai_brain.models import ClaudeClient
from ai_brain.rate_limiter import DualRateLimiter
from ai_brain.scope import ScopeEnforcer
from ai_brain.solver import SOLVER_REGISTRY, create_solver
from ai_brain.validator import ValidationOrchestrator

# Active testing imports (lazy to avoid hard dependency)
_active_available = True
try:
    from ai_brain.active.graph import build_active_subgraph
    from ai_brain.active.scope_guard import ActiveScopeGuard
    from ai_brain.active.browser import BrowserController
    from ai_brain.active.proxy import TrafficInterceptor
    from ai_brain.active.email import EmailManager
    from ai_brain.active.tools import ToolRunner
except ImportError:
    _active_available = False

logger = structlog.get_logger()


# ── State Definition ─────────────────────────────────────────────────


class ScanState(TypedDict, total=False):
    """Full scan state persisted via LangGraph checkpointer.

    Annotated types use operator.add for list fields and operator.or_
    for dict fields, enabling incremental state updates.
    """

    # Program info
    program_text: str
    scope_analysis: str
    target_priorities: list[str]

    # Recon results (accumulated per target)
    recon_results: Annotated[dict[str, Any], operator.or_]

    # Findings (accumulated)
    raw_findings: Annotated[list[dict[str, Any]], operator.add]
    validated_findings: Annotated[list[dict[str, Any]], operator.add]
    false_positives: Annotated[list[str], operator.add]

    # Attack chains and reports
    attack_chains: Annotated[list[dict[str, Any]], operator.add]
    reports: Annotated[list[dict[str, Any]], operator.add]

    # Current state tracking
    phase: str
    status: str
    current_target: str
    current_target_idx: int
    targets_completed: Annotated[list[str], operator.add]

    # Budget and timing
    budget_summary: dict[str, Any]
    start_time: float
    elapsed_seconds: float

    # Error tracking
    errors: Annotated[list[str], operator.add]

    # Idempotency keys
    action_keys: Annotated[set[str], operator.or_]

    # Vuln detection state
    vuln_solvers_run: Annotated[list[str], operator.add]
    finding_rate: float  # findings per minute

    # Active testing
    active_testing_enabled: bool
    active_testing_results: Annotated[list[dict[str, Any]], operator.add]
    active_target: str  # Optional single target for --active-target


# ── Node Functions ───────────────────────────────────────────────────


async def program_analysis_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 0: Analyze program scope and prioritize targets."""
    coordinator: CoordinatorAgent = config["configurable"]["coordinator"]
    idem: IdempotencyTracker = config["configurable"]["idempotency"]

    if not idem.check_and_mark("program_analysis", "scope", ""):
        logger.info("skipping_duplicate", action="program_analysis")
        return {}

    try:
        # 0.1 Scope analysis
        scope_result = await coordinator.analyze_program(state["program_text"])
        scope_json = scope_result.raw_text or json.dumps(
            scope_result.parsed.model_dump() if scope_result.parsed else {}
        )

        # 0.2 Target prioritization
        priority_result = await coordinator.prioritize_targets(scope_json)
        targets = []
        if priority_result.parsed:
            targets = priority_result.parsed.recommended_scan_order

        return {
            "scope_analysis": scope_json,
            "target_priorities": targets,
            "current_target_idx": 0,
            "current_target": targets[0] if targets else "",
            "phase": "recon",
            "status": "running",
        }
    except BudgetExhausted as e:
        return {"errors": [str(e)], "phase": "reporting", "status": "emergency"}


async def recon_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 1: Run reconnaissance solvers on current target."""
    client: ClaudeClient = config["configurable"]["client"]
    scope: ScopeEnforcer = config["configurable"]["scope"]
    context: ContextManager = config["configurable"]["context"]
    idem: IdempotencyTracker = config["configurable"]["idempotency"]
    target = state.get("current_target", "")

    if not target:
        return {"phase": "strategy", "errors": ["No target for recon"]}

    recon_data: dict[str, Any] = {}

    # Run recon solvers: subdomain classification, JS analysis
    recon_solver_types = ["subdomain_classification", "js_analysis"]

    for solver_type in recon_solver_types:
        if not idem.check_and_mark("recon", target, solver_type):
            continue

        try:
            solver = create_solver(solver_type, client, scope, context)
            # Provide minimal data structure for the solver
            data = _build_recon_data(solver_type, target, state)
            result = await solver.solve(target, data)
            if result.parsed:
                recon_data[solver_type] = result.parsed.model_dump()
        except BudgetExhausted as e:
            return {
                "errors": [str(e)],
                "phase": "reporting",
                "status": "emergency",
            }
        except Exception as e:
            logger.error(
                "recon_solver_error",
                solver=solver_type,
                target=target,
                error=str(e),
            )

    return {
        "recon_results": {target: recon_data},
        "phase": "recon_correlate",
    }


async def recon_correlate_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 1.5: Correlate all recon data."""
    coordinator: CoordinatorAgent = config["configurable"]["coordinator"]
    idem: IdempotencyTracker = config["configurable"]["idempotency"]
    target = state.get("current_target", "")

    if not idem.check_and_mark("recon_correlate", target, ""):
        return {"phase": "vuln_detection"}

    try:
        recon = state.get("recon_results", {}).get(target, {})
        result = await coordinator.correlate_recon(
            subdomain_data=json.dumps(recon.get("subdomain_classification", {})),
            js_analysis=json.dumps(recon.get("js_analysis", {})),
        )
        return {"phase": "vuln_detection"}
    except BudgetExhausted as e:
        return {"errors": [str(e)], "phase": "reporting", "status": "emergency"}


async def vuln_detection_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 2: Run vulnerability detection solvers."""
    client: ClaudeClient = config["configurable"]["client"]
    scope: ScopeEnforcer = config["configurable"]["scope"]
    context: ContextManager = config["configurable"]["context"]
    budget: BudgetManager = config["configurable"]["budget"]
    idem: IdempotencyTracker = config["configurable"]["idempotency"]
    target = state.get("current_target", "")

    if not target:
        return {"phase": "strategy"}

    findings: list[dict[str, Any]] = []
    solvers_run: list[str] = []

    # Vuln detection solvers to run
    vuln_solver_types = [
        "idor_detection",
        "auth_bypass",
        "cors_detection",
        "jwt_oauth_detection",
        "ssrf_detection",
        "mass_assignment",
        "error_message_analysis",
        "business_logic",
        "graphql_detection",
    ]

    for solver_type in vuln_solver_types:
        # Check budget before each solver
        if budget.is_emergency:
            logger.warning("emergency_budget", target=target)
            return {
                "raw_findings": findings,
                "vuln_solvers_run": solvers_run,
                "phase": "reporting",
                "status": "emergency",
            }

        if not idem.check_and_mark("vuln_detection", target, solver_type):
            continue

        try:
            solver = create_solver(solver_type, client, scope, context)
            data = _build_vuln_data(solver_type, target, state)
            result = await solver.solve(target, data)

            if result.parsed:
                finding_dict = result.parsed.model_dump()
                finding_dict["_solver"] = solver_type
                finding_dict["_target"] = target
                findings.append(finding_dict)

                # Track finding rate
                if _has_actionable_findings(finding_dict):
                    context.record_finding(target)

            solvers_run.append(solver_type)

        except BudgetExhausted as e:
            return {
                "raw_findings": findings,
                "vuln_solvers_run": solvers_run,
                "errors": [str(e)],
                "phase": "reporting",
                "status": "emergency",
            }
        except Exception as e:
            logger.error(
                "vuln_solver_error",
                solver=solver_type,
                target=target,
                error=str(e),
            )
            solvers_run.append(solver_type)

    return {
        "raw_findings": findings,
        "vuln_solvers_run": solvers_run,
        "phase": "validation",
    }


async def validation_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 3: Validate findings using non-AI validators + AI FP filter."""
    coordinator: CoordinatorAgent = config["configurable"]["coordinator"]
    validator_orch: ValidationOrchestrator = config["configurable"]["validator"]

    raw_findings = state.get("raw_findings", [])
    if not raw_findings:
        return {"phase": "strategy"}

    validated: list[dict[str, Any]] = []
    false_positives: list[str] = []

    # 1. Non-AI validation first
    for finding in raw_findings:
        vuln_type = finding.get("vuln_type", "")
        if not vuln_type:
            continue

        results = await validator_orch.validate(
            finding, context={"raw_response": ""}
        )

        # Adjust confidence based on validation
        confidence = finding.get("confidence", 50)
        for vr in results:
            confidence += vr.confidence_adjustment

        finding["validated_confidence"] = max(0, min(100, confidence))
        finding["validation_results"] = [
            {"method": r.method, "is_valid": r.is_valid, "evidence": r.evidence}
            for r in results
        ]

    # 2. AI false positive filter (batch all findings)
    try:
        findings_json = json.dumps(
            [
                {
                    "vuln_id": f.get("_solver", ""),
                    "vuln_type": f.get("vuln_type", ""),
                    "confidence": f.get("validated_confidence", 50),
                    "title": f.get("title", ""),
                    "evidence": f.get("evidence", []),
                }
                for f in raw_findings
            ],
            indent=2,
        )

        fp_result = await coordinator.filter_false_positives(findings_json)
        if fp_result.parsed:
            for assessment in fp_result.parsed.assessments:
                if assessment.is_false_positive:
                    false_positives.append(assessment.vuln_id)

    except BudgetExhausted as e:
        logger.warning("budget_exhausted_during_validation", error=str(e))

    # 3. Separate validated from FP
    for finding in raw_findings:
        solver = finding.get("_solver", "")
        if solver not in false_positives:
            conf = finding.get("validated_confidence", 50)
            if conf >= 30:  # Minimum threshold
                validated.append(finding)

    return {
        "validated_findings": validated,
        "false_positives": false_positives,
        "phase": "strategy",
    }


async def strategy_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 6: Decide whether to continue, pivot, or move on."""
    coordinator: CoordinatorAgent = config["configurable"]["coordinator"]
    budget: BudgetManager = config["configurable"]["budget"]
    target = state.get("current_target", "")
    targets = state.get("target_priorities", [])
    idx = state.get("current_target_idx", 0)
    completed = state.get("targets_completed", [])

    # Calculate time spent
    elapsed = time.time() - state.get("start_time", time.time())

    # Check if we should force-move to reporting
    if budget.is_emergency:
        return {"phase": "chain_discovery", "status": "emergency"}

    try:
        remaining = [t for t in targets if t not in completed and t != target]
        result = await coordinator.evaluate_strategy(
            current_target=target,
            findings_summary=json.dumps(
                {"count": len(state.get("validated_findings", []))}
            ),
            budget_status=json.dumps(budget.summary()),
            time_spent=f"{elapsed / 60:.1f} minutes",
            remaining_targets=", ".join(remaining[:5]),
        )

        if result.parsed:
            decision = result.parsed.decision
            if decision == "move_on":
                # Move to next target or finish
                next_idx = idx + 1
                if next_idx < len(targets):
                    return {
                        "current_target_idx": next_idx,
                        "current_target": targets[next_idx],
                        "targets_completed": [target],
                        "phase": "recon",
                        "vuln_solvers_run": [],
                    }
                else:
                    return {
                        "targets_completed": [target],
                        "phase": "chain_discovery",
                    }
            elif decision == "pivot":
                # Same target, reset vuln solvers
                return {"phase": "vuln_detection", "vuln_solvers_run": []}
            else:
                # Continue with same target
                return {"phase": "vuln_detection"}

    except BudgetExhausted:
        return {"phase": "chain_discovery", "status": "emergency"}

    return {"phase": "chain_discovery"}


async def chain_discovery_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 4: Discover attack chains from validated findings."""
    coordinator: CoordinatorAgent = config["configurable"]["coordinator"]
    idem: IdempotencyTracker = config["configurable"]["idempotency"]

    validated = state.get("validated_findings", [])
    if not validated or not idem.check_and_mark("chain_discovery", "all", ""):
        return {"phase": "reporting"}

    try:
        result = await coordinator.discover_chains(
            validated_findings=json.dumps(validated, indent=2),
            target_context=json.dumps(
                {"targets_completed": state.get("targets_completed", [])}
            ),
        )

        chains: list[dict[str, Any]] = []
        if result.parsed:
            chains = [c.model_dump() for c in result.parsed.chains]

        return {"attack_chains": chains, "phase": "reporting"}
    except BudgetExhausted:
        return {"phase": "reporting", "status": "emergency"}


async def reporting_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Phase 5: Generate reports for validated findings."""
    coordinator: CoordinatorAgent = config["configurable"]["coordinator"]
    budget: BudgetManager = config["configurable"]["budget"]

    validated = state.get("validated_findings", [])
    chains = state.get("attack_chains", [])
    reports: list[dict[str, Any]] = []

    # Sort by confidence (highest first) for budget efficiency
    reportable = sorted(
        validated,
        key=lambda f: f.get("validated_confidence", 0),
        reverse=True,
    )

    for finding in reportable:
        if budget.is_emergency and reports:
            # In emergency, at least generate one report
            break

        try:
            # 5.2 Score CVSS
            cvss_result = await coordinator.score_cvss(
                finding=json.dumps(finding, indent=2)
            )
            cvss_json = ""
            if cvss_result.parsed:
                cvss_json = json.dumps(cvss_result.parsed.model_dump())

            # 5.1 Generate report
            report_result = await coordinator.generate_report(
                finding=json.dumps(finding, indent=2),
                evidence=json.dumps(finding.get("evidence", [])),
                cvss=cvss_json,
            )

            if report_result.parsed:
                reports.append(report_result.parsed.model_dump())

        except BudgetExhausted:
            logger.warning("budget_exhausted_during_reporting")
            break

    # Also report chains
    for chain in chains:
        reports.append({"type": "attack_chain", **chain})

    elapsed = time.time() - state.get("start_time", time.time())
    return {
        "reports": reports,
        "phase": "done",
        "status": "completed",
        "elapsed_seconds": elapsed,
        "budget_summary": budget.summary(),
    }


# ── Active Testing Node ──────────────────────────────────────────────


async def active_testing_node(
    state: ScanState, config: RunnableConfig
) -> dict[str, Any]:
    """Run active testing subgraph against high-priority targets.

    Initializes browser, proxy, email, and tool runner infrastructure,
    then executes the active testing LangGraph subgraph for each target.
    """
    if not state.get("active_testing_enabled") or not _active_available:
        return {"phase": "chain_discovery"}

    c = config["configurable"]
    client: ClaudeClient = c["client"]
    scope: ScopeEnforcer = c["scope"]
    budget: BudgetManager = c["budget"]
    ai_config: AIBrainConfig = c["ai_config"]

    active_cfg = ai_config.active_testing
    scope_guard = ActiveScopeGuard(scope)
    results: list[dict[str, Any]] = []

    # Choose targets: --active-target overrides auto-selection
    active_target = state.get("active_target", "")
    if active_target:
        targets = [active_target]
    else:
        targets = state.get("target_priorities", [])[:3]

    if not targets:
        return {"phase": "chain_discovery"}

    active_subgraph = build_active_subgraph()

    for target in targets:
        if budget.is_emergency:
            break

        browser = BrowserController(scope_guard, active_cfg)
        proxy = TrafficInterceptor(scope_guard, active_cfg)
        email_mgr = EmailManager(active_cfg)
        tool_runner = ToolRunner(scope_guard, active_cfg)

        try:
            if not active_cfg.dry_run:
                await browser.start()
                await proxy.start(port=active_cfg.proxy_port)
                if email_mgr.is_configured:
                    await email_mgr.start()

            # Calculate active testing budget allocation
            active_budget = budget.phases.get("active_testing")
            budget_limit = active_budget.remaining if active_budget else 0

            # Build subgraph config
            subgraph_config = {
                "configurable": {
                    "client": client,
                    "scope_guard": scope_guard,
                    "browser": browser,
                    "proxy": proxy,
                    "email_mgr": email_mgr,
                    "tool_runner": tool_runner,
                    "budget": budget,
                    "kill_switch_checker": c.get("kill_switch_checker"),
                    "thread_id": f"active_{target}",
                }
            }

            # Passive recon data for this target
            passive_recon = state.get("recon_results", {}).get(target, {})

            initial_active_state = {
                "target_url": target,
                "session_id": f"active_{target}",
                "passive_recon": passive_recon,
                "config": active_cfg.model_dump() if hasattr(active_cfg, "model_dump") else {},
                "budget_spent": 0,
                "budget_limit": budget_limit,
                "kill_switch_active": False,
                "phase": "planning",
            }

            active_result = await active_subgraph.ainvoke(
                initial_active_state, config=subgraph_config
            )

            # Collect results
            result_summary = {
                "target": target,
                "findings": active_result.get("validated_findings", []),
                "reports": active_result.get("reports", []),
                "errors": active_result.get("errors", []),
                "phase": active_result.get("phase", "completed"),
            }
            results.append(result_summary)

            logger.info(
                "active_test_target_done",
                target=target,
                findings=len(result_summary["findings"]),
                reports=len(result_summary["reports"]),
            )

        except Exception as e:
            logger.error("active_test_error", target=target, error=str(e))
            results.append({
                "target": target,
                "findings": [],
                "reports": [],
                "errors": [str(e)],
                "phase": "error",
            })

        finally:
            try:
                await browser.stop()
            except Exception:
                pass
            try:
                await proxy.stop()
            except Exception:
                pass
            try:
                await email_mgr.stop()
            except Exception:
                pass

    # Merge active findings into main pipeline
    active_findings = []
    active_reports = []
    for r in results:
        for f in r.get("findings", []):
            finding_dict = f.model_dump() if hasattr(f, "model_dump") else f
            finding_dict["_source"] = "active_testing"
            active_findings.append(finding_dict)
        for rpt in r.get("reports", []):
            report_dict = rpt.model_dump() if hasattr(rpt, "model_dump") else rpt
            report_dict["_source"] = "active_testing"
            active_reports.append(report_dict)

    return {
        "active_testing_results": results,
        "validated_findings": active_findings,
        "reports": active_reports,
        "phase": "chain_discovery",
    }


# ── Graph Builder ────────────────────────────────────────────────────


def _route_after_vuln(state: ScanState) -> str:
    """Route after vuln detection based on state."""
    phase = state.get("phase", "validation")
    status = state.get("status", "running")
    if status == "emergency":
        return "reporting"
    return phase


def _route_after_strategy(state: ScanState) -> str:
    """Route after strategy decision."""
    phase = state.get("phase", "chain_discovery")
    if phase == "recon":
        return "recon"
    elif phase == "vuln_detection":
        return "vuln_detection"
    # Route through active testing if enabled
    if state.get("active_testing_enabled") and _active_available:
        return "active_testing"
    return "chain_discovery"


def _route_after_validation(state: ScanState) -> str:
    """Route after validation."""
    return state.get("phase", "strategy")


def build_graph() -> StateGraph:
    """Build the LangGraph state machine.

    Graph structure:
        program_analysis → recon → recon_correlate → vuln_detection
        vuln_detection → validation | reporting (emergency)
        validation → strategy
        strategy → recon (next target) | vuln_detection (continue) | chain_discovery (done)
        chain_discovery → reporting
        reporting → END
    """
    graph = StateGraph(ScanState)

    # Add nodes
    graph.add_node("program_analysis", program_analysis_node)
    graph.add_node("recon", recon_node)
    graph.add_node("recon_correlate", recon_correlate_node)
    graph.add_node("vuln_detection", vuln_detection_node)
    graph.add_node("validation", validation_node)
    graph.add_node("strategy", strategy_node)
    graph.add_node("active_testing", active_testing_node)
    graph.add_node("chain_discovery", chain_discovery_node)
    graph.add_node("reporting", reporting_node)

    # Set entry point
    graph.set_entry_point("program_analysis")

    # Add edges
    graph.add_edge("program_analysis", "recon")
    graph.add_edge("recon", "recon_correlate")
    graph.add_edge("recon_correlate", "vuln_detection")

    # Conditional edges
    graph.add_conditional_edges(
        "vuln_detection",
        _route_after_vuln,
        {
            "validation": "validation",
            "reporting": "reporting",
        },
    )

    graph.add_conditional_edges(
        "validation",
        _route_after_validation,
        {
            "strategy": "strategy",
        },
    )

    graph.add_conditional_edges(
        "strategy",
        _route_after_strategy,
        {
            "recon": "recon",
            "vuln_detection": "vuln_detection",
            "active_testing": "active_testing",
            "chain_discovery": "chain_discovery",
        },
    )

    # Active testing feeds into chain discovery
    graph.add_edge("active_testing", "chain_discovery")

    graph.add_edge("chain_discovery", "reporting")
    graph.add_edge("reporting", END)

    return graph


# ── Entry Point ──────────────────────────────────────────────────────


async def run_scan(
    program_text: str,
    config: AIBrainConfig,
    scope: ScopeEnforcer,
    scan_id: str = "",
    db_dsn: str = "",
    active_testing: bool = False,
    active_dry_run: bool = False,
    active_target: str = "",
) -> dict[str, Any]:
    """Run a complete scan from program text to reports.

    Args:
        program_text: Bug bounty program description
        config: AI brain configuration
        scope: Scope enforcer instance
        scan_id: Unique scan ID for checkpointing
        db_dsn: PostgreSQL DSN for checkpointing (optional)
        active_testing: Enable active testing engine
        active_dry_run: Dry run mode (AI reasons but no browser/network actions)
        active_target: Test single URL instead of all targets

    Returns:
        Final scan state with reports
    """
    # Apply active testing config overrides
    if active_testing:
        config.active_testing.enabled = True
    if active_dry_run:
        config.active_testing.dry_run = True

    # Initialize components
    budget = BudgetManager(config.budget, active_testing=config.active_testing.enabled)
    rate_limiter = DualRateLimiter(
        target_rps=3.0,
        api_rpm=config.rate_limits.requests_per_minute,
        api_itpm=config.rate_limits.input_tokens_per_minute,
    )
    circuit_breaker = CircuitBreaker()
    client = ClaudeClient(
        config=config,
        budget=budget,
        rate_limiter=rate_limiter,
        circuit_breaker=circuit_breaker,
    )
    context = ContextManager()
    coordinator = CoordinatorAgent(
        client=client, scope=scope, context=context, budget=budget
    )
    idempotency = IdempotencyTracker()
    validator = ValidationOrchestrator()

    # Build graph
    graph = build_graph()

    # Set up checkpointer if DSN provided
    checkpointer = None
    if db_dsn:
        try:
            from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

            saver = AsyncPostgresSaver.from_conn_string(db_dsn)
            # Handle both direct and context-manager return styles
            if hasattr(saver, "__aenter__"):
                checkpointer = await saver.__aenter__()
            else:
                checkpointer = saver
            await checkpointer.setup()
        except Exception as e:
            checkpointer = None
            logger.warning("checkpointer_init_failed", error=str(e))

    compiled = graph.compile(checkpointer=checkpointer)

    # Initial state
    initial_state: ScanState = {
        "program_text": program_text,
        "scope_analysis": "",
        "target_priorities": [],
        "recon_results": {},
        "raw_findings": [],
        "validated_findings": [],
        "false_positives": [],
        "attack_chains": [],
        "reports": [],
        "phase": "program_analysis",
        "status": "starting",
        "current_target": "",
        "current_target_idx": 0,
        "targets_completed": [],
        "budget_summary": {},
        "start_time": time.time(),
        "elapsed_seconds": 0,
        "errors": [],
        "action_keys": set(),
        "vuln_solvers_run": [],
        "finding_rate": 0.0,
        "active_testing_enabled": config.active_testing.enabled,
        "active_testing_results": [],
        "active_target": active_target,
    }

    # Configure the graph execution
    run_config = {
        "configurable": {
            "client": client,
            "coordinator": coordinator,
            "scope": scope,
            "context": context,
            "budget": budget,
            "idempotency": idempotency,
            "validator": validator,
            "ai_config": config,
            "thread_id": scan_id or "default",
        }
    }

    # Execute the graph
    logger.info("scan_starting", scan_id=scan_id)

    final_state = await compiled.ainvoke(initial_state, config=run_config)

    logger.info(
        "scan_complete",
        scan_id=scan_id,
        reports=len(final_state.get("reports", [])),
        elapsed=f"{final_state.get('elapsed_seconds', 0) / 60:.1f}m",
        budget=final_state.get("budget_summary", {}),
    )

    return final_state


# ── Helper Functions ─────────────────────────────────────────────────


def _build_recon_data(
    solver_type: str, target: str, state: ScanState
) -> dict[str, Any]:
    """Build input data dict for a recon solver."""
    if solver_type == "subdomain_classification":
        return {
            "subdomains": target,
            "httpx_data": "",
        }
    elif solver_type == "js_analysis":
        return {
            "js_content": "",
            "source_url": target,
        }
    elif solver_type == "api_swagger_analysis":
        return {
            "api_spec": "",
            "base_url": target,
        }
    elif solver_type == "wordlist_generation":
        return {
            "target": target,
            "tech_stack": "",
        }
    return {"target": target}


def _build_vuln_data(
    solver_type: str, target: str, state: ScanState
) -> dict[str, Any]:
    """Build input data dict for a vuln detection solver."""
    recon = state.get("recon_results", {}).get(target, {})

    if solver_type == "idor_detection":
        return {"endpoints": json.dumps(recon), "request_data": ""}
    elif solver_type == "auth_bypass":
        return {"auth_data": json.dumps(recon)}
    elif solver_type == "cors_detection":
        return {"cors_data": json.dumps(recon)}
    elif solver_type == "jwt_oauth_detection":
        return {"token_data": json.dumps(recon)}
    elif solver_type == "ssrf_detection":
        return {"endpoint_data": json.dumps(recon)}
    elif solver_type == "mass_assignment":
        return {"endpoint_data": json.dumps(recon)}
    elif solver_type == "error_message_analysis":
        return {"error_data": json.dumps(recon)}
    elif solver_type == "business_logic":
        return {"workflow_data": json.dumps(recon), "endpoint_data": ""}
    elif solver_type == "graphql_detection":
        return {"graphql_data": json.dumps(recon)}
    return {"data": json.dumps(recon)}


def _has_actionable_findings(finding: dict[str, Any]) -> bool:
    """Check if a finding contains actionable results."""
    confidence = finding.get("confidence", 0)
    if confidence >= 40:
        return True

    # Check for specific finding indicators
    if finding.get("candidates"):
        return True
    if finding.get("findings"):
        return True

    severity = finding.get("severity", "")
    if severity in ("medium", "high", "critical"):
        return True

    return False
