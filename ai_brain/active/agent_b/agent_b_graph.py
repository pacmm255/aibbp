"""Agent B LangGraph — Plan-and-Execute knowledge-augmented pentester.

Reads Agent A's state, retrieves novel techniques from RAG corpus,
plans attacks using Claude, and executes them using Agent A's tools.
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any, TypedDict

import structlog
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph

logger = structlog.get_logger()


class AgentBState(TypedDict, total=False):
    """State for Agent B's Plan-and-Execute loop."""
    # Target info (from Agent A)
    target_url: str
    tech_stack: list[str]
    endpoints: dict
    agent_a_findings: dict
    agent_a_tested: dict
    agent_a_failed: dict
    agent_a_accounts: dict

    # Agent B's own state
    plans: list[dict]           # Generated attack plans
    current_plan_idx: int       # Which plan we're executing
    current_step_idx: int       # Which step within the plan
    step_results: list[dict]    # Results from executed steps
    findings: dict              # Agent B's own findings
    tested_techniques: dict     # What Agent B has tested
    reflections: list[str]      # Post-failure reflections

    # Control
    turn_count: int
    max_turns: int
    done: bool
    done_reason: str
    last_state_update: float    # timestamp of last Agent A state read
    cycle_count: int            # How many plan-execute cycles


async def retrieve_node(state: AgentBState, config: RunnableConfig) -> dict:
    """Read Agent A's state and retrieve relevant techniques from RAG."""
    kb = config["configurable"]["knowledge_base"]
    scorer = config["configurable"]["novelty_scorer"]
    watcher = config["configurable"]["state_watcher"]

    # Read latest Agent A state
    agent_a_state = watcher.read_current()
    if agent_a_state is None:
        logger.warning("agent_a_state_not_available")
        return {"done": True, "done_reason": "Agent A state not available"}

    key_fields = watcher.extract_key_fields(agent_a_state)
    tech_stack = key_fields["tech_stack"]
    endpoints = key_fields["endpoints"]
    tested = key_fields["tested_techniques"]
    findings = key_fields["findings"]
    failed = key_fields["failed_approaches"]

    # Update novelty scorer with Agent A's history
    scorer.update_agent_a_state(tested, findings, failed)

    # Retrieve techniques from knowledge base
    techniques = kb.search_for_target(
        tech_stack=tech_stack,
        endpoints=endpoints,
        tested_techniques=tested,
        limit=20,
    )

    # Filter to novel ones only
    novel_techniques = scorer.filter_novel(techniques, threshold=0.4)
    logger.info("agent_b_retrieve",
                total_retrieved=len(techniques),
                novel=len(novel_techniques),
                tech_stack=tech_stack[:5])

    if not novel_techniques:
        logger.info("agent_b_no_novel_techniques")
        return {
            "done": True,
            "done_reason": "No novel techniques found — Agent A has good coverage",
        }

    # Store in state for planner
    return {
        "target_url": key_fields["target_url"],
        "tech_stack": tech_stack,
        "endpoints": endpoints,
        "agent_a_findings": findings,
        "agent_a_tested": tested,
        "agent_a_failed": failed,
        "agent_a_accounts": key_fields["accounts"],
        "last_state_update": time.time(),
        # Store technique cards in config for planner access
        "_novel_techniques": novel_techniques,
    }


async def plan_node(state: AgentBState, config: RunnableConfig) -> dict:
    """Generate attack plans using Claude + RAG technique cards."""
    from ai_brain.active.agent_b.planner import build_plan_prompt, parse_plans

    client = config["configurable"]["planner_client"]  # Claude
    novel_techniques = state.get("_novel_techniques", [])

    if not novel_techniques:
        return {"done": True, "done_reason": "No techniques to plan with"}

    # Build planning prompt
    messages = build_plan_prompt(
        target_url=state.get("target_url", ""),
        tech_stack=state.get("tech_stack", []),
        endpoints=state.get("endpoints", {}),
        findings=state.get("agent_a_findings", {}),
        tested_techniques=state.get("agent_a_tested", {}),
        technique_cards=novel_techniques[:5],
        failed_approaches=state.get("agent_a_failed"),
    )

    # Call Claude for planning
    try:
        response = await client.call(
            messages=messages,
            model_tier="complex",  # Use Sonnet for planning
            max_tokens=4096,
        )
        response_text = response.content[0].text if response.content else ""
        plans = parse_plans(response_text)

        if not plans:
            logger.warning("agent_b_no_plans_generated")
            return {"done": True, "done_reason": "Planner produced no valid plans"}

        logger.info("agent_b_plans_generated", count=len(plans),
                    plan_names=[p.get("rationale", "")[:50] for p in plans])

        return {
            "plans": plans,
            "current_plan_idx": 0,
            "current_step_idx": 0,
            "step_results": [],
        }
    except Exception as e:
        logger.error("agent_b_plan_failed", error=str(e))
        return {"done": True, "done_reason": f"Planning failed: {e}"}


async def execute_node(state: AgentBState, config: RunnableConfig) -> dict:
    """Execute the current step of the current plan using Agent A's tools."""
    tool_runner = config["configurable"]["tool_runner"]
    scope_guard = config["configurable"]["scope_guard"]

    plans = state.get("plans", [])
    plan_idx = state.get("current_plan_idx", 0)
    step_idx = state.get("current_step_idx", 0)
    step_results = list(state.get("step_results", []))
    findings = dict(state.get("findings", {}))
    tested = dict(state.get("tested_techniques", {}))

    if plan_idx >= len(plans):
        return {"done": True, "done_reason": "All plans executed"}

    plan = plans[plan_idx]
    steps = plan.get("steps", [])

    if step_idx >= len(steps):
        # Move to next plan
        return {
            "current_plan_idx": plan_idx + 1,
            "current_step_idx": 0,
            "step_results": [],
        }

    step = steps[step_idx]
    tool_name = step.get("tool", "")
    tool_input = step.get("tool_input", {})
    description = step.get("description", "")

    logger.info("agent_b_executing_step",
                plan=plan_idx + 1, step=step_idx + 1,
                tool=tool_name, desc=description[:80])

    # Execute the tool
    try:
        # Ensure target URL is set in input if needed
        if "url" not in tool_input and "target" not in tool_input:
            tool_input["url"] = state.get("target_url", "")

        result = await asyncio.wait_for(
            tool_runner.run(tool_name, tool_input),
            timeout=120.0,
        )

        step_result = {
            "step_num": step_idx + 1,
            "tool": tool_name,
            "success": not result.get("error"),
            "output_preview": str(result.get("output", result.get("raw_text", "")))[:500],
            "error": result.get("error", ""),
        }
        step_results.append(step_result)

        # Track as tested
        tech_key = f"{tool_input.get('url', '')}::{tool_name}::agent_b"
        tested[tech_key] = True

        # Check for findings in result
        if result.get("findings"):
            for f in result["findings"]:
                fid = f"agent_b_{len(findings)}"
                f["source"] = "agent_b"
                f["plan_rationale"] = plan.get("rationale", "")
                findings[fid] = f

        # Check success criteria
        success_criteria = step.get("success_criteria", "")
        output_text = str(result.get("output", ""))
        failure_action = step.get("failure_action", "skip")

        if result.get("error") and failure_action == "abort":
            # Abort this plan
            return {
                "current_plan_idx": plan_idx + 1,
                "current_step_idx": 0,
                "step_results": [],
                "findings": findings,
                "tested_techniques": tested,
            }

        return {
            "current_step_idx": step_idx + 1,
            "step_results": step_results,
            "findings": findings,
            "tested_techniques": tested,
            "turn_count": state.get("turn_count", 0) + 1,
        }

    except asyncio.TimeoutError:
        logger.warning("agent_b_step_timeout", tool=tool_name)
        step_results.append({
            "step_num": step_idx + 1,
            "tool": tool_name,
            "success": False,
            "error": "timeout",
        })
        return {
            "current_step_idx": step_idx + 1,
            "step_results": step_results,
            "turn_count": state.get("turn_count", 0) + 1,
        }
    except Exception as e:
        logger.error("agent_b_step_error", tool=tool_name, error=str(e))
        return {
            "current_step_idx": step_idx + 1,
            "step_results": step_results,
            "turn_count": state.get("turn_count", 0) + 1,
        }


async def reflect_node(state: AgentBState, config: RunnableConfig) -> dict:
    """Post-plan reflection — what worked, what didn't, what to try next."""
    plans = state.get("plans", [])
    plan_idx = state.get("current_plan_idx", 0)
    step_results = state.get("step_results", [])
    reflections = list(state.get("reflections", []))
    cycle_count = state.get("cycle_count", 0)

    # If we've executed all plans, reflect on the cycle
    if plan_idx >= len(plans):
        findings = state.get("findings", {})
        total_steps = sum(len(p.get("steps", [])) for p in plans)
        successful_steps = sum(1 for r in step_results if r.get("success"))

        reflection = (
            f"Cycle {cycle_count + 1}: Executed {len(plans)} plans, "
            f"{total_steps} steps ({successful_steps} successful). "
            f"Found {len(findings)} findings."
        )
        reflections.append(reflection)
        logger.info("agent_b_cycle_reflection", reflection=reflection)

        return {
            "reflections": reflections,
            "cycle_count": cycle_count + 1,
        }

    return {}


def _should_continue(state: AgentBState) -> str:
    """Route: continue executing or move to next phase."""
    if state.get("done"):
        return "end"

    plans = state.get("plans", [])
    plan_idx = state.get("current_plan_idx", 0)

    if not plans:
        return "end"

    # Still have steps to execute in current plan
    if plan_idx < len(plans):
        step_idx = state.get("current_step_idx", 0)
        steps = plans[plan_idx].get("steps", [])
        if step_idx < len(steps):
            return "execute"

    # All plans done — reflect
    if plan_idx >= len(plans):
        return "reflect"

    return "execute"


def _after_reflect(state: AgentBState) -> str:
    """After reflection: start new cycle or finish."""
    max_turns = state.get("max_turns", 50)
    turn_count = state.get("turn_count", 0)
    cycle_count = state.get("cycle_count", 0)

    if turn_count >= max_turns and max_turns > 0:
        return "end"
    if cycle_count >= 3:  # Max 3 plan-execute cycles per session
        return "end"

    # Start new retrieval cycle
    return "retrieve"


def build_agent_b_graph() -> StateGraph:
    """Build the Agent B Plan-and-Execute LangGraph."""
    graph = StateGraph(AgentBState)

    graph.add_node("retrieve", retrieve_node)
    graph.add_node("plan", plan_node)
    graph.add_node("execute", execute_node)
    graph.add_node("reflect", reflect_node)

    # Flow: retrieve → plan → execute (loop) → reflect → (retrieve or end)
    graph.set_entry_point("retrieve")

    graph.add_edge("retrieve", "plan")

    graph.add_conditional_edges(
        "plan",
        _should_continue,
        {"execute": "execute", "reflect": "reflect", "end": END},
    )

    graph.add_conditional_edges(
        "execute",
        _should_continue,
        {"execute": "execute", "reflect": "reflect", "end": END},
    )

    graph.add_conditional_edges(
        "reflect",
        _after_reflect,
        {"retrieve": "retrieve", "end": END},
    )

    return graph.compile()
