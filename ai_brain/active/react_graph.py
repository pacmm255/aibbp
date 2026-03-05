"""3-node LangGraph for the single-brain ReAct pentesting agent.

brain_node  → Claude reasons and selects tools
tool_executor_node → Dispatches tool calls to backends
context_compressor → Compresses conversation when it grows large

Loop: brain → tools → compress → brain (until done or budget exhausted).
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog
from langchain_core.runnables import RunnableConfig
from langgraph.graph import END, StateGraph

from ai_brain.active.chain_discovery import ChainDiscoveryEngine, AdversarialReasoningEngine
from ai_brain.active.react_knowledge_graph import KnowledgeGraph
from ai_brain.active.react_prompt import (
    build_static_prompt, build_free_brain_prompt, build_dynamic_prompt,
    build_system_prompt, get_tool_schemas, _detect_phase, CHAIN_TEMPLATES,
)
from ai_brain.active.react_state import PentestState
from ai_brain.active.react_tools import ToolDeps, dispatch_tool
from ai_brain.errors import BudgetExhausted

logger = structlog.get_logger()

# ── Reasoning & Chain Engines (module-level singletons, zero LLM cost) ──
_reasoning_engine = AdversarialReasoningEngine()
_chain_engine = ChainDiscoveryEngine()

# ── Live Display ─────────────────────────────────────────────────────

# ANSI colors
_DIM = "\033[2m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_MAGENTA = "\033[35m"
_BLUE = "\033[34m"
_RESET = "\033[0m"
_WHITE = "\033[97m"

_LIVE = True  # Always on — use --quiet to suppress


def _elapsed_str(state: dict) -> str:
    """Human-readable elapsed time."""
    start = state.get("start_time", 0)
    if not start:
        return "0s"
    secs = int(time.time() - start)
    if secs < 60:
        return f"{secs}s"
    mins = secs // 60
    if mins < 60:
        return f"{mins}m{secs % 60:02d}s"
    hours = mins // 60
    return f"{hours}h{mins % 60:02d}m"


def _status_bar(state: dict, budget_obj=None) -> str:
    """One-line status bar."""
    turn = state.get("turn_count", 0)
    spent = budget_obj.total_spent if budget_obj else state.get("budget_spent", 0)
    limit = state.get("budget_limit", 0)
    findings = len(state.get("findings", {}))
    elapsed = _elapsed_str(state)
    techniques = len(state.get("tested_techniques", {}))
    return (
        f"{_DIM}──── "
        f"Turn {_WHITE}{turn}{_DIM} │ "
        f"${_WHITE}{spent:.2f}{_DIM}/${limit:.0f} │ "
        f"Findings: {_GREEN if findings else _DIM}{findings}{_DIM} │ "
        f"Techniques: {techniques} │ "
        f"{elapsed}"
        f" ────{_RESET}"
    )


def _print_reasoning(text: str) -> None:
    """Print the brain's reasoning/thinking."""
    if not text.strip():
        return
    print(f"\n{_CYAN}{_BOLD}🧠 THINKING:{_RESET}")
    # Wrap long lines for readability
    for line in text.split("\n"):
        if len(line) > 120:
            # Soft wrap
            while len(line) > 120:
                print(f"  {_CYAN}{line[:120]}{_RESET}")
                line = line[120:]
            if line:
                print(f"  {_CYAN}{line}{_RESET}")
        else:
            print(f"  {_CYAN}{line}{_RESET}")


def _print_thinking(text: str) -> None:
    """Print the brain's extended thinking (Opus/Z.ai)."""
    if not text.strip():
        return
    display = text[:2000]
    if len(text) > 2000:
        display += f"\n... [{len(text) - 2000} more chars]"
    print(f"\n{_BLUE}{_BOLD}\U0001f4ad DEEP THINKING:{_RESET}")
    for line in display.split("\n"):
        if len(line) > 120:
            while len(line) > 120:
                print(f"  {_BLUE}{line[:120]}{_RESET}")
                line = line[120:]
            if line:
                print(f"  {_BLUE}{line}{_RESET}")
        else:
            print(f"  {_BLUE}{line}{_RESET}")


def _print_tool_call(name: str, tool_input: dict) -> None:
    """Print a tool call with key parameters."""
    # Extract the most useful params to show
    show_params = {}
    for key in ("url", "target", "start_url", "action", "method", "description"):
        if key in tool_input:
            val = str(tool_input[key])
            show_params[key] = val[:100] + "..." if len(val) > 100 else val

    params_str = ", ".join(f"{k}={v}" for k, v in show_params.items())
    print(f"  {_YELLOW}⚡ {name}{_RESET}({_DIM}{params_str}{_RESET})")

    # For run_custom_exploit, show the code being run
    if name == "run_custom_exploit" and "code" in tool_input:
        code = tool_input["code"]
        lines = code.strip().split("\n")
        print(f"  {_DIM}┌── Python exploit ({len(lines)} lines) ──{_RESET}")
        # Show first 15 and last 5 lines
        show_lines = lines[:15]
        if len(lines) > 20:
            show_lines += [f"  ... ({len(lines) - 20} more lines) ..."]
            show_lines += lines[-5:]
        elif len(lines) > 15:
            show_lines = lines
        for line in show_lines:
            print(f"  {_DIM}│ {line}{_RESET}")
        print(f"  {_DIM}└{'─' * 40}{_RESET}")

    # For send_http_request, show body
    if name == "send_http_request" and "body" in tool_input:
        body = str(tool_input["body"])
        if len(body) > 200:
            body = body[:200] + "..."
        print(f"  {_DIM}  body: {body}{_RESET}")


def _print_tool_result(name: str, result_str: str, is_error: bool = False) -> None:
    """Print a tool result summary."""
    color = _RED if is_error else _GREEN
    # Parse JSON result if possible
    try:
        result = json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        result = {"raw": result_str[:300]}

    # Show compact result
    if is_error:
        print(f"  {_RED}✗ {name}: {str(result.get('error', result))[:200]}{_RESET}")
        return

    # For successful results, show key info
    result_preview = ""
    if isinstance(result, dict):
        # Skip _state_update internals
        visible = {k: v for k, v in result.items() if not k.startswith("_")}
        if "status_code" in visible:
            result_preview += f"HTTP {visible['status_code']} "
        if "stdout" in visible:
            stdout = str(visible["stdout"])
            # Show last meaningful lines of stdout
            lines = [l for l in stdout.strip().split("\n") if l.strip()][-8:]
            result_preview = "\n".join(lines)
        elif "body" in visible:
            body = str(visible["body"])[:300]
            result_preview += body
        elif "links" in visible or "forms" in visible:
            result_preview += f"links={len(visible.get('links', []))} forms={len(visible.get('forms', []))}"
        elif "error" in visible:
            result_preview += str(visible["error"])[:200]
        else:
            # Generic: show first few keys and values
            for k, v in list(visible.items())[:3]:
                val_str = str(v)[:100]
                result_preview += f"{k}={val_str} "

    if not result_preview:
        result_preview = result_str[:200]

    # Truncate final output
    lines = result_preview.strip().split("\n")
    if len(lines) > 10:
        lines = lines[:8] + [f"  ... ({len(lines) - 8} more lines)"]
    print(f"  {color}✓ {name}:{_RESET}")
    for line in lines:
        print(f"  {_DIM}  {line}{_RESET}")


def _extract_intended_tool(text: str, tools: list[dict]) -> str | None:
    """Scan text for mentions of tool names and return the best match.

    Used by the free-brain retry logic to craft specific nudge messages.
    """
    text_lower = text.lower()
    tool_names = [t["name"] for t in tools]
    # Check for exact tool name mentions (most specific first)
    for name in sorted(tool_names, key=len, reverse=True):
        if name in text_lower or name.replace("_", " ") in text_lower:
            return name
    return None


def _print_finding(finding_id: str, finding: dict) -> None:
    """Print a finding prominently."""
    sev = finding.get("severity", "?").upper()
    vtype = finding.get("vuln_type", "?")
    ep = finding.get("endpoint", "?")
    confirmed = finding.get("confirmed", False)
    sev_color = _RED if sev in ("CRITICAL", "HIGH") else _YELLOW
    status = f"{_GREEN}CONFIRMED{_RESET}" if confirmed else f"{_YELLOW}unconfirmed{_RESET}"
    print(f"\n  {sev_color}{_BOLD}{'🚨' if confirmed else '⚠️ '} [{sev}] {vtype}{_RESET}")
    print(f"  {_WHITE}  Endpoint: {ep}{_RESET}")
    print(f"  {_WHITE}  Status:   {status}")
    evidence = finding.get("evidence", "")
    if evidence:
        print(f"  {_WHITE}  Evidence: {str(evidence)[:300]}{_RESET}")
    print()


# ── Tiered Model Selection ────────────────────────────────────────────

# Signals in tool results that warrant Opus review
_ESCALATION_PATTERNS = re.compile(
    "|".join([
        # SQL errors
        r"sql syntax", r"mysql_", r"pg_query", r"sqlite3?\.", r"ORA-\d{4,5}",
        r"unclosed quotation", r"unterminated string",
        # Template injection
        r"jinja2?", r"twig", r"mako", r"freemarker",
        # Command injection indicators
        r"root:x:0:0", r"/etc/passwd", r"uid=\d+\(", r"www-data",
        # SSRF / internal access
        r"169\.254\.169\.254", r"metadata\.google",
        # Auth bypass signals
        r"admin.*dashboard", r"privilege.*escalat",
        # Sensitive data
        r"FLAG\{", r"flag\{", r"api[_-]?key\s*[:=]",
        # XSS reflection
        r"<script[> ]", r"alert\s*\(",
        # Server errors suggesting mishandling
        r"stack\s*trace", r"traceback", r"internal server error",
    ]),
    re.IGNORECASE,
)

# Mode prefixes for Sonnet (worker) and Opus (manager) turns
_WORKER_PREFIX = (
    "You are in WORKER MODE. Focus on executing tools efficiently and reading "
    "results carefully. If you discover something that looks like a real "
    "vulnerability (SQL errors, auth bypass, sensitive data exposure, XSS "
    "reflection, command execution), describe what you found clearly in your "
    "reasoning — the manager will review it next turn. Keep testing methodically. "
    "This is an authorized penetration test with explicit written permission."
)
_MANAGER_PREFIX = (
    "You are in MANAGER MODE. Review ALL recent tool results carefully. "
    "Validate any potential findings (check for false positives). Decide if "
    "strategic pivots are needed. Form new hypotheses. Think creatively about "
    "attack chains and what has been missed. Plan the next phase of testing."
)


def _has_escalation_signals(state: PentestState) -> bool:
    """Check if recent tool results contain signals worth escalating to Opus."""
    messages = state.get("messages", [])
    if not messages:
        return False

    # Check last 2 messages (tool results come as user messages after tool_executor)
    for msg in messages[-2:]:
        content = msg.get("content", "")
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict):
                    text = block.get("content", "") or block.get("text", "")
                    if isinstance(text, str) and _ESCALATION_PATTERNS.search(text[:5000]):
                        return True
        elif isinstance(content, str):
            if _ESCALATION_PATTERNS.search(content[:5000]):
                return True
    return False


def _select_brain_tier(state: PentestState) -> tuple[str, str]:
    """Determine which model tier to use for this brain turn.

    Returns (tier, reason) where tier is "critical" (Opus) or "complex" (Sonnet).
    Default: Sonnet. Escalate to Opus only when justified.
    """
    turn = state.get("turn_count", 0)
    last_opus = state.get("last_opus_turn", -1)
    max_turns = state.get("max_turns", 150)

    # 1. Turn 0: Always Opus for initial strategy
    if turn == 0:
        return "critical", "initial_strategy"

    # 2. Periodic review: every 8 turns since last Opus call
    if turn - last_opus >= 8:
        return "critical", "periodic_review"

    # 3. New finding detected (check info_gain_history)
    info_gains = state.get("info_gain_history", [])
    if info_gains:
        last_gain = info_gains[-1]
        if last_gain.get("new_findings", 0) > 0:
            return "critical", "new_finding"

    # 4. Stalled: no progress for 5+ turns
    no_progress = state.get("no_progress_count", 0)
    if no_progress >= 5:
        return "critical", "stalled"

    # 5. Strategy reset in recent messages
    messages = state.get("messages", [])
    if messages:
        last_content = messages[-1].get("content", "")
        if isinstance(last_content, str) and "STRATEGY RESET" in last_content:
            return "critical", "strategy_reset"

    # 6. Interesting signals in recent tool results
    if _has_escalation_signals(state):
        return "critical", "escalation_signal"

    # 7. Budget wrapping up (>80% used, finite mode only)
    if max_turns != 0:
        budget_spent = state.get("budget_spent", 0.0)
        budget_limit = state.get("budget_limit", 1.0)
        if budget_limit > 0 and (budget_spent / budget_limit) > 0.80:
            return "critical", "budget_high"

    # Default: Sonnet worker
    return "complex", "routine"


# ── Node 1: Brain ────────────────────────────────────────────────────


async def brain_node(state: PentestState, config: RunnableConfig) -> dict:
    """The brain: Claude reasons about what to test and selects tools.

    Builds the system prompt from current state, sends the full conversation
    to Claude with tool definitions, and returns the assistant response
    (which may contain tool_use blocks).
    """
    # Check for graceful shutdown request (SIGINT)
    from ai_brain.active.react_main import _shutdown_requested
    if _shutdown_requested:
        return {"done": True, "done_reason": "Shutdown requested (SIGINT)"}

    client = config["configurable"]["client"]
    budget = config["configurable"]["budget"]

    # Check budget before calling Claude
    budget_pct = budget.total_spent / max(budget.config.total_dollars, 0.01) * 100
    if budget_pct >= 95:
        logger.warning("brain_budget_critical", pct=f"{budget_pct:.0f}%")
        return {
            "done": True,
            "done_reason": f"Budget critical ({budget_pct:.0f}% used)",
        }

    # Check turn limit (0 = indefinite — no turn limit)
    turn_count = state.get("turn_count", 0)
    max_turns = state.get("max_turns", 150)
    if max_turns > 0 and turn_count >= max_turns:
        return {"done": True, "done_reason": f"Max turns reached ({max_turns})"}

    # Initialize or retrieve knowledge graph (persists via config)
    kg = config["configurable"].get("_knowledge_graph")
    if kg is None:
        kg = KnowledgeGraph()
        config["configurable"]["_knowledge_graph"] = kg

    # Inject knowledge graph and default headers into state for prompt builder
    state_with_kg = dict(state)
    state_with_kg["_knowledge_graph"] = kg
    state_with_kg["_default_headers"] = config["configurable"].get("default_headers", {})

    # Detect Z.ai or ChatGPT mode (non-Claude clients use text-based tool calling)
    is_zai = hasattr(client, "MODEL")  # ZaiClient has MODEL attr
    is_chatgpt = type(client).__name__ == "ChatGPTClient"
    is_free_brain = is_zai or is_chatgpt

    # Build system prompt as split blocks: static (cached) + dynamic (not cached)
    # Free brains get few-shot examples appended to static prompt
    static_text = build_free_brain_prompt() if is_free_brain else build_static_prompt()
    dynamic_text = build_dynamic_prompt(state_with_kg)

    # Select model tier: Opus for strategy/validation, Sonnet for routine testing
    if is_free_brain:
        task_tier = "complex"
        tier_reason = "chatgpt" if is_chatgpt else "zai"
    else:
        task_tier, tier_reason = _select_brain_tier(state)
    logger.info("brain_tier_selected", tier=task_tier, reason=tier_reason, turn=turn_count)

    # Build system blocks with mode prefix + cached static + dynamic state
    mode_prefix = _WORKER_PREFIX if task_tier == "complex" else _MANAGER_PREFIX
    system_blocks = [
        # 1. Mode prefix (~50 tokens, not cached)
        {"type": "text", "text": mode_prefix},
        # 2. Static methodology (~7K tokens, CACHED at 90% discount after first call)
        {"type": "text", "text": static_text, "cache_control": {"type": "ephemeral"}},
        # 3. Dynamic state (NOT cached — changes every turn)
        {"type": "text", "text": dynamic_text},
    ]

    if _LIVE:
        if is_chatgpt:
            tier_label = f"{_GREEN}ChatGPT (free){_RESET}"
        elif is_zai:
            tier_label = f"{_GREEN}GLM-5 (Z.ai free){_RESET}"
        elif task_tier == "critical":
            tier_label = f"{_MAGENTA}OPUS (manager: {tier_reason}){_RESET}"
        else:
            tier_label = f"{_BLUE}SONNET (worker){_RESET}"
        print(f"  {_DIM}Brain: {tier_label}")

    # Get tool schemas
    tools = get_tool_schemas(state)

    # Build messages for Claude
    messages = state.get("messages", [])

    # If this is the first turn, add a bootstrap user message
    if not messages:
        target = state.get("target_url", "")
        messages = [
            {
                "role": "user",
                "content": (
                    f"You are starting a penetration test against {target}. "
                    "Begin with thorough reconnaissance: crawl the site, detect "
                    "technologies, discover hidden endpoints (use systematic_fuzz "
                    "with common-dirs AND common-files), and analyze the attack surface. "
                    "Check for config/source code exposure (.git, .env, Dockerfile, backup files). "
                    "Look for S3 buckets, API endpoints, JWT tokens in cookies/responses. "
                    "Form hypotheses about what might be vulnerable and why. "
                    "When you find something exploitable, create an attack chain "
                    "with manage_chain if it needs multiple steps. Then test systematically."
                ),
            }
        ]

    # ── Auto-strategy injection for free brains (every 5 turns) ──
    if is_free_brain and turn_count > 0 and turn_count % 5 == 0:
        tested = state.get("tested_techniques", {})
        endpoints = state.get("endpoints", {})
        findings = state.get("findings", {})
        no_prog = state.get("no_progress_count", 0)

        # Identify untested attack categories
        tested_categories = set()
        for key in tested:
            parts = key.split("::")
            if len(parts) > 1:
                tested_categories.add(parts[1])
        all_categories = {
            "crawl_target", "systematic_fuzz", "test_sqli", "test_xss",
            "test_auth_bypass", "response_diff_analyze", "test_jwt",
            "test_file_upload", "test_idor", "blind_sqli_extract",
            "run_content_discovery", "test_cmdi", "test_ssrf",
        }
        untested = sorted(all_categories - tested_categories)

        # Get chain suggestions
        chain_suggestions = []
        try:
            for chain_id, chain_info in state.get("attack_chains", {}).items():
                if chain_info.get("current_step", 0) < len(chain_info.get("steps", [])):
                    chain_suggestions.append(
                        f"Continue chain '{chain_id}': {chain_info.get('goal', '?')}"
                    )
        except Exception:
            pass

        checkpoint_parts = [
            f"\n\nSTRATEGY CHECKPOINT (Turn {turn_count}):",
            f"- Tested: {len(tested)} techniques on {len(endpoints)} endpoints",
            f"- Findings: {len(findings)}",
            f"- No-progress streak: {no_prog} turns",
        ]
        if untested:
            checkpoint_parts.append(f"- UNTESTED techniques: {', '.join(untested[:6])}")
        if chain_suggestions:
            checkpoint_parts.append("\nSUGGESTED NEXT ACTIONS:")
            for i, sug in enumerate(chain_suggestions[:3], 1):
                checkpoint_parts.append(f"  {i}. {sug}")
        if no_prog >= 3:
            checkpoint_parts.append(
                "\n⚠ You are STALLED. Try a completely different technique or endpoint."
            )
        checkpoint_parts.append(
            "\nPick ONE action and execute it NOW. Output the JSON tool call."
        )
        checkpoint = "\n".join(checkpoint_parts)

        # Inject into last user message or append
        messages = list(messages)
        if messages and messages[-1].get("role") == "user":
            last = dict(messages[-1])
            content = last.get("content", "")
            if isinstance(content, str):
                last["content"] = content + checkpoint
            elif isinstance(content, list):
                last["content"] = content + [{"type": "text", "text": checkpoint}]
            messages[-1] = last
        else:
            messages.append({"role": "user", "content": checkpoint})

        logger.info("free_brain_strategy_injected", turn=turn_count,
                     untested=len(untested), findings=len(findings))
        if _LIVE:
            print(f"  {_MAGENTA}📋 Strategy checkpoint injected (turn {turn_count}){_RESET}")

    try:
        response = await client.call_with_tools(
            phase="active_testing",
            task_tier=task_tier,
            system_blocks=system_blocks,
            messages=messages,
            tools=tools,
            target=state.get("target_url", ""),
        )
    except BudgetExhausted as e:
        logger.warning("brain_budget_exhausted", error=str(e))
        _transcript_be = config["configurable"].get("transcript")
        if _transcript_be:
            try:
                _transcript_be.log_error(str(e), context="brain_budget_exhausted")
            except Exception:
                pass
        return {
            "done": True,
            "done_reason": f"Budget exhausted: {e}",
        }
    except Exception as e:
        import asyncio as _aio
        error_str = str(e)
        logger.error("brain_call_failed", error=error_str)
        _transcript_bf = config["configurable"].get("transcript")
        if _transcript_bf:
            try:
                _transcript_bf.log_error(error_str, context="brain_call_failed")
            except Exception:
                pass
        # For transient errors: DON'T die — wait and let the graph loop retry
        transient_keywords = ["rate_limit", "405", "429", "500", "502", "503", "504",
                              "timeout", "connection", "OAuth", "expired", "401"]
        is_transient = any(kw.lower() in error_str.lower() for kw in transient_keywords)
        if is_transient:
            # 405 = IP-level rate limit on Z.ai, needs longer cooldown
            wait = 300 if "405" in error_str else 60
            logger.warning("brain_transient_error_waiting", wait=wait, error=error_str[:100])
            print(f"\n  [!] Transient error — waiting {wait}s before retry...")
            await _aio.sleep(wait)
            # Return empty result — graph will loop back to brain
            return {
                "errors": [f"brain_call_failed (transient, retrying): {e}"],
            }
        return {
            "errors": [f"brain_call_failed: {e}"],
            "done": True,
            "done_reason": f"API error: {e}",
        }

    # Parse response content into our message format
    content_blocks = response.content

    # Build assistant message for conversation history
    # We need to serialize content blocks into a format we can store and replay
    serialized_content = _serialize_content(content_blocks)
    new_messages = [{"role": "assistant", "content": serialized_content}]

    # Extract tool calls and thinking blocks
    tool_calls = [b for b in content_blocks if getattr(b, "type", "") == "tool_use"]
    thinking_blocks = [b for b in content_blocks if getattr(b, "type", "") == "thinking"]

    # ── Sonnet refusal fallback: if Sonnet refuses, retry with Opus ──
    # (Skip in Z.ai/ChatGPT mode — no Opus fallback available)
    text_blocks = [b for b in content_blocks if getattr(b, "type", "") == "text"]
    if not is_free_brain and task_tier == "complex" and not tool_calls and response.stop_reason == "end_turn":
        all_text = " ".join(_block_text(b) for b in text_blocks).lower()
        _refusal_phrases = [
            "i can't", "i cannot", "i'm unable", "i am unable",
            "not appropriate", "safety concern", "won't be able",
            "decline to", "i shouldn't", "not comfortable",
        ]
        if any(phrase in all_text for phrase in _refusal_phrases):
            logger.warning("sonnet_refused_escalating", turn=turn_count, preview=all_text[:200])
            if _LIVE:
                print(f"  {_YELLOW}⚠ Sonnet refused — escalating to Opus{_RESET}")
            try:
                # Switch system blocks to manager mode
                system_blocks[0] = {"type": "text", "text": _MANAGER_PREFIX}
                response = await client.call_with_tools(
                    phase="active_testing",
                    task_tier="critical",
                    system_blocks=system_blocks,
                    messages=messages,
                    tools=tools,
                    target=state.get("target_url", ""),
                )
                task_tier = "critical"
                tier_reason = "sonnet_refused"
                content_blocks = response.content
                serialized_content = _serialize_content(content_blocks)
                new_messages = [{"role": "assistant", "content": serialized_content}]
                tool_calls = [b for b in content_blocks if getattr(b, "type", "") == "tool_use"]
                text_blocks = [b for b in content_blocks if getattr(b, "type", "") == "text"]
            except Exception as e:
                logger.error("opus_fallback_failed", error=str(e))

    # ── Free brain no-tool retry: up to 3 attempts with specific feedback ──
    if is_free_brain and not tool_calls and response.stop_reason == "end_turn":
        brain_name = "ChatGPT" if is_chatgpt else "GLM-5"
        all_text = " ".join(getattr(b, "text", "") for b in text_blocks)
        target_url = state.get("target_url", "http://localhost")

        for retry_num in range(3):
            logger.warning("free_brain_no_tool_call_retrying",
                           brain=brain_name, turn=turn_count, retry=retry_num + 1)
            if _LIVE:
                print(f"  {_YELLOW}⚠ {brain_name} no tool call — retry {retry_num + 1}/3{_RESET}")

            # Analyze failure mode and craft specific nudge
            if "```" in all_text and '"name"' in all_text:
                nudge = (
                    "Your tool call was inside a code block (```). "
                    "Remove the ``` markers. Output ONLY the raw JSON on its own line:\n"
                    '{"name": "TOOL_NAME", "input": {PARAMS}}'
                )
            elif "<executed" in all_text or "[Called tool" in all_text:
                nudge = (
                    "You used the wrong format. Do NOT use <executed> or [Called tool] tags. "
                    "Output a plain JSON object on its own line:\n"
                    '{"name": "TOOL_NAME", "input": {PARAMS}}'
                )
            elif any(p in all_text.lower() for p in [
                "i would", "i will", "let me", "i'll", "we should",
                "next step", "i need to", "my plan",
            ]):
                # Model described intent but didn't output JSON
                intended = _extract_intended_tool(all_text, tools)
                if intended:
                    nudge = (
                        f"You described wanting to use {intended} but didn't "
                        f"output the JSON. Output it now on its own line:\n"
                        f'{{"name": "{intended}", "input": {{...}}}}'
                    )
                else:
                    nudge = (
                        "You described what you want to do but didn't output the tool call JSON. "
                        "You MUST output a JSON object. Pick the most appropriate tool and output:\n"
                        '{"name": "crawl_target", "input": {"start_url": "' + target_url + '"}}'
                    )
            else:
                nudge = (
                    "No tool call detected. You MUST output a JSON tool call. "
                    "Choose from the available tools and output on its own line:\n"
                    '{"name": "TOOL_NAME", "input": {PARAMS}}\n'
                    "If unsure, start with:\n"
                    '{"name": "crawl_target", "input": {"start_url": "' + target_url + '"}}'
                )

            try:
                nudge_messages = list(messages) + [
                    {"role": "assistant", "content": serialized_content},
                    {"role": "user", "content": nudge},
                ]
                response = await client.call_with_tools(
                    phase="active_testing",
                    task_tier="complex",
                    system_blocks=system_blocks,
                    messages=nudge_messages,
                    tools=tools,
                    target=target_url,
                )
                content_blocks = response.content
                serialized_content = _serialize_content(content_blocks)
                new_messages = [{"role": "assistant", "content": serialized_content}]
                tool_calls = [b for b in content_blocks if getattr(b, "type", "") == "tool_use"]
                text_blocks = [b for b in content_blocks if getattr(b, "type", "") == "text"]
                thinking_blocks = [b for b in content_blocks if getattr(b, "type", "") == "thinking"]

                if tool_calls:
                    logger.info("free_brain_retry_succeeded",
                                brain=brain_name, retry=retry_num + 1,
                                tools=[tc.name for tc in tool_calls])
                    break  # Success
                else:
                    # Update text for next retry's analysis
                    all_text = " ".join(getattr(b, "text", "") for b in text_blocks)
                    logger.warning("free_brain_retry_still_no_tools",
                                   brain=brain_name, retry=retry_num + 1, turn=turn_count)
            except Exception as e:
                logger.error("free_brain_retry_failed",
                             brain=brain_name, retry=retry_num + 1, error=str(e))
                break  # Don't retry on exceptions

    # Log brain thinking (extended thinking from Opus/Z.ai)
    if thinking_blocks:
        tb = thinking_blocks[0]
        thinking_content = getattr(tb, "thinking", "") or str(tb)
        logger.info("brain_thinking", preview=thinking_content[:500], full_len=len(thinking_content))

    # Log brain reasoning
    if text_blocks:
        reasoning = _block_text(text_blocks[0])[:500]
        logger.info("brain_reasoning", preview=reasoning)

    # ── Transcript logging: brain response ──
    transcript = config["configurable"].get("transcript")
    if transcript:
        try:
            transcript.log_brain_response(
                turn=turn_count + 1,
                content_blocks=content_blocks,
                tool_calls=tool_calls,
                stop_reason=getattr(response, "stop_reason", ""),
            )
        except Exception:
            pass

    if tool_calls:
        logger.info(
            "brain_tool_calls",
            tools=[tc.name for tc in tool_calls],
            count=len(tool_calls),
        )

    # ── Live display ──
    if _LIVE:
        print(_status_bar(state, budget))
        if thinking_blocks:
            tb = thinking_blocks[0]
            thinking_content = getattr(tb, "thinking", "") or str(tb)
            _print_thinking(thinking_content)
        if text_blocks:
            full_reasoning = "\n".join(_block_text(b) for b in text_blocks)
            _print_reasoning(full_reasoning)
        if tool_calls:
            print(f"\n{_MAGENTA}{_BOLD}🔧 TOOLS ({len(tool_calls)}):{_RESET}")
            for tc in tool_calls:
                _print_tool_call(_block_attr(tc, "name", "?"), _block_attr(tc, "input", {}))

    # Update budget tracking from state
    budget_spent = budget.total_spent

    # ── Phase budget tracking ─────────────────────────────────
    phase = _detect_phase(state)
    prev_budget = state.get("budget_spent", 0.0)
    turn_cost = max(0.0, budget_spent - prev_budget)
    phase_budgets = {k: dict(v) for k, v in state.get("phase_budgets", {}).items()}
    if phase in phase_budgets:
        phase_budgets[phase]["spent"] = phase_budgets[phase].get("spent", 0.0) + turn_cost
        phase_budgets[phase]["turns_used"] = phase_budgets[phase].get("turns_used", 0) + 1

    result: dict[str, Any] = {
        "messages": new_messages,
        "turn_count": turn_count + 1,
        "budget_spent": budget_spent,
        "phase_budgets": phase_budgets,
        "last_brain_tier": task_tier,
    }
    if task_tier == "critical":
        result["last_opus_turn"] = turn_count

    if tool_calls:
        result["_pending_tool_calls"] = tool_calls
    elif response.stop_reason == "end_turn":
        # Brain stopped without calling tools — might be final thoughts
        # In indefinite mode, never auto-detect "done" from text
        max_turns = state.get("max_turns", 150)
        if max_turns != 0:
            all_text = " ".join(_block_text(b) for b in text_blocks).lower()
            if any(phrase in all_text for phrase in [
                "testing complete", "finished testing", "concluding",
                "no more", "all done", "wrapping up",
            ]):
                result["done"] = True
                result["done_reason"] = "brain_decided_done"

    return result


# ── Node 2: Tool Executor ────────────────────────────────────────────


def _build_technique_key(tool_name: str, tool_input: dict) -> str:
    """Build a dedup key from tool name + significant inputs.

    Groups by endpoint + technique so that testing the same endpoint
    with the same tool and params is detected as a repeat. Ignores
    volatile fields like context_name, cookies.
    """
    # Extract the endpoint/url from input
    url = tool_input.get("url") or tool_input.get("target") or tool_input.get("start_url") or ""
    if url:
        parsed = urlparse(url)
        # Normalize to path only (ignore query params for grouping)
        url = parsed.path or "/"

    # Build a stable hash of the significant parameters
    significant = {}
    for key in ("params", "method", "selector", "code", "token", "attacks", "options"):
        if key in tool_input:
            significant[key] = tool_input[key]

    if significant:
        sig_hash = hashlib.md5(
            json.dumps(significant, sort_keys=True, default=str).encode()
        ).hexdigest()[:8]
        return f"{url}::{tool_name}::{sig_hash}"

    return f"{url}::{tool_name}"


def _summarize_tool_result_for_free_brain(tool_name: str, result_str: str) -> str:
    """Extract key signals from tool results for free brain models.

    Prepends a structured summary header so GLM-5 focuses on what matters.
    Only called for Z.ai/ChatGPT — Claude doesn't need this.
    """
    try:
        result = json.loads(result_str)
    except (json.JSONDecodeError, TypeError):
        return result_str

    if not isinstance(result, dict):
        return result_str

    signals: list[str] = []

    # HTTP status
    status = result.get("status_code")
    if status:
        signals.append(f"HTTP {status}")

    body = str(result.get("body", result.get("stdout", "")))

    # Flag detection
    flag_match = re.search(r"FLAG\{[^}]+\}", body, re.IGNORECASE)
    if flag_match:
        signals.append(f"*** FLAG FOUND: {flag_match.group(0)} ***")

    # SQL error detection
    _sql_patterns = ["sql syntax", "mysql", "postgresql", "sqlite", "ORA-",
                     "unclosed quotation", "unterminated string"]
    body_lower = body.lower()
    for pat in _sql_patterns:
        if pat.lower() in body_lower:
            signals.append("SQL ERROR DETECTED: likely SQL injection")
            break

    # XSS reflection
    if "<script" in body.lower() or "alert(" in body.lower():
        signals.append("XSS REFLECTION DETECTED in response body")

    # Interesting status codes
    if status == 403:
        signals.append("403 Forbidden — resource exists but protected")
    elif status == 500:
        signals.append("500 Internal Server Error — input reaches backend code")
    elif status == 302:
        location = result.get("headers", {}).get("location", "")
        if location:
            signals.append(f"Redirect to: {location}")

    # Fuzz/scan hits
    hits = result.get("hits", result.get("results", result.get("matches", [])))
    if isinstance(hits, list) and hits:
        signals.append(f"{len(hits)} interesting hits found")
        for hit in hits[:5]:
            if isinstance(hit, dict):
                word = hit.get("payload", hit.get("word", hit.get("path", "?")))
                hit_status = hit.get("status", hit.get("status_code", "?"))
                signals.append(f"  - {word}: status={hit_status}")

    # Crawl summary
    if tool_name == "crawl_target":
        pages = result.get("pages_visited", result.get("urls", []))
        forms = result.get("forms", [])
        if isinstance(pages, (list, int)):
            count = pages if isinstance(pages, int) else len(pages)
            signals.append(f"Discovered {count} pages")
        if isinstance(forms, list) and forms:
            signals.append(f"Found {len(forms)} forms")

    # response_diff_analyze verdicts
    if tool_name == "response_diff_analyze":
        diffs = result.get("results", result.get("analysis", []))
        if isinstance(diffs, list):
            for d in diffs:
                if isinstance(d, dict):
                    label = d.get("label", "?")
                    verdict = d.get("classification", d.get("verdict",
                              d.get("interesting", "?")))
                    signals.append(f"  {label}: {verdict}")

    # Error in result
    error = result.get("error")
    if error:
        signals.append(f"ERROR: {str(error)[:200]}")

    if not signals:
        return result_str

    header = "KEY SIGNALS:\n" + "\n".join(f"  - {s}" for s in signals)
    return header + "\n\nFULL RESULT:\n" + result_str


async def tool_executor_node(state: PentestState, config: RunnableConfig) -> dict:
    """Execute pending tool calls and return results to the brain.

    Also tracks tested techniques and failed approaches to prevent
    circular testing (inspired by deadend-cli's dedup pattern).
    """
    tool_calls = state.get("_pending_tool_calls", [])
    if not tool_calls:
        return {"_pending_tool_calls": []}

    deps = _get_tool_deps(config)
    deps.current_state = dict(state)  # For tools that need state read access

    # Detect free brain for result pre-summarization
    _client = config["configurable"]["client"]
    _is_free = hasattr(_client, "MODEL") or type(_client).__name__ == "ChatGPTClient"

    tool_results = []
    state_updates: dict[str, Any] = {}
    errors: list[str] = []
    new_tested: dict[str, bool] = {}
    new_failed: dict[str, str] = {}
    failure_count = 0
    had_progress = False

    for tc in tool_calls:
        tool_name = tc.name
        tool_input = tc.input if hasattr(tc, "input") else {}
        tool_id = tc.id if hasattr(tc, "id") else "unknown"

        # Build a technique key for dedup tracking
        technique_key = _build_technique_key(tool_name, tool_input)

        # Check if already tested (warn but don't block — brain may have reasons)
        tested = state.get("tested_techniques", {})
        if technique_key in tested:
            logger.info("tool_already_tested", tool=tool_name, key=technique_key)

        logger.info("tool_executing", tool=tool_name, input_keys=list(tool_input.keys()))

        # ── Transcript: log tool call ──
        _transcript = config["configurable"].get("transcript")
        if _transcript:
            try:
                _transcript.log_tool_call(tool_name, tool_input, tool_id)
            except Exception:
                pass

        _tool_start = time.time()
        try:
            import asyncio as _asyncio
            _tool_timeout = 120 if tool_name in ("run_custom_exploit", "test_sqli") else 90
            result_str = await _asyncio.wait_for(
                dispatch_tool(tool_name, tool_input, deps),
                timeout=_tool_timeout,
            )
            try:
                result_data = json.loads(result_str)
            except json.JSONDecodeError:
                # Sanitize control characters and retry
                import re as _re
                sanitized = _re.sub(r'[\x00-\x1f\x7f]', ' ', result_str)
                try:
                    result_data = json.loads(sanitized)
                except json.JSONDecodeError:
                    result_data = {"raw_output": result_str[:3000]}

            # Track this technique as tested
            new_tested[technique_key] = True

            # Check if tool returned an error result (not exception, but error in output)
            if result_data.get("error"):
                failure_count += 1
                new_failed[technique_key] = str(result_data["error"])[:200]
            else:
                had_progress = True

            # Handle special state-update tools
            if "_state_update" in result_data:
                _merge_state_update(state_updates, result_data["_state_update"])
                visible_result = {k: v for k, v in result_data.items() if k != "_state_update"}
                if not visible_result:
                    visible_result = {"status": "Knowledge updated successfully."}
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": json.dumps(visible_result, default=str),
                })
                had_progress = True
            elif "_done" in result_data:
                state_updates["done"] = True
                state_updates["done_reason"] = result_data.get("assessment", "finished")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": json.dumps(result_data, default=str),
                })
            else:
                # Pre-summarize for free brains (prepend key signals header)
                content_for_msg = (
                    _summarize_tool_result_for_free_brain(tool_name, result_str)
                    if _is_free else result_str
                )
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": tool_id,
                    "content": content_for_msg,
                })

            logger.info("tool_completed", tool=tool_name, result_size=len(result_str))

            # ── Transcript: log tool result ──
            if _transcript:
                try:
                    _elapsed_ms = (time.time() - _tool_start) * 1000
                    _transcript.log_tool_result(
                        tool_name, result_str, elapsed_ms=_elapsed_ms,
                        is_error=bool(result_data.get("error")),
                    )
                except Exception:
                    pass

            # ── Live display: tool result ──
            if _LIVE:
                _print_tool_result(tool_name, result_str, is_error=bool(result_data.get("error")))

            # ── Adversarial reasoning: analyze tool result for hypotheses ──
            try:
                current_findings = list(state.get("findings", {}).values())
                # Merge any findings from state_updates so far this turn
                if "findings" in state_updates:
                    current_findings.extend(state_updates["findings"].values())
                new_hypotheses = _reasoning_engine.analyze_tool_result(
                    tool_name, tool_input, result_str, current_findings,
                )
                if new_hypotheses:
                    # Append hypotheses as a supplementary JSON note to the
                    # last tool_result content so the brain sees them
                    hints = [
                        {
                            "hypothesis": h["hypothesis"],
                            "priority": h.get("priority", "medium"),
                            "suggested_tool": h.get("suggested_tool", ""),
                        }
                        for h in new_hypotheses[:5]  # Cap at 5 per tool call
                    ]
                    addendum = json.dumps(
                        {"_adversarial_hints": hints}, default=str,
                    )
                    # Patch the last tool_result entry
                    last_tr = tool_results[-1]
                    existing_content = last_tr.get("content", "")
                    last_tr["content"] = existing_content + "\n" + addendum
                    logger.info(
                        "adversarial_hypotheses",
                        tool=tool_name,
                        count=len(new_hypotheses),
                    )
                    if _LIVE:
                        print(f"  {_MAGENTA}💡 {len(new_hypotheses)} new hypothesis(es) generated{_RESET}")
            except Exception:
                pass  # Reasoning is best-effort; never break the tool flow

        except Exception as e:
            error_msg = f"{tool_name}: {e}"
            errors.append(error_msg)
            failure_count += 1
            new_failed[technique_key] = str(e)[:200]
            logger.error("tool_failed", tool=tool_name, error=str(e))
            # ── Transcript: log tool error ──
            if _transcript:
                try:
                    _elapsed_ms = (time.time() - _tool_start) * 1000
                    _transcript.log_tool_result(
                        tool_name, error_msg, elapsed_ms=_elapsed_ms, is_error=True,
                    )
                    _transcript.log_error(error_msg, context=f"tool_execution:{tool_name}")
                except Exception:
                    pass
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tool_id,
                "content": json.dumps({"error": error_msg}),
                "is_error": True,
            })
            # ── Live display: tool error ──
            if _LIVE:
                _print_tool_result(tool_name, json.dumps({"error": error_msg}), is_error=True)

    # Append tool results as user message (Claude expects tool_results in user role)
    new_messages = [{"role": "user", "content": tool_results}]

    result: dict[str, Any] = {
        "messages": new_messages,
        "_pending_tool_calls": [],  # Clear pending
    }

    # ── Dedup tracking updates ────────────────────────────────────
    # Merge tested techniques
    existing_tested = dict(state.get("tested_techniques", {}))
    existing_tested.update(new_tested)
    result["tested_techniques"] = existing_tested

    # Merge failed approaches
    existing_failed = dict(state.get("failed_approaches", {}))
    existing_failed.update(new_failed)
    result["failed_approaches"] = existing_failed

    # Track consecutive failures
    prev_failures = state.get("consecutive_failures", 0)
    if failure_count > 0 and not had_progress:
        result["consecutive_failures"] = prev_failures + failure_count
    else:
        result["consecutive_failures"] = 0

    # Track no-progress turns
    prev_no_progress = state.get("no_progress_count", 0)
    if not had_progress and not state_updates:
        result["no_progress_count"] = prev_no_progress + 1
    else:
        result["no_progress_count"] = 0

    # Same-result detection via hash
    result_hash = str(hash(json.dumps(tool_results, default=str, sort_keys=True)))
    prev_hashes = list(state.get("last_result_hashes", []))
    prev_hashes.append(result_hash)
    result["last_result_hashes"] = prev_hashes[-5:]  # Keep last 5

    # ── Stopping conditions ───────────────────────────────────────
    no_progress = result.get("no_progress_count", 0)
    consec_fail = result.get("consecutive_failures", 0)
    same_results = prev_hashes[-3:].count(result_hash) if len(prev_hashes) >= 3 else 0

    max_turns = state.get("max_turns", 150)
    indefinite = max_turns == 0  # 0 = run until budget/timeout/stop

    # Thresholds are relaxed in indefinite mode
    no_progress_limit = 25 if indefinite else 10
    consec_fail_limit = 15 if indefinite else 5
    same_result_limit = 5 if indefinite else 3

    if no_progress >= no_progress_limit:
        if indefinite:
            # In indefinite mode, inject a strategy reset instead of stopping
            logger.warning("strategy_reset_injected", no_progress=no_progress)
            if _LIVE:
                print(f"\n  {_RED}{_BOLD}🔄 STRATEGY RESET — no progress for {no_progress} turns{_RESET}")
            # ── Transcript: log strategy reset ──
            _transcript_sr = config["configurable"].get("transcript")
            if _transcript_sr:
                try:
                    _transcript_sr.log_strategy_reset(
                        f"no_progress_{no_progress}", state.get("turn_count", 0),
                    )
                except Exception:
                    pass
            result["no_progress_count"] = 0
            result["consecutive_failures"] = 0
            tested_count = len(state.get("tested_techniques", {}))
            reset_msg = {
                "role": "user",
                "content": (
                    f"STRATEGY RESET: {no_progress} turns with no progress. "
                    f"You have {tested_count} techniques already tested — DO NOT REPEAT THEM. "
                    "Pick something COMPLETELY NEW from this list:\n"
                    "1. Create accounts and test authenticated surfaces\n"
                    "2. Download and grep JS bundles for secrets/API keys/internal URLs\n"
                    "3. Test business logic: race conditions, negative values, step-skipping\n"
                    "4. Find new subdomains or API versions (/v1/, /v2/, /internal/, /mobile/)\n"
                    "5. Test WebSocket endpoints\n"
                    "6. Chain existing findings into bigger exploits\n"
                    "7. OAuth/SSO redirect manipulation\n"
                    "8. Second-order attacks: store payload via one endpoint, trigger via another\n"
                    "9. Cache poisoning via Host/X-Forwarded-Host headers\n"
                    "10. Email-based: password reset Host header poisoning\n"
                    "DO NOT go back to what you were doing. Pick a number above and execute it."
                ),
            }
            result["messages"] = [reset_msg] + result.get("messages", [])
        else:
            logger.warning("stopping_no_progress", count=no_progress)
            result["done"] = True
            result["done_reason"] = f"No progress for {no_progress} consecutive turns"
    elif consec_fail >= consec_fail_limit:
        if indefinite:
            logger.warning("strategy_reset_failures", consec_fail=consec_fail)
            result["consecutive_failures"] = 0
            reset_msg = {
                "role": "user",
                "content": (
                    f"TOOL FAILURE RESET: {consec_fail} consecutive tool failures. "
                    "The current approach is NOT WORKING. Switch to:\n"
                    "- Browser-based testing (navigate_and_extract, browser_interact) instead of HTTP\n"
                    "- Different target subdomains or API endpoints\n"
                    "- JS bundle analysis (fetch .js files, search for secrets)\n"
                    "- Account creation and authenticated testing\n"
                    "DO NOT retry the same endpoint/tool that keeps failing."
                ),
            }
            result["messages"] = [reset_msg] + result.get("messages", [])
        else:
            logger.warning("stopping_consecutive_failures", count=consec_fail)
            result["done"] = True
            result["done_reason"] = f"{consec_fail} consecutive tool failures"
    elif same_results >= same_result_limit:
        if indefinite:
            logger.warning("strategy_reset_loop", same_results=same_results)
            result["last_result_hashes"] = []
            reset_msg = {
                "role": "user",
                "content": (
                    "LOOP DETECTED: You keep getting the same result. You're stuck. "
                    "You MUST pick a COMPLETELY DIFFERENT attack surface — different "
                    "subdomain, different API, different vuln class. Read your "
                    "tested_techniques list and do something NOT on it."
                ),
            }
            result["messages"] = [reset_msg] + result.get("messages", [])
        else:
            logger.warning("stopping_same_results")
            result["done"] = True
            result["done_reason"] = "Same result 3 consecutive times — stuck in a loop"

    # ── Track info before merging for info gain calculation ────
    prev_ep_count = len(state.get("endpoints", {}))
    prev_finding_count = len(state.get("findings", {}))
    prev_hyp_count = len(state.get("hypotheses", {}))

    # Merge state updates from tools
    if state_updates:
        for key, value in state_updates.items():
            if key in ("endpoints", "findings", "hypotheses", "accounts"):
                existing = dict(state.get(key, {}))
                existing.update(value)
                result[key] = existing
            elif key == "tech_stack":
                existing = list(state.get("tech_stack", []))
                for item in value:
                    if item not in existing:
                        existing.append(item)
                result["tech_stack"] = existing
            elif key == "working_memory":
                # Nested dict merge at section level
                existing_wm = dict(state.get("working_memory", {}))
                for section, entries in value.items():
                    if section not in existing_wm:
                        existing_wm[section] = {}
                    if isinstance(entries, dict):
                        existing_wm[section].update(entries)
                    else:
                        existing_wm[section] = entries
                result["working_memory"] = existing_wm
            elif key == "attack_chains":
                # Replace entire chains dict (manage_chain handles its own merging)
                result["attack_chains"] = value
            else:
                result[key] = value

    # ── Transcript: log state updates and findings ──
    _transcript_te = config["configurable"].get("transcript")
    if _transcript_te and state_updates:
        try:
            _transcript_te.log_state_update(state_updates)
            # Log individual new findings
            new_f_te = state_updates.get("findings", {})
            existing_f_te = state.get("findings", {})
            for fid, fdata in new_f_te.items():
                if fid not in existing_f_te:
                    _transcript_te.log_finding(fid, fdata)
        except Exception:
            pass

    # ── Live display: new findings ──
    if _LIVE and state_updates:
        new_f = state_updates.get("findings", {})
        existing_f = state.get("findings", {})
        for fid, fdata in new_f.items():
            if fid not in existing_f:
                _print_finding(fid, fdata)

    # ── Push new findings to DB ──
    if state_updates and state_updates.get("findings"):
        _newly_added = {
            fid: fd for fid, fd in state_updates.get("findings", {}).items()
            if fid not in state.get("findings", {})
        }
        if _newly_added:
            _fdb = config["configurable"].get("findings_db")
            if _fdb:
                try:
                    await _fdb.bulk_upsert(
                        _newly_added,
                        domain=state.get("domain", ""),
                        target_url=state.get("target_url", ""),
                        session_id=state.get("session_id", ""),
                    )
                except Exception as _fdb_err:
                    logger.warning("findings_db_push_failed", error=str(_fdb_err))

    # ── Info gain tracking ────────────────────────────────────
    new_ep = len(result.get("endpoints", state.get("endpoints", {}))) - prev_ep_count
    new_findings = len(result.get("findings", state.get("findings", {}))) - prev_finding_count
    new_hyps = len(result.get("hypotheses", state.get("hypotheses", {}))) - prev_hyp_count
    total_gain = new_ep + new_findings + new_hyps

    info_gain_history = list(state.get("info_gain_history", []))
    info_gain_history.append({
        "turn": state.get("turn_count", 0),
        "new_endpoints": new_ep,
        "new_findings": new_findings,
        "new_hypotheses": new_hyps,
        "total_gain": total_gain,
    })
    result["info_gain_history"] = info_gain_history[-20:]  # Keep last 20

    # Update snapshots for next brain iteration
    if "endpoints" in result:
        result["endpoints_snapshot"] = json.dumps(result["endpoints"], default=str, indent=2)[:5000]
    if "findings" in result:
        result["findings_snapshot"] = json.dumps(result["findings"], default=str, indent=2)[:5000]

    if errors:
        result["errors"] = errors

    # ── Chain discovery: feed new findings into the chain engine ──
    # When findings are updated, check for chain opportunities.
    # Results are injected into the last tool_result content (not as new messages)
    # to avoid breaking the tool_use/tool_result pairing that Claude expects.
    try:
        merged_findings = result.get("findings", state.get("findings", {}))
        if state_updates.get("findings"):
            # New findings were added this turn — feed them to chain engine
            existing_finding_ids = {
                f.get("vuln_type", "") + ":" + f.get("endpoint", "")
                for f in _chain_engine._findings
            }
            new_chains_this_turn: list[dict] = []
            for fid, fdata in state_updates["findings"].items():
                dedup_key = fdata.get("vuln_type", "") + ":" + fdata.get("endpoint", "")
                if dedup_key not in existing_finding_ids:
                    chains = _chain_engine.add_finding(fdata)
                    new_chains_this_turn.extend(chains)

            if new_chains_this_turn:
                logger.info(
                    "chain_discovery_new_chains",
                    count=len(new_chains_this_turn),
                    chains=[c.get("chain_name") for c in new_chains_this_turn],
                )
                # ── Transcript: log chain discoveries ──
                if _transcript_te:
                    try:
                        for chain in new_chains_this_turn:
                            _transcript_te.log_chain_discovery(chain)
                    except Exception:
                        pass
                if _LIVE:
                    for chain in new_chains_this_turn:
                        sev = chain.get("combined_severity", "?").upper()
                        print(
                            f"\n  {_RED}{_BOLD}🔗 CHAIN DISCOVERED [{sev}]: "
                            f"{chain.get('chain_name', '?')}{_RESET}"
                        )
                        print(f"  {_WHITE}  {chain.get('description', '')}{_RESET}")

                # Append chain info to the last tool_result so brain sees it
                if tool_results:
                    chain_addendum = json.dumps(
                        {
                            "_chain_opportunities": [
                                {
                                    "chain_name": c.get("chain_name"),
                                    "combined_severity": c.get("combined_severity"),
                                    "description": c.get("description"),
                                    "real_world_impact": c.get("real_world_impact", ""),
                                }
                                for c in new_chains_this_turn
                            ],
                        },
                        default=str,
                    )
                    last_tr = tool_results[-1]
                    existing_content = last_tr.get("content", "")
                    last_tr["content"] = existing_content + "\n" + chain_addendum

            # Also get chain-based suggestions for next steps
            suggestions = _chain_engine.get_chain_suggestions()
            if suggestions and tool_results:
                suggestion_addendum = json.dumps(
                    {"_chain_suggestions": suggestions[:3]}, default=str,
                )
                last_tr = tool_results[-1]
                existing_content = last_tr.get("content", "")
                last_tr["content"] = existing_content + "\n" + suggestion_addendum
    except Exception:
        pass  # Chain discovery is best-effort; never break the tool flow

    return result


# ── Node 3: Context Compressor ───────────────────────────────────────


async def context_compressor(state: PentestState, config: RunnableConfig) -> dict:
    """Compress context when messages grow too large.

    Tier 1 (< 50K chars): Keep everything
    Tier 2 (50K-100K): Replace large tool outputs with summaries
    Tier 3 (> 100K): Haiku summarization of old messages

    Also auto-saves target memory every 10 turns.
    """
    # Auto-save target memory every 10 turns
    turn_count = state.get("turn_count", 0)
    memory_path = state.get("memory_path", "")
    if memory_path and turn_count > 0 and turn_count % 10 == 0:
        try:
            from ai_brain.active.react_memory import TargetMemory
            mem = TargetMemory(state.get("target_url", ""))
            mem.memory_path = Path(memory_path).expanduser()
            mem.memory_dir = mem.memory_path.parent
            mem.save(state)
            logger.info("memory_auto_saved", turn=turn_count)
            # ── Transcript: log memory save ──
            _transcript_ms = config["configurable"].get("transcript")
            if _transcript_ms:
                try:
                    _transcript_ms.log_memory_save(turn_count, str(memory_path))
                except Exception:
                    pass
        except Exception as e:
            logger.warning("memory_auto_save_failed", error=str(e))

    # Bulk sync all findings to DB (catches any missed)
    if turn_count > 0 and turn_count % 10 == 0:
        _fdb_cc = config["configurable"].get("findings_db")
        if _fdb_cc and state.get("findings"):
            try:
                await _fdb_cc.bulk_upsert(
                    state.get("findings", {}),
                    domain=state.get("domain", ""),
                    target_url=state.get("target_url", ""),
                    session_id=state.get("session_id", ""),
                )
            except Exception:
                pass

    messages = state.get("messages", [])
    total_chars = sum(len(json.dumps(m, default=str)) for m in messages)

    # Auto-extract critical values to working memory from recent messages
    working_memory = dict(state.get("working_memory", {}))
    # Deep copy sections
    for section in list(working_memory):
        working_memory[section] = dict(working_memory.get(section, {}))
    updated_wm = _auto_extract_to_memory(messages, working_memory)

    # Persist chain engine state into working_memory so chains survive compression
    try:
        chains = _chain_engine.get_chains()
        suggestions = _chain_engine.get_chain_suggestions()
        if chains or suggestions:
            chain_data = {}
            if chains:
                chain_data["active_chains"] = [
                    {
                        "chain_name": c.get("chain_name", "?"),
                        "severity": c.get("combined_severity", "?"),
                        "description": c.get("description", "")[:200],
                    }
                    for c in chains[:10]
                ]
            if suggestions:
                chain_data["suggestions"] = suggestions[:5]
            updated_wm.setdefault("chain_evidence", {}).update(chain_data)
    except Exception:
        pass

    wm_result: dict[str, Any] = {}
    if updated_wm != state.get("working_memory", {}):
        wm_result["working_memory"] = updated_wm

    # Tier 1: Keep everything
    if total_chars < 80_000:
        return wm_result

    logger.info("context_compression", total_chars=total_chars, message_count=len(messages))

    # Tier 2: Truncate large tool outputs
    if total_chars < 160_000:
        compressed = []
        for msg in messages:
            if msg.get("role") == "user" and isinstance(msg.get("content"), list):
                # Tool results — truncate large ones
                new_content = []
                for block in msg["content"]:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        content = block.get("content", "")
                        if isinstance(content, str) and len(content) > 3000:
                            # Truncate large tool outputs
                            block = dict(block)
                            block["content"] = content[:2000] + "\n... [truncated]"
                        new_content.append(block)
                    else:
                        new_content.append(block)
                compressed.append({"role": msg["role"], "content": new_content})
            else:
                compressed.append(msg)

        new_total = sum(len(json.dumps(m, default=str)) for m in compressed)
        logger.info("tier2_compression", before=total_chars, after=new_total)

        # ── Transcript: log tier 2 compression ──
        _transcript_c2 = config["configurable"].get("transcript")
        if _transcript_c2:
            try:
                _transcript_c2.log_compression(
                    tier=2, before_chars=total_chars, after_chars=new_total,
                    messages_before=len(messages), messages_after=len(compressed),
                )
            except Exception:
                pass

        # Replace messages list entirely (sentinel triggers full replacement)
        return {**wm_result, "messages": [{"_replace_all": True}] + compressed}

    # Tier 3: Haiku summarization of old messages
    # Use claude_client (always Claude/Haiku) for compression, even in Z.ai mode
    client = config["configurable"].get("claude_client") or config["configurable"]["client"]
    # Adaptive keep_recent: fewer messages when context is very large
    keep_recent = 10 if total_chars > 400_000 else 15
    old_messages = messages[:-keep_recent] if len(messages) > keep_recent else []
    recent_messages = messages[-keep_recent:] if len(messages) > keep_recent else messages

    if old_messages:
        # Fix tool_use/tool_result pairing: ensure recent tool_results
        # have their matching tool_use in a preceding assistant message.
        recent_messages = _fix_tool_pairing(old_messages, recent_messages)

        # Truncate large tool outputs AND inputs in recent messages
        truncated_recent = []
        max_block_chars = 2000 if total_chars > 400_000 else 3000
        for msg in recent_messages:
            if isinstance(msg.get("content"), list):
                new_content = []
                for block in msg["content"]:
                    if isinstance(block, dict):
                        block = dict(block)  # shallow copy
                        # Truncate tool_result content
                        if block.get("type") == "tool_result":
                            content = block.get("content", "")
                            if isinstance(content, str) and len(content) > max_block_chars:
                                block["content"] = content[:max_block_chars] + "\n... [truncated]"
                        # Truncate large tool_use inputs (custom exploit code, etc.)
                        elif block.get("type") == "tool_use":
                            inp = block.get("input", {})
                            if isinstance(inp, dict):
                                for k, v in inp.items():
                                    if isinstance(v, str) and len(v) > max_block_chars:
                                        inp = dict(inp)
                                        inp[k] = v[:max_block_chars] + "\n... [truncated]"
                                block["input"] = inp
                    new_content.append(block)
                truncated_recent.append({"role": msg["role"], "content": new_content})
            elif isinstance(msg.get("content"), str) and len(msg["content"]) > max_block_chars * 2:
                truncated_recent.append({
                    "role": msg["role"],
                    "content": msg["content"][:max_block_chars * 2] + "\n... [truncated]",
                })
            else:
                truncated_recent.append(msg)

        summary = await _summarize_with_haiku(client, old_messages, state)
        logger.info(
            "tier3_compression",
            old_messages=len(old_messages),
            summary_len=len(summary),
        )

        # ── Transcript: log tier 3 compression ──
        _transcript_c3 = config["configurable"].get("transcript")
        if _transcript_c3:
            try:
                after_chars = sum(len(json.dumps(m, default=str)) for m in truncated_recent)
                _transcript_c3.log_compression(
                    tier=3, before_chars=total_chars, after_chars=after_chars,
                    messages_before=len(messages), messages_after=len(truncated_recent),
                )
            except Exception:
                pass

        return {
            **wm_result,
            "messages": [{"_replace_all": True}] + truncated_recent,
            "compressed_summary": summary,
        }

    return wm_result


# ── Graph Construction ───────────────────────────────────────────────


def build_react_graph():
    """Build and compile the 3-node ReAct graph."""
    graph = StateGraph(PentestState)

    graph.add_node("brain", brain_node)
    graph.add_node("tools", tool_executor_node)
    graph.add_node("compress", context_compressor)

    graph.set_entry_point("brain")

    # brain → tools (if tool calls pending) or END (if done)
    graph.add_conditional_edges(
        "brain",
        _route_after_brain,
        {"tools": "tools", END: END},
    )

    # tools → compress → brain (always loop back)
    graph.add_edge("tools", "compress")

    # compress → brain (unless done was set by a tool)
    graph.add_conditional_edges(
        "compress",
        _route_after_compress,
        {"brain": "brain", END: END},
    )

    return graph.compile()


def _route_after_brain(state: PentestState) -> str:
    """Route after brain node: tools if pending, END if done."""
    max_turns = state.get("max_turns", 150)
    indefinite = max_turns == 0
    if state.get("done"):
        if indefinite:
            # In indefinite mode, never truly end — loop back to brain
            logger.info("indefinite_mode_rejecting_done", turn=state.get("turn_count", 0))
            return "tools"  # Will go through compress → brain again
        return END
    if state.get("_pending_tool_calls"):
        return "tools"
    if indefinite:
        # In indefinite mode, brain idling = needs a nudge, not an exit
        logger.warning("brain_no_action_indefinite", turn=state.get("turn_count", 0))
        return "tools"  # compress will handle the loop
    # Brain didn't call tools and didn't finish — safety exit
    logger.warning("brain_no_action", turn=state.get("turn_count", 0))
    return END


def _route_after_compress(state: PentestState) -> str:
    """Route after compression: back to brain unless done.

    Implements ADaPT-inspired confidence-based continuation policy:
    - confidence < 0.20: Force finish (too low to be productive)
    - confidence 0.20-0.80: Continue testing
    - confidence >= 0.80: Continue (brain should validate and finish)

    Budget thresholds:
    - Finite mode (max_turns > 0): hard stop at 90%
    - Indefinite mode (max_turns == 0): warn at 90%, hard stop at 98%
    """
    if state.get("done"):
        return END

    max_turns = state.get("max_turns", 150)
    indefinite = max_turns == 0

    # Budget stop
    budget_spent = state.get("budget_spent", 0.0)
    budget_limit = state.get("budget_limit", 10.0)
    if budget_limit > 0:
        budget_pct = budget_spent / budget_limit
        if indefinite:
            # Indefinite mode: hard stop at 98%
            if budget_pct >= 0.98:
                logger.warning("budget_hard_stop", pct=f"{budget_pct * 100:.0f}%")
                return END
            # Warn at 90% (brain sees this in system prompt and can decide to finish)
        else:
            # Finite mode: hard stop at 90% (existing behavior)
            if budget_pct >= 0.90:
                logger.warning("adapt_budget_stop", pct=f"{budget_pct * 100:.0f}%")
                return END

    # Confidence-based routing (ADaPT thresholds)
    confidence = state.get("confidence", 0.5)
    no_progress = state.get("no_progress_count", 0)

    # If confidence is critically low AND we've been stuck, stop
    # In indefinite mode, require more stalling before giving up
    no_progress_threshold = 8 if indefinite else 3
    if confidence < 0.20 and no_progress >= no_progress_threshold:
        logger.warning("adapt_low_confidence_stop", confidence=confidence, no_progress=no_progress)
        return END

    return "brain"


# ── Helpers ──────────────────────────────────────────────────────────


def _block_text(block) -> str:
    """Safely get text from a content block (works with both objects and dicts)."""
    if isinstance(block, dict):
        return block.get("text", "")
    return getattr(block, "text", "")


def _block_attr(block, attr: str, default=None):
    """Safely get an attribute from a content block (works with both objects and dicts)."""
    if isinstance(block, dict):
        return block.get(attr, default)
    return getattr(block, attr, default)


def _serialize_content(content_blocks: list) -> list[dict[str, Any]]:
    """Serialize Anthropic content blocks to dicts for message storage."""
    serialized = []
    for block in content_blocks:
        block_type = getattr(block, "type", "text")

        if block_type == "text":
            serialized.append({"type": "text", "text": _block_text(block)})
        elif block_type == "tool_use":
            serialized.append({
                "type": "tool_use",
                "id": _block_attr(block, "id", ""),
                "name": _block_attr(block, "name", ""),
                "input": _block_attr(block, "input", {}),
            })
        elif block_type == "thinking":
            # Don't store thinking blocks — they're internal
            pass
        else:
            # Unknown block type — store as text
            serialized.append({"type": "text", "text": str(block)})

    return serialized


def _merge_state_update(target: dict, source: dict) -> None:
    """Merge a state update dict into target, handling nested dicts."""
    for key, value in source.items():
        if key in target and isinstance(target[key], dict) and isinstance(value, dict):
            target[key].update(value)
        else:
            target[key] = value


def _get_tool_deps(config: RunnableConfig) -> ToolDeps:
    """Extract tool dependencies from graph config."""
    c = config["configurable"]
    return ToolDeps(
        browser=c["browser"],
        proxy=c["proxy"],
        email_mgr=c["email_mgr"],
        tool_runner=c["tool_runner"],
        hexstrike_client=c.get("hexstrike_client"),
        scope_guard=c["scope_guard"],
        http_repeater=c["http_repeater"],
        authz_tester=c["authz_tester"],
        traffic_intelligence=c["traffic_intelligence"],
        traffic_analyzer=c["traffic_analyzer"],
        client=c["client"],
        config=c["config"],
        goja_socks5_url=c.get("goja_socks5_url"),
        max_turns=c.get("max_turns", 150),
        default_headers=c.get("default_headers", {}),
        captcha_solver=c.get("captcha_solver"),
    )


def _auto_extract_to_memory(messages: list[dict], working_memory: dict) -> dict:
    """Extract critical values from recent tool outputs into working memory."""
    for msg in messages[-5:]:  # Only scan recent messages
        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                str(b.get("content", "")) if isinstance(b, dict) else str(b)
                for b in content
            )
        content = str(content)

        # JWT tokens
        for jwt in re.findall(
            r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', content
        ):
            working_memory.setdefault("credentials", {})[f"jwt_{jwt[:20]}"] = jwt

        # Version strings (e.g., "Apache/2.4.49", "PHP/8.1.2", "nginx/1.21")
        for ver in re.findall(
            r'(?:Apache|nginx|PHP|Node|Express|Django|Rails|Tomcat|IIS)[/\s][\d.]+',
            content,
        ):
            key = ver.split("/")[0].split()[0]
            working_memory.setdefault("attack_surface", {})[key] = ver

        # Error messages with file paths
        for err in re.findall(
            r'(?:Error|Exception|Warning|Fatal).*?(?:/[\w./]+\.[\w]+)', content
        ):
            key = f"error_{hash(err) % 10000}"
            working_memory.setdefault("vuln_findings", {})[key] = err[:500]

        # S3 bucket names from XML responses
        for bucket in re.findall(r'<Name>([^<]+)</Name>', content):
            if len(bucket) < 50:
                working_memory.setdefault("attack_surface", {})[f"s3_bucket_{bucket}"] = bucket

        # API endpoints from JSON/text responses
        for api in re.findall(r'(/api/[a-zA-Z0-9/_-]{2,40})', content):
            working_memory.setdefault("attack_surface", {})[f"api_{api}"] = api

        # Credentials from DB dumps / responses
        for cred_pattern in re.findall(
            r'(?:password|passwd|secret|token)\s*[:=]\s*["\']?([^\s"\'<>,]{4,60})',
            content, re.IGNORECASE,
        ):
            key = f"cred_{hash(cred_pattern) % 10000}"
            working_memory.setdefault("credentials", {})[key] = cred_pattern

        # HTTP status codes per endpoint → response_signatures
        for status_match in re.findall(
            r'(?:status_code|HTTP)\s*[:=]?\s*(\d{3}).*?(?:url|endpoint|path)\s*[:=]?\s*["\']?([^\s"\'<>,]+)',
            content, re.IGNORECASE,
        ):
            code, endpoint = status_match
            key = f"{endpoint[:50]}_{code}"
            working_memory.setdefault("response_signatures", {})[key] = f"{code}"

        # Form parameter names → parameter_map
        for param_match in re.findall(
            r'(?:name|param|parameter)\s*[:=]\s*["\']?([a-zA-Z_][a-zA-Z0-9_]{1,40})',
            content,
        ):
            if param_match not in ("type", "value", "class", "style", "id", "action"):
                working_memory.setdefault("parameter_map", {})[param_match] = True

        # WAF block patterns → waf_profiles
        for waf_match in re.findall(
            r'(?:blocked|403|406|WAF|firewall|mod_security|cloudflare|akamai|incapsula|sucuri)[\s:]+([^\n]{5,100})',
            content, re.IGNORECASE,
        ):
            key = f"waf_{hash(waf_match) % 10000}"
            working_memory.setdefault("waf_profiles", {})[key] = waf_match[:200]

    return working_memory


def _fix_tool_pairing(
    old_messages: list[dict],
    recent_messages: list[dict],
) -> list[dict]:
    """Ensure tool_result blocks in recent messages have matching tool_use blocks.

    When Tier 3 compression drops old messages, tool_result blocks may reference
    tool_use IDs from dropped assistant messages. This function:
    1. Finds all tool_use_ids referenced in recent tool_result blocks
    2. Checks if their matching tool_use blocks exist in recent messages
    3. If not, either pulls the matching assistant message from old_messages
       or removes the orphaned tool_result blocks.
    """
    # Collect all tool_use IDs in recent assistant messages
    recent_tool_use_ids: set[str] = set()
    for msg in recent_messages:
        if msg.get("role") == "assistant":
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        recent_tool_use_ids.add(block.get("id", ""))

    # Collect all tool_use_ids referenced in recent tool_result blocks
    needed_tool_use_ids: set[str] = set()
    for msg in recent_messages:
        if msg.get("role") == "user":
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_result":
                        tid = block.get("tool_use_id", "")
                        if tid and tid not in recent_tool_use_ids:
                            needed_tool_use_ids.add(tid)

    if not needed_tool_use_ids:
        return recent_messages  # No orphaned tool_results

    # Try to find matching assistant messages in old_messages
    rescued: list[dict] = []
    for msg in reversed(old_messages):
        if msg.get("role") == "assistant":
            content = msg.get("content", [])
            if isinstance(content, list):
                for block in content:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        if block.get("id", "") in needed_tool_use_ids:
                            rescued.append(msg)
                            # Remove rescued IDs
                            for b in content:
                                if isinstance(b, dict) and b.get("type") == "tool_use":
                                    needed_tool_use_ids.discard(b.get("id", ""))
                            break
        if not needed_tool_use_ids:
            break

    # If we rescued messages, prepend them to recent
    if rescued:
        rescued.reverse()
        logger.info("tool_pairing_rescued", count=len(rescued), remaining_orphans=len(needed_tool_use_ids))
        recent_messages = rescued + recent_messages

    # If there are still orphaned tool_results, remove them
    if needed_tool_use_ids:
        fixed_messages = []
        for msg in recent_messages:
            if msg.get("role") == "user":
                content = msg.get("content", [])
                if isinstance(content, list):
                    cleaned = [
                        b for b in content
                        if not (isinstance(b, dict) and b.get("type") == "tool_result"
                                and b.get("tool_use_id", "") in needed_tool_use_ids)
                    ]
                    if cleaned:
                        fixed_messages.append({"role": "user", "content": cleaned})
                    # If all blocks were orphaned, skip the entire message
                    continue
            fixed_messages.append(msg)
        logger.info("tool_pairing_orphans_removed", count=len(needed_tool_use_ids))
        return fixed_messages

    return recent_messages


async def _summarize_with_haiku(
    client: Any,
    old_messages: list[dict],
    state: dict,
) -> str:
    """Summarize old conversation messages using Haiku for compression."""
    # Format old messages into a text block
    msg_text = []
    for msg in old_messages:
        role = msg.get("role", "?")
        content = msg.get("content", "")
        if isinstance(content, list):
            # Tool results or multi-block content
            parts = []
            for block in content:
                if isinstance(block, dict):
                    if block.get("type") == "tool_result":
                        parts.append(f"[tool_result: {block.get('content', '')[:500]}]")
                    elif block.get("type") == "text":
                        parts.append(block.get("text", "")[:500])
                    elif block.get("type") == "tool_use":
                        parts.append(f"[tool_use: {block.get('name', '?')}({json.dumps(block.get('input', {}), default=str)[:200]})]")
                else:
                    parts.append(str(block)[:500])
            content = " | ".join(parts)
        elif isinstance(content, str):
            content = content[:1000]
        msg_text.append(f"{role}: {content}")

    conversation_text = "\n".join(msg_text)[:20000]  # Cap at 20K

    try:
        from ai_brain.models import CallResult
        result: CallResult = await client.call(
            phase="active_testing",
            task_tier="routine",  # Haiku
            system_blocks=[{
                "type": "text",
                "text": (
                    "Summarize the following penetration testing conversation. "
                    "Focus on: (1) what was discovered, (2) what was tested, "
                    "(3) what worked/failed, (4) current hypotheses and next steps. "
                    "Be concise but preserve all security-relevant details."
                ),
            }],
            user_message=conversation_text,
        )
        return result.raw_text if hasattr(result, "raw_text") and result.raw_text else str(result)
    except Exception as e:
        logger.error("compression_failed", error=str(e))
        return f"[Compression failed: {e}. {len(old_messages)} messages dropped.]"
