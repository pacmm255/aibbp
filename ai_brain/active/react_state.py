"""State definition for the single-brain ReAct pentesting agent.

PentestState holds all knowledge the brain accumulates during a test:
persistent knowledge stores (endpoints, findings, hypotheses, accounts),
the Claude conversation history, and control flow fields.
"""

from __future__ import annotations

import operator
from typing import Annotated, Any, TypedDict


def _messages_reducer(existing: list[dict], update: list[dict]) -> list[dict]:
    """Custom reducer: append by default, REPLACE if first element is a sentinel.

    - brain_node and tool_executor_node return [new_message] → appended.
    - context_compressor returns [{"_replace_all": True}, ...messages] → replaces entire list.
    """
    if update and isinstance(update[0], dict) and update[0].get("_replace_all"):
        return update[1:]  # Skip the sentinel, use rest as full replacement
    return existing + update


class PentestState(TypedDict, total=False):
    """State for the ReAct pentesting agent.

    Persistent knowledge dicts (endpoints, findings, hypotheses, accounts)
    are NEVER compressed — they're always injected into the system prompt.
    The messages list (Claude conversation history) IS compressed when it
    grows large.
    """

    # ── Target ──────────────────────────────────────────────────────
    target_url: str
    session_id: str
    allowed_domains: list[str]

    # ── Persistent Knowledge (always in context) ────────────────────
    # url → {method, params, auth_required, notes, status_codes, response_size}
    endpoints: dict[str, dict[str, Any]]
    # finding_id → {vuln_type, endpoint, parameter, evidence, severity, confirmed, chained_from, tool_used}
    findings: dict[str, dict[str, Any]]
    # hypothesis_id → {description, status: pending|confirmed|rejected, evidence, related_endpoints}
    hypotheses: dict[str, dict[str, Any]]
    # username → {password, cookies, role, context_name, created_at}
    accounts: dict[str, dict[str, Any]]
    # Detected technologies
    tech_stack: list[str]

    # ── Conversation History (compressed when large) ────────────────
    # Claude messages: list of {role, content} dicts
    # Uses custom reducer: append by default, replace with sentinel
    messages: Annotated[list[dict[str, Any]], _messages_reducer]
    # Haiku-generated summary of compressed old messages
    compressed_summary: str

    # ── Tool Output Offloading ──────────────────────────────────────
    # ref_id → filepath (large tool outputs written to disk)
    tool_output_files: dict[str, str]

    # ── Snapshots (JSON strings injected into system prompt) ────────
    endpoints_snapshot: str
    findings_snapshot: str

    # ── Traffic Intelligence ────────────────────────────────────────
    traffic_intelligence: dict[str, Any]

    # ── Dedup Tracking (prevents circular testing) ──────────────────
    # Set of "endpoint::technique" strings already tested
    tested_techniques: dict[str, bool]  # key → True (using dict as set for LangGraph)
    # Set of "tool::params_hash" strings that failed
    failed_approaches: dict[str, str]  # key → error message
    # Counter for consecutive no-progress turns
    no_progress_count: int
    # Last tool results hash for same-result detection
    last_result_hashes: list[str]
    # Consecutive tool failure count
    consecutive_failures: int

    # ── Control Flow ────────────────────────────────────────────────
    phase: str  # "running" | "wrapping_up" | "done"
    budget_spent: float
    budget_limit: float
    turn_count: int
    max_turns: int  # default 150
    done: bool
    done_reason: str
    # ADaPT confidence score (0.0-1.0) from last brain assessment
    confidence: float

    # ── Working Memory (structured, NEVER compressed) ──────────────
    # 5 sections: attack_surface, vuln_findings, credentials, attack_chain, lessons
    working_memory: dict[str, Any]

    # ── Attack Chains (structured, NEVER compressed) ──────────────
    # chain_id → {goal, steps: [{description, status, output, depends_on}],
    #             current_step, confidence, chain_type}
    attack_chains: dict[str, dict[str, Any]]

    # ── Phase-Aware Budget ────────────────────────────────────────
    # {phase_name: {allocated_pct, spent, max_turns, turns_used}}
    phase_budgets: dict[str, dict[str, Any]]
    # {hypothesis_id: dollars_spent} — cap each at 15% of total budget
    hypothesis_budgets: dict[str, float]
    # [{turn, new_endpoints, new_findings, new_hypotheses, total_gain}]
    info_gain_history: list[dict[str, Any]]

    # ── Memory ─────────────────────────────────────────────────────
    # Path to memory.json for auto-save in compress node
    memory_path: str

    # ── Tiered Model Control ─────────────────────────────────────────
    # Which tier was used last turn ("complex" = Sonnet, "critical" = Opus)
    last_brain_tier: str
    # Turn number of last Opus call (for periodic review scheduling)
    last_opus_turn: int

    # ── Internal (not for brain consumption) ────────────────────────
    # Pending tool calls from brain_node → tool_executor_node
    _pending_tool_calls: list[Any]

    # ── Timing & Errors ─────────────────────────────────────────────
    start_time: float
    errors: Annotated[list[str], operator.add]
