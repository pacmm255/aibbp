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

    # ── Application Model (required to unlock exploitation in real-world mode) ──
    app_model: dict[str, Any]

    # ── Thompson Sampling (Bayesian bandit for test prioritization) ──
    # "{endpoint}::{technique}" -> [alpha, beta]
    bandit_state: dict[str, list[float]]

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

    # ── Tool Diversity Tracking ──────────────────────────────────────
    # Last N tool names called (ring buffer, max 20)
    recent_tool_names: list[str]

    # ── Strategic Intelligence Layers (Sonnet/Opus hooks) ───────────
    recon_blitz_done: bool       # Hook 0: Recon blitz + Opus detection fired
    sonnet_app_model_done: bool  # Hook 1: Sonnet app comprehension fired
    sonnet_exploit_calls: int    # Hook 2: Sonnet exploitation strategy counter (max 2)
    opus_chain_reasoning_done: bool  # Hook 3: Opus chain reasoning fired

    # ── Hard Phase Gates ─────────────────────────────────────────────
    # Deterministic phase: "recon" → "vuln_scan" → "exploitation" → "reporting"
    current_phase: str  # one of "recon", "vuln_scan", "exploitation", "reporting"
    phase_turn_count: int  # turns spent in current phase
    phase_history: list[tuple[str, int]]  # (phase, turns_spent) for completed phases
    consecutive_bookkeeping: int  # consecutive bookkeeping tool calls (rate limiter)

    # ── Reflector Pattern (retry when brain returns text without tools) ──
    reflector_retries: int  # Count of consecutive reflector retries (reset on tool call)

    # ── Repeating Detector (block identical consecutive tool calls) ──
    # Keys: last_tool, last_args_hash, count
    repeat_detector_state: dict[str, Any]

    # ── Subtask Plan (structured test plan) ──────────────────────────
    # List of {id, description, priority, status, result_summary}
    # status: "pending" | "in_progress" | "done" | "skipped"
    subtask_plan: list[dict[str, Any]]

    # ── UCB1 Coverage Queue ─────────────────────────────────────────
    # {endpoint: {technique: {tested: bool, score: float, times: int}}}
    coverage_queue: dict[str, dict[str, dict[str, Any]]]
    # tested_endpoints / total_endpoints ratio (updated each turn)
    coverage_ratio: float

    # ── Work Queue (Sprint 3: replaces coverage_queue) ───────────────
    # item_id -> serialized WorkItem
    work_queue: dict[str, dict[str, Any]]
    # Cached queue stats for prompt
    work_queue_stats: dict[str, Any]
    # Capability graph summary for prompt
    capability_snapshot: str

    # ── AuthZ & Schema Intelligence (Sprint 4) ────────────────────────
    # role -> serialized RoleContext
    role_contexts: dict[str, dict[str, Any]]
    # object_id -> serialized ObjectLineage
    object_lineage: dict[str, dict[str, Any]]
    # workflow_name -> serialized Workflow
    discovered_workflows: dict[str, dict[str, Any]]
    # Parsed API schema data
    api_schema: dict[str, Any]

    # ── Response Baselines (fingerprints of normal responses) ────────
    # "METHOD url" → {status, content_type, body_hash, body_length, template_hash, key_headers}
    baselines: dict[str, dict[str, Any]]

    # ── Tool Health & Circuit Breaker ────────────────────────────────
    # {tool_name: "healthy"|"degraded"|"unavailable"} — set by preflight checks
    tool_health: dict[str, str]

    # ── Internal (not for brain consumption) ────────────────────────
    # Pending tool calls from brain_node → tool_executor_node
    _pending_tool_calls: list[Any]

    # ── Timing & Errors ─────────────────────────────────────────────
    start_time: float
    errors: Annotated[list[str], operator.add]
