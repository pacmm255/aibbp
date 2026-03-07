"""Agent B Planner — generates structured attack plans from RAG-retrieved techniques.

Uses Claude (strong LLM) infrequently to create multi-step attack plans.
Plans reference Agent A's existing tool schemas for the executor to call.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

logger = structlog.get_logger()

# Agent A's tool names that Agent B can reference in plans
AVAILABLE_TOOLS = [
    "crawl_target", "enumerate_subdomains", "scan_ports", "fingerprint_tech",
    "discover_endpoints", "extract_js_endpoints", "check_headers",
    "analyze_robots_sitemap", "google_dork",
    "test_sqli", "test_xss", "test_ssrf", "test_lfi", "test_ssti",
    "test_xxe", "test_cmdi", "test_open_redirect", "test_cors",
    "test_csrf", "test_idor", "test_jwt", "test_graphql",
    "systematic_fuzz", "fuzz_parameters", "test_auth_bypass",
    "test_race_condition", "test_file_upload", "test_deserialization",
    "test_http_smuggling", "test_cache_poisoning", "test_mass_assignment",
    "test_prototype_pollution",
    "send_http_request", "run_custom_exploit", "take_screenshot",
    "read_file", "navigate_browser", "fill_form", "click_element",
    "get_page_source", "run_nuclei", "search_exploitdb",
]

PLAN_SYSTEM_PROMPT = """You are an expert offensive security researcher planning novel attack strategies.

You are Agent B — a knowledge-augmented pentester that works alongside Agent A (an independent scanner).
Your job is to find vulnerabilities that Agent A would miss, using techniques from real-world bug bounty reports.

CRITICAL RULES:
1. NEVER repeat techniques Agent A has already tried (listed below)
2. Focus on CREATIVE, NON-OBVIOUS attack vectors from the retrieved technique cards
3. Plans must reference specific tools from the available tool list
4. Each step must have clear success/failure criteria
5. Think like a $100K bug bounty hunter — look for business logic flaws, chained attacks, edge cases

AVAILABLE TOOLS: {tools}

You will receive:
- Target context (tech stack, endpoints, Agent A's findings)
- Retrieved technique cards from real bug bounty reports
- Agent A's tested techniques (DO NOT REPEAT)

Generate a structured attack plan as JSON:
{{
  "plan_id": "unique_id",
  "rationale": "Why this plan is novel and worth trying",
  "technique_source": "Which technique card(s) inspired this",
  "estimated_steps": 3-8,
  "steps": [
    {{
      "step_num": 1,
      "description": "What to do and why",
      "tool": "tool_name from available tools",
      "tool_input": {{"param": "value"}},
      "success_criteria": "What indicates this step worked",
      "failure_action": "skip | abort | retry_with_variation",
      "depends_on": null
    }}
  ]
}}
"""


def build_plan_prompt(
    target_url: str,
    tech_stack: list[str],
    endpoints: dict,
    findings: dict,
    tested_techniques: dict,
    technique_cards: list[dict],
    failed_approaches: dict | None = None,
) -> list[dict]:
    """Build the planning prompt with all context."""
    system = PLAN_SYSTEM_PROMPT.format(tools=", ".join(AVAILABLE_TOOLS))

    # Build target context
    target_ctx = f"TARGET: {target_url}\n"
    if tech_stack:
        target_ctx += f"TECH STACK: {', '.join(tech_stack)}\n"

    # Summarize endpoints (top 20)
    if endpoints:
        target_ctx += f"\nENDPOINTS ({len(endpoints)} total, showing top 20):\n"
        for ep, data in list(endpoints.items())[:20]:
            if isinstance(data, dict):
                method = data.get("method", "GET")
                status = data.get("status", "?")
                target_ctx += f"  {method} {ep} [{status}]\n"
            else:
                target_ctx += f"  {ep}\n"

    # Summarize findings
    if findings:
        target_ctx += f"\nAGENT A FINDINGS ({len(findings)}):\n"
        for fid, fd in findings.items():
            if isinstance(fd, dict):
                sev = fd.get("severity", "?")
                vtype = fd.get("vuln_type", "?")
                ep = fd.get("endpoint", "?")
                confirmed = "CONFIRMED" if fd.get("confirmed") else "unconfirmed"
                target_ctx += f"  [{sev}] {vtype} @ {ep} ({confirmed})\n"

    # Already tested (Agent B must NOT repeat)
    tested_summary = ""
    if tested_techniques:
        tested_list = list(tested_techniques.keys())[:50]
        tested_summary = f"\nALREADY TESTED BY AGENT A ({len(tested_techniques)} total, DO NOT REPEAT):\n"
        for t in tested_list:
            tested_summary += f"  - {t}\n"

    if failed_approaches:
        tested_summary += f"\nFAILED APPROACHES ({len(failed_approaches)}):\n"
        for k, v in list(failed_approaches.items())[:20]:
            tested_summary += f"  - {k}\n"

    # Technique cards from RAG
    techniques_ctx = "\nRELEVANT TECHNIQUE CARDS FROM BUG BOUNTY REPORTS:\n"
    for i, card in enumerate(technique_cards[:5]):
        techniques_ctx += f"\n--- Technique {i+1} ---\n"
        techniques_ctx += f"Title: {card.get('title', '')}\n"
        techniques_ctx += f"Vuln Class: {card.get('vuln_class', '')}\n"
        techniques_ctx += f"Heuristic: {card.get('heuristic', '')}\n"
        reasoning = card.get("reasoning_chain", "")
        if reasoning:
            techniques_ctx += f"Reasoning: {reasoning[:500]}\n"
        novelty = card.get("_novelty_score", "")
        if novelty:
            techniques_ctx += f"Novelty Score: {novelty:.2f}\n"
        bounty = card.get("bounty_amount", 0)
        if bounty:
            techniques_ctx += f"Original Bounty: ${bounty}\n"
        source = card.get("source_url", "")
        if source:
            techniques_ctx += f"Source: {source}\n"

    user_msg = (
        f"{target_ctx}\n{tested_summary}\n{techniques_ctx}\n\n"
        f"Generate 1-3 novel attack plans. Each plan should combine "
        f"insights from the technique cards with the target's specific "
        f"attack surface. Focus on what Agent A likely MISSED.\n\n"
        f"Output as a JSON array of plan objects."
    )

    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user_msg},
    ]


def parse_plans(response_text: str) -> list[dict]:
    """Parse LLM response into structured plans."""
    # Try to extract JSON from response
    text = response_text.strip()

    # Try full response as JSON
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict):
            return [parsed]
    except json.JSONDecodeError:
        pass

    # Try to find JSON array in text
    import re
    # Find JSON array
    match = re.search(r'\[.*\]', text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass

    # Find JSON object
    match = re.search(r'\{.*\}', text, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group())
            return [parsed] if isinstance(parsed, dict) else []
        except json.JSONDecodeError:
            pass

    logger.warning("plan_parse_failed", response_preview=text[:200])
    return []
