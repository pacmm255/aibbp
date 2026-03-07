"""Agent B Hypothesis Injector — reads Agent A state, queries RAG KB,
generates creative attack hypotheses via Z.ai (free), and writes them
into Agent A's memory.json for execution.

Usage:
    # Inject into all running Agent A targets
    python -m ai_brain.active.agent_b.inject_hypotheses --all

    # Inject into specific target
    python -m ai_brain.active.agent_b.inject_hypotheses --target https://crypto.com

    # Dry run (show hypotheses without writing)
    python -m ai_brain.active.agent_b.inject_hypotheses --all --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import time
from pathlib import Path

import structlog

logger = structlog.get_logger()


ZAI_PLAN_PROMPT = """You are an elite bug bounty hunter reviewing a target that another scanner (Agent A) has been testing.
Your job: find what Agent A MISSED by using techniques from real-world disclosed bug bounty reports.

TARGET: {target_url}
TECH STACK: {tech_stack}

AGENT A HAS ALREADY TESTED ({tested_count} techniques):
{tested_summary}

AGENT A'S CURRENT FINDINGS ({findings_count}):
{findings_summary}

AGENT A'S FAILED APPROACHES:
{failed_summary}

ENDPOINTS ({endpoint_count}):
{endpoints_summary}

NOVEL TECHNIQUE CARDS FROM REAL BUG BOUNTY REPORTS (Agent A hasn't tried these):
{technique_cards}

Based on these technique cards and the target's attack surface, generate 3-5 CREATIVE attack hypotheses that Agent A should try next. Each hypothesis should:
1. Be inspired by a specific technique card
2. Target a specific endpoint or feature
3. Describe the exact attack approach
4. Explain why Agent A likely missed it

Output as JSON array:
[
  {{
    "description": "Detailed hypothesis — what to test and how",
    "status": "pending",
    "evidence": "Which technique card inspired this + why it applies here",
    "priority": "high|medium",
    "source": "agent_b_rag",
    "technique_card_title": "Title of the inspiring technique"
  }}
]

IMPORTANT: Output ONLY the JSON array. No other text."""


async def generate_hypotheses_zai(
    target_url: str,
    tech_stack: list[str],
    tested: dict,
    findings: dict,
    failed: dict,
    endpoints: dict,
    technique_cards: list[dict],
) -> list[dict]:
    """Use Z.ai (free) to generate creative hypotheses from RAG technique cards."""
    from ai_brain.active.zai_client import ZaiClient
    from ai_brain.budget import BudgetManager
    from ai_brain.config import AIBrainConfig, BudgetConfig

    # Build prompt context
    tested_summary = "\n".join(f"  - {k}" for k in list(tested.keys())[:30])
    findings_summary = "\n".join(
        f"  [{f.get('severity','?')}] {f.get('vuln_type','?')} @ {f.get('endpoint','?')}"
        for f in (list(findings.values()) if isinstance(findings, dict) else [])[:15]
        if isinstance(f, dict)
    )
    failed_summary = "\n".join(f"  - {k}" for k in list(failed.keys())[:20])
    endpoints_summary = "\n".join(f"  {ep}" for ep in list(endpoints.keys())[:30])

    cards_text = ""
    for i, card in enumerate(technique_cards[:5], 1):
        cards_text += f"\n--- Technique {i} ---\n"
        cards_text += f"Title: {card.get('title', '')}\n"
        cards_text += f"Vuln Class: {card.get('vuln_class', '')}\n"
        cards_text += f"Heuristic: {card.get('heuristic', '')}\n"
        reasoning = card.get("reasoning_chain", "")
        if reasoning:
            cards_text += f"Reasoning: {reasoning[:400]}\n"
        bounty = card.get("bounty_amount", 0)
        if bounty:
            cards_text += f"Original Bounty: ${bounty}\n"

    prompt = ZAI_PLAN_PROMPT.format(
        target_url=target_url,
        tech_stack=", ".join(tech_stack[:10]) or "unknown",
        tested_count=len(tested),
        tested_summary=tested_summary or "  (none)",
        findings_count=len(findings),
        findings_summary=findings_summary or "  (none)",
        failed_summary=failed_summary or "  (none)",
        endpoint_count=len(endpoints),
        endpoints_summary=endpoints_summary or "  (none)",
        technique_cards=cards_text or "  (none available)",
    )

    # Call Z.ai with a dummy tool so the response gets properly structured
    config = AIBrainConfig()
    budget = BudgetManager(BudgetConfig(total_dollars=9999), active_testing=True)
    zai = ZaiClient(budget=budget, config=config)
    try:
        # Use a dummy "output_json" tool to get structured output from Z.ai
        dummy_tool = {
            "name": "output_hypotheses",
            "description": "Output the generated hypotheses as a JSON array",
            "input_schema": {
                "type": "object",
                "properties": {
                    "hypotheses": {
                        "type": "array",
                        "description": "Array of hypothesis objects",
                        "items": {
                            "type": "object",
                            "properties": {
                                "description": {"type": "string"},
                                "evidence": {"type": "string"},
                                "priority": {"type": "string"},
                                "technique_card_title": {"type": "string"},
                            },
                        },
                    },
                },
                "required": ["hypotheses"],
            },
        }
        response = await zai.call_with_tools(
            phase="active_testing",
            task_tier="complex",
            system_blocks=[{"type": "text", "text": "You are Agent B. Use the output_hypotheses tool to return your results."}],
            messages=[{"role": "user", "content": prompt}],
            tools=[dummy_tool],
        )
        # Extract from tool_use block or text
        text = ""
        for block in response.content:
            if getattr(block, "type", "") == "tool_use" and hasattr(block, "input"):
                # Got structured output via tool
                inp = block.input
                if isinstance(inp, dict) and "hypotheses" in inp:
                    return inp["hypotheses"]
                # Maybe the whole input is our array
                return [inp] if isinstance(inp, dict) else []
            if hasattr(block, "text") and getattr(block, "type", "") == "text":
                text += block.text
        # Fallback: check thinking blocks too
        if not text:
            for block in response.content:
                if hasattr(block, "thinking"):
                    text += block.thinking
        logger.info("agent_b_zai_response", text_len=len(text), text_preview=text[:200])

        # Parse JSON from response — strip markdown fences
        import re
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r'^```\w*\n?', '', text)
            text = re.sub(r'\n?```\s*$', '', text)
            text = text.strip()

        # Try full text as JSON
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except json.JSONDecodeError:
            pass

        # Try to find JSON array
        match = re.search(r'\[.*\]', text, re.DOTALL)
        if match:
            try:
                hypotheses = json.loads(match.group())
                if isinstance(hypotheses, list):
                    return hypotheses
            except json.JSONDecodeError:
                pass

        # Try JSON object
        match = re.search(r'\{.*\}', text, re.DOTALL)
        if match:
            try:
                h = json.loads(match.group())
                return [h] if isinstance(h, dict) else []
            except json.JSONDecodeError:
                pass

    except Exception as e:
        logger.error("zai_hypothesis_gen_failed", error=str(e))

    return []


async def generate_hypotheses_fallback(
    target_url: str,
    tech_stack: list[str],
    tested: dict,
    findings: dict,
    endpoints: dict,
    technique_cards: list[dict],
) -> list[dict]:
    """Generate hypotheses without LLM — pure heuristic mapping from technique cards."""
    hypotheses = []
    for card in technique_cards[:5]:
        vuln_class = card.get("vuln_class", "")
        title = card.get("title", "")
        heuristic = card.get("heuristic", "")
        reasoning = card.get("reasoning_chain", "")

        # Map vuln class to specific test suggestions
        desc = f"Try technique from H1 report: {title[:100]}. "
        if heuristic:
            desc += f"Heuristic: {heuristic[:200]}. "
        if reasoning:
            desc += f"Approach: {reasoning[:200]}"

        hypotheses.append({
            "description": desc,
            "status": "pending",
            "evidence": f"Source: Agent B RAG KB — {vuln_class} technique from disclosed H1 report",
            "priority": "high" if card.get("severity") in ("critical", "high") else "medium",
            "source": "agent_b_rag",
            "technique_card_title": title[:100],
        })

    return hypotheses


async def inject_for_target(
    memory_path: str,
    kb_path: str,
    use_zai: bool = True,
    dry_run: bool = False,
) -> int:
    """Inject novel hypotheses into one Agent A target."""
    from ai_brain.active.agent_b.knowledge_base import KnowledgeBase
    from ai_brain.active.agent_b.novelty_scorer import NoveltyScorer
    from ai_brain.active.agent_b.state_watcher import AgentAStateWatcher

    watcher = AgentAStateWatcher(memory_path)
    state = watcher.read_current()
    if not state:
        print(f"  [!] Cannot read state from {memory_path}")
        return 0

    key = watcher.extract_key_fields(state)
    target_url = key["target_url"]
    tech_stack = key["tech_stack"]
    endpoints = key["endpoints"]
    findings = key["findings"]
    tested = key["tested_techniques"]
    failed = key["failed_approaches"]

    print(f"  Target: {target_url}")
    print(f"  Agent A: {key['total_turns']} turns, {len(findings)} findings, {len(tested)} tested")

    # Query KB for novel techniques
    kb = KnowledgeBase(kb_path)
    techniques = kb.search_for_target(
        tech_stack=tech_stack,
        endpoints=endpoints,
        tested_techniques=tested,
        limit=20,
    )

    # Filter for novelty
    scorer = NoveltyScorer()
    scorer.update_agent_a_state(tested, findings, failed)
    novel = scorer.filter_novel(techniques, threshold=0.4)

    print(f"  KB search: {len(techniques)} retrieved, {len(novel)} novel")

    if not novel:
        print(f"  [*] No novel techniques — Agent A has good coverage")
        return 0

    # Generate hypotheses
    if use_zai:
        try:
            hypotheses = await generate_hypotheses_zai(
                target_url, tech_stack, tested, findings, failed, endpoints, novel,
            )
        except Exception as e:
            print(f"  [!] Z.ai failed ({e}), using heuristic fallback")
            hypotheses = await generate_hypotheses_fallback(
                target_url, tech_stack, tested, findings, endpoints, novel,
            )
    else:
        hypotheses = await generate_hypotheses_fallback(
            target_url, tech_stack, tested, findings, endpoints, novel,
        )

    if not hypotheses:
        print(f"  [!] No hypotheses generated")
        return 0

    print(f"  Generated {len(hypotheses)} hypotheses:")
    for h in hypotheses:
        print(f"    [{h.get('priority', '?')}] {h.get('description', '?')[:100]}")

    if dry_run:
        print(f"  [DRY RUN] Would inject {len(hypotheses)} hypotheses")
        return len(hypotheses)

    # Write to sidecar file (agent_b_hypotheses.json) instead of memory.json
    # to avoid race condition where Agent A overwrites our hypotheses on save
    sidecar_path = str(Path(memory_path).parent / "agent_b_hypotheses.json")

    # Load existing sidecar hypotheses
    existing_hyps = {}
    if os.path.exists(sidecar_path):
        try:
            with open(sidecar_path) as f:
                existing_hyps = json.load(f)
        except Exception:
            pass

    # Also check memory.json for existing agent_b hypotheses (for ID numbering)
    all_agent_b_ids = set(existing_hyps.keys())
    for hid in state.get("hypotheses", {}):
        if hid.startswith("agent_b_"):
            all_agent_b_ids.add(hid)

    max_id = 0
    for hid in all_agent_b_ids:
        try:
            num = int(hid.replace("agent_b_", ""))
            max_id = max(max_id, num)
        except ValueError:
            pass

    injected = 0
    for h in hypotheses:
        max_id += 1
        hid = f"agent_b_{max_id}"
        h["status"] = "pending"
        h["source"] = "agent_b_rag"
        h["injected_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        existing_hyps[hid] = h
        injected += 1

    # Write atomically
    tmp_path = sidecar_path + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(existing_hyps, f, indent=2, default=str)
    os.replace(tmp_path, sidecar_path)

    print(f"  [+] Injected {injected} hypotheses into {sidecar_path}")
    return injected


async def main_async(args):
    kb_path = str(Path(args.kb_path).expanduser())

    # Check KB
    from ai_brain.active.agent_b.knowledge_base import KnowledgeBase
    kb = KnowledgeBase(kb_path)
    count = kb.count()
    print(f"Knowledge base: {count} technique cards")
    if count == 0:
        print("[!] Empty KB. Run --ingest first.")
        sys.exit(1)

    targets_dir = Path.home() / ".aibbp" / "targets"
    memory_files = []

    if args.target:
        # Find specific target
        target_clean = args.target.replace("https://", "").replace("http://", "").rstrip("/")
        for d in targets_dir.iterdir():
            if d.is_dir() and (target_clean.replace("/", "_") in d.name or target_clean.replace(".", "_") in d.name):
                mem = d / "memory.json"
                if mem.exists():
                    memory_files.append(str(mem))
                    break
        if not memory_files:
            print(f"[!] No memory.json for {args.target}")
            sys.exit(1)
    elif args.all:
        # All targets with enough data
        for d in sorted(targets_dir.iterdir()):
            mem = d / "memory.json"
            if mem.exists():
                try:
                    data = json.load(open(mem))
                    if data.get("total_turns", 0) > 100 and len(data.get("tested_techniques", {})) > 10:
                        memory_files.append(str(mem))
                except Exception:
                    pass
    else:
        print("Usage: --target <url> or --all")
        sys.exit(1)

    print(f"Processing {len(memory_files)} targets...\n")
    total_injected = 0

    for mem_path in memory_files:
        try:
            n = await inject_for_target(
                mem_path, kb_path,
                use_zai=not args.no_zai,
                dry_run=args.dry_run,
            )
            total_injected += n
        except Exception as e:
            print(f"  [!] Error: {e}")
        print()

    print(f"Done! Injected {total_injected} hypotheses across {len(memory_files)} targets")


def main():
    parser = argparse.ArgumentParser(description="Agent B Hypothesis Injector")
    parser.add_argument("--target", type=str, help="Specific target URL")
    parser.add_argument("--all", action="store_true", help="All targets with Agent A data")
    parser.add_argument("--dry-run", action="store_true", help="Show hypotheses without writing")
    parser.add_argument("--no-zai", action="store_true", help="Use heuristic fallback instead of Z.ai")
    parser.add_argument("--kb-path", type=str, default="~/.aibbp/knowledge_base")
    args = parser.parse_args()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
