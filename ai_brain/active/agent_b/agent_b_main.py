"""Agent B — Independent knowledge-augmented pentester.

Agent B reads Agent A's state (read-only), retrieves novel attack techniques
from a RAG knowledge base of real H1 bug bounty reports, and runs as an
independent ReAct agent with its own browser/proxy/tools.

Agent A is completely unaware of Agent B.

Architecture:
    Agent A memory.json (read-only)
            │
            ▼
    Agent B reads tested_techniques, findings, endpoints, tech_stack
            │
            ▼
    RAG KB (8K+ H1 technique cards) → novel techniques not tried by Agent A
            │
            ▼
    Agent B launches as independent ReAct agent with:
      - Agent A's tested_techniques pre-loaded (to avoid repeating)
      - RAG technique cards injected as initial hypotheses
      - Own memory directory (~/.aibbp/targets_b/)
      - Own browser, proxy, Z.ai session

Usage:
    # Run Agent B for a specific target (Agent A must already be running/have data)
    python -m ai_brain.active.agent_b.agent_b_main \
        --target https://example.com \
        --allowed-domains example.com \
        --zai --enable-proxylist

    # Run for all targets that have enough Agent A data
    python -m ai_brain.active.agent_b.agent_b_main --launch-all \
        --zai --enable-proxylist

    # Ingest H1 reports into knowledge base
    python -m ai_brain.active.agent_b.agent_b_main --ingest /root/aibbp/data/h1_reports

    # Show knowledge base stats
    python -m ai_brain.active.agent_b.agent_b_main --stats
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import structlog

logger = structlog.get_logger()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="AIBBP Agent B — Knowledge-augmented independent pentester",
    )
    # Mode flags
    parser.add_argument("--ingest", type=str, default="",
                        help="Ingest H1 reports from directory into knowledge base")
    parser.add_argument("--stats", action="store_true", default=False,
                        help="Show knowledge base statistics")
    parser.add_argument("--launch-all", action="store_true", default=False,
                        help="Launch Agent B for all targets with sufficient Agent A data")

    # Single-target mode
    parser.add_argument("--target", type=str, default="",
                        help="Target URL (must match an existing Agent A target)")
    parser.add_argument("--allowed-domains", type=str, nargs="*", default=[],
                        help="In-scope domains (comma-separated or space-separated)")

    # Agent options (passed through to react_main)
    parser.add_argument("--budget", type=float, default=9999,
                        help="Budget in dollars (default: $9999)")
    parser.add_argument("--max-turns", type=int, default=0,
                        help="Maximum brain turns (0 = indefinite)")
    parser.add_argument("--zai", action="store_true", default=False,
                        help="Use Z.ai GLM-5 (free brain)")
    parser.add_argument("--enable-proxylist", action="store_true", default=False,
                        help="Use rotating proxy pool for Z.ai")
    parser.add_argument("--proxy-ratelimit", type=float, default=3.0)
    parser.add_argument("--min-proxies", type=int, default=8)
    parser.add_argument("--max-proxies", type=int, default=100)
    parser.add_argument("--max-rss", type=int, default=700)
    parser.add_argument("--min-turns", type=int, default=200,
                        help="Min Agent A turns before launching Agent B (default: 200)")
    parser.add_argument("--min-techniques", type=int, default=20,
                        help="Min Agent A tested techniques before launching (default: 20)")

    # KB options
    parser.add_argument("--kb-path", type=str, default="~/.aibbp/knowledge_base",
                        help="Knowledge base directory")

    return parser.parse_args()


def cmd_ingest(reports_dir: str, kb_path: str) -> None:
    """Ingest H1 reports into knowledge base."""
    from ai_brain.active.agent_b.knowledge_base import KnowledgeBase
    from ai_brain.active.agent_b.technique_extractor import (
        process_h1_reports_dir,
        vuln_class_stats,
    )

    print(f"[*] Processing reports from {reports_dir}...")
    cards = process_h1_reports_dir(reports_dir, min_confidence=0.3)
    print(f"[*] Extracted {len(cards)} technique cards")

    if not cards:
        print("[!] No cards extracted")
        return

    stats = vuln_class_stats(cards)
    print(f"\n[*] Vulnerability class distribution:")
    for cls, count in sorted(stats.items(), key=lambda x: -x[1])[:20]:
        print(f"    {cls:25s} {count:5d}")

    print(f"\n[*] Storing in knowledge base at {kb_path}...")
    kb = KnowledgeBase(kb_path)
    kb.init_techniques_table()

    batch_size = 100
    total_added = 0
    for i in range(0, len(cards), batch_size):
        batch = cards[i:i + batch_size]
        added = kb.add_techniques_batch(batch)
        total_added += added
        if (i + batch_size) % 1000 == 0 or i + batch_size >= len(cards):
            print(f"    Progress: {min(i + batch_size, len(cards))}/{len(cards)} "
                  f"processed, {total_added} added")

    print(f"\n[*] Done! {total_added} technique cards stored in knowledge base")
    print(f"    Total in KB: {kb.count()}")


def cmd_stats(kb_path: str) -> None:
    """Show knowledge base statistics."""
    from ai_brain.active.agent_b.knowledge_base import KnowledgeBase

    kb_path = str(Path(kb_path).expanduser())
    kb = KnowledgeBase(kb_path)
    stats = kb.stats()

    print(f"Knowledge Base: {kb_path}")
    print(f"  Total technique cards: {stats.get('total', 0)}")

    if stats.get("total", 0) > 0:
        print(f"\n  Sample search: 'SQL injection bypass'")
        results = kb.search_techniques("SQL injection bypass techniques", limit=3)
        for r in results:
            print(f"    [{r.get('severity', '?')}] {r.get('title', '?')[:80]}")
            print(f"          vuln_class={r.get('vuln_class', '?')}, "
                  f"bounty=${r.get('bounty_amount', 0)}")


def _find_agent_a_memory(target: str) -> Path | None:
    """Find Agent A's memory.json for a target URL."""
    from urllib.parse import urlparse
    domain = urlparse(target).netloc or target.replace("https://", "").replace("http://", "")

    targets_dir = Path.home() / ".aibbp" / "targets"
    if not targets_dir.exists():
        return None

    # Try matching domain in directory name (dirs are like "www.binance.com_c3408c04")
    for d in targets_dir.iterdir():
        if d.is_dir() and domain in d.name:
            mem = d / "memory.json"
            if mem.exists():
                return mem
    # Fallback: try with dots replaced by underscores
    clean = domain.replace(".", "_").replace(":", "_")
    for d in targets_dir.iterdir():
        if d.is_dir() and clean in d.name:
            mem = d / "memory.json"
            if mem.exists():
                return mem
    return None


def _read_agent_a_state(memory_path: Path) -> dict | None:
    """Read Agent A's state from memory.json."""
    try:
        data = json.loads(memory_path.read_text())
        return data
    except Exception as e:
        logger.warning("agent_a_read_failed", path=str(memory_path), error=str(e))
        return None


def _get_novel_techniques(
    agent_a_state: dict,
    kb_path: str,
    limit: int = 10,
) -> list[dict]:
    """Query RAG KB for techniques Agent A hasn't tried."""
    from ai_brain.active.agent_b.knowledge_base import KnowledgeBase
    from ai_brain.active.agent_b.novelty_scorer import NoveltyScorer

    tech_stack = agent_a_state.get("tech_stack", [])
    endpoints = agent_a_state.get("endpoints", {})
    tested = agent_a_state.get("tested_techniques", {})
    findings = agent_a_state.get("findings", {})
    failed = agent_a_state.get("failed_approaches", {})

    kb = KnowledgeBase(kb_path)
    techniques = kb.search_for_target(
        tech_stack=tech_stack,
        endpoints=endpoints,
        tested_techniques=tested,
        limit=30,
    )

    scorer = NoveltyScorer()
    scorer.update_agent_a_state(tested, findings, failed)
    novel = scorer.filter_novel(techniques, threshold=0.4)

    return novel[:limit]


def _build_seed_file(
    target: str,
    agent_a_state: dict,
    novel_techniques: list[dict],
    seed_path: Path,
) -> None:
    """Write a seed file that Agent B's ReAct agent will load on startup.

    The seed file contains:
    - Agent A's tested_techniques (so Agent B avoids repeating)
    - Agent A's findings (so Agent B knows what's already found)
    - Novel technique cards as initial hypotheses for Agent B
    """
    # Build hypotheses from technique cards
    hypotheses = {}
    for i, card in enumerate(novel_techniques, 1):
        title = card.get("title", "")
        vuln_class = card.get("vuln_class", "")
        heuristic = card.get("heuristic", "")
        reasoning = card.get("reasoning_chain", "")
        bounty = card.get("bounty_amount", 0)

        desc = f"[H1 Technique] {title[:120]}."
        if heuristic:
            desc += f" Heuristic: {heuristic[:250]}."
        if reasoning:
            desc += f" Approach: {reasoning[:250]}"

        hypotheses[f"rag_{i}"] = {
            "description": desc,
            "status": "pending",
            "evidence": (f"From real H1 bug bounty report. Vuln class: {vuln_class}. "
                         f"Bounty: ${bounty}" if bounty else
                         f"From real H1 bug bounty report. Vuln class: {vuln_class}."),
            "priority": "high" if card.get("severity") in ("critical", "high") else "medium",
            "source": "rag_kb",
        }

    seed = {
        "target_url": target,
        "domain": agent_a_state.get("domain", ""),
        # Carry over Agent A's knowledge so Agent B doesn't repeat
        "tested_techniques": agent_a_state.get("tested_techniques", {}),
        "failed_approaches": agent_a_state.get("failed_approaches", {}),
        # Agent A's endpoints = Agent B's starting point for exploration
        "endpoints": agent_a_state.get("endpoints", {}),
        "tech_stack": agent_a_state.get("tech_stack", []),
        # Agent A's findings (context, not to repeat)
        "findings": agent_a_state.get("findings", {}),
        # RAG-derived hypotheses — Agent B's unique mission
        "hypotheses": hypotheses,
        # Metadata
        "total_sessions": 0,
        "total_turns": 0,
        "total_budget_spent": 0.0,
        "agent_b_seed": True,
        "agent_a_turns": agent_a_state.get("total_turns", 0),
        "agent_a_sessions": agent_a_state.get("total_sessions", 0),
        "seeded_at": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "novel_technique_count": len(novel_techniques),
    }

    seed_path.parent.mkdir(parents=True, exist_ok=True)
    seed_path.write_text(json.dumps(seed, indent=2, default=str))


def launch_agent_b(
    target: str,
    allowed_domains: list[str],
    agent_a_state: dict,
    novel_techniques: list[dict],
    args: argparse.Namespace,
    background: bool = True,
) -> subprocess.Popen | None:
    """Launch Agent B as a separate react_main process."""
    from urllib.parse import urlparse
    domain = urlparse(target).netloc

    # Agent B uses a separate memory directory
    memory_dir = Path.home() / ".aibbp" / "targets_b"
    memory_dir.mkdir(parents=True, exist_ok=True)

    # Write seed file (Agent B will load this as saved memory)
    import hashlib
    domain_hash = hashlib.sha256(domain.encode()).hexdigest()[:8]
    safe_domain = domain.replace(":", "_").replace("/", "_")
    target_dir = memory_dir / f"{safe_domain}_{domain_hash}"
    target_dir.mkdir(parents=True, exist_ok=True)
    seed_path = target_dir / "memory.json"

    _build_seed_file(target, agent_a_state, novel_techniques, seed_path)

    # Find free proxy port (Agent A uses 8085, Agent B uses 9085+)
    import socket
    proxy_port = 9085
    for p in range(9085, 9185):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(("127.0.0.1", p))
            s.close()
            proxy_port = p
            break
        except OSError:
            continue

    # Build react_main command
    cmd = [
        sys.executable, "-m", "ai_brain.active.react_main",
        "--target", target,
        "--memory-dir", str(memory_dir),
        "--budget", str(args.budget),
        "--max-turns", str(args.max_turns),
        "--max-rss", str(args.max_rss),
        "--proxy-port", str(proxy_port),
    ]

    # Allowed domains
    if allowed_domains:
        cmd.extend(["--allowed-domains"] + allowed_domains)

    # Z.ai options
    if args.zai:
        cmd.append("--zai")
    if args.enable_proxylist:
        cmd.extend([
            "--enable-proxylist",
            "--proxy-ratelimit", str(args.proxy_ratelimit),
            "--min-proxies", str(args.min_proxies),
            "--max-proxies", str(args.max_proxies),
        ])

    log_path = f"/tmp/agent_b_{safe_domain}.log"

    if background:
        with open(log_path, "w") as log_f:
            proc = subprocess.Popen(
                cmd,
                stdout=log_f,
                stderr=subprocess.STDOUT,
                cwd="/root/aibbp",
                start_new_session=True,
            )
        print(f"  [+] Launched PID {proc.pid} → {log_path}")
        return proc
    else:
        print(f"  [*] Running: {' '.join(cmd)}")
        os.execvp(cmd[0], cmd)
        return None


def cmd_launch_all(args: argparse.Namespace) -> None:
    """Launch Agent B for all targets with sufficient Agent A data."""
    kb_path = str(Path(args.kb_path).expanduser())

    from ai_brain.active.agent_b.knowledge_base import KnowledgeBase
    kb = KnowledgeBase(kb_path)
    kb_count = kb.count()
    print(f"Knowledge Base: {kb_count} technique cards")
    if kb_count == 0:
        print("[!] Empty KB. Run --ingest first.")
        sys.exit(1)

    targets_dir = Path.home() / ".aibbp" / "targets"
    if not targets_dir.exists():
        print("[!] No Agent A targets found")
        sys.exit(1)

    # Find Agent A targets with enough data
    candidates = []
    for d in sorted(targets_dir.iterdir()):
        if not d.is_dir():
            continue
        mem = d / "memory.json"
        if not mem.exists():
            continue
        try:
            data = json.loads(mem.read_text())
            turns = data.get("total_turns", 0)
            techniques = len(data.get("tested_techniques", {}))
            target_url = data.get("target_url", "")
            if turns >= args.min_turns and techniques >= args.min_techniques and target_url:
                candidates.append((target_url, data, mem))
        except Exception:
            pass

    print(f"Candidates: {len(candidates)} targets with >={args.min_turns} turns, "
          f">={args.min_techniques} techniques\n")

    # Check which already have Agent B running
    import subprocess as sp
    existing = set()
    try:
        ps_out = sp.check_output(
            ["ps", "aux"], text=True, timeout=5,
        )
        for line in ps_out.splitlines():
            if "targets_b" in line and "react_main" in line:
                # Extract target URL
                parts = line.split("--target ")
                if len(parts) > 1:
                    url = parts[1].split()[0]
                    existing.add(url)
    except Exception:
        pass

    launched = 0
    for target_url, agent_a_state, mem_path in candidates:
        if target_url in existing:
            print(f"  [skip] {target_url} — Agent B already running")
            continue

        print(f"  {target_url}:")
        print(f"    Agent A: {agent_a_state.get('total_turns', 0)} turns, "
              f"{len(agent_a_state.get('findings', {}))} findings, "
              f"{len(agent_a_state.get('tested_techniques', {}))} techniques")

        # Get novel techniques
        novel = _get_novel_techniques(agent_a_state, kb_path, limit=10)
        if not novel:
            print(f"    [skip] No novel techniques — Agent A has good coverage")
            continue

        print(f"    RAG: {len(novel)} novel techniques found")

        # Guess allowed-domains from Agent A's target
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc
        allowed = [domain]

        launch_agent_b(
            target=target_url,
            allowed_domains=allowed,
            agent_a_state=agent_a_state,
            novel_techniques=novel,
            args=args,
            background=True,
        )
        launched += 1
        time.sleep(2)  # Stagger launches

    print(f"\nLaunched {launched} Agent B instances")


def cmd_run_single(args: argparse.Namespace) -> None:
    """Launch Agent B for a single target."""
    kb_path = str(Path(args.kb_path).expanduser())

    # Find Agent A's memory
    mem_path = _find_agent_a_memory(args.target)
    if not mem_path:
        print(f"[!] No Agent A data found for {args.target}")
        print(f"    Agent A must run first to build target knowledge.")
        sys.exit(1)

    agent_a_state = _read_agent_a_state(mem_path)
    if not agent_a_state:
        print(f"[!] Cannot read Agent A state from {mem_path}")
        sys.exit(1)

    turns = agent_a_state.get("total_turns", 0)
    techniques = len(agent_a_state.get("tested_techniques", {}))
    print(f"Agent A state: {turns} turns, {techniques} techniques, "
          f"{len(agent_a_state.get('findings', {}))} findings")

    # Get novel techniques
    novel = _get_novel_techniques(agent_a_state, kb_path, limit=10)
    if not novel:
        print("[!] No novel techniques found — Agent A has good coverage.")
        print("    Nothing for Agent B to do.")
        sys.exit(0)

    print(f"RAG KB: {len(novel)} novel techniques for Agent B to try:")
    for t in novel[:5]:
        print(f"  - [{t.get('vuln_class', '?')}] {t.get('title', '?')[:80]}")

    # Parse allowed domains
    allowed = []
    if args.allowed_domains:
        for d in args.allowed_domains:
            allowed.extend(d.split(","))

    launch_agent_b(
        target=args.target,
        allowed_domains=allowed,
        agent_a_state=agent_a_state,
        novel_techniques=novel,
        args=args,
        background=False,  # Run in foreground for single target
    )


def main():
    args = parse_args()

    if args.ingest:
        kb_path = str(Path(args.kb_path).expanduser())
        cmd_ingest(args.ingest, kb_path)
    elif args.stats:
        cmd_stats(args.kb_path)
    elif args.launch_all:
        cmd_launch_all(args)
    elif args.target:
        cmd_run_single(args)
    else:
        print("Usage:")
        print("  --ingest <dir>     Ingest H1 reports into knowledge base")
        print("  --stats            Show knowledge base statistics")
        print("  --target <url>     Run Agent B for a specific target")
        print("  --launch-all       Launch Agent B for all qualifying targets")
        sys.exit(1)


if __name__ == "__main__":
    main()
