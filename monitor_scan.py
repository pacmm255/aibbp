#!/usr/bin/env python3
"""Real-time scan monitor — watches transcript JSONL and prints analytics.

Usage:
    python3 monitor_scan.py <transcript_path>
    python3 monitor_scan.py --latest           # auto-find latest transcript
    python3 monitor_scan.py --session <id>     # find by session ID
"""

import json
import sys
import time
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime


class ScanMonitor:
    def __init__(self, path: str):
        self.path = path
        self.stats = {
            "turns": 0,
            "tool_calls": defaultdict(int),
            "tool_errors": defaultdict(int),
            "tool_times_ms": defaultdict(list),
            "findings": [],
            "compressions": 0,
            "errors": [],
            "api_calls": [],
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cache_read": 0,
            "total_cost": 0.0,
            "start_time": None,
            "last_event_time": None,
            "strategy_resets": 0,
            "hypotheses": 0,
            "chains": 0,
            "state_endpoints": 0,
            "state_findings": 0,
            "reflector_retries": 0,
        }
        self._last_pos = 0
        self._seen_lines = 0

    def process_line(self, line: str):
        try:
            entry = json.loads(line.strip())
        except json.JSONDecodeError:
            return

        event = entry.get("event", "")
        data = entry.get("data", {})
        ts = entry.get("ts", 0)
        turn = entry.get("turn", 0)

        if ts:
            self.stats["last_event_time"] = ts
            if not self.stats["start_time"]:
                self.stats["start_time"] = ts

        if event == "session_start":
            self._print_header(data)

        elif event == "brain_response":
            self.stats["turns"] = max(self.stats["turns"], turn)
            tools = data.get("tool_calls", [])
            blocks = data.get("content_blocks", [])
            thinking = [b for b in blocks if b.get("type") == "thinking"]
            text = [b for b in blocks if b.get("type") == "text"]

            tool_str = ", ".join(tools) if tools else "(no tools)"
            thinking_len = sum(len(b.get("text", "")) for b in thinking)
            text_len = sum(len(b.get("text", "")) for b in text)

            print(f"\n\033[1;36m[Turn {turn}]\033[0m "
                  f"tools: \033[1m{tool_str}\033[0m  "
                  f"thinking: {thinking_len:,}ch  text: {text_len:,}ch  "
                  f"stop: {data.get('stop_reason', '?')}")

        elif event == "brain_prompt":
            sys_chars = data.get("system_prompt_chars", 0)
            msg_count = data.get("message_count", 0)
            tool_count = data.get("tool_count", 0)
            tier = data.get("task_tier", "?")
            think = data.get("thinking_budget", 0)
            print(f"  \033[2m[prompt] system: {sys_chars:,}ch  messages: {msg_count}  "
                  f"tools: {tool_count}  tier: {tier}  thinking: {think}\033[0m")

        elif event == "api_response_meta":
            inp = data.get("input_tokens", 0)
            out = data.get("output_tokens", 0)
            cache = data.get("cache_read_tokens", 0)
            cost = data.get("cost", 0)
            model = data.get("model", "?")
            self.stats["total_input_tokens"] += inp
            self.stats["total_output_tokens"] += out
            self.stats["total_cache_read"] += cache
            self.stats["total_cost"] += cost
            self.stats["api_calls"].append(data)
            print(f"  \033[2m[api] model: {model}  in: {inp:,}  out: {out:,}  "
                  f"cache: {cache:,}  cost: ${cost:.4f}\033[0m")

        elif event == "tool_call":
            name = data.get("tool_name", "?")
            self.stats["tool_calls"][name] += 1
            inp = data.get("input", "")
            inp_preview = inp[:120].replace("\n", " ") if isinstance(inp, str) else str(inp)[:120]
            print(f"  \033[33m-> {name}\033[0m {inp_preview}")

        elif event == "tool_result":
            name = data.get("tool_name", "?")
            elapsed = data.get("elapsed_ms", 0)
            is_error = data.get("is_error", False)
            result = data.get("result", "")
            result_preview = result[:150].replace("\n", " ") if isinstance(result, str) else ""

            self.stats["tool_times_ms"][name].append(elapsed)
            if is_error:
                self.stats["tool_errors"][name] += 1
                print(f"  \033[31m<- {name} ERROR ({elapsed:.0f}ms)\033[0m {result_preview}")
            else:
                print(f"  \033[32m<- {name} ({elapsed:.0f}ms)\033[0m {result_preview}")

        elif event == "finding":
            self.stats["findings"].append(data)
            sev = data.get("severity", "?")
            vtype = data.get("vuln_type", "?")
            ep = data.get("endpoint", "?")[:60]
            colors = {"critical": "91", "high": "91", "medium": "93", "low": "92", "info": "94"}
            c = colors.get(sev, "37")
            print(f"\n  \033[1;{c}m*** FINDING [{sev}] {vtype}: {ep}\033[0m")

        elif event == "compression":
            self.stats["compressions"] += 1
            before = data.get("before_chars", 0)
            after = data.get("after_chars", 0)
            tier = data.get("tier", "?")
            ratio = (after / before * 100) if before else 0
            print(f"  \033[35m[compress] tier {tier}: {before:,} -> {after:,} ({ratio:.0f}%)\033[0m")

        elif event == "state_snapshot":
            ep = data.get("endpoints_count", data.get("endpoints_keys", []))
            if isinstance(ep, list):
                ep = len(ep)
            self.stats["state_endpoints"] = ep
            self.stats["state_findings"] = data.get("findings_count", 0)

        elif event == "error":
            self.stats["errors"].append(data)
            print(f"  \033[31m[ERROR] {data.get('context', '')}: {data.get('error', '')[:200]}\033[0m")

        elif event == "strategy_reset":
            self.stats["strategy_resets"] += 1
            print(f"  \033[35m[strategy reset] {data.get('reason', '?')}\033[0m")

        elif event == "hypothesis":
            self.stats["hypotheses"] += 1

        elif event == "chain_discovery":
            self.stats["chains"] += 1
            print(f"  \033[36m[chain] {data.get('chain_name', '?')}: "
                  f"{data.get('description', '')[:100]}\033[0m")

        elif event == "session_end":
            self._print_summary()

    def _print_header(self, data):
        target = data.get("target_url", "?")
        sid = data.get("session_id", "?")
        print(f"\n{'='*80}")
        print(f"\033[1;37m  AIBBP Scan Monitor\033[0m")
        print(f"  Target:  {target}")
        print(f"  Session: {sid}")
        print(f"  Time:    {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'='*80}\n")

    def _print_summary(self):
        s = self.stats
        elapsed = (s["last_event_time"] - s["start_time"]) if s["start_time"] and s["last_event_time"] else 0
        mins = elapsed / 60

        print(f"\n{'='*80}")
        print(f"\033[1;37m  SCAN COMPLETE — SUMMARY\033[0m")
        print(f"{'='*80}")
        print(f"  Duration:        {mins:.1f} min")
        print(f"  Turns:           {s['turns']}")
        print(f"  Total API calls: {len(s['api_calls'])}")
        print(f"  Input tokens:    {s['total_input_tokens']:,}")
        print(f"  Output tokens:   {s['total_output_tokens']:,}")
        print(f"  Cache read:      {s['total_cache_read']:,}")
        print(f"  Total cost:      ${s['total_cost']:.4f}")
        print(f"  Findings:        {len(s['findings'])}")
        print(f"  Errors:          {len(s['errors'])}")
        print(f"  Compressions:    {s['compressions']}")
        print(f"  Strategy resets: {s['strategy_resets']}")
        print(f"  Hypotheses:      {s['hypotheses']}")
        print(f"  Chains:          {s['chains']}")

        print(f"\n  \033[1mTool Usage:\033[0m")
        for name, count in sorted(s["tool_calls"].items(), key=lambda x: -x[1]):
            times = s["tool_times_ms"].get(name, [])
            avg_ms = sum(times) / len(times) if times else 0
            errors = s["tool_errors"].get(name, 0)
            err_str = f" \033[31m({errors} errors)\033[0m" if errors else ""
            print(f"    {name:35s} {count:4d} calls  avg {avg_ms:7.0f}ms{err_str}")

        if s["findings"]:
            print(f"\n  \033[1mFindings:\033[0m")
            for f in s["findings"]:
                print(f"    [{f.get('severity', '?'):8s}] {f.get('vuln_type', '?'):25s} "
                      f"{f.get('endpoint', '?')[:50]}")

        print(f"{'='*80}\n")

    def _print_status_bar(self):
        s = self.stats
        elapsed = (s["last_event_time"] - s["start_time"]) if s["start_time"] and s["last_event_time"] else 0
        mins = elapsed / 60
        total_tools = sum(s["tool_calls"].values())
        print(f"\r\033[2m[{mins:.0f}m] turn {s['turns']} | "
              f"tools: {total_tools} | findings: {len(s['findings'])} | "
              f"endpoints: {s['state_endpoints']} | "
              f"tokens: {s['total_input_tokens']+s['total_output_tokens']:,} | "
              f"cost: ${s['total_cost']:.4f} | "
              f"errors: {len(s['errors'])}\033[0m", end="", flush=True)

    def tail(self):
        """Tail the transcript file, printing new events as they arrive."""
        print(f"Monitoring: {self.path}")
        print(f"Waiting for events... (Ctrl+C to stop)\n")

        # Process existing content first
        if os.path.exists(self.path):
            with open(self.path, "r") as f:
                for line in f:
                    if line.strip():
                        self.process_line(line)
                        self._seen_lines += 1
                self._last_pos = f.tell()

        # Tail for new lines
        while True:
            try:
                if os.path.exists(self.path):
                    with open(self.path, "r") as f:
                        f.seek(self._last_pos)
                        new_lines = f.readlines()
                        if new_lines:
                            for line in new_lines:
                                if line.strip():
                                    self.process_line(line)
                                    self._seen_lines += 1
                            self._last_pos = f.tell()
                        else:
                            self._print_status_bar()

                time.sleep(1)
            except KeyboardInterrupt:
                print(f"\n\nStopped monitoring. {self._seen_lines} events processed.")
                self._print_summary()
                break


def find_latest_transcript():
    """Find the most recently modified transcript file."""
    base = Path("~/.aibbp/targets").expanduser()
    if not base.exists():
        return None
    transcripts = list(base.glob("*/transcript_*.jsonl"))
    if not transcripts:
        return None
    return str(max(transcripts, key=lambda p: p.stat().st_mtime))


def find_by_session(session_id: str):
    """Find transcript by session ID."""
    base = Path("~/.aibbp/targets").expanduser()
    if not base.exists():
        return None
    for p in base.glob(f"*/transcript_{session_id}*.jsonl"):
        return str(p)
    # Also check /tmp
    for p in Path("/tmp").glob(f"*{session_id}*"):
        if p.suffix == ".jsonl":
            return str(p)
    return None


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 monitor_scan.py <transcript.jsonl>")
        print("       python3 monitor_scan.py --latest")
        print("       python3 monitor_scan.py --session <id>")
        sys.exit(1)

    if sys.argv[1] == "--latest":
        path = find_latest_transcript()
        if not path:
            print("No transcript files found in ~/.aibbp/targets/")
            sys.exit(1)
    elif sys.argv[1] == "--session":
        if len(sys.argv) < 3:
            print("Provide session ID")
            sys.exit(1)
        path = find_by_session(sys.argv[2])
        if not path:
            print(f"No transcript found for session: {sys.argv[2]}")
            sys.exit(1)
    else:
        path = sys.argv[1]

    monitor = ScanMonitor(path)
    monitor.tail()
