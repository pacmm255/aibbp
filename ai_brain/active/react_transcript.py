"""Full conversation transcript logging for the ReAct pentesting agent.

Writes JSONL transcripts to ~/.aibbp/targets/<hash>/transcript_<session_id>.jsonl.
Every brain response, tool call, tool result, state update, finding, compression
event, and error is logged with timestamps and turn numbers.

Thread-safe, append-mode, flushed immediately after each write.
"""

from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# Cap sizes — very high limits for full analytics runs
_MAX_TOOL_RESULT_SIZE = 200_000
_MAX_TOOL_INPUT_SIZE = 200_000
_MAX_FIELD_SIZE = 200_000


def _cap(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"...[truncated {len(text)} chars]"


class TranscriptLogger:
    """Append-only JSONL transcript logger.

    Usage:
        transcript = TranscriptLogger(target_url="https://example.com",
                                       memory_dir="~/.aibbp/targets")
        transcript.start()
        transcript.log_brain_response(turn=1, content_blocks=[...])
        transcript.stop()
    """

    def __init__(
        self,
        target_url: str,
        memory_dir: str = "~/.aibbp/targets",
        session_id: str | None = None,
    ):
        self.target_url = target_url
        self.session_id = session_id or uuid.uuid4().hex[:12]
        self._lock = threading.Lock()
        self._file = None
        self._started = False
        self._turn = 0

        # Compute path: ~/.aibbp/targets/<domain_hash>/transcript_<session>.jsonl
        import hashlib
        domain_hash = hashlib.md5(target_url.encode()).hexdigest()[:12]
        base_dir = Path(memory_dir).expanduser() / domain_hash
        base_dir.mkdir(parents=True, exist_ok=True)
        self.path = base_dir / f"transcript_{self.session_id}.jsonl"

    def start(self) -> None:
        """Open the transcript file for appending."""
        self._file = open(self.path, "a", encoding="utf-8")
        self._started = True
        self._write_event("session_start", {
            "target_url": self.target_url,
            "session_id": self.session_id,
        })
        logger.info("transcript_started", path=str(self.path))

    def stop(self) -> None:
        """Flush and close the transcript file."""
        if self._file:
            self._write_event("session_end", {
                "total_turns": self._turn,
            })
            try:
                self._file.flush()
                self._file.close()
            except Exception:
                pass
            self._file = None
        self._started = False

    @property
    def current_turn(self) -> int:
        return self._turn

    @current_turn.setter
    def current_turn(self, value: int) -> None:
        self._turn = value

    def _write_event(self, event: str, data: dict[str, Any]) -> None:
        """Write a single JSONL event line."""
        if not self._file:
            return
        entry = {
            "ts": time.time(),
            "turn": self._turn,
            "event": event,
            "data": data,
        }
        with self._lock:
            try:
                line = json.dumps(entry, default=str, ensure_ascii=True)
                self._file.write(line + "\n")
                self._file.flush()
            except Exception as e:
                logger.warning("transcript_write_failed", error=str(e))

    # ── Event methods ────────────────────────────────────────────────

    def log_brain_response(
        self,
        turn: int,
        content_blocks: list[Any],
        tool_calls: list[Any] | None = None,
        stop_reason: str = "",
    ) -> None:
        """Log the full Claude brain response."""
        self._turn = turn
        blocks = []
        for b in content_blocks:
            btype = getattr(b, "type", "unknown")
            if btype == "text":
                blocks.append({"type": "text", "text": _cap(b.text, _MAX_FIELD_SIZE)})
            elif btype == "thinking":
                blocks.append({"type": "thinking", "text": _cap(getattr(b, "thinking", ""), _MAX_FIELD_SIZE)})
            elif btype == "tool_use":
                inp = getattr(b, "input", {})
                inp_str = json.dumps(inp, default=str)
                blocks.append({
                    "type": "tool_use",
                    "name": getattr(b, "name", "?"),
                    "id": getattr(b, "id", "?"),
                    "input": _cap(inp_str, _MAX_TOOL_INPUT_SIZE),
                })
            else:
                blocks.append({"type": str(btype), "text": str(b)[:500]})

        tc_names = []
        if tool_calls:
            tc_names = [getattr(tc, "name", "?") for tc in tool_calls]

        self._write_event("brain_response", {
            "content_blocks": blocks,
            "tool_calls": tc_names,
            "stop_reason": stop_reason,
        })

    def log_tool_call(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_id: str = "",
    ) -> None:
        """Log an individual tool call before execution."""
        inp_str = json.dumps(tool_input, default=str)
        self._write_event("tool_call", {
            "tool_name": tool_name,
            "tool_id": tool_id,
            "input": _cap(inp_str, _MAX_TOOL_INPUT_SIZE),
        })

    def log_tool_result(
        self,
        tool_name: str,
        result: str,
        elapsed_ms: float = 0,
        is_error: bool = False,
    ) -> None:
        """Log a tool result after execution."""
        self._write_event("tool_result", {
            "tool_name": tool_name,
            "result": _cap(result, _MAX_TOOL_RESULT_SIZE),
            "elapsed_ms": round(elapsed_ms, 1),
            "is_error": is_error,
        })

    def log_state_update(self, updates: dict[str, Any]) -> None:
        """Log state updates from tool execution."""
        # Summarize large state updates
        summary = {}
        for key, value in updates.items():
            if isinstance(value, dict):
                summary[key] = f"dict({len(value)} keys)"
            elif isinstance(value, list):
                summary[key] = f"list({len(value)} items)"
            elif isinstance(value, str) and len(value) > 200:
                summary[key] = value[:200] + "..."
            else:
                summary[key] = value
        self._write_event("state_update", summary)

    def log_finding(self, finding_id: str, finding: dict[str, Any]) -> None:
        """Log a new vulnerability finding."""
        self._write_event("finding", {
            "finding_id": finding_id,
            "vuln_type": finding.get("vuln_type", "?"),
            "severity": finding.get("severity", "?"),
            "endpoint": finding.get("endpoint", "?"),
            "confirmed": finding.get("confirmed", False),
            "evidence": _cap(str(finding.get("evidence", "")), _MAX_FIELD_SIZE),
        })

    def log_compression(
        self,
        tier: int,
        before_chars: int,
        after_chars: int,
        messages_before: int = 0,
        messages_after: int = 0,
    ) -> None:
        """Log a context compression event."""
        self._write_event("compression", {
            "tier": tier,
            "before_chars": before_chars,
            "after_chars": after_chars,
            "messages_before": messages_before,
            "messages_after": messages_after,
        })

    def log_hypothesis(self, hypothesis: dict[str, Any]) -> None:
        """Log a new hypothesis from adversarial reasoning."""
        self._write_event("hypothesis", {
            "hypothesis": _cap(str(hypothesis.get("hypothesis", "")), _MAX_FIELD_SIZE),
            "priority": hypothesis.get("priority", "medium"),
            "suggested_tool": hypothesis.get("suggested_tool", ""),
        })

    def log_chain_discovery(self, chain: dict[str, Any]) -> None:
        """Log a chain discovery event."""
        self._write_event("chain_discovery", {
            "chain_name": chain.get("chain_name", "?"),
            "combined_severity": chain.get("combined_severity", "?"),
            "description": _cap(str(chain.get("description", "")), _MAX_FIELD_SIZE),
        })

    def log_strategy_reset(self, reason: str, turn: int) -> None:
        """Log a strategy reset event."""
        self._turn = turn
        self._write_event("strategy_reset", {
            "reason": reason,
        })

    def log_error(self, error: str, context: str = "") -> None:
        """Log an error event."""
        self._write_event("error", {
            "error": _cap(error, _MAX_FIELD_SIZE),
            "context": context,
        })

    def log_memory_save(self, turn: int, memory_path: str) -> None:
        """Log a memory auto-save event."""
        self._turn = turn
        self._write_event("memory_save", {
            "memory_path": memory_path,
        })

    def log_api_response_meta(
        self,
        model: str = "",
        input_tokens: int = 0,
        output_tokens: int = 0,
        cache_read_tokens: int = 0,
        cache_creation_tokens: int = 0,
        cost: float = 0.0,
        stop_reason: str = "",
        latency_ms: float = 0.0,
    ) -> None:
        """Log API response metadata: tokens, cost, latency."""
        self._write_event("api_response_meta", {
            "model": model,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read_tokens,
            "cache_creation_tokens": cache_creation_tokens,
            "cost": round(cost, 6),
            "stop_reason": stop_reason,
            "latency_ms": round(latency_ms, 1),
        })

    def log_state_snapshot(self, state: dict) -> None:
        """Log a full state snapshot (endpoints, findings counts, budget, etc.)."""
        snap = {}
        for key, value in state.items():
            if key == "messages":
                snap["messages_count"] = len(value) if isinstance(value, list) else 0
            elif key in ("endpoints", "findings", "hypotheses", "accounts"):
                snap[f"{key}_count"] = len(value) if isinstance(value, (dict, list)) else 0
                if isinstance(value, dict):
                    snap[f"{key}_keys"] = list(value.keys())[:50]
            elif isinstance(value, (str, int, float, bool)) or value is None:
                snap[key] = value
            elif isinstance(value, list):
                snap[f"{key}_count"] = len(value)
            elif isinstance(value, dict):
                snap[f"{key}_count"] = len(value)
            else:
                snap[key] = str(value)[:200]
        self._write_event("state_snapshot", snap)

    def log_full_messages(self, messages: list) -> None:
        """Log the complete message history sent to the API."""
        serialized = []
        for m in messages:
            role = m.get("role", "?") if isinstance(m, dict) else getattr(m, "role", "?")
            content = m.get("content", "") if isinstance(m, dict) else getattr(m, "content", "")
            if isinstance(content, list):
                content_str = json.dumps(content, default=str)
            else:
                content_str = str(content)
            serialized.append({
                "role": role,
                "content": _cap(content_str, _MAX_FIELD_SIZE),
            })
        self._write_event("full_messages", {
            "count": len(serialized),
            "messages": serialized,
        })

    def log_custom(self, event_name: str, data: dict) -> None:
        """Log any custom event for analytics."""
        self._write_event(event_name, data)
