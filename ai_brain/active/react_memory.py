"""Persistent target memory that survives across sessions.

Stores knowledge about a target (endpoints, findings, techniques tried, etc.)
in ~/.aibbp/targets/<domain_hash>/memory.json so that the ReAct agent can
resume testing without repeating work.
"""

from __future__ import annotations

import hashlib
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()

# Fields from PentestState that get persisted to memory.json
_PERSISTENT_FIELDS = (
    "endpoints",
    "findings",
    "hypotheses",
    "accounts",
    "tech_stack",
    "tested_techniques",
    "failed_approaches",
    "traffic_intelligence",
    "working_memory",
)

# Account fields that are safe to persist (no cookies/sessions)
_SAFE_ACCOUNT_FIELDS = ("password", "role", "context_name", "created_at")


class TargetMemory:
    """Persistent target knowledge that survives across sessions."""

    def __init__(self, target_url: str, base_dir: str = "~/.aibbp/targets"):
        self.target_url = target_url
        self.domain = urlparse(target_url).netloc or target_url
        self.memory_dir = Path(base_dir).expanduser() / self._domain_hash()
        self.memory_path = self.memory_dir / "memory.json"

    def _domain_hash(self) -> str:
        """Short hash of domain for directory naming (human-readable prefix)."""
        # e.g. "example.com_a1b2c3d4"
        h = hashlib.sha256(self.domain.encode()).hexdigest()[:8]
        safe_domain = self.domain.replace(":", "_").replace("/", "_")
        return f"{safe_domain}_{h}"

    def load(self) -> dict[str, Any] | None:
        """Load existing memory for this target, or return None."""
        if not self.memory_path.exists():
            return None
        try:
            data = json.loads(self.memory_path.read_text())
            logger.info(
                "memory_loaded",
                domain=self.domain,
                sessions=data.get("total_sessions", 0),
                techniques=len(data.get("tested_techniques", {})),
                findings=len(data.get("findings", {})),
            )
            return data
        except Exception as e:
            logger.warning("memory_load_failed", error=str(e), path=str(self.memory_path))
            return None

    def save(self, state: dict[str, Any]) -> None:
        """Extract persistent fields from state and save to disk."""
        self.memory_dir.mkdir(parents=True, exist_ok=True)

        # Load existing memory to merge session metadata
        existing = self.load() or {}

        now = datetime.now(timezone.utc).isoformat()

        memory: dict[str, Any] = {
            "target_url": self.target_url,
            "domain": self.domain,
            "last_session": now,
            "total_sessions": existing.get("total_sessions", 0) + 1,
            "total_budget_spent": (
                existing.get("total_budget_spent", 0.0)
                + state.get("budget_spent", 0.0)
            ),
            "total_turns": (
                existing.get("total_turns", 0)
                + state.get("turn_count", 0)
            ),
        }

        # Persist knowledge fields
        for field in _PERSISTENT_FIELDS:
            value = state.get(field)
            if value is not None:
                if field == "accounts":
                    # Strip cookies/session data from accounts
                    memory[field] = {
                        username: {
                            k: v for k, v in info.items()
                            if k in _SAFE_ACCOUNT_FIELDS
                        }
                        for username, info in value.items()
                    }
                else:
                    memory[field] = value
            elif field in existing:
                # Preserve from previous session if current state is empty
                memory[field] = existing[field]

        # Merge tested_techniques and failed_approaches (union, never lose data)
        for union_field in ("tested_techniques", "failed_approaches"):
            old = existing.get(union_field, {})
            new = memory.get(union_field, {})
            if isinstance(old, dict) and isinstance(new, dict):
                merged = dict(old)
                merged.update(new)
                memory[union_field] = merged

        # Merge tech_stack (union)
        old_tech = set(existing.get("tech_stack", []))
        new_tech = set(memory.get("tech_stack", []))
        memory["tech_stack"] = sorted(old_tech | new_tech)

        # Append session summary
        session_summaries = list(existing.get("session_summaries", []))
        findings = state.get("findings", {})
        confirmed = sum(1 for f in findings.values() if f.get("confirmed"))
        session_summaries.append({
            "date": now,
            "turns": state.get("turn_count", 0),
            "cost": round(state.get("budget_spent", 0.0), 4),
            "findings_total": len(findings),
            "findings_confirmed": confirmed,
            "done_reason": state.get("done_reason", ""),
            "endpoints_discovered": len(state.get("endpoints", {})),
        })
        # Keep last 20 session summaries
        memory["session_summaries"] = session_summaries[-20:]

        # Write atomically (write to .tmp then rename)
        tmp_path = self.memory_path.with_suffix(".tmp")
        try:
            tmp_path.write_text(json.dumps(memory, indent=2, default=str))
            tmp_path.rename(self.memory_path)
            logger.info(
                "memory_saved",
                domain=self.domain,
                path=str(self.memory_path),
                techniques=len(memory.get("tested_techniques", {})),
                sessions=memory["total_sessions"],
            )
        except Exception as e:
            logger.error("memory_save_failed", error=str(e))
            # Clean up temp file
            tmp_path.unlink(missing_ok=True)

    def merge_into_state(self, state: dict[str, Any], memory: dict[str, Any]) -> dict[str, Any]:
        """Merge loaded memory into initial state (additive, not overwrite)."""
        state = dict(state)  # Don't mutate the original

        # Endpoints: merge (prior endpoints as baseline)
        if memory.get("endpoints"):
            existing = state.get("endpoints", {})
            merged = dict(memory["endpoints"])
            merged.update(existing)  # Current state takes priority
            state["endpoints"] = merged
            state["endpoints_snapshot"] = json.dumps(
                merged, default=str, indent=2
            )[:5000]

        # Findings: merge (prior confirmed findings as baseline)
        if memory.get("findings"):
            existing = state.get("findings", {})
            merged = dict(memory["findings"])
            merged.update(existing)
            state["findings"] = merged
            state["findings_snapshot"] = json.dumps(
                merged, default=str, indent=2
            )[:5000]

        # Hypotheses: only load pending ones (skip confirmed/rejected)
        if memory.get("hypotheses"):
            existing = state.get("hypotheses", {})
            for hid, h in memory["hypotheses"].items():
                if h.get("status") == "pending" and hid not in existing:
                    existing[hid] = h
            state["hypotheses"] = existing

        # Accounts: load all (may need re-authentication)
        if memory.get("accounts"):
            existing = state.get("accounts", {})
            merged = dict(memory["accounts"])
            merged.update(existing)
            state["accounts"] = merged

        # Tech stack: union merge
        if memory.get("tech_stack"):
            existing = set(state.get("tech_stack", []))
            existing.update(memory["tech_stack"])
            state["tech_stack"] = sorted(existing)

        # Tested techniques: union merge
        if memory.get("tested_techniques"):
            existing = dict(state.get("tested_techniques", {}))
            existing.update(memory["tested_techniques"])
            state["tested_techniques"] = existing

        # Failed approaches: union merge
        if memory.get("failed_approaches"):
            existing = dict(state.get("failed_approaches", {}))
            existing.update(memory["failed_approaches"])
            state["failed_approaches"] = existing

        # Traffic intelligence: load as baseline
        if memory.get("traffic_intelligence") and not state.get("traffic_intelligence"):
            state["traffic_intelligence"] = memory["traffic_intelligence"]

        # Working memory: section-level merge (don't overwrite current session data)
        if memory.get("working_memory"):
            saved_wm = memory["working_memory"]
            for section, entries in saved_wm.items():
                state_wm = state.setdefault("working_memory", {}).setdefault(section, {})
                if isinstance(entries, dict):
                    # Only add entries not already present in current state
                    for k, v in entries.items():
                        if k not in state_wm:
                            state_wm[k] = v

        return state

    def is_stale(self, memory: dict[str, Any], max_age_hours: int = 72) -> bool:
        """Check if memory is too old (target may have changed)."""
        last_session = memory.get("last_session")
        if not last_session:
            return True
        try:
            last_dt = datetime.fromisoformat(last_session)
            age_hours = (datetime.now(timezone.utc) - last_dt).total_seconds() / 3600
            return age_hours > max_age_hours
        except (ValueError, TypeError):
            return True

    def is_very_stale(self, memory: dict[str, Any], max_age_hours: int = 720) -> bool:
        """Check if memory is extremely old (30+ days). Clear volatile data."""
        return self.is_stale(memory, max_age_hours=max_age_hours)

    def get_memory_context(self, memory: dict[str, Any]) -> str:
        """Build a context string for the system prompt from memory data."""
        lines = []

        total_sessions = memory.get("total_sessions", 0)
        total_budget = memory.get("total_budget_spent", 0.0)
        total_turns = memory.get("total_turns", 0)
        findings = memory.get("findings", {})
        confirmed = sum(1 for f in findings.values() if f.get("confirmed"))
        tested = memory.get("tested_techniques", {})
        failed = memory.get("failed_approaches", {})

        lines.append(f"This is session #{total_sessions + 1} for this target.")
        lines.append(
            f"Previous sessions: {total_sessions} sessions, "
            f"${total_budget:.2f} total spent, {total_turns} total turns."
        )
        lines.append(
            f"Prior findings: {len(findings)} "
            f"({confirmed} confirmed)"
        )
        lines.append(
            f"Techniques already tried: {len(tested)} (DO NOT repeat these)"
        )
        lines.append(
            f"Failed approaches: {len(failed)} (try DIFFERENT strategies)"
        )

        # Previously failed approaches summary
        if failed:
            lines.append("\n### Previously Failed Approaches")
            for key, err in list(failed.items())[-10:]:
                lines.append(f"  - {key}: {err[:100]}")

        # Session history (last 3)
        summaries = memory.get("session_summaries", [])
        if summaries:
            lines.append("\n### Recent Session History")
            for s in summaries[-3:]:
                date = s.get("date", "?")[:19]
                turns = s.get("turns", 0)
                cost = s.get("cost", 0.0)
                f_total = s.get("findings_total", 0)
                f_conf = s.get("findings_confirmed", 0)
                reason = s.get("done_reason", "?")
                lines.append(
                    f"  - {date}: {turns} turns, ${cost:.2f}, "
                    f"{f_total} findings ({f_conf} confirmed), "
                    f"ended: {reason}"
                )

        # Staleness warning
        if self.is_very_stale(memory):
            lines.append(
                "\nWARNING: Last session was >30 days ago. Endpoints and tech stack "
                "may be outdated. Re-verify everything before deep testing."
            )
        elif self.is_stale(memory):
            last = memory.get("last_session", "?")[:19]
            lines.append(
                f"\nNOTE: Previous session data is from {last}. "
                "Target may have changed. Re-verify key endpoints before deep testing."
            )

        return "\n".join(lines)
