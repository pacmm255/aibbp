"""Breadcrumb context manager for maintaining rolling action history.

Provides per-target context tracking with deterministic compression.
No AI is used for context management -- only string operations.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field


@dataclass
class Breadcrumb:
    """A single action record in the breadcrumb trail."""

    timestamp: float
    phase: str
    action: str
    target: str
    result_summary: str
    tokens_used: int = 0


@dataclass
class ContextManager:
    """Manages rolling context breadcrumbs for AI prompts.

    Key features:
    - Per-target action history
    - Rolling window of recent actions (~500 tokens)
    - Deterministic compression (no AI needed)
    - XML-formatted output for clean prompt injection
    """

    max_breadcrumbs: int = 50
    max_target_breadcrumbs: int = 20
    max_summary_chars: int = 200

    _global_trail: deque[Breadcrumb] = field(init=False)
    _target_trails: dict[str, deque[Breadcrumb]] = field(init=False)
    _findings_count: dict[str, int] = field(init=False)

    def __post_init__(self) -> None:
        self._global_trail = deque(maxlen=self.max_breadcrumbs)
        self._target_trails = {}
        self._findings_count = {}

    def record(
        self,
        phase: str,
        action: str,
        target: str,
        result_summary: str,
        tokens_used: int = 0,
    ) -> None:
        """Record an action in the breadcrumb trail."""
        breadcrumb = Breadcrumb(
            timestamp=time.time(),
            phase=phase,
            action=action,
            target=target,
            result_summary=self._truncate(result_summary),
            tokens_used=tokens_used,
        )

        self._global_trail.append(breadcrumb)

        if target:
            if target not in self._target_trails:
                self._target_trails[target] = deque(
                    maxlen=self.max_target_breadcrumbs
                )
            self._target_trails[target].append(breadcrumb)

    def record_finding(self, target: str) -> None:
        """Increment the findings counter for a target."""
        self._findings_count[target] = self._findings_count.get(target, 0) + 1

    def get_context_xml(self, target: str = "") -> str:
        """Build XML-formatted context for prompt injection.

        Returns a string like:
        <context>
          <recent_actions>
            <action phase="recon" target="example.com">Ran subfinder: 42 subdomains</action>
            ...
          </recent_actions>
          <target_history target="example.com">
            ...
          </target_history>
          <stats>
            <targets_scanned>5</targets_scanned>
            <total_findings>12</total_findings>
          </stats>
        </context>
        """
        parts = ['<context>']

        # Recent actions (last 10 from global trail)
        parts.append('  <recent_actions>')
        recent = list(self._global_trail)[-10:]
        for b in recent:
            parts.append(
                f'    <action phase="{b.phase}" target="{b.target}">'
                f'{b.result_summary}</action>'
            )
        parts.append('  </recent_actions>')

        # Target-specific history if requested
        if target and target in self._target_trails:
            parts.append(f'  <target_history target="{target}">')
            for b in self._target_trails[target]:
                parts.append(
                    f'    <action phase="{b.phase}">{b.action}: '
                    f'{b.result_summary}</action>'
                )
            parts.append('  </target_history>')

        # Summary stats
        parts.append('  <stats>')
        parts.append(
            f'    <targets_scanned>{len(self._target_trails)}</targets_scanned>'
        )
        total_findings = sum(self._findings_count.values())
        parts.append(
            f'    <total_findings>{total_findings}</total_findings>'
        )
        if target:
            parts.append(
                f'    <target_findings>{self._findings_count.get(target, 0)}'
                f'</target_findings>'
            )
        parts.append('  </stats>')

        parts.append('</context>')
        return '\n'.join(parts)

    def get_global_summary(self) -> str:
        """Return a compact text summary of all activity."""
        if not self._global_trail:
            return "No actions recorded yet."

        lines = []
        phases_seen: dict[str, int] = {}
        for b in self._global_trail:
            phases_seen[b.phase] = phases_seen.get(b.phase, 0) + 1

        lines.append(
            f"Actions: {len(self._global_trail)} across "
            f"{len(phases_seen)} phases"
        )
        lines.append(
            f"Targets: {len(self._target_trails)}, "
            f"Findings: {sum(self._findings_count.values())}"
        )

        # Phase breakdown
        for phase, count in sorted(phases_seen.items()):
            lines.append(f"  {phase}: {count} actions")

        return "\n".join(lines)

    def get_target_summary(self, target: str) -> str:
        """Return a compact summary for a specific target."""
        if target not in self._target_trails:
            return f"No actions recorded for {target}."

        trail = self._target_trails[target]
        findings = self._findings_count.get(target, 0)

        lines = [
            f"Target: {target}",
            f"Actions: {len(trail)}, Findings: {findings}",
        ]

        # Last 5 actions
        for b in list(trail)[-5:]:
            lines.append(f"  [{b.phase}] {b.action}: {b.result_summary}")

        return "\n".join(lines)

    def _truncate(self, text: str) -> str:
        """Truncate text to max_summary_chars."""
        if len(text) <= self.max_summary_chars:
            return text
        return text[: self.max_summary_chars - 3] + "..."
