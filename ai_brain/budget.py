"""Token budget manager with phase allocation and adaptive reallocation."""

from __future__ import annotations

import time
import structlog
from dataclasses import dataclass, field

from ai_brain.config import BudgetConfig
from ai_brain.errors import BudgetExhausted

logger = structlog.get_logger()

# Phase names matching config
PHASES = [
    "program_analysis",
    "recon",
    "vuln_detection",
    "validation",
    "chain_discovery",
    "reporting",
    "strategy",
    "active_testing",
]


@dataclass
class PhaseSpend:
    """Tracks spending within a single phase."""

    allocated: float = 0.0
    spent: float = 0.0

    @property
    def remaining(self) -> float:
        return max(0, self.allocated - self.spent)

    @property
    def utilization_pct(self) -> float:
        if self.allocated == 0:
            return 0
        return (self.spent / self.allocated) * 100


@dataclass
class BudgetManager:
    """Manages token budget across phases with adaptive reallocation.

    Key features:
    - Phase-level allocation from total budget
    - Per-target spending caps
    - Emergency reserve (force reporting when budget < 15%)
    - Adaptive reallocation from underused phases
    - Active testing phase allocation when enabled
    """

    config: BudgetConfig
    active_testing: bool = False
    phases: dict[str, PhaseSpend] = field(init=False)
    total_spent: float = field(init=False, default=0.0)
    per_target_spent: dict[str, float] = field(default_factory=dict)
    cost_log: list[dict] = field(default_factory=list)

    def __post_init__(self) -> None:
        total = self.config.total_dollars

        if self.active_testing:
            # Rebalanced allocations when active testing is enabled
            # Active testing gets 45% because Opus business logic calls are ~$0.09 each
            self.phases = {
                "program_analysis": PhaseSpend(allocated=total * 3 / 100),
                "recon": PhaseSpend(allocated=total * 15 / 100),
                "vuln_detection": PhaseSpend(allocated=total * 15 / 100),
                "validation": PhaseSpend(allocated=total * 7 / 100),
                "chain_discovery": PhaseSpend(allocated=total * 3 / 100),
                "reporting": PhaseSpend(allocated=total * 5 / 100),
                "strategy": PhaseSpend(allocated=total * 10 / 100),
                "active_testing": PhaseSpend(allocated=total * 87 / 100),
            }
        else:
            self.phases = {
                "program_analysis": PhaseSpend(
                    allocated=total * self.config.phase_program_analysis / 100
                ),
                "recon": PhaseSpend(allocated=total * self.config.phase_recon / 100),
                "vuln_detection": PhaseSpend(
                    allocated=total * self.config.phase_vuln_detection / 100
                ),
                "validation": PhaseSpend(
                    allocated=total * self.config.phase_validation / 100
                ),
                "chain_discovery": PhaseSpend(
                    allocated=total * self.config.phase_chain_discovery / 100
                ),
                "reporting": PhaseSpend(
                    allocated=total * self.config.phase_reporting / 100
                ),
                "strategy": PhaseSpend(
                    allocated=total * self.config.phase_strategy / 100
                ),
                "active_testing": PhaseSpend(allocated=0),
            }

    @property
    def total_remaining(self) -> float:
        return max(0, self.config.total_dollars - self.total_spent)

    @property
    def emergency_threshold(self) -> float:
        return self.config.total_dollars * self.config.emergency_reserve_pct / 100

    @property
    def is_emergency(self) -> bool:
        """True when budget drops below emergency reserve threshold."""
        return self.total_remaining <= self.emergency_threshold

    def check_budget(self, phase: str, estimated_cost: float = 0) -> None:
        """Check if budget allows this call. Raises BudgetExhausted if not."""
        if phase not in self.phases:
            raise ValueError(f"Unknown phase: {phase}")

        phase_spend = self.phases[phase]

        # Check phase budget (with reallocation)
        if estimated_cost > 0 and phase_spend.remaining < estimated_cost:
            # Try to reallocate from underused phases
            self._try_reallocate(phase, estimated_cost - phase_spend.remaining)

        if estimated_cost > 0 and phase_spend.remaining < estimated_cost:
            raise BudgetExhausted(phase, phase_spend.spent, phase_spend.allocated)

        # Check total budget
        if self.total_remaining < estimated_cost:
            raise BudgetExhausted(
                "total", self.total_spent, self.config.total_dollars
            )

    def record_cost(
        self,
        phase: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int = 0,
        cache_creation_tokens: int = 0,
        target: str = "",
        tool: str = "",
    ) -> float:
        """Record actual cost from an API call. Returns the cost in dollars."""
        cost = self._calculate_cost(
            model, input_tokens, output_tokens, cache_read_tokens, cache_creation_tokens
        )

        self.total_spent += cost

        if phase in self.phases:
            self.phases[phase].spent += cost

        if target:
            self.per_target_spent[target] = (
                self.per_target_spent.get(target, 0) + cost
            )

        # Append to cost log for detailed attribution
        self.cost_log.append({
            "timestamp": time.time(),
            "model": model,
            "phase": phase,
            "tool": tool,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "cache_read_tokens": cache_read_tokens,
            "cost": cost,
        })
        # Cap cost_log at 2000 entries
        if len(self.cost_log) > 2000:
            self.cost_log = self.cost_log[-1500:]

        logger.debug(
            "cost_recorded",
            phase=phase,
            model=model,
            cost=f"${cost:.6f}",
            total_spent=f"${self.total_spent:.4f}",
            remaining=f"${self.total_remaining:.4f}",
        )

        return cost

    def check_target_budget(self, target: str) -> bool:
        """Check if a target has exceeded its per-target budget."""
        spent = self.per_target_spent.get(target, 0)
        return spent < self.config.per_target_max_dollars

    def _calculate_cost(
        self,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int,
        cache_creation_tokens: int,
    ) -> float:
        """Calculate cost in dollars for a given API call."""
        cfg = self.config

        if model.startswith("zai-"):
            # Z.ai models are free
            return 0.0
        elif "haiku" in model:
            input_price = cfg.haiku_input
            output_price = cfg.haiku_output
        elif "opus" in model:
            input_price = cfg.opus_input
            output_price = cfg.opus_output
        else:
            # Default to Sonnet pricing
            input_price = cfg.sonnet_input
            output_price = cfg.sonnet_output

        cache_read_price = input_price * cfg.cache_read_multiplier

        cost = (
            (input_tokens / 1_000_000) * input_price
            + (output_tokens / 1_000_000) * output_price
            + (cache_read_tokens / 1_000_000) * cache_read_price
            + (cache_creation_tokens / 1_000_000) * input_price  # Same as input
        )

        return cost

    def _try_reallocate(self, target_phase: str, needed: float) -> None:
        """Try to reallocate budget from underused phases."""
        for phase_name, phase_spend in self.phases.items():
            if phase_name == target_phase:
                continue

            # Only take from phases that have used < 50% of their budget
            if phase_spend.utilization_pct < 50 and phase_spend.remaining > 0:
                available = phase_spend.remaining * 0.3  # Take max 30%
                transfer = min(available, needed)

                phase_spend.allocated -= transfer
                self.phases[target_phase].allocated += transfer
                needed -= transfer

                logger.info(
                    "budget_reallocated",
                    from_phase=phase_name,
                    to_phase=target_phase,
                    amount=f"${transfer:.4f}",
                )

                if needed <= 0:
                    break

    def cost_breakdown(self) -> dict:
        """Return detailed cost attribution breakdown."""
        per_phase: dict[str, float] = {}
        per_model: dict[str, float] = {}
        per_tool: dict[str, float] = {}
        for entry in self.cost_log:
            c = entry["cost"]
            phase = entry.get("phase", "unknown")
            model = entry.get("model", "unknown")
            tool = entry.get("tool", "") or "brain"
            per_phase[phase] = per_phase.get(phase, 0) + c
            per_model[model] = per_model.get(model, 0) + c
            per_tool[tool] = per_tool.get(tool, 0) + c

        call_count = len(self.cost_log)
        avg_cost = self.total_spent / max(call_count, 1)

        # Top 10 most expensive calls
        sorted_log = sorted(self.cost_log, key=lambda x: x["cost"], reverse=True)
        top_expensive = [
            {"cost": round(e["cost"], 6), "model": e["model"],
             "phase": e["phase"], "tool": e.get("tool", "")}
            for e in sorted_log[:10]
        ]

        return {
            "total": round(self.total_spent, 4),
            "per_phase": {k: round(v, 4) for k, v in sorted(per_phase.items(), key=lambda x: -x[1])},
            "per_model": {k: round(v, 4) for k, v in sorted(per_model.items(), key=lambda x: -x[1])},
            "per_tool": {k: round(v, 4) for k, v in sorted(per_tool.items(), key=lambda x: -x[1])},
            "call_count": call_count,
            "avg_cost_per_call": round(avg_cost, 6),
            "top_expensive_calls": top_expensive,
        }

    def rebalance_phases(
        self,
        info_gain_history: list[dict] | None = None,
        phase_budgets: dict[str, dict] | None = None,
    ) -> dict[str, dict]:
        """Adaptive budget rebalance based on information gain patterns.

        Returns dict of updated phase_budget entries (only changed ones).
        """
        if not phase_budgets:
            return {}
        updates: dict[str, dict] = {}
        history = info_gain_history or []

        # Rule 1: Last 5 exploitation turns = 0 gain → transfer 30% to recon
        if len(history) >= 5:
            last_5 = history[-5:]
            exploit_gains = [h.get("total_gain", 0) for h in last_5]
            if all(g == 0 for g in exploit_gains):
                exploit_budget = phase_budgets.get("exploitation", {})
                recon_budget = phase_budgets.get("recon", {})
                remaining_exploit = exploit_budget.get("allocated_pct", 60) - exploit_budget.get("spent", 0)
                if remaining_exploit > 10:
                    transfer = remaining_exploit * 0.3
                    updates["exploitation"] = {
                        **exploit_budget,
                        "allocated_pct": exploit_budget.get("allocated_pct", 60) - transfer,
                    }
                    updates["recon"] = {
                        **recon_budget,
                        "allocated_pct": recon_budget.get("allocated_pct", 20) + transfer,
                    }
                    logger.info("budget_rebalance_rule1", transfer_pct=round(transfer, 1))

        # Rule 2: Recon productive at turn 20+ → extend recon by 5%
        if len(history) >= 20:
            last_10 = history[-10:]
            new_endpoints = sum(h.get("new_endpoints", 0) for h in last_10)
            if new_endpoints >= 3:
                recon_budget = updates.get("recon", phase_budgets.get("recon", {}))
                current_pct = recon_budget.get("allocated_pct", 20)
                if current_pct < 40:
                    updates["recon"] = {**recon_budget, "allocated_pct": current_pct + 5}
                    logger.info("budget_rebalance_rule2", new_recon_pct=current_pct + 5)

        # Rule 3: Finding cluster (3+ finding turns in last 10) → burst +10% exploit
        if len(history) >= 10:
            last_10 = history[-10:]
            finding_turns = sum(1 for h in last_10 if h.get("new_findings", 0) > 0)
            if finding_turns >= 3:
                exploit_budget = updates.get("exploitation", phase_budgets.get("exploitation", {}))
                current_pct = exploit_budget.get("allocated_pct", 60)
                if current_pct < 80:
                    updates["exploitation"] = {
                        **exploit_budget,
                        "allocated_pct": min(80, current_pct + 10),
                    }
                    logger.info("budget_rebalance_rule3", new_exploit_pct=min(80, current_pct + 10))

        return updates

    def summary(self) -> dict:
        """Return a summary of budget status."""
        return {
            "total_budget": self.config.total_dollars,
            "total_spent": round(self.total_spent, 4),
            "total_remaining": round(self.total_remaining, 4),
            "is_emergency": self.is_emergency,
            "phases": {
                name: {
                    "allocated": round(ps.allocated, 4),
                    "spent": round(ps.spent, 4),
                    "remaining": round(ps.remaining, 4),
                    "utilization_pct": round(ps.utilization_pct, 1),
                }
                for name, ps in self.phases.items()
            },
        }
