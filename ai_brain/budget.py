"""Token budget manager with phase allocation and adaptive reallocation."""

from __future__ import annotations

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
                "strategy": PhaseSpend(allocated=total * 2 / 100),
                "active_testing": PhaseSpend(allocated=total * 50 / 100),
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

        if "haiku" in model:
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
