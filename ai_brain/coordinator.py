"""Coordinator agent - the strategic brain of the scanning operation.

The coordinator handles high-level decisions:
- Phase 0: Analyze program scope and prioritize targets
- Phase 1.5: Correlate recon results
- Phase 4: Plan attack chains (uses Opus)
- Phase 5: Generate reports (uses Opus)
- Phase 6: Strategy decisions (continue/pivot/move on)
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from ai_brain.budget import BudgetManager
from ai_brain.context import ContextManager
from ai_brain.models import CallResult, ClaudeClient
from ai_brain.prompts.phase0_program import (
    ProgramScopeAnalysisPrompt,
    TargetPrioritizationPrompt,
)
from ai_brain.prompts.phase1_recon import ReconCorrelationPrompt
from ai_brain.prompts.phase3_validate import (
    DifferentialAnalysisPrompt,
    ExploitabilityAssessmentPrompt,
    FalsePositiveFilterPrompt,
)
from ai_brain.prompts.phase4_chain import AttackChainDiscoveryPrompt
from ai_brain.prompts.phase5_report import (
    CVSSScoringPrompt,
    ReportGenerationPrompt,
)
from ai_brain.prompts.phase6_strategy import ContinueVsMoveOnPrompt
from ai_brain.schemas import (
    AttackChainResult,
    CVSSScore,
    DifferentialAnalysis,
    ExploitabilityAssessment,
    FalsePositiveFilterResult,
    ReconCorrelation,
    ScopeAnalysis,
    StrategyDecision,
    TargetPrioritizationResult,
    VulnReport,
)
from ai_brain.scope import ScopeEnforcer

logger = structlog.get_logger()


class CoordinatorAgent:
    """Strategic coordinator for the scanning operation.

    Uses higher-tier models (Sonnet/Opus) for strategic decisions
    that require deeper reasoning than individual solvers.
    """

    def __init__(
        self,
        client: ClaudeClient,
        scope: ScopeEnforcer,
        context: ContextManager,
        budget: BudgetManager,
    ) -> None:
        self.client = client
        self.scope = scope
        self.context = context
        self.budget = budget

    # ── Phase 0: Program Analysis ────────────────────────────────────

    async def analyze_program(
        self, program_text: str
    ) -> CallResult[ScopeAnalysis]:
        """0.1 - Analyze bug bounty program scope and rules."""
        prompt = ProgramScopeAnalysisPrompt()
        result = await self.client.call(
            phase="program_analysis",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(program_text=program_text),
            output_schema=ScopeAnalysis,
        )

        self.context.record(
            phase="program_analysis",
            action="analyze_program",
            target="",
            result_summary=self._scope_summary(result.parsed),
        )

        return result

    async def prioritize_targets(
        self,
        scope_analysis: str,
        initial_data: str = "",
    ) -> CallResult[TargetPrioritizationResult]:
        """0.2 - Prioritize targets for scanning."""
        prompt = TargetPrioritizationPrompt()
        result = await self.client.call(
            phase="program_analysis",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(
                scope_analysis=scope_analysis,
                initial_data=initial_data,
            ),
            output_schema=TargetPrioritizationResult,
        )

        self.context.record(
            phase="program_analysis",
            action="prioritize_targets",
            target="",
            result_summary=self._priority_summary(result.parsed),
        )

        return result

    # ── Phase 1.5: Recon Correlation ─────────────────────────────────

    async def correlate_recon(
        self,
        subdomain_data: str = "",
        port_data: str = "",
        httpx_data: str = "",
        js_analysis: str = "",
        api_specs: str = "",
    ) -> CallResult[ReconCorrelation]:
        """1.5 - Correlate all recon data into actionable intelligence."""
        prompt = ReconCorrelationPrompt()
        result = await self.client.call(
            phase="recon",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks_with_context(
                self.context.get_context_xml()
            ),
            user_message=prompt.user_template(
                subdomain_data=subdomain_data,
                port_data=port_data,
                httpx_data=httpx_data,
                js_analysis=js_analysis,
                api_specs=api_specs,
            ),
            output_schema=ReconCorrelation,
        )

        self.context.record(
            phase="recon",
            action="correlate_recon",
            target="",
            result_summary=self._recon_summary(result.parsed),
        )

        return result

    # ── Phase 3: Validation ──────────────────────────────────────────

    async def filter_false_positives(
        self, findings: str
    ) -> CallResult[FalsePositiveFilterResult]:
        """3.1 - Filter false positives from findings."""
        prompt = FalsePositiveFilterPrompt()
        return await self.client.call(
            phase="validation",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(findings=findings),
            output_schema=FalsePositiveFilterResult,
        )

    async def differential_analysis(
        self,
        baseline: str,
        attack: str,
        vuln_type: str = "unknown",
    ) -> CallResult[DifferentialAnalysis]:
        """3.2 - Compare baseline vs attack responses."""
        prompt = DifferentialAnalysisPrompt()
        return await self.client.call(
            phase="validation",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(
                baseline=baseline,
                attack=attack,
                vuln_type=vuln_type,
            ),
            output_schema=DifferentialAnalysis,
        )

    async def assess_exploitability(
        self,
        finding: str,
        validation_data: str = "",
    ) -> CallResult[ExploitabilityAssessment]:
        """3.3 - Assess exploitability of a validated finding."""
        prompt = ExploitabilityAssessmentPrompt()
        return await self.client.call(
            phase="validation",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(
                finding=finding,
                validation_data=validation_data,
            ),
            output_schema=ExploitabilityAssessment,
        )

    # ── Phase 4: Attack Chaining ─────────────────────────────────────

    async def discover_chains(
        self,
        validated_findings: str,
        target_context: str = "",
    ) -> CallResult[AttackChainResult]:
        """4.1 - Discover attack chains from validated findings.

        Uses Opus for deep reasoning about vulnerability interactions.
        """
        prompt = AttackChainDiscoveryPrompt()
        result = await self.client.call(
            phase="chain_discovery",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks_with_context(
                self.context.get_context_xml()
            ),
            user_message=prompt.user_template(
                validated_findings=validated_findings,
                target_context=target_context,
            ),
            output_schema=AttackChainResult,
        )

        self.context.record(
            phase="chain_discovery",
            action="discover_chains",
            target="",
            result_summary=self._chain_summary(result.parsed),
        )

        return result

    # ── Phase 5: Reporting ───────────────────────────────────────────

    async def generate_report(
        self,
        finding: str,
        evidence: str = "",
        cvss: str = "",
    ) -> CallResult[VulnReport]:
        """5.1 - Generate HackerOne-ready vulnerability report.

        Uses Opus for high-quality, precise reports.
        """
        prompt = ReportGenerationPrompt()
        return await self.client.call(
            phase="reporting",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(
                finding=finding,
                evidence=evidence,
                cvss=cvss,
            ),
            output_schema=VulnReport,
        )

    async def score_cvss(self, finding: str) -> CallResult[CVSSScore]:
        """5.2 - Calculate CVSS v3.1 score for a finding."""
        prompt = CVSSScoringPrompt()
        return await self.client.call(
            phase="reporting",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(finding=finding),
            output_schema=CVSSScore,
        )

    # ── Phase 6: Strategy ────────────────────────────────────────────

    async def evaluate_strategy(
        self,
        current_target: str,
        findings_summary: str = "",
        budget_status: str = "",
        time_spent: str = "",
        remaining_targets: str = "",
    ) -> CallResult[StrategyDecision]:
        """6.1 - Decide whether to continue, pivot, or move on."""
        prompt = ContinueVsMoveOnPrompt()

        # Include budget summary if not provided
        if not budget_status:
            budget_status = json.dumps(self.budget.summary(), indent=2)

        result = await self.client.call(
            phase="strategy",
            task_tier=prompt.model_tier,
            system_blocks=prompt.build_system_blocks(),
            user_message=prompt.user_template(
                current_target=current_target,
                findings_summary=findings_summary,
                budget_status=budget_status,
                time_spent=time_spent,
                remaining_targets=remaining_targets,
                context=self.context.get_context_xml(current_target),
            ),
            output_schema=StrategyDecision,
            target=current_target,
        )

        self.context.record(
            phase="strategy",
            action="evaluate_strategy",
            target=current_target,
            result_summary=self._strategy_summary(result.parsed),
        )

        return result

    # ── Summary Helpers ──────────────────────────────────────────────

    @staticmethod
    def _scope_summary(parsed: ScopeAnalysis | None) -> str:
        if not parsed:
            return "No scope analysis"
        n = len(parsed.in_scope_assets)
        return f"{parsed.program_name}: {n} in-scope assets"

    @staticmethod
    def _priority_summary(parsed: TargetPrioritizationResult | None) -> str:
        if not parsed:
            return "No prioritization"
        n = len(parsed.targets)
        return f"Prioritized {n} targets"

    @staticmethod
    def _recon_summary(parsed: ReconCorrelation | None) -> str:
        if not parsed:
            return "No correlation"
        hv = len(parsed.high_value_targets)
        vc = len(parsed.potential_vuln_classes)
        return f"{hv} high-value targets, {vc} vuln classes identified"

    @staticmethod
    def _chain_summary(parsed: AttackChainResult | None) -> str:
        if not parsed:
            return "No chains"
        return f"Found {len(parsed.chains)} attack chains"

    @staticmethod
    def _strategy_summary(parsed: StrategyDecision | None) -> str:
        if not parsed:
            return "No decision"
        return f"Decision: {parsed.decision} - {parsed.next_action}"
