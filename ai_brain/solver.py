"""Solver agents for specialized vulnerability analysis tasks.

Each solver wraps a specific prompt template and handles:
- Input preprocessing for the prompt
- Scope validation before any action
- Output parsing and finding extraction
- Error handling and retry logic

Solver types:
- Recon: SubdomainClassifier, JSAnalyzer, APISwaggerAnalyzer, WordlistGenerator
- Vuln: IDORSolver, AuthBypassSolver, BusinessLogicSolver, CORSSolver,
        GraphQLSolver, MassAssignmentSolver, SSRFSolver, JWTOAuthSolver,
        ErrorMessageSolver
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import structlog
from pydantic import BaseModel

from ai_brain.context import ContextManager
from ai_brain.models import CallResult, ClaudeClient
from ai_brain.prompts.base import PromptTemplate
from ai_brain.prompts.phase1_recon import (
    APISwaggerAnalysisPrompt,
    CustomWordlistPrompt,
    JSAnalysisPrompt,
    SubdomainClassificationPrompt,
)
from ai_brain.prompts.phase2_vuln import (
    AuthFlowAnalysisPrompt,
    BusinessLogicDetectionPrompt,
    CORSDetectionPrompt,
    ErrorMessageAnalysisPrompt,
    GraphQLDetectionPrompt,
    IDORDetectionPrompt,
    JWTOAuthDetectionPrompt,
    MassAssignmentDetectionPrompt,
    SSRFDetectionPrompt,
)
from ai_brain.scope import ScopeEnforcer, ScopeViolation

logger = structlog.get_logger()


class BaseSolver(ABC):
    """Base class for all solver agents.

    Each solver is responsible for:
    1. Validating scope before any action
    2. Preparing input data for the prompt template
    3. Making the Claude API call via ClaudeClient
    4. Processing and returning results
    """

    def __init__(
        self,
        client: ClaudeClient,
        scope: ScopeEnforcer,
        context: ContextManager,
    ) -> None:
        self.client = client
        self.scope = scope
        self.context = context

    @property
    @abstractmethod
    def solver_type(self) -> str:
        """Unique identifier for this solver type."""
        ...

    @property
    @abstractmethod
    def phase(self) -> str:
        """Budget phase this solver belongs to."""
        ...

    @property
    @abstractmethod
    def prompt(self) -> PromptTemplate:
        """The prompt template for this solver."""
        ...

    async def solve(
        self, target: str, data: dict[str, Any]
    ) -> CallResult[Any]:
        """Run the solver on the given target with input data.

        Args:
            target: The target domain/URL being analyzed
            data: Input data dict passed to the prompt template

        Returns:
            CallResult with parsed output
        """
        # 1. Validate scope
        try:
            self.scope.validate_action(
                action=self.solver_type, target=target
            )
        except ScopeViolation as e:
            logger.warning(
                "scope_violation",
                solver=self.solver_type,
                target=target,
                error=str(e),
            )
            raise

        # 2. Build prompt
        prompt = self.prompt
        context_xml = self.context.get_context_xml(target)
        system_blocks = prompt.build_system_blocks_with_context(context_xml)
        user_message = prompt.user_template(**data)

        # 3. Make API call
        logger.info(
            "solver_start",
            solver=self.solver_type,
            target=target,
            tier=prompt.model_tier,
        )

        result = await self.client.call(
            phase=self.phase,
            task_tier=prompt.model_tier,
            system_blocks=system_blocks,
            user_message=user_message,
            output_schema=prompt.output_schema,
            target=target,
            temperature=prompt.temperature,
        )

        # 4. Record in context
        summary = self._summarize_result(result)
        self.context.record(
            phase=self.phase,
            action=self.solver_type,
            target=target,
            result_summary=summary,
            tokens_used=result.total_tokens,
        )

        logger.info(
            "solver_complete",
            solver=self.solver_type,
            target=target,
            tokens=result.total_tokens,
            cost=f"${result.cost:.6f}",
        )

        return result

    def _summarize_result(self, result: CallResult[Any]) -> str:
        """Generate a brief summary of the result for breadcrumbs."""
        parsed = result.parsed
        if parsed is None:
            return f"Raw response ({result.output_tokens} tokens)"
        if hasattr(parsed, "confidence"):
            return f"Confidence: {parsed.confidence}%"
        return f"Completed ({result.output_tokens} tokens)"


# ── Recon Solvers ────────────────────────────────────────────────────


class SubdomainClassifier(BaseSolver):
    """1.1 - Classify subdomains by interest level."""

    @property
    def solver_type(self) -> str:
        return "subdomain_classification"

    @property
    def phase(self) -> str:
        return "recon"

    @property
    def prompt(self) -> PromptTemplate:
        return SubdomainClassificationPrompt()

    def _summarize_result(self, result: CallResult[Any]) -> str:
        parsed = result.parsed
        if parsed and hasattr(parsed, "classifications"):
            n = len(parsed.classifications)
            hv = len(parsed.high_value_targets)
            return f"Classified {n} subdomains, {hv} high-value"
        return super()._summarize_result(result)


class JSAnalyzer(BaseSolver):
    """1.3 - Analyze JavaScript for endpoints and secrets."""

    @property
    def solver_type(self) -> str:
        return "js_analysis"

    @property
    def phase(self) -> str:
        return "recon"

    @property
    def prompt(self) -> PromptTemplate:
        return JSAnalysisPrompt()

    def _summarize_result(self, result: CallResult[Any]) -> str:
        parsed = result.parsed
        if parsed and hasattr(parsed, "endpoints"):
            ne = len(parsed.endpoints)
            ns = len(parsed.secrets)
            return f"Found {ne} endpoints, {ns} secrets"
        return super()._summarize_result(result)


class APISwaggerAnalyzer(BaseSolver):
    """1.4 - Analyze API/Swagger specifications."""

    @property
    def solver_type(self) -> str:
        return "api_swagger_analysis"

    @property
    def phase(self) -> str:
        return "recon"

    @property
    def prompt(self) -> PromptTemplate:
        return APISwaggerAnalysisPrompt()


class WordlistGenerator(BaseSolver):
    """1.6 - Generate custom wordlists."""

    @property
    def solver_type(self) -> str:
        return "wordlist_generation"

    @property
    def phase(self) -> str:
        return "recon"

    @property
    def prompt(self) -> PromptTemplate:
        return CustomWordlistPrompt()

    def _summarize_result(self, result: CallResult[Any]) -> str:
        parsed = result.parsed
        if parsed and hasattr(parsed, "words"):
            return f"Generated {len(parsed.words)} words"
        return super()._summarize_result(result)


# ── Vulnerability Detection Solvers ──────────────────────────────────


class IDORSolver(BaseSolver):
    """2.1 - Detect IDOR/BOLA vulnerabilities."""

    @property
    def solver_type(self) -> str:
        return "idor_detection"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return IDORDetectionPrompt()

    def _summarize_result(self, result: CallResult[Any]) -> str:
        parsed = result.parsed
        if parsed and hasattr(parsed, "candidates"):
            nc = len(parsed.candidates)
            nf = len(parsed.findings)
            return f"Found {nc} IDOR candidates, {nf} confirmed"
        return super()._summarize_result(result)


class AuthBypassSolver(BaseSolver):
    """2.2 - Detect authentication bypass vulnerabilities."""

    @property
    def solver_type(self) -> str:
        return "auth_bypass"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return AuthFlowAnalysisPrompt()


class BusinessLogicSolver(BaseSolver):
    """2.3 - Detect business logic vulnerabilities."""

    @property
    def solver_type(self) -> str:
        return "business_logic"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return BusinessLogicDetectionPrompt()


class CORSSolver(BaseSolver):
    """2.4 - Detect CORS misconfiguration vulnerabilities."""

    @property
    def solver_type(self) -> str:
        return "cors_detection"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return CORSDetectionPrompt()


class GraphQLSolver(BaseSolver):
    """2.5 - Detect GraphQL security issues."""

    @property
    def solver_type(self) -> str:
        return "graphql_detection"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return GraphQLDetectionPrompt()


class MassAssignmentSolver(BaseSolver):
    """2.6 - Detect mass assignment vulnerabilities."""

    @property
    def solver_type(self) -> str:
        return "mass_assignment"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return MassAssignmentDetectionPrompt()


class SSRFSolver(BaseSolver):
    """2.7 - Detect SSRF vulnerabilities."""

    @property
    def solver_type(self) -> str:
        return "ssrf_detection"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return SSRFDetectionPrompt()


class JWTOAuthSolver(BaseSolver):
    """2.8 - Detect JWT/OAuth vulnerabilities."""

    @property
    def solver_type(self) -> str:
        return "jwt_oauth_detection"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return JWTOAuthDetectionPrompt()


class ErrorMessageSolver(BaseSolver):
    """2.9 - Detect information disclosure via error messages."""

    @property
    def solver_type(self) -> str:
        return "error_message_analysis"

    @property
    def phase(self) -> str:
        return "vuln_detection"

    @property
    def prompt(self) -> PromptTemplate:
        return ErrorMessageAnalysisPrompt()


# ── Solver Registry ──────────────────────────────────────────────────

SOLVER_REGISTRY: dict[str, type[BaseSolver]] = {
    # Recon
    "subdomain_classification": SubdomainClassifier,
    "js_analysis": JSAnalyzer,
    "api_swagger_analysis": APISwaggerAnalyzer,
    "wordlist_generation": WordlistGenerator,
    # Vuln Detection
    "idor_detection": IDORSolver,
    "auth_bypass": AuthBypassSolver,
    "business_logic": BusinessLogicSolver,
    "cors_detection": CORSSolver,
    "graphql_detection": GraphQLSolver,
    "mass_assignment": MassAssignmentSolver,
    "ssrf_detection": SSRFSolver,
    "jwt_oauth_detection": JWTOAuthSolver,
    "error_message_analysis": ErrorMessageSolver,
}


def create_solver(
    solver_type: str,
    client: ClaudeClient,
    scope: ScopeEnforcer,
    context: ContextManager,
) -> BaseSolver:
    """Factory function to create a solver by type.

    Args:
        solver_type: Key from SOLVER_REGISTRY
        client: ClaudeClient instance
        scope: ScopeEnforcer instance
        context: ContextManager instance

    Returns:
        Initialized solver instance

    Raises:
        ValueError: If solver_type is not registered
    """
    cls = SOLVER_REGISTRY.get(solver_type)
    if cls is None:
        raise ValueError(
            f"Unknown solver type: {solver_type}. "
            f"Available: {list(SOLVER_REGISTRY.keys())}"
        )
    return cls(client=client, scope=scope, context=context)
