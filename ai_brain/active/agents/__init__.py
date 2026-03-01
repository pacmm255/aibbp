"""Active testing agent registry and factory.

Each agent handles a specific phase of active security testing:
- recon: Maps application attack surface
- auth: Creates test accounts and analyzes authentication
- injection: Tests for SQL injection, XSS, command injection
- business_logic: Tests for business logic flaws (Opus)
- validator: Verifies findings and generates PoCs
- reporter: Generates HackerOne-format reports
"""

from __future__ import annotations

from typing import Any

from ai_brain.active.agents.auth import AuthAgent
from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active.agents.business_logic import BusinessLogicAgent
from ai_brain.active.agents.hexstrike import HexstrikeAgent
from ai_brain.active.agents.injection import InjectionAgent
from ai_brain.active.agents.recon import ActiveReconAgent
from ai_brain.active.agents.reporter import ActiveReporterAgent
from ai_brain.active.agents.validator import ActiveValidatorAgent

ACTIVE_AGENT_REGISTRY: dict[str, type[BaseActiveAgent]] = {
    "recon": ActiveReconAgent,
    "auth": AuthAgent,
    "injection": InjectionAgent,
    "business_logic": BusinessLogicAgent,
    "hexstrike": HexstrikeAgent,
    "validator": ActiveValidatorAgent,
    "reporter": ActiveReporterAgent,
}


def create_active_agent(agent_type: str, **deps: Any) -> BaseActiveAgent:
    """Create an active agent by type name.

    Args:
        agent_type: Key from ACTIVE_AGENT_REGISTRY.
        **deps: Dependencies passed to agent constructor
            (client, scope_guard, browser, proxy, email_mgr, tool_runner, budget).

    Returns:
        Instantiated agent.

    Raises:
        ValueError: If agent_type is not registered.
    """
    cls = ACTIVE_AGENT_REGISTRY.get(agent_type)
    if cls is None:
        raise ValueError(
            f"Unknown active agent type: {agent_type}. "
            f"Available: {list(ACTIVE_AGENT_REGISTRY.keys())}"
        )
    return cls(**deps)
