"""Base class for all active testing agents.

Provides shared helpers for Claude API calls, browser actions, tool execution,
kill switch checking, and step logging.
"""

from __future__ import annotations

import json
import time
from abc import ABC, abstractmethod
from typing import Any

import structlog
from pydantic import BaseModel

from ai_brain.active.browser import BrowserController
from ai_brain.active.email import EmailManager
from ai_brain.active.errors import KillSwitchTriggered
from ai_brain.active.proxy import TrafficInterceptor
from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active.tools import ToolRunner
from ai_brain.budget import BudgetManager
from ai_brain.models import ClaudeClient
from ai_brain.prompts.base import PromptTemplate

logger = structlog.get_logger()


class BaseActiveAgent(ABC):
    """Abstract base class for active testing agents.

    Each agent receives the full toolkit (browser, proxy, email, tools)
    and orchestrates a specific testing phase using Claude for reasoning
    and the toolkit for actions.
    """

    def __init__(
        self,
        client: ClaudeClient,
        scope_guard: ActiveScopeGuard,
        browser: BrowserController,
        proxy: TrafficInterceptor,
        email_mgr: EmailManager,
        tool_runner: ToolRunner,
        budget: BudgetManager,
        kill_switch_checker: Any = None,
    ) -> None:
        self.client = client
        self.scope_guard = scope_guard
        self.browser = browser
        self.proxy = proxy
        self.email_mgr = email_mgr
        self.tool_runner = tool_runner
        self.budget = budget
        self._kill_check = kill_switch_checker

    @property
    @abstractmethod
    def agent_type(self) -> str:
        """Unique identifier for this agent type."""
        ...

    @abstractmethod
    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        """Main entry point. Receives and returns LangGraph state updates.

        Args:
            state: Current ActiveTestState dict.

        Returns:
            Dict of state updates to merge.
        """
        ...

    def _check_kill_switch(self) -> None:
        """Check kill switch and raise if active."""
        if self._kill_check and self._kill_check():
            raise KillSwitchTriggered(reason=f"checked_in_{self.agent_type}")

    async def _call_claude(
        self,
        prompt: PromptTemplate,
        target: str = "",
        **template_kwargs: Any,
    ) -> Any:
        """Call Claude via ClaudeClient with the given prompt template.

        Args:
            prompt: PromptTemplate instance.
            target: Target URL for budget tracking.
            **template_kwargs: Variables for prompt.user_template().

        Returns:
            Parsed output model instance (never None).
        """
        self._check_kill_switch()

        system_blocks = prompt.build_system_blocks()
        user_message = prompt.user_template(**template_kwargs)

        result = await self.client.call(
            phase="active_testing",
            task_tier=prompt.model_tier,
            system_blocks=system_blocks,
            user_message=user_message,
            output_schema=prompt.output_schema,
            target=target,
            temperature=prompt.temperature,
            max_tokens=prompt.max_tokens,
        )

        logger.info(
            "active_agent_claude_call",
            agent=self.agent_type,
            prompt=type(prompt).__name__,
            tokens=result.total_tokens,
            cost=f"${result.cost:.6f}",
        )

        parsed = result.parsed
        if parsed is None and prompt.output_schema is not None:
            # Fallback: construct a default instance via model_construct()
            # which skips validation and fills missing fields with defaults
            logger.warning(
                "claude_parse_fallback_default",
                agent=self.agent_type,
                schema=prompt.output_schema.__name__,
            )
            try:
                parsed = prompt.output_schema.model_construct()
            except Exception:
                pass

        return parsed

    async def _safe_browser_action(
        self,
        action: str,
        context_name: str,
        **kwargs: Any,
    ) -> Any:
        """Wrap a browser action with error handling and kill switch check.

        Args:
            action: Method name on BrowserController (navigate, click, fill, etc.)
            context_name: Browser context to use.
            **kwargs: Arguments for the browser method.

        Returns:
            BrowserActionResult or other return value.
        """
        self._check_kill_switch()

        method = getattr(self.browser, action, None)
        if method is None:
            raise ValueError(f"Unknown browser action: {action}")

        start = time.monotonic()
        try:
            result = await method(context_name, **kwargs)
            logger.debug(
                "browser_action",
                agent=self.agent_type,
                action=action,
                context=context_name,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            return result
        except Exception as e:
            logger.warning(
                "browser_action_error",
                agent=self.agent_type,
                action=action,
                error=str(e),
            )
            raise

    async def _safe_tool_run(
        self,
        tool: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Wrap a tool execution with error handling and kill switch check.

        Args:
            tool: Tool name (sqlmap, dalfox, jwt_tool, commix, custom_poc).
            **kwargs: Arguments for the tool runner method.

        Returns:
            Tool result dict.
        """
        self._check_kill_switch()

        method_name = f"run_{tool}"
        method = getattr(self.tool_runner, method_name, None)
        if method is None:
            raise ValueError(f"Unknown tool: {tool}")

        start = time.monotonic()
        try:
            result = await method(**kwargs)
            logger.info(
                "tool_execution",
                agent=self.agent_type,
                tool=tool,
                duration_ms=int((time.monotonic() - start) * 1000),
            )
            return result
        except Exception as e:
            logger.warning(
                "tool_execution_error",
                agent=self.agent_type,
                tool=tool,
                error=str(e),
            )
            raise

    def _log_step(
        self,
        action: str,
        input_data: dict[str, Any] | None = None,
        output_data: dict[str, Any] | None = None,
        error: str = "",
    ) -> dict[str, Any]:
        """Create a step log entry for persistence.

        Returns:
            Step dict suitable for recording in active_test_steps table.
        """
        step = {
            "agent_type": self.agent_type,
            "action": action,
            "input_data": input_data or {},
            "output_data": output_data or {},
            "error": error,
            "timestamp": time.time(),
        }
        logger.info("active_step", **step)
        return step
