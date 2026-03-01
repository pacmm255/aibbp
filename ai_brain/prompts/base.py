"""Base prompt template class for all AI brain prompts.

Every prompt template includes:
- System prompt with cache_control for prompt caching
- User message template with XML-tagged data sections
- Output schema for structured output
- Model tier for automatic model selection
- Anti-hallucination clause
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier


ANTI_HALLUCINATION_CLAUSE = """<anti_hallucination>
CRITICAL RULES:
1. Base your analysis STRICTLY on the provided data. Do not invent findings.
2. If evidence is insufficient, set confidence LOW and list uncertainties.
3. Rate confidence 0-100. Below 40 means "insufficient evidence."
4. Every finding MUST cite specific evidence from the input data.
5. "I found nothing" is a valid and valuable answer — do NOT fabricate results.
6. Distinguish between "tested and not vulnerable" vs "not tested."
</anti_hallucination>"""


class PromptTemplate(ABC):
    """Base class for all AI brain prompt templates.

    Subclasses must implement:
    - system_prompt: The static system prompt (cached)
    - user_template(): Formats the user message with input data
    - output_schema: The Pydantic model for structured output
    - model_tier: Which model tier to use (routine/complex/critical)
    """

    @property
    @abstractmethod
    def system_prompt(self) -> str:
        """Static system prompt text. Will be cached via cache_control."""
        ...

    @property
    @abstractmethod
    def output_schema(self) -> type[BaseModel]:
        """Pydantic model class for structured output."""
        ...

    @property
    @abstractmethod
    def model_tier(self) -> TaskTier:
        """Model tier: routine (Haiku), complex (Sonnet), critical (Opus)."""
        ...

    @property
    def temperature(self) -> float:
        """Temperature for this prompt. Override for non-default."""
        return 0.0

    @property
    def max_tokens(self) -> int | None:
        """Max tokens for this prompt. Override for prompts needing more output."""
        return None

    @abstractmethod
    def user_template(self, **kwargs: Any) -> str:
        """Format the user message with input data.

        Args:
            **kwargs: Template variables (data, target, context, etc.)

        Returns:
            Formatted user message string
        """
        ...

    def build_system_blocks(self) -> list[dict[str, Any]]:
        """Build system prompt blocks with cache control.

        Returns a list suitable for the Anthropic API system parameter.
        The main system prompt is cached (ephemeral) since it's stable
        across multiple calls.
        """
        return [
            {
                "type": "text",
                "text": self.system_prompt,
                "cache_control": {"type": "ephemeral"},
            }
        ]

    def build_system_blocks_with_context(
        self, context_xml: str = ""
    ) -> list[dict[str, Any]]:
        """Build system blocks with optional dynamic context.

        The system prompt is cached (stable), but the context is not
        (changes per call).
        """
        blocks = self.build_system_blocks()
        if context_xml:
            blocks.append({"type": "text", "text": context_xml})
        return blocks
