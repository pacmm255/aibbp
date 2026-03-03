"""ClaudeClient wrapper with all optimizations.

Wraps the Anthropic Python SDK with:
- Prompt caching (system prompts with cache_control)
- Structured output (output_config.format with json_schema)
- Model tiering (routine → Haiku, complex → Sonnet, critical → Opus)
- Budget check before every call
- Rate limiter acquisition before every call
- Circuit breaker wrapping every call
- Token usage tracking after every call
- Adaptive thinking for Opus 4.6
- Streaming for large outputs
"""

from __future__ import annotations

import asyncio
import json
import pathlib
from typing import Any, Generic, Literal, TypeVar

import anthropic
import structlog
from pydantic import BaseModel

from ai_brain.budget import BudgetManager
from ai_brain.config import AIBrainConfig
from ai_brain.errors import CircuitBreaker, CircuitBreakerOpen
from ai_brain.rate_limiter import DualRateLimiter

logger = structlog.get_logger()

T = TypeVar("T", bound=BaseModel)


def _read_claude_credentials() -> str:
    """Read OAuth token from Claude Code's credentials file.

    Returns the access token if found and not expired, empty string otherwise.
    """
    import time

    creds_path = pathlib.Path.home() / ".claude" / ".credentials.json"
    if not creds_path.exists():
        return ""
    try:
        data = json.loads(creds_path.read_text())
        oauth = data.get("claudeAiOauth", {})
        token = oauth.get("accessToken", "")
        expires_at = oauth.get("expiresAt", 0)
        # expiresAt is in milliseconds
        if token and expires_at > time.time() * 1000:
            logger.info("claude_credentials_loaded", source=str(creds_path))
            return token
        elif token:
            logger.warning("claude_credentials_expired", source=str(creds_path))
    except Exception as e:
        logger.warning("claude_credentials_read_error", error=str(e))
    return ""

TaskTier = Literal["routine", "complex", "critical"]


def _create_demo_instance(schema: type[BaseModel]) -> BaseModel:
    """Create a minimal valid instance of a Pydantic model for demo mode."""
    import enum
    from typing import Literal as TypingLiteral, Union, get_args, get_origin

    fields = schema.model_fields
    kwargs: dict[str, Any] = {}

    for name, field_info in fields.items():
        annotation = field_info.annotation
        origin = get_origin(annotation)
        args = get_args(annotation)

        # Handle Literal types — pick the first allowed value
        if origin is TypingLiteral:
            kwargs[name] = args[0] if args else ""
            continue

        # Handle Optional (Union[X, None])
        if origin is Union and type(None) in args:
            kwargs[name] = None
            continue

        # Handle list types
        if origin is list:
            kwargs[name] = []
            continue

        # Handle dict types
        if origin is dict:
            kwargs[name] = {}
            continue

        # Handle enum types
        if isinstance(annotation, type) and issubclass(annotation, enum.Enum):
            members = list(annotation)
            kwargs[name] = members[0] if members else None
            continue

        # Simple type defaults
        if annotation is str or annotation == str:
            kwargs[name] = f"demo_{name}"
        elif annotation is int or annotation == int:
            kwargs[name] = 0
        elif annotation is float or annotation == float:
            kwargs[name] = 0.0
        elif annotation is bool or annotation == bool:
            kwargs[name] = False
        elif isinstance(annotation, type) and issubclass(annotation, BaseModel):
            kwargs[name] = _create_demo_instance(annotation)
        else:
            # Let pydantic use default if available
            if field_info.default is not None:
                continue
            kwargs[name] = None

    try:
        return schema(**kwargs)
    except Exception:
        # Fall back to construct (skips validation)
        return schema.model_construct(**kwargs)


class _DemoToolResponse:
    """Mock response for call_with_tools() in demo mode."""

    def __init__(self) -> None:
        self.content = [type("TextBlock", (), {"type": "text", "text": "Demo mode: testing complete."})()]
        self.stop_reason = "end_turn"
        self.usage = type("Usage", (), {
            "input_tokens": 0, "output_tokens": 0,
            "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
        })()


class ClaudeClient:
    """Wrapper around the Anthropic API client with all optimizations.

    Usage:
        client = ClaudeClient(config, budget_manager)
        result = await client.call(
            phase="recon",
            task_tier="routine",
            system_blocks=[{"type": "text", "text": "...", "cache_control": {...}}],
            user_message="Analyze these subdomains...",
            output_schema=SubdomainClassificationResult,
            target="example.com",
        )
    """

    def __init__(
        self,
        config: AIBrainConfig,
        budget: BudgetManager,
        rate_limiter: DualRateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        self.config = config
        self.budget = budget
        self.rate_limiter = rate_limiter or DualRateLimiter(
            target_rps=3.0,
            api_rpm=config.rate_limits.requests_per_minute,
            api_itpm=config.rate_limits.input_tokens_per_minute,
        )
        self.circuit_breaker = circuit_breaker or CircuitBreaker()

        # Initialize Anthropic client
        # Support both API key and OAuth token authentication
        client_kwargs: dict[str, Any] = {
            "max_retries": config.rate_limits.max_retries,
        }
        api_key = config.anthropic_api_key or ""
        auth_token = getattr(config, "anthropic_auth_token", "") or ""
        self.demo_mode = getattr(config, "demo_mode", False)

        # Auto-read OAuth token from Claude Code credentials if no key/token set
        if not api_key and not auth_token and not self.demo_mode:
            auth_token = _read_claude_credentials()

        self._using_oauth = False
        self._api_key = api_key
        self._client_max_retries = config.rate_limits.max_retries
        if auth_token:
            client_kwargs["auth_token"] = auth_token
            # OAuth tokens require the beta header to authenticate
            client_kwargs["default_headers"] = {
                "anthropic-beta": "oauth-2025-04-20",
            }
            self._using_oauth = True
        elif api_key:
            client_kwargs["api_key"] = api_key
        self._client = anthropic.AsyncAnthropic(**client_kwargs)

        self._total_calls = 0
        self._total_input_tokens = 0
        self._total_output_tokens = 0

    def _refresh_oauth_token(self) -> bool:
        """Re-read OAuth token from disk and recreate the client.

        Claude Code refreshes tokens automatically in the background.
        When our token expires, a fresh one should already be on disk.
        Returns True if a new token was loaded successfully.
        """
        if not self._using_oauth:
            return False

        new_token = _read_claude_credentials()
        if not new_token:
            logger.warning("oauth_refresh_failed", reason="no_valid_token_on_disk")
            return False

        logger.info("oauth_token_refreshed")
        self._client = anthropic.AsyncAnthropic(
            max_retries=self._client_max_retries,
            auth_token=new_token,
            default_headers={"anthropic-beta": "oauth-2025-04-20"},
        )
        return True

    def select_model(self, task_tier: TaskTier) -> str:
        """Select the appropriate model based on task tier.

        Tiers:
        - routine (80%): Haiku - classification, triage, simple analysis
        - complex (18%): Sonnet - vulnerability analysis, strategy, correlation
        - critical (2%): Opus - attack chains, final reports, complex reasoning
        """
        models = self.config.models
        if task_tier == "routine":
            return models.routine
        elif task_tier == "complex":
            return models.complex
        else:
            return models.critical

    async def call(
        self,
        phase: str,
        task_tier: TaskTier,
        system_blocks: list[dict[str, Any]],
        user_message: str,
        output_schema: type[T] | None = None,
        target: str = "",
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> CallResult[T]:
        """Make a Claude API call with all safety layers.

        Args:
            phase: Budget phase (recon, vuln_detection, etc.)
            task_tier: Model tier (routine, complex, critical)
            system_blocks: System prompt blocks (with cache_control)
            user_message: The user message content
            output_schema: Optional Pydantic model for structured output
            target: Target domain for per-target budget tracking
            temperature: Override default temperature
            max_tokens: Override default max tokens

        Returns:
            CallResult with parsed output, raw text, and usage stats
        """
        model = self.select_model(task_tier)
        temp = temperature if temperature is not None else self.config.default_temperature
        max_tok = max_tokens or self.config.default_max_tokens

        # Estimate input tokens for budget check (~4 chars per token)
        estimated_input = len(user_message) // 4
        for block in system_blocks:
            estimated_input += len(block.get("text", "")) // 4
        estimated_cost = self._estimate_cost(model, estimated_input, max_tok // 2)

        # 1. Budget check
        self.budget.check_budget(phase, estimated_cost)
        if target:
            if not self.budget.check_target_budget(target):
                from ai_brain.errors import BudgetExhausted

                raise BudgetExhausted(
                    f"target:{target}",
                    self.budget.per_target_spent.get(target, 0),
                    self.budget.config.per_target_max_dollars,
                )

        # 2. Circuit breaker check
        self.circuit_breaker.before_call()

        # 3. Rate limiter
        await self.rate_limiter.acquire_api(estimated_input)

        # 4. Build request params
        params = self._build_params(
            model=model,
            system_blocks=system_blocks,
            user_message=user_message,
            output_schema=output_schema,
            temperature=temp,
            max_tokens=max_tok,
        )

        # 5. Make the API call (pass phase/target as metadata)
        try:
            response = await self._execute(
                params, output_schema, phase=phase, target=target
            )
            self.circuit_breaker.record_success()
            return response

        except anthropic.RateLimitError as e:
            self.circuit_breaker.record_failure()
            logger.warning("rate_limited", model=model, phase=phase)
            raise
        except anthropic.AuthenticationError as e:
            # OAuth token expired — try refreshing from disk
            logger.warning("auth_error_attempting_refresh", model=model, phase=phase)
            if self._refresh_oauth_token():
                # Rebuild params (the client is already replaced)
                params = self._build_params(
                    model=model,
                    system_blocks=system_blocks,
                    user_message=user_message,
                    output_schema=output_schema,
                    temperature=temp,
                    max_tokens=max_tok,
                )
                try:
                    response = await self._execute(
                        params, output_schema, phase=phase, target=target
                    )
                    self.circuit_breaker.record_success()
                    return response
                except Exception as retry_e:
                    logger.error("api_retry_after_refresh_failed", error=str(retry_e))
                    raise
            logger.error("api_error", model=model, phase=phase,
                         status=401, message=str(e))
            raise
        except anthropic.APIStatusError as e:
            if e.status_code >= 500:
                self.circuit_breaker.record_failure()
            logger.error(
                "api_error",
                model=model,
                phase=phase,
                status=e.status_code,
                message=str(e),
            )
            raise
        except CircuitBreakerOpen:
            logger.warning("circuit_breaker_open", model=model, phase=phase)
            raise

    async def call_vision(
        self,
        phase: str,
        image_b64: str,
        prompt: str,
        target: str = "",
        model_override: str | None = None,
        media_type: str = "image/png",
    ) -> str:
        """Send an image to Claude Vision and get a text response.

        Used for CAPTCHA solving, screenshot analysis, etc. Uses Haiku
        for speed and cost efficiency.

        Args:
            phase: Budget phase for cost tracking.
            image_b64: Base64-encoded image data.
            prompt: Text prompt to accompany the image.
            target: Target domain for budget tracking.
            model_override: Override model (defaults to Haiku for speed).
            media_type: MIME type of image (image/png, image/jpeg, etc.).

        Returns:
            Text response from Claude.
        """
        model = model_override or self.select_model("routine")

        # Budget + rate limiting
        estimated_cost = self._estimate_cost(model, 1000, 100)
        self.budget.check_budget(phase, estimated_cost)
        await self.rate_limiter.acquire_api(1000)

        messages = [{
            "role": "user",
            "content": [
                {
                    "type": "image",
                    "source": {
                        "type": "base64",
                        "media_type": media_type,
                        "data": image_b64,
                    },
                },
                {"type": "text", "text": prompt},
            ],
        }]

        try:
            response = await self._client.messages.create(
                model=model,
                max_tokens=256,
                messages=messages,
            )
        except Exception as e:
            logger.warning("vision_call_failed", error=str(e))
            return ""

        # Extract text
        raw_text = ""
        for block in response.content:
            if hasattr(block, "text"):
                raw_text += block.text

        # Record cost
        usage = response.usage
        cost = self.budget.record_cost(
            phase=phase,
            model=model,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            target=target,
        )

        logger.info(
            "vision_call_complete",
            model=model,
            phase=phase,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cost=f"${cost:.6f}",
            response_preview=raw_text[:100],
        )

        return raw_text.strip()

    async def call_with_tools(
        self,
        phase: str,
        task_tier: TaskTier,
        system_blocks: list[dict[str, Any]],
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        target: str = "",
        max_tokens: int | None = None,
    ) -> Any:
        """Claude API call with native tool-use support.

        Unlike call() which uses structured output for a single response,
        this method passes tools as Anthropic tool definitions and returns
        the raw response (which may contain tool_use blocks).

        Args:
            phase: Budget phase for cost tracking.
            task_tier: Model tier (routine, complex, critical).
            system_blocks: System prompt blocks (with cache_control).
            messages: Full conversation history (user/assistant/tool_result).
            tools: Anthropic tool definitions (name, description, input_schema).
            target: Target domain for budget tracking.
            max_tokens: Override default max tokens.

        Returns:
            Raw Anthropic Message response with content blocks.
        """
        if self.demo_mode:
            # In demo mode, return a mock response that signals end_turn
            return _DemoToolResponse()

        model = self.select_model(task_tier)
        max_tok = max_tokens or self.config.default_max_tokens

        # Estimate input tokens for budget check
        estimated_input = sum(
            len(json.dumps(m, default=str)) // 4 for m in messages
        )
        for block in system_blocks:
            estimated_input += len(block.get("text", "")) // 4
        estimated_cost = self._estimate_cost(model, estimated_input, max_tok // 2)

        # 1. Budget check
        self.budget.check_budget(phase, estimated_cost)
        if target and not self.budget.check_target_budget(target):
            from ai_brain.errors import BudgetExhausted

            raise BudgetExhausted(
                f"target:{target}",
                self.budget.per_target_spent.get(target, 0),
                self.budget.config.per_target_max_dollars,
            )

        # 2. Circuit breaker + rate limiter
        self.circuit_breaker.before_call()
        await self.rate_limiter.acquire_api(estimated_input)

        # 3. Build params
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tok,
            "system": system_blocks,
            "messages": messages,
            "tools": tools,
        }

        if "opus" in model:
            params["thinking"] = {"type": "enabled", "budget_tokens": 10000}
            params["max_tokens"] = max(max_tok, 16384)  # must exceed budget_tokens

        # 4. Make the API call with aggressive retry for transient errors
        max_retries = 10
        response = None
        for attempt in range(max_retries):
            try:
                response = await self._client.messages.create(**params)
                self.circuit_breaker.record_success()
                break
            except anthropic.AuthenticationError:
                if self._refresh_oauth_token():
                    logger.info("oauth_refreshed_retrying", attempt=attempt)
                    continue  # retry with refreshed token
                # Token refresh failed — wait and retry (Claude Code may refresh it)
                if attempt < max_retries - 1:
                    wait = min(60, 15 * (attempt + 1))
                    logger.warning("auth_failed_waiting_for_refresh", wait=wait, attempt=attempt)
                    await asyncio.sleep(wait)
                    self._refresh_oauth_token()  # try again after wait
                    continue
                raise
            except anthropic.RateLimitError as e:
                self.circuit_breaker.record_failure()
                if attempt < max_retries - 1:
                    wait = min(120, 30 * (attempt + 1))
                    logger.warning("rate_limited_retrying", wait=wait, attempt=attempt)
                    await asyncio.sleep(wait)
                    continue
                raise
            except anthropic.APIStatusError as e:
                if e.status_code >= 500:
                    self.circuit_breaker.record_failure()
                    if attempt < max_retries - 1:
                        wait = min(60, 10 * (attempt + 1))
                        logger.warning("server_error_retrying", status=e.status_code, wait=wait, attempt=attempt)
                        await asyncio.sleep(wait)
                        continue
                raise
            except (anthropic.APIConnectionError, anthropic.APITimeoutError) as e:
                if attempt < max_retries - 1:
                    wait = min(30, 5 * (attempt + 1))
                    logger.warning("connection_error_retrying", error=str(e)[:100], wait=wait, attempt=attempt)
                    await asyncio.sleep(wait)
                    continue
                raise
        if response is None:
            raise RuntimeError("call_with_tools: all retries exhausted")

        # 5. Record usage
        usage = response.usage
        cost = self.budget.record_cost(
            phase=phase,
            model=model,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=getattr(usage, "cache_read_input_tokens", 0) or 0,
            cache_creation_tokens=getattr(usage, "cache_creation_input_tokens", 0) or 0,
            target=target,
        )

        self.rate_limiter.record_tokens(usage.input_tokens)
        self._total_calls += 1
        self._total_input_tokens += usage.input_tokens
        self._total_output_tokens += usage.output_tokens

        logger.info(
            "tool_use_call_complete",
            model=model,
            phase=phase,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cost=f"${cost:.6f}",
            stop_reason=response.stop_reason,
            tool_calls=sum(1 for b in response.content if getattr(b, "type", "") == "tool_use"),
        )

        return response

    async def _execute(
        self,
        params: dict[str, Any],
        output_schema: type[T] | None = None,
        phase: str = "unknown",
        target: str = "",
    ) -> CallResult[T]:
        """Execute the API call and process the response."""
        model = params["model"]

        if self.demo_mode:
            return self._demo_response(model, output_schema, phase, target)

        if output_schema is not None:
            # Skip messages.parse() for all models via OAuth:
            # - Opus: returns empty content with messages.parse()
            # - Haiku/Sonnet: complex schemas (nested models, inheritance, union
            #   types) trigger 500 InternalServerError with ~3 min timeout
            # The JSON fallback (schema hint in system prompt + Pydantic
            # validation) works reliably for all models and avoids the timeout.
            logger.debug(
                "structured_output_direct_json",
                schema=output_schema.__name__,
                model=model,
            )
            response, parsed, raw_text = await self._fallback_json_parse(
                params, output_schema
            )
        else:
            # Regular message call
            response = await self._client.messages.create(**params)
            parsed = None
            raw_text = ""
            for block in response.content:
                if hasattr(block, "text"):
                    raw_text += block.text

        # Record usage
        usage = response.usage
        input_tokens = usage.input_tokens
        output_tokens = usage.output_tokens
        cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
        cache_creation = getattr(usage, "cache_creation_input_tokens", 0) or 0

        cost = self.budget.record_cost(
            phase=phase,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_creation,
            target=target,
        )

        # Track rate limiter actual usage
        self.rate_limiter.record_tokens(input_tokens)

        self._total_calls += 1
        self._total_input_tokens += input_tokens
        self._total_output_tokens += output_tokens

        logger.info(
            "api_call_complete",
            model=model,
            phase=phase,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read=cache_read,
            cost=f"${cost:.6f}",
        )

        return CallResult(
            parsed=parsed,
            raw_text=raw_text,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_creation_tokens=cache_creation,
            cost=cost,
        )

    async def _fallback_json_parse(
        self,
        params: dict[str, Any],
        output_schema: type[T],
    ) -> tuple[Any, T | None, str]:
        """Fallback: ask for JSON text, then validate with Pydantic."""
        schema_hint = json.dumps(output_schema.model_json_schema(), indent=2)[:3000]
        # Add JSON instruction to system prompt
        fallback_params = dict(params)
        system = list(fallback_params.get("system", []))
        system.append({
            "type": "text",
            "text": (
                f"\n\nYou MUST respond with ONLY valid JSON matching this schema "
                f"(no markdown, no explanation):\n{schema_hint}"
            ),
        })
        fallback_params["system"] = system

        response = await self._client.messages.create(**fallback_params)
        raw_text = ""
        for block in response.content:
            if hasattr(block, "text"):
                raw_text += block.text

        # Strip markdown code fences if present
        text = raw_text.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1] if "\n" in text else text[3:]
        if text.endswith("```"):
            text = text[:-3].strip()

        parsed = None
        try:
            parsed = output_schema.model_validate_json(text)
        except Exception as e:
            logger.warning("json_fallback_parse_error", error=str(e)[:200])
            try:
                data = json.loads(text)
                parsed = output_schema.model_validate(data)
            except Exception:
                # Try extracting JSON object from text with trailing chars
                extracted = self._extract_json_object(text)
                if extracted:
                    try:
                        data = json.loads(extracted)
                        parsed = output_schema.model_validate(data)
                    except Exception:
                        try:
                            valid_keys = set(output_schema.model_fields.keys())
                            filtered = {k: v for k, v in data.items() if k in valid_keys}
                            parsed = output_schema.model_construct(**filtered)
                        except Exception:
                            pass

        return response, parsed, raw_text

    @staticmethod
    def _extract_json_object(text: str) -> str:
        """Extract the first complete JSON object from text with trailing chars."""
        # Find the first { and match braces to find the closing }
        start = text.find("{")
        if start == -1:
            return ""
        depth = 0
        in_string = False
        escape = False
        for i, ch in enumerate(text[start:], start):
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = True
                continue
            if ch == '"' and not escape:
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    return text[start:i + 1]
        return ""

    def _demo_response(
        self,
        model: str,
        output_schema: type[T] | None,
        phase: str,
        target: str,
    ) -> CallResult[T]:
        """Generate a mock response for demo mode (no API key needed)."""
        self._total_calls += 1
        self._total_input_tokens += 100
        self._total_output_tokens += 50

        logger.info(
            "demo_mode_call",
            model=model,
            phase=phase,
            target=target,
            schema=output_schema.__name__ if output_schema else "none",
        )

        parsed = None
        if output_schema is not None:
            # Create a minimal valid instance of the output schema
            parsed = _create_demo_instance(output_schema)

        cost = self.budget.record_cost(
            phase=phase,
            model=model,
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            target=target,
        )

        return CallResult(
            parsed=parsed,
            raw_text="[DEMO MODE] Mock response for testing infrastructure.",
            model=model,
            input_tokens=100,
            output_tokens=50,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            cost=cost,
        )

    def _build_params(
        self,
        model: str,
        system_blocks: list[dict[str, Any]],
        user_message: str,
        output_schema: type[T] | None,
        temperature: float,
        max_tokens: int,
    ) -> dict[str, Any]:
        """Build API request parameters."""
        params: dict[str, Any] = {
            "model": model,
            "max_tokens": max_tokens,
            "system": system_blocks,
            "messages": [{"role": "user", "content": user_message}],
        }

        # Temperature (not compatible with thinking on some models)
        is_opus = "opus" in model
        if is_opus:
            params["thinking"] = {"type": "enabled", "budget_tokens": 10000}
            params["max_tokens"] = max(max_tokens, 16384)  # must exceed budget_tokens
        else:
            params["temperature"] = temperature

        # Structured output via output_config.format (when NOT using .parse())
        # When using .parse(), the SDK handles this internally
        if output_schema is not None and not is_opus:
            # For non-Opus with structured output, set temperature
            params["temperature"] = temperature

        return params

    def _estimate_cost(
        self, model: str, input_tokens: int, output_tokens: int
    ) -> float:
        """Rough cost estimate for budget pre-check."""
        cfg = self.config.budget
        if "haiku" in model:
            return (
                input_tokens / 1_000_000 * cfg.haiku_input
                + output_tokens / 1_000_000 * cfg.haiku_output
            )
        elif "opus" in model:
            return (
                input_tokens / 1_000_000 * cfg.opus_input
                + output_tokens / 1_000_000 * cfg.opus_output
            )
        else:
            return (
                input_tokens / 1_000_000 * cfg.sonnet_input
                + output_tokens / 1_000_000 * cfg.sonnet_output
            )

    @property
    def stats(self) -> dict[str, Any]:
        """Return client usage statistics."""
        return {
            "total_calls": self._total_calls,
            "total_input_tokens": self._total_input_tokens,
            "total_output_tokens": self._total_output_tokens,
        }


class CallResult(Generic[T]):
    """Result from a Claude API call."""

    __slots__ = (
        "parsed",
        "raw_text",
        "model",
        "input_tokens",
        "output_tokens",
        "cache_read_tokens",
        "cache_creation_tokens",
        "cost",
    )

    def __init__(
        self,
        parsed: T | None,
        raw_text: str,
        model: str,
        input_tokens: int,
        output_tokens: int,
        cache_read_tokens: int,
        cache_creation_tokens: int,
        cost: float,
    ) -> None:
        self.parsed = parsed
        self.raw_text = raw_text
        self.model = model
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_tokens = cache_read_tokens
        self.cache_creation_tokens = cache_creation_tokens
        self.cost = cost

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    def __repr__(self) -> str:
        return (
            f"CallResult(model={self.model!r}, "
            f"tokens={self.total_tokens}, "
            f"cost=${self.cost:.6f})"
        )


def build_system_blocks(
    system_text: str,
    cached: bool = True,
) -> list[dict[str, Any]]:
    """Build system prompt blocks with optional cache control.

    Args:
        system_text: The system prompt text
        cached: Whether to enable prompt caching

    Returns:
        List of system content blocks
    """
    block: dict[str, Any] = {"type": "text", "text": system_text}
    if cached:
        block["cache_control"] = {"type": "ephemeral"}
    return [block]


def build_system_blocks_multi(
    *parts: tuple[str, bool],
) -> list[dict[str, Any]]:
    """Build multi-part system prompt blocks.

    Args:
        *parts: Tuples of (text, should_cache)

    Returns:
        List of system content blocks

    Example:
        blocks = build_system_blocks_multi(
            (role_prompt, True),       # Cached - stable across calls
            (vuln_patterns, True),     # Cached - reference data
            (context_data, False),     # Not cached - changes per call
        )
    """
    blocks = []
    for text, cached in parts:
        block: dict[str, Any] = {"type": "text", "text": text}
        if cached:
            block["cache_control"] = {"type": "ephemeral"}
        blocks.append(block)
    return blocks
