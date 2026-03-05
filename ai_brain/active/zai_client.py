"""Z.ai (chat.z.ai) GLM-5 client — drop-in replacement for ClaudeClient.

Provides free GLM-5 with thinking via Zhipu's Open WebUI instance.
Guest accounts are auto-created (no signup needed). Uses HMAC-SHA256
signed requests to the /api/v2/chat/completions streaming endpoint.

Returns mock Anthropic-compatible response objects so brain_node()
works without modification.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import time
import uuid
from typing import Any

import httpx
import structlog

logger = structlog.get_logger("zai_client")

# ── HMAC signing key (extracted from Open WebUI JS bundle) ──────────────
_HMAC_SECRET_KEY = "key-@@@@)))()((9))-xxxx&&&%%%%%"
_BUCKET_INTERVAL_MS = 5 * 60 * 1000  # 5 minutes

# ── Global rate limiter (shared across all ZaiClient instances) ─────────
# Z.ai CDN blocks IPs with concurrent streams. Use a global semaphore to
# ensure at most 1 concurrent Z.ai API call, plus minimum interval between calls.
_ZAI_SEMAPHORE = asyncio.Semaphore(1)
_ZAI_LAST_CALL_TIME: float = 0.0
_ZAI_MIN_INTERVAL: float = 8.0  # seconds between calls (safe: ~7.5 calls/min)


# ── Mock Anthropic-compatible response objects ──────────────────────────

class ZaiTextBlock:
    """Mimics anthropic.types.TextBlock."""
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class ZaiThinkingBlock:
    """Mimics anthropic.types.ThinkingBlock."""
    def __init__(self, thinking: str):
        self.type = "thinking"
        self.thinking = thinking


class ZaiToolUseBlock:
    """Mimics anthropic.types.ToolUseBlock."""
    def __init__(self, id: str, name: str, input: dict):
        self.type = "tool_use"
        self.id = id
        self.name = name
        self.input = input


class ZaiUsage:
    """Mimics anthropic.types.Usage."""
    def __init__(self, input_tokens: int = 0, output_tokens: int = 0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = 0
        self.cache_creation_input_tokens = 0


class ZaiResponse:
    """Mimics anthropic.types.Message."""
    def __init__(self, content: list, stop_reason: str, usage: ZaiUsage):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage


# ── Tool call extraction from text ──────────────────────────────────────

_TOOL_CALL_PATTERN = re.compile(
    r'<tool_call>\s*(\{.*?\})\s*</tool_call>',
    re.DOTALL,
)

# GLM-5 sometimes mimics the history format: [Called tool: name({...})]
_CALLED_TOOL_PATTERN = re.compile(
    r'\[Called tool:\s*(\w+)\((\{.*?\})\)\]',
    re.DOTALL,
)

# GLM-5 mimics multi-line history format:
# [Called tool: name]
# Arguments: {...}
# [End tool call]   (end tag optional)
_CALLED_TOOL_MULTILINE_PATTERN = re.compile(
    r'\[Called tool:\s*(\w+)\]\s*\n\s*Arguments:\s*(\{.*?\})\s*(?:\n\s*\[End tool call\])?',
    re.DOTALL,
)

# GLM-5 mimics <executed tool="name" args={...} /> format from conversation history
_EXECUTED_TOOL_PATTERN = re.compile(
    r'<executed\s+tool="(\w+)"\s+args=',
    re.DOTALL,
)

# JSON array in code block: ```json [{"name": "...", "input": {...}}] ```
_TOOL_CALL_JSON_PATTERN = re.compile(
    r'```(?:json)?\s*(\[\s*\{[^`]*\}\s*\])\s*```',
    re.DOTALL,
)

# Single JSON object in code block: ```{"name": "...", "input": {...}}```
# or ```json {"name": "...", "input": {...}}```
_TOOL_CALL_CODEBLOCK_PATTERN = re.compile(
    r'```(?:json)?\s*(\{[^`]*"name"[^`]*"input"[^`]*\})\s*```',
    re.DOTALL,
)


def _repair_json(text: str) -> str:
    """Attempt to repair common JSON errors from GLM-5.

    Handles: trailing commas, Python booleans/None, single quotes,
    trailing text after JSON object.
    """
    s = text.strip()

    # Brace-balanced extraction: remove trailing text after JSON object
    if s.startswith("{"):
        depth = 0
        in_string = False
        escape = False
        end = -1
        for i, ch in enumerate(s):
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
                    end = i + 1
                    break
        if end > 0:
            s = s[:end]

    # Fix trailing commas before } or ]
    s = re.sub(r",\s*([}\]])", r"\1", s)

    # Fix Python booleans/None
    s = re.sub(r"\bTrue\b", "true", s)
    s = re.sub(r"\bFalse\b", "false", s)
    s = re.sub(r"\bNone\b", "null", s)

    # Fix single quotes when no double quotes present
    if "'" in s and '"' not in s:
        s = s.replace("'", '"')

    return s


def _try_parse_tool_json(text: str) -> dict | None:
    """Try to parse a JSON object that looks like a tool call.

    Returns dict with 'name' and 'input' keys, or None.
    Attempts JSON repair on failure (trailing commas, Python bools, etc.).
    """
    for attempt_text in (text, _repair_json(text)):
        try:
            data = json.loads(attempt_text)
            if isinstance(data, dict) and "name" in data:
                return {
                    "name": data["name"],
                    "input": data.get("input", data.get("parameters",
                             data.get("arguments", {}))),
                }
        except json.JSONDecodeError:
            continue
    return None


def _extract_tool_calls(text: str) -> tuple[str, list[ZaiToolUseBlock]]:
    """Extract tool calls from GLM-5 text output.

    Supports multiple formats (GLM-5 varies its output format):
    1. <tool_call>{"name": "...", "input": {...}}</tool_call>
    2. ```json {"name": "...", "input": {...}} ```
    3. JSON object on its own line: {"name": "...", "input": {...}}
    4. JSON object at end of text

    Returns (clean_text, tool_calls) where clean_text has tool call
    markup removed.
    """
    tool_calls: list[ZaiToolUseBlock] = []
    lines_to_remove: list[str] = []

    # Format 1: <tool_call> tags
    for match in _TOOL_CALL_PATTERN.finditer(text):
        parsed = _try_parse_tool_json(match.group(1))
        if parsed:
            tool_calls.append(ZaiToolUseBlock(
                id=f"toolu_{uuid.uuid4().hex[:24]}",
                name=parsed["name"],
                input=parsed["input"],
            ))
            lines_to_remove.append(match.group(0))

    # Format 2: JSON in code blocks
    if not tool_calls:
        for match in _TOOL_CALL_CODEBLOCK_PATTERN.finditer(text):
            parsed = _try_parse_tool_json(match.group(1))
            if parsed:
                tool_calls.append(ZaiToolUseBlock(
                    id=f"toolu_{uuid.uuid4().hex[:24]}",
                    name=parsed["name"],
                    input=parsed["input"],
                ))
                lines_to_remove.append(match.group(0))

        # Also try JSON array in code block
        for match in _TOOL_CALL_JSON_PATTERN.finditer(text):
            try:
                items = json.loads(match.group(1))
                if isinstance(items, list):
                    for item in items:
                        if isinstance(item, dict) and "name" in item:
                            tool_calls.append(ZaiToolUseBlock(
                                id=f"toolu_{uuid.uuid4().hex[:24]}",
                                name=item["name"],
                                input=item.get("input", item.get("parameters", {})),
                            ))
                    lines_to_remove.append(match.group(0))
            except json.JSONDecodeError:
                continue

    # Format 2b: [Called tool: name({...})] — GLM-5 mimics history format (inline)
    if not tool_calls:
        for match in _CALLED_TOOL_PATTERN.finditer(text):
            tool_name = match.group(1)
            try:
                args = json.loads(match.group(2))
                tool_calls.append(ZaiToolUseBlock(
                    id=f"toolu_{uuid.uuid4().hex[:24]}",
                    name=tool_name,
                    input=args if isinstance(args, dict) else {},
                ))
                lines_to_remove.append(match.group(0))
            except json.JSONDecodeError:
                continue

    # Format 2b2: [Called tool: name]\nArguments: {...}\n[End tool call] — GLM-5 multiline history format
    if not tool_calls:
        for match in _CALLED_TOOL_MULTILINE_PATTERN.finditer(text):
            tool_name = match.group(1)
            try:
                args = json.loads(match.group(2))
                tool_calls.append(ZaiToolUseBlock(
                    id=f"toolu_{uuid.uuid4().hex[:24]}",
                    name=tool_name,
                    input=args if isinstance(args, dict) else {},
                ))
                lines_to_remove.append(match.group(0))
            except json.JSONDecodeError:
                # Try brace-balanced extraction for nested JSON
                raw = match.group(2)
                parsed = _try_parse_tool_json(raw)
                if parsed:
                    tool_calls.append(ZaiToolUseBlock(
                        id=f"toolu_{uuid.uuid4().hex[:24]}",
                        name=tool_name,
                        input=parsed.get("input", parsed) if "name" in parsed else parsed,
                    ))
                    lines_to_remove.append(match.group(0))

    # Format 2c: <executed tool="name" args={...} /> — GLM-5 mimics history XML format
    # Uses brace-balanced extraction since args contain nested JSON
    if not tool_calls:
        for match in _EXECUTED_TOOL_PATTERN.finditer(text):
            tool_name = match.group(1)
            rest = text[match.end():]
            if rest.startswith("{"):
                depth = 0
                end_idx = -1
                for i, ch in enumerate(rest):
                    if ch == "{":
                        depth += 1
                    elif ch == "}":
                        depth -= 1
                        if depth == 0:
                            end_idx = i + 1
                            break
                if end_idx > 0:
                    try:
                        args = json.loads(rest[:end_idx])
                        tool_calls.append(ZaiToolUseBlock(
                            id=f"toolu_{uuid.uuid4().hex[:24]}",
                            name=tool_name,
                            input=args if isinstance(args, dict) else {},
                        ))
                        # Remove the full <executed ... /> tag from text
                        full_match_end = match.end() + end_idx
                        # Skip trailing whitespace and />
                        remaining = text[full_match_end:]
                        tag_end = remaining.find("/>")
                        if tag_end >= 0:
                            full_tag = text[match.start():full_match_end + tag_end + 2]
                        else:
                            full_tag = text[match.start():full_match_end]
                        lines_to_remove.append(full_tag)
                    except json.JSONDecodeError:
                        continue

    # Format 2d: Tool call preceded by a text label
    # e.g. "Tool call: {"name": "...", ...}" or "Calling tool: {"name": "...", ...}"
    if not tool_calls:
        for prefix_pat in [r'(?:Tool call|Calling tool|Execute|Action):\s*']:
            for match in re.finditer(
                prefix_pat + r'(\{[^\n]*"name"[^\n]*\})', text,
            ):
                parsed = _try_parse_tool_json(match.group(1))
                if parsed:
                    tool_calls.append(ZaiToolUseBlock(
                        id=f"toolu_{uuid.uuid4().hex[:24]}",
                        name=parsed["name"],
                        input=parsed["input"],
                    ))
                    lines_to_remove.append(match.group(0))

    # Format 3: JSON object on its own line (primary format for text-based calling)
    if not tool_calls:
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("{") and stripped.endswith("}") and '"name"' in stripped:
                parsed = _try_parse_tool_json(stripped)
                if parsed:
                    tool_calls.append(ZaiToolUseBlock(
                        id=f"toolu_{uuid.uuid4().hex[:24]}",
                        name=parsed["name"],
                        input=parsed["input"],
                    ))
                    lines_to_remove.append(line)

    # Format 4: Brace-balanced JSON at end of text
    if not tool_calls:
        stripped = text.rstrip()
        if stripped.endswith("}"):
            brace_depth = 0
            start_idx = -1
            for i in range(len(stripped) - 1, -1, -1):
                if stripped[i] == "}":
                    brace_depth += 1
                elif stripped[i] == "{":
                    brace_depth -= 1
                    if brace_depth == 0:
                        start_idx = i
                        break
            if start_idx >= 0:
                parsed = _try_parse_tool_json(stripped[start_idx:])
                if parsed:
                    tool_calls.append(ZaiToolUseBlock(
                        id=f"toolu_{uuid.uuid4().hex[:24]}",
                        name=parsed["name"],
                        input=parsed["input"],
                    ))
                    lines_to_remove.append(stripped[start_idx:])

    # Clean text by removing tool call markup
    clean_text = text
    for item in lines_to_remove:
        clean_text = clean_text.replace(item, "", 1)

    return clean_text.strip(), tool_calls


# ── Z.ai Client ────────────────────────────────────────────────────────

class ZaiClient:
    """GLM-5 client via chat.z.ai — compatible with ClaudeClient interface.

    Usage:
        client = ZaiClient(budget=budget_manager, config=ai_config)
        response = await client.call_with_tools(
            phase="active_testing",
            task_tier="complex",
            system_blocks=[...],
            messages=[...],
            tools=[...],
        )
    """

    BASE_URL = "https://chat.z.ai"
    MODEL = "glm-5"

    def __init__(
        self,
        budget: Any,
        config: Any,
        model: str = "glm-5",
        enable_thinking: bool = True,
        proxy_pool: Any | None = None,
    ):
        self.budget = budget
        self.config = config
        self.model = model
        self.enable_thinking = enable_thinking
        self.demo_mode = False
        self.proxy_pool = proxy_pool  # Optional ProxyPool for rate limit bypass

        # Session state — primary + backup tokens for resilience
        self._token: str | None = None
        self._user_id: str | None = None
        self._cookies: dict[str, str] = {}
        self._backup_tokens: list[dict[str, str]] = []  # [{token, user_id}]
        self._session_failures: int = 0  # Track consecutive failures

        # Stats (for compatibility with ClaudeClient interface)
        self._total_calls = 0
        self._total_input_tokens = 0
        self._total_output_tokens = 0

        # HTTP client — shorter timeout for faster failures
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(90.0, connect=15.0),
            follow_redirects=True,
        )

    # ── Session management ──────────────────────────────────────────

    async def _ensure_session(self) -> None:
        """Get or refresh guest token with resilience."""
        if self._token:
            return

        # Try backup token first if primary failed
        if self._backup_tokens:
            backup = self._backup_tokens.pop(0)
            self._token = backup["token"]
            self._user_id = backup["user_id"]
            logger.info("zai_using_backup_token", user_id=self._user_id[:8] if self._user_id else "?")
            return

        logger.info("zai_getting_guest_token")
        resp = await self._http.get(
            f"{self.BASE_URL}/api/v1/auths/",
            headers={"Accept": "application/json"},
        )

        if resp.status_code != 200:
            raise RuntimeError(f"Z.ai auth failed: {resp.status_code} {resp.text[:200]}")

        data = resp.json()
        self._token = data.get("token", "")
        self._user_id = data.get("id", "")

        # Collect cookies
        for name, value in resp.cookies.items():
            self._cookies[name] = value

        self._session_failures = 0
        logger.info("zai_guest_session", user_id=self._user_id[:8] if self._user_id else "?")

    def _rotate_session(self) -> None:
        """Invalidate current session so next call gets a fresh token."""
        self._session_failures += 1
        self._token = None
        self._cookies = {}
        logger.info("zai_session_rotated", failures=self._session_failures)

    # ── HMAC signing ────────────────────────────────────────────────

    @staticmethod
    def _generate_signature(prompt: str, user_id: str, request_id: str, timestamp_ms: int) -> str:
        """Two-layer HMAC-SHA256 signature.

        Layer 1: HMAC(static_key, time_bucket) → intermediate key
        Layer 2: HMAC(intermediate, sorted_payload|base64(prompt)|timestamp)
        """
        # Sorted payload entries
        entries = sorted([
            ("requestId", request_id),
            ("timestamp", str(timestamp_ms)),
            ("user_id", user_id),
        ])
        sorted_payload = ",".join(f"{k},{v}" for k, v in entries)

        # Base64 encode prompt
        prompt_b64 = base64.b64encode(prompt.encode("utf-8")).decode("ascii")

        # Build message
        message = f"{sorted_payload}|{prompt_b64}|{timestamp_ms}"

        # Time bucket (5-minute window)
        bucket = timestamp_ms // _BUCKET_INTERVAL_MS

        # Layer 1: intermediate key
        intermediate = hmac.new(
            _HMAC_SECRET_KEY.encode("utf-8"),
            str(bucket).encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        # Layer 2: final signature
        signature = hmac.new(
            intermediate.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

        return signature

    # ── Format tools as text instruction ──────────────────────────────

    # Inline examples for common tools (tool_name → example input dict)
    _TOOL_EXAMPLES: dict[str, dict[str, Any]] = {
        "crawl_target": {"start_url": "http://TARGET", "max_pages": 30},
        "send_http_request": {"url": "http://TARGET/path", "method": "POST", "body": "param=value"},
        "systematic_fuzz": {"url_template": "http://TARGET/{FUZZ}", "wordlist": "common-dirs"},
        "response_diff_analyze": {
            "base_request": {"url": "http://TARGET/search", "method": "POST", "body": {"q": "test"}},
            "test_requests": [{"label": "sqli", "body": {"q": "test'"}}],
        },
        "test_sqli": {"url": "http://TARGET/search", "method": "POST", "body": "q=test"},
        "test_xss": {"url": "http://TARGET/search?q=test"},
        "blind_sqli_extract": {"url": "http://TARGET/search", "method": "POST", "param_name": "q", "query": "SELECT version()"},
        "run_custom_exploit": {"code": "import httpx\nr=httpx.get('http://TARGET/')\nprint(r.text)"},
        "update_knowledge": {"findings": {"sqli_1": {"vuln_type": "sqli", "endpoint": "/search", "evidence": "MySQL error", "severity": "high", "confirmed": True}}},
        "finish_test": {"assessment": "Found SQLi at /search. Extracted admin credentials."},
    }

    @staticmethod
    def _format_tools_instruction(tools: list[dict[str, Any]]) -> str:
        """Format tools with full descriptions, parameter docs, and examples.

        GLM-5's native tool calling via OpenAI format has a bug where arguments
        get truncated. Instead, we use text-based tool calling: the model outputs
        tool calls as JSON objects that we parse from the response.
        """
        lines = [
            "",
            "<tool_calling_instructions>",
            "YOU MUST CALL TOOLS. Every response MUST end with a JSON tool call.",
            "",
            "FORMAT: Write reasoning first, then a JSON object on its own line as the LAST thing:",
            '{"name": "TOOL_NAME", "input": {PARAMETERS}}',
            "",
            "RULES:",
            "1. The JSON MUST be on its own line — NOT inside ``` code blocks.",
            "2. Write reasoning BEFORE the JSON. The JSON must be the LAST thing you output.",
            "3. Do NOT just describe what you would do — you MUST OUTPUT THE ACTUAL JSON.",
            "4. Use double quotes for all strings. No trailing commas.",
            "5. For multiple tools, output multiple JSON lines.",
            "6. EVERY response MUST end with a JSON tool call. If you respond without one, you FAIL.",
            "7. After receiving tool results, analyze them briefly then IMMEDIATELY output the next tool call JSON.",
            "</tool_calling_instructions>",
            "",
            "<available_tools>",
        ]

        for tool in tools:
            name = tool["name"]
            desc = tool.get("description", "")
            schema = tool.get("input_schema", {})
            required = schema.get("required", [])
            props = schema.get("properties", {})

            lines.append(f"\n### {name}")
            lines.append(desc)

            if props:
                lines.append("Parameters:")
                for pname, pdef in props.items():
                    ptype = pdef.get("type", "string")
                    pdesc = pdef.get("description", "")
                    req_label = "REQUIRED" if pname in required else "optional"
                    default = pdef.get("default")
                    default_str = f", default={default}" if default is not None else ""
                    lines.append(f"  - {pname} ({ptype}, {req_label}{default_str}): {pdesc}")

            # Add inline example for common tools
            example = ZaiClient._TOOL_EXAMPLES.get(name)
            if example:
                example_json = json.dumps({"name": name, "input": example}, default=str)
                lines.append(f"Example: {example_json}")

        lines.append("</available_tools>")

        return "\n".join(lines)

    # ── Convert messages for GLM-5 ──────────────────────────────────

    @staticmethod
    def _convert_messages(messages: list[dict[str, Any]]) -> list[dict[str, str]]:
        """Convert Anthropic-style messages to OpenAI-compatible format for GLM-5.

        Handles:
        - text blocks → concatenate text
        - tool_use blocks → assistant text describing the tool call
        - tool_result blocks → user message with tool output
        """
        converted = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if isinstance(content, str):
                converted.append({"role": role, "content": content})
            elif isinstance(content, list):
                parts = []
                for block in content:
                    if isinstance(block, dict):
                        btype = block.get("type", "text")
                        if btype == "text":
                            parts.append(block.get("text", ""))
                        elif btype == "tool_use":
                            # Format tool calls for history context
                            # Use [Called tool:] format (not <executed> — GLM-5 mimics XML tags)
                            name = block.get("name", "?")
                            inp = block.get("input", {})
                            args_str = json.dumps(inp, default=str)
                            parts.append(
                                f"[Called tool: {name}]\n"
                                f"Arguments: {args_str}\n"
                                f"[End tool call]"
                            )
                        elif btype == "tool_result":
                            result_content = block.get("content", "")
                            if isinstance(result_content, list):
                                result_content = "\n".join(
                                    b.get("text", "") for b in result_content
                                    if isinstance(b, dict)
                                )
                            # Keep generous context (8K); for very large outputs
                            # keep first 6K + last 2K
                            if len(result_content) > 8000:
                                result_content = (
                                    result_content[:6000]
                                    + f"\n\n... [{len(result_content) - 8000} chars omitted] ...\n\n"
                                    + result_content[-2000:]
                                )
                            parts.append(
                                f"--- TOOL RESULT ---\n"
                                f"{result_content}\n"
                                f"--- END RESULT ---"
                            )
                    elif isinstance(block, str):
                        parts.append(block)

                if parts:
                    # Map tool_result role to user (GLM-5 uses user/assistant/system)
                    glm_role = "user" if role == "tool" else role
                    converted.append({"role": glm_role, "content": "\n".join(parts)})

        # Append tool-call reminder to the LAST user message containing tool results
        # GLM-5 almost never outputs JSON tool calls on first attempt without this nudge.
        # This reminder right before generation cuts retry rate from ~95% to near 0%.
        _TOOL_CALL_NUDGE = (
            '\n\nIMPORTANT: Analyze the result above, then output your next action as a JSON object '
            'on its own line. Example:\n'
            '{"name": "send_http_request", "input": {"url": "https://TARGET/path", "method": "GET"}}'
        )
        for i in range(len(converted) - 1, -1, -1):
            c = converted[i].get("content", "")
            if isinstance(c, str) and "--- TOOL RESULT ---" in c:
                converted[i] = dict(converted[i])
                converted[i]["content"] = c + _TOOL_CALL_NUDGE
                break

        # Merge consecutive same-role messages
        merged = []
        for msg in converted:
            if merged and merged[-1]["role"] == msg["role"]:
                merged[-1]["content"] += "\n\n" + msg["content"]
            else:
                merged.append(msg)

        # Ensure starts with user message
        if merged and merged[0]["role"] != "user":
            merged.insert(0, {"role": "user", "content": "Begin."})

        # Ensure alternating user/assistant
        final = []
        for msg in merged:
            if final and final[-1]["role"] == msg["role"]:
                bridge_role = "assistant" if msg["role"] == "user" else "user"
                final.append({"role": bridge_role, "content": "Continue."})
            final.append(msg)

        return final

    # ── Main API call ───────────────────────────────────────────────

    async def call_with_tools(
        self,
        phase: str,
        task_tier: str,
        system_blocks: list[dict[str, Any]],
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        target: str = "",
        max_tokens: int | None = None,
    ) -> ZaiResponse:
        """Send chat completion request to Z.ai — compatible with ClaudeClient.

        Args:
            phase: Budget phase for cost tracking.
            task_tier: Ignored (always uses GLM-5).
            system_blocks: System prompt blocks (concatenated).
            messages: Conversation history.
            tools: Tool definitions (converted to text instructions).
            target: Target domain for budget tracking.
            max_tokens: Ignored.

        Returns:
            ZaiResponse mimicking Anthropic Message.
        """
        await self._ensure_session()

        # Build system prompt from blocks + tool instructions
        system_parts = []
        for block in system_blocks:
            text = block.get("text", "")
            if text:
                system_parts.append(text)

        # Add tool calling instructions as text (not OpenAI format — Z.ai truncates args)
        if tools:
            system_parts.append(self._format_tools_instruction(tools))

        system_text = "\n\n".join(system_parts)

        # Convert messages
        glm_messages = self._convert_messages(messages)

        # Prepend system as system message (GLM-5 supports system role)
        glm_messages.insert(0, {"role": "system", "content": system_text})

        # Build request — use the ORIGINAL user message for signature (not system-prepended)
        # The signature_prompt must match what the frontend would send
        original_user_msg = ""
        for m in reversed(messages):
            content = m.get("content", "")
            if isinstance(content, str):
                original_user_msg = content
                break
            elif isinstance(content, list):
                parts = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"]
                original_user_msg = " ".join(parts)
                break
        prompt_text = original_user_msg[:500]  # Signature uses short prompt
        request_id = str(uuid.uuid4())
        chat_id = str(uuid.uuid4())
        message_id = str(uuid.uuid4())
        timestamp_ms = int(time.time() * 1000)

        # Generate signature
        signature = self._generate_signature(
            prompt=prompt_text,
            user_id=self._user_id or "",
            request_id=request_id,
            timestamp_ms=timestamp_ms,
        )

        # Query parameters (browser fingerprint)
        query_params = {
            "requestId": request_id,
            "timestamp": str(timestamp_ms),
            "user_id": self._user_id or "",
            "screenWidth": "1920",
            "screenHeight": "1080",
            "userAgent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
            "timezone": "Asia/Shanghai",
            "language": "en-US",
            "signature_timestamp": str(timestamp_ms),
        }

        url = f"{self.BASE_URL}/api/v2/chat/completions"

        headers = {
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "Accept": "text/event-stream",
            "Accept-Language": "en-US",
            "X-FE-Version": "prod-fe-1.0.250",
            "X-Signature": signature,
            "Origin": self.BASE_URL,
            "Referer": f"{self.BASE_URL}/",
        }

        # Set cookie header
        cookie_parts = [f"token={self._token}"]
        for k, v in self._cookies.items():
            if k != "token":
                cookie_parts.append(f"{k}={v}")
        headers["Cookie"] = "; ".join(cookie_parts)

        body: dict[str, Any] = {
            "model": self.model,
            "messages": glm_messages,
            "stream": True,
            "signature_prompt": prompt_text,
            "params": {},
            "features": {
                "image_generation": False,
                "web_search": False,
                "auto_web_search": False,
                "preview_mode": False,
                "flags": [],
                "enable_thinking": self.enable_thinking,
            },
            "variables": {},
            "session_id": None,
            "chat_id": chat_id,
            "id": message_id,
            "current_user_message_id": message_id,
            "current_user_message_parent_id": None,
        }

        # NOTE: OpenAI-format tools NOT used — Z.ai truncates arguments in <glm_block>.
        # Tool calling is done via text-based format instructions instead.

        # Estimate input tokens (rough: 4 chars per token)
        input_chars = len(json.dumps(body, default=str))
        estimated_input_tokens = input_chars // 4

        logger.info("zai_calling", model=self.model, msg_count=len(glm_messages),
                     est_input_tokens=estimated_input_tokens)

        # ── Proxy pool path: route through rotating proxies ──
        if self.proxy_pool:
            return await self._call_via_proxy_pool(
                url=url, query_params=query_params, headers=headers,
                body=body, prompt_text=prompt_text,
                estimated_input_tokens=estimated_input_tokens,
                phase=phase, target=target, tools=tools,
            )

        # ── Global rate limiter: enforce single-concurrency + min interval ──
        global _ZAI_LAST_CALL_TIME
        async with _ZAI_SEMAPHORE:
            elapsed_since_last = time.time() - _ZAI_LAST_CALL_TIME
            if elapsed_since_last < _ZAI_MIN_INTERVAL:
                wait = _ZAI_MIN_INTERVAL - elapsed_since_last
                logger.debug("zai_rate_wait", wait=f"{wait:.1f}s")
                await asyncio.sleep(wait)
            _ZAI_LAST_CALL_TIME = time.time()

        # Stream the response using document buffer approach.
        # Z.ai sends a mix of delta_content (appends) and edit_content
        # with edit_index (splices). The full document includes a
        # <details type="reasoning"> block with thinking content,
        # followed by the actual answer. We build the full doc, then
        # strip the thinking block at the end.
        #
        # When tools are passed, GLM-5 emits phase=tool_call events with
        # <glm_block> tags containing the tool call. We capture these and
        # stop streaming (GLM-5 otherwise hallucinates tool results).
        doc_buffer: list[str] = []  # Character-level buffer
        native_tool_calls: list[ZaiToolUseBlock] = []
        output_tokens = 0

        max_retries = 3
        for attempt in range(max_retries):
            try:
                async def _stream_direct() -> bool:
                    """Stream Z.ai response directly. Returns True on success, False to retry."""
                    nonlocal doc_buffer, output_tokens, estimated_input_tokens
                    nonlocal headers, query_params

                    async with self._http.stream(
                        "POST", url, params=query_params,
                        headers=headers, json=body,
                    ) as stream:
                        if stream.status_code in (400, 403, 405, 429):
                            error_body = ""
                            async for chunk in stream.aiter_text():
                                error_body += chunk
                            logger.warning("zai_http_error", status=stream.status_code,
                                           body=error_body[:300], attempt=attempt)
                            if attempt < max_retries - 1:
                                backoff = 5 if stream.status_code == 405 else min(10 * (3 ** attempt), 120)
                                logger.info("zai_rate_limit_backoff", wait=backoff,
                                            attempt=attempt, status=stream.status_code)
                                await asyncio.sleep(backoff)
                                self._rotate_session()
                                await self._ensure_session()
                                headers["Authorization"] = f"Bearer {self._token}"
                                cookie_parts = [f"token={self._token}"]
                                for k, v in self._cookies.items():
                                    if k != "token":
                                        cookie_parts.append(f"{k}={v}")
                                headers["Cookie"] = "; ".join(cookie_parts)
                                request_id = str(uuid.uuid4())
                                timestamp_ms = int(time.time() * 1000)
                                query_params["requestId"] = request_id
                                query_params["user_id"] = self._user_id or ""
                                query_params["timestamp"] = str(timestamp_ms)
                                query_params["signature_timestamp"] = str(timestamp_ms)
                                signature = self._generate_signature(
                                    prompt_text, self._user_id or "",
                                    request_id, timestamp_ms,
                                )
                                headers["X-Signature"] = signature
                                return False  # Retry
                            raise RuntimeError(f"Z.ai {stream.status_code}: {error_body[:300]}")

                        if stream.status_code != 200:
                            error_body = ""
                            async for chunk in stream.aiter_text():
                                error_body += chunk
                            raise RuntimeError(f"Z.ai {stream.status_code}: {error_body[:300]}")

                        # Parse SSE stream into document buffer
                        async for line in stream.aiter_lines():
                            if not line.startswith("data: "):
                                continue
                            data_str = line[6:].strip()

                            if data_str == "[DONE]" or data_str == '{"data":"[DONE]"}':
                                break

                            try:
                                event = json.loads(data_str)
                            except json.JSONDecodeError:
                                continue

                            event_data = event.get("data", event)
                            if isinstance(event_data, str):
                                if event_data == "[DONE]":
                                    break
                                continue

                            phase_val = event_data.get("phase", "")
                            delta = event_data.get("delta_content", "")
                            edit = event_data.get("edit_content", "")
                            edit_idx = event_data.get("edit_index")

                            # ── Native tool call detection ──
                            if phase_val == "tool_call" and edit:
                                doc_buffer.append(edit)
                                output_tokens += 1

                            if delta:
                                doc_buffer.append(delta)
                                output_tokens += 1

                            if edit and edit_idx is not None and phase_val != "tool_call":
                                current_doc = "".join(doc_buffer)
                                if edit_idx >= len(current_doc):
                                    doc_buffer.append(edit)
                                else:
                                    new_doc = current_doc[:edit_idx] + edit
                                    doc_buffer = [new_doc]
                                output_tokens += 1

                            if event_data.get("done"):
                                break

                            usage_data = event_data.get("usage", {})
                            if usage_data:
                                estimated_input_tokens = usage_data.get("prompt_tokens", estimated_input_tokens)
                                output_tokens = max(output_tokens, usage_data.get("completion_tokens", output_tokens))

                    return True  # Success

                # Wrap stream in 180s timeout to prevent infinite hangs
                try:
                    success = await asyncio.wait_for(_stream_direct(), timeout=180.0)
                except asyncio.TimeoutError:
                    logger.warning("zai_stream_timeout", attempt=attempt,
                                   msg="Stream hung (180s timeout)")
                    if attempt < max_retries - 1:
                        continue
                    raise RuntimeError("Z.ai stream timed out after 180s")

                if success:
                    break  # Exit retry loop
                continue  # Retry (returned False)

            except httpx.ReadTimeout:
                if attempt < max_retries - 1:
                    logger.warning("zai_timeout_retrying", attempt=attempt)
                    continue
                raise

        # Parse the streamed response into a ZaiResponse
        return self._parse_streamed_response(
            doc_buffer=doc_buffer,
            native_tool_calls=native_tool_calls,
            output_tokens=output_tokens,
            estimated_input_tokens=estimated_input_tokens,
            phase=phase,
            target=target,
            tools=tools,
        )

    # ── Shared response parsing ────────────────────────────────────

    def _parse_streamed_response(
        self,
        doc_buffer: list[str],
        native_tool_calls: list[ZaiToolUseBlock],
        output_tokens: int,
        estimated_input_tokens: int,
        phase: str,
        target: str,
        tools: list[dict[str, Any]],
    ) -> ZaiResponse:
        """Parse SSE doc buffer into a ZaiResponse.

        Shared by both direct and proxy-pool call paths.
        """
        full_doc = "".join(doc_buffer)

        # Extract <glm_block> tool calls from the full document
        for glm_match in re.finditer(
            r'<glm_block\s+tool_call_name="([^"]+)">(.*?)</glm_block>',
            full_doc, re.DOTALL,
        ):
            tool_name = glm_match.group(1)
            raw_block = glm_match.group(2)
            try:
                block_data = json.loads(raw_block)
                metadata = block_data.get("data", {}).get("metadata", {})
                args_str = metadata.get("arguments", "{}")
                args = json.loads(args_str) if isinstance(args_str, str) else args_str
                call_id = metadata.get("id", f"call_{uuid.uuid4().hex[:24]}")
                native_tool_calls.append(ZaiToolUseBlock(
                    id=call_id, name=tool_name, input=args,
                ))
                logger.info("zai_tool_call_detected", name=tool_name, args=args)
            except (json.JSONDecodeError, KeyError) as e:
                logger.warning("zai_tool_call_parse_error", error=str(e),
                               raw_content=raw_block[:200])
                # Fallback: extract arguments with regex
                args_match = re.search(r'"arguments"\s*:\s*"((?:[^"\\]|\\.)*)"', raw_block)
                if args_match:
                    try:
                        decoded = args_match.group(1).replace('\\"', '"')
                        args = json.loads(decoded)
                        native_tool_calls.append(ZaiToolUseBlock(
                            id=f"call_{uuid.uuid4().hex[:24]}",
                            name=tool_name, input=args,
                        ))
                        logger.info("zai_tool_call_fallback_ok", name=tool_name, args=args)
                    except json.JSONDecodeError:
                        # Last resort: just pass the tool name with empty args
                        native_tool_calls.append(ZaiToolUseBlock(
                            id=f"call_{uuid.uuid4().hex[:24]}",
                            name=tool_name, input={},
                        ))
                        logger.warning("zai_tool_call_empty_args", name=tool_name)

        # Remove <glm_block>...</glm_block> from the document
        full_doc = re.sub(
            r'<glm_block\s+tool_call_name="[^"]*">.*?</glm_block>',
            '', full_doc, flags=re.DOTALL,
        )

        # Strip <details type="reasoning"...>...</details> block to get answer
        thinking_text = ""
        _details_pattern = re.compile(
            r'<details\s+type="reasoning"[^>]*>.*?</details>\s*',
            re.DOTALL,
        )
        details_match = _details_pattern.search(full_doc)
        if details_match:
            thinking_text = details_match.group(0)
            full_text = full_doc[:details_match.start()] + full_doc[details_match.end():]
        else:
            # No thinking block — might be unclosed. Try stripping from <details to end of thinking
            _unclosed_pattern = re.compile(
                r'<details\s+type="reasoning"[^>]*>.*',
                re.DOTALL,
            )
            unclosed_match = _unclosed_pattern.search(full_doc)
            if unclosed_match:
                # Find where answer text starts (after the > prefixed lines)
                rest = full_doc[unclosed_match.start():]
                # Look for the first line NOT starting with > after a blank line
                lines = rest.split("\n")
                answer_start = len(rest)
                in_thinking = True
                for i, line in enumerate(lines):
                    stripped = line.strip()
                    if in_thinking:
                        if stripped.startswith(">") or stripped == "" or stripped.startswith("<details"):
                            continue
                        elif stripped.startswith("</details"):
                            in_thinking = False
                            continue
                        else:
                            # First non-thinking line
                            answer_start = sum(len(l) + 1 for l in lines[:i])
                            break
                thinking_text = rest[:answer_start]
                full_text = rest[answer_start:]
            else:
                full_text = full_doc

        full_text = full_text.strip()

        logger.info("zai_response", text_len=len(full_text), thinking_len=len(thinking_text),
                     output_tokens=output_tokens,
                     native_tool_calls=len(native_tool_calls))

        # Combine native tool calls (from <glm_block>) with text-parsed tool calls
        # Native tool calls take priority (more reliable)
        all_tool_calls = list(native_tool_calls)

        # If no native tool calls, try parsing from text (fallback)
        if not all_tool_calls:
            clean_text, text_tool_calls = _extract_tool_calls(full_text)
            all_tool_calls = text_tool_calls
            if not all_tool_calls and full_text.strip():
                logger.warning("zai_no_tool_calls_in_text",
                             text_preview=full_text[:300],
                             text_len=len(full_text))
        else:
            clean_text = full_text

        # Build content blocks (thinking first, then text, then tool calls)
        content: list[ZaiThinkingBlock | ZaiTextBlock | ZaiToolUseBlock] = []
        if thinking_text:
            # Strip <details> tags to get raw thinking content
            raw_thinking = re.sub(
                r'<details\s+type="reasoning"[^>]*>\s*', '', thinking_text,
            )
            raw_thinking = re.sub(r'\s*</details>\s*', '', raw_thinking)
            # Strip leading > quote markers from each line
            raw_thinking = "\n".join(
                line.lstrip("> ") for line in raw_thinking.split("\n")
            ).strip()
            if raw_thinking:
                content.append(ZaiThinkingBlock(raw_thinking))
        if clean_text:
            content.append(ZaiTextBlock(clean_text))
        content.extend(all_tool_calls)

        # Determine stop reason
        stop_reason = "tool_use" if all_tool_calls else "end_turn"

        # Record (zero) cost — it's free
        usage = ZaiUsage(
            input_tokens=estimated_input_tokens,
            output_tokens=output_tokens,
        )

        self._total_calls += 1
        self._total_input_tokens += estimated_input_tokens
        self._total_output_tokens += output_tokens

        # Record zero cost in budget (track usage but $0)
        self.budget.record_cost(
            phase=phase,
            model=f"zai-{self.model}",
            input_tokens=estimated_input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=0,
            cache_creation_tokens=0,
            target=target,
        )

        return ZaiResponse(content=content, stop_reason=stop_reason, usage=usage)

    # ── Proxy pool call path ──────────────────────────────────────

    async def _call_via_proxy_pool(
        self,
        url: str,
        query_params: dict[str, str],
        headers: dict[str, str],
        body: dict[str, Any],
        prompt_text: str,
        estimated_input_tokens: int,
        phase: str,
        target: str,
        tools: list[dict[str, Any]],
    ) -> ZaiResponse:
        """Route Z.ai call through proxy pool with per-proxy rate limiting."""
        from ai_brain.active.proxy_pool import ProxyPool  # noqa: F811

        max_retries = 5
        last_error: Exception | None = None
        _call_start = time.time()
        _max_total_time = 600.0  # 10 min max for entire proxy call (all retries)

        for attempt in range(max_retries):
            # Hard time limit across all retries
            if time.time() - _call_start > _max_total_time:
                logger.error("zai_proxy_total_timeout", elapsed=time.time() - _call_start)
                break
            try:
                proxy = await self.proxy_pool.acquire()
            except RuntimeError as e:
                # No healthy proxies available — wait and retry
                logger.warning("zai_proxy_acquire_failed", error=str(e), attempt=attempt)
                await asyncio.sleep(5 * (attempt + 1))
                continue
            try:
                # Ensure this proxy has a Z.ai guest session
                # Wrap in 30s timeout to prevent hanging on dead proxies
                try:
                    await asyncio.wait_for(
                        self.proxy_pool.ensure_proxy_session(proxy), timeout=30.0
                    )
                except asyncio.TimeoutError:
                    self.proxy_pool.release(proxy, success=False)
                    logger.warning("zai_proxy_session_timeout", proxy=proxy.url[:30])
                    last_error = RuntimeError(f"Session setup timeout via {proxy.url[:30]}")
                    continue

                # Override auth with proxy's session
                p_headers = dict(headers)
                p_headers["Authorization"] = f"Bearer {proxy.zai_token}"
                cookie_parts = [f"token={proxy.zai_token}"]
                for k, v in proxy.zai_cookies.items():
                    if k != "token":
                        cookie_parts.append(f"{k}={v}")
                p_headers["Cookie"] = "; ".join(cookie_parts)

                # Re-sign with proxy's user_id
                p_params = dict(query_params)
                p_params["user_id"] = proxy.zai_user_id or ""
                request_id = str(uuid.uuid4())
                timestamp_ms = int(time.time() * 1000)
                p_params["requestId"] = request_id
                p_params["timestamp"] = str(timestamp_ms)
                p_params["signature_timestamp"] = str(timestamp_ms)
                signature = self._generate_signature(
                    prompt_text, proxy.zai_user_id or "",
                    request_id, timestamp_ms,
                )
                p_headers["X-Signature"] = signature

                client = self.proxy_pool.get_http_client(proxy)

                # Stream the response (same SSE parsing as direct path)
                doc_buffer: list[str] = []
                native_tool_calls: list[ZaiToolUseBlock] = []
                output_tokens = 0

                async def _stream_via_proxy() -> ZaiResponse | None:
                    """Stream Z.ai response via proxy, returns None on retriable error."""
                    nonlocal doc_buffer, native_tool_calls, output_tokens
                    nonlocal estimated_input_tokens, last_error

                    async with client.stream(
                        "POST", url, params=p_params,
                        headers=p_headers, json=body,
                    ) as stream:
                        if stream.status_code in (400, 403, 405, 429):
                            error_body = ""
                            async for chunk in stream.aiter_text():
                                error_body += chunk
                            logger.warning(
                                "zai_proxy_http_error",
                                status=stream.status_code,
                                proxy=proxy.url[:30],
                                body=error_body[:300],
                                attempt=attempt,
                            )
                            if stream.status_code in (403, 405):
                                self.proxy_pool.invalidate_proxy_session(proxy)
                            self.proxy_pool.release(proxy, success=False)
                            last_error = RuntimeError(f"Z.ai {stream.status_code} via {proxy.url[:30]}")
                            return None

                        if stream.status_code != 200:
                            error_body = ""
                            async for chunk in stream.aiter_text():
                                error_body += chunk
                            self.proxy_pool.release(proxy, success=False)
                            last_error = RuntimeError(f"Z.ai {stream.status_code} via {proxy.url[:30]}: {error_body[:300]}")
                            return None

                        # Parse SSE stream
                        async for line in stream.aiter_lines():
                            if not line.startswith("data: "):
                                continue
                            data_str = line[6:].strip()

                            if data_str == "[DONE]" or data_str == '{"data":"[DONE]"}':
                                break

                            try:
                                event = json.loads(data_str)
                            except json.JSONDecodeError:
                                continue

                            event_data = event.get("data", event)
                            if isinstance(event_data, str):
                                if event_data == "[DONE]":
                                    break
                                continue

                            phase_val = event_data.get("phase", "")
                            delta = event_data.get("delta_content", "")
                            edit = event_data.get("edit_content", "")
                            edit_idx = event_data.get("edit_index")

                            if phase_val == "tool_call" and edit:
                                doc_buffer.append(edit)
                                output_tokens += 1

                            if delta:
                                doc_buffer.append(delta)
                                output_tokens += 1

                            if edit and edit_idx is not None and phase_val != "tool_call":
                                current_doc = "".join(doc_buffer)
                                if edit_idx >= len(current_doc):
                                    doc_buffer.append(edit)
                                else:
                                    new_doc = current_doc[:edit_idx] + edit
                                    doc_buffer = [new_doc]
                                output_tokens += 1

                            if event_data.get("done"):
                                break

                            usage_data = event_data.get("usage", {})
                            if usage_data:
                                estimated_input_tokens = usage_data.get(
                                    "prompt_tokens", estimated_input_tokens,
                                )
                                output_tokens = max(
                                    output_tokens,
                                    usage_data.get("completion_tokens", output_tokens),
                                )

                    self.proxy_pool.release(proxy, success=True)
                    return self._parse_streamed_response(
                        doc_buffer=doc_buffer,
                        native_tool_calls=native_tool_calls,
                        output_tokens=output_tokens,
                        estimated_input_tokens=estimated_input_tokens,
                        phase=phase,
                        target=target,
                        tools=tools,
                    )

                # Wrap entire stream in a 120s timeout to prevent infinite hangs
                # when proxy dies mid-stream after sending HTTP 200
                try:
                    result = await asyncio.wait_for(_stream_via_proxy(), timeout=120.0)
                except asyncio.TimeoutError:
                    self.proxy_pool.release(proxy, success=False)
                    logger.warning(
                        "zai_proxy_stream_timeout",
                        proxy=proxy.url[:30],
                        attempt=attempt,
                        msg="Proxy hung mid-stream (180s timeout)",
                    )
                    last_error = RuntimeError(f"Stream timeout via {proxy.url[:30]}")
                    continue

                if result is not None:
                    return result
                # result is None → retriable error, continue to next attempt

            except Exception as e:
                self.proxy_pool.release(proxy, success=False)
                last_error = e
                logger.warning(
                    "zai_proxy_call_failed",
                    proxy=proxy.url[:30],
                    error=str(e),
                    attempt=attempt,
                )
                # Backoff before retry
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 * (attempt + 1))

        # All retries exhausted — return error response instead of crashing
        logger.error("zai_proxy_all_retries_failed", error=str(last_error))
        return ZaiResponse(
            content=[{"type": "text", "text": f"[ERROR: All {max_retries} proxy retries failed: {last_error}]"}],
            stop_reason="error",
            usage=ZaiUsage(input_tokens=estimated_input_tokens, output_tokens=0),
        )

    def select_model(self, task_tier: str) -> str:
        """Always returns the Z.ai model."""
        return f"zai-{self.model}"

    async def close(self) -> None:
        """Close the HTTP client."""
        await self._http.aclose()
