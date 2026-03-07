"""ChatGPT.com anonymous client — drop-in replacement for ClaudeClient.

Provides free GPT-4o-mini (unlimited) or GPT-5-2 via ChatGPT's anonymous
backend. Uses Goja TLS proxy for Chrome fingerprinting, plus the full
5-token challenge pipeline (VM → Sentinel → PoW → Turnstile → Conduit).

Adapted from realasfngl/ChatGPT + custom Goja integration.

Returns mock Anthropic-compatible response objects so brain_node()
works without modification.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
import uuid
from random import choice, randint, random
from typing import Any

import httpx
import structlog

from ai_brain.active.goja_manager import GojaManager
from ai_brain.active.chatgpt_reverse import Challenges, VM

logger = structlog.get_logger("chatgpt_client")

# Window keys for VM fingerprint
_WINDOW_KEYS = [
    "0", "window", "self", "document", "name", "location",
    "customElements", "history", "navigation", "locationbar",
    "menubar", "personalbar", "scrollbars", "statusbar", "toolbar",
]

# Sec-CH-UA header matching Chrome 140
_SEC_CH_UA = '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"'
_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36"
)


# ── Mock Anthropic-compatible response objects ──────────────────────────

class ChatGPTTextBlock:
    """Mimics anthropic.types.TextBlock."""
    def __init__(self, text: str):
        self.type = "text"
        self.text = text


class ChatGPTToolUseBlock:
    """Mimics anthropic.types.ToolUseBlock."""
    def __init__(self, id: str, name: str, input: dict):
        self.type = "tool_use"
        self.id = id
        self.name = name
        self.input = input


class ChatGPTUsage:
    """Mimics anthropic.types.Usage."""
    def __init__(self, input_tokens: int = 0, output_tokens: int = 0):
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.cache_read_input_tokens = 0
        self.cache_creation_input_tokens = 0


class ChatGPTResponse:
    """Mimics anthropic.types.Message."""
    def __init__(self, content: list, stop_reason: str, usage: ChatGPTUsage):
        self.content = content
        self.stop_reason = stop_reason
        self.usage = usage


# ── Tool call extraction (reuse from ZaiClient patterns) ──────────────

_TOOL_CALL_PATTERN = re.compile(
    r'<tool_call>\s*(\{.*?\})\s*</tool_call>',
    re.DOTALL,
)


def _try_parse_tool_json(text: str) -> dict | None:
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "name" in data:
            return {
                "name": data["name"],
                "input": data.get("input", data.get("parameters", {})),
            }
    except json.JSONDecodeError:
        pass
    return None


def _extract_tool_calls(text: str) -> tuple[str, list[ChatGPTToolUseBlock]]:
    """Extract tool calls from ChatGPT text output.

    Supports multiple formats (ChatGPT varies its output):
    1. <tool_call>{"name": "...", "input": {...}}</tool_call>
    2. JSON object on its own line: {"name": "...", "input": {...}}
    3. ```json {"name": "...", "input": {...}} ```
    4. JSON object at end of text (brace-balanced)
    """
    tool_calls: list[ChatGPTToolUseBlock] = []
    lines_to_remove: list[str] = []

    # Format 1: <tool_call> tags (ChatGPT often uses this format)
    for match in _TOOL_CALL_PATTERN.finditer(text):
        parsed = _try_parse_tool_json(match.group(1))
        if parsed:
            tool_calls.append(ChatGPTToolUseBlock(
                id=f"toolu_{uuid.uuid4().hex[:24]}",
                name=parsed["name"],
                input=parsed["input"],
            ))
            lines_to_remove.append(match.group(0))

    # Format 2: JSON object on its own line
    if not tool_calls:
        for line in text.split("\n"):
            stripped = line.strip()
            if stripped.startswith("{") and stripped.endswith("}") and '"name"' in stripped:
                parsed = _try_parse_tool_json(stripped)
                if parsed:
                    tool_calls.append(ChatGPTToolUseBlock(
                        id=f"toolu_{uuid.uuid4().hex[:24]}",
                        name=parsed["name"],
                        input=parsed["input"],
                    ))
                    lines_to_remove.append(line)

    # Format 3: JSON in code blocks (handles ```json on same or separate line)
    if not tool_calls:
        for match in re.finditer(
            r'```(?:\s*json)?\s*(\{[^`]*"name"[^`]*\})\s*```',
            text, re.DOTALL,
        ):
            parsed = _try_parse_tool_json(match.group(1).strip())
            if parsed:
                tool_calls.append(ChatGPTToolUseBlock(
                    id=f"toolu_{uuid.uuid4().hex[:24]}",
                    name=parsed["name"],
                    input=parsed["input"],
                ))
                lines_to_remove.append(match.group(0))

    # Format 4: Brace-balanced JSON anywhere in text (find all { that could start a tool call)
    if not tool_calls and '"name"' in text:
        i = 0
        while i < len(text):
            if text[i] == '{':
                # Find matching closing brace
                depth = 0
                for j in range(i, len(text)):
                    if text[j] == '{':
                        depth += 1
                    elif text[j] == '}':
                        depth -= 1
                        if depth == 0:
                            candidate = text[i:j + 1]
                            if '"name"' in candidate:
                                parsed = _try_parse_tool_json(candidate)
                                if parsed:
                                    tool_calls.append(ChatGPTToolUseBlock(
                                        id=f"toolu_{uuid.uuid4().hex[:24]}",
                                        name=parsed["name"],
                                        input=parsed["input"],
                                    ))
                                    lines_to_remove.append(candidate)
                            break
            i += 1
            if tool_calls:
                break

    clean_text = text
    for item in lines_to_remove:
        clean_text = clean_text.replace(item, "", 1)

    return clean_text.strip(), tool_calls


# ── ChatGPT Client ────────────────────────────────────────────────────

class ChatGPTClient:
    """ChatGPT anonymous client via Goja TLS proxy.

    Usage:
        client = ChatGPTClient(budget=budget_manager, config=ai_config)
        response = await client.call_with_tools(
            phase="active_testing",
            task_tier="complex",
            system_blocks=[...],
            messages=[...],
            tools=[...],
        )
        await client.close()
    """

    def __init__(
        self,
        budget: Any,
        config: Any,
        model: str = "auto",
        goja_port: int = 1082,
    ):
        self.budget = budget
        self.config = config
        self.model = model
        self.demo_mode = False

        # Goja TLS proxy
        self._goja = GojaManager(port=goja_port)
        self._goja_started = False

        # Session state
        self._http: httpx.AsyncClient | None = None
        self._device_id: str = ""
        self._prod: str = ""  # Build version from HTML
        self._sid: str = str(uuid.uuid4())
        self._start_time: int = 0
        self._config: list[Any] = []
        self._reacts: list[str] = []
        self._session_valid: bool = False

        # Conversation state
        self._conversation_id: str | None = None
        self._parent_message_id: str = "client-created-root"

        # Stats
        self._total_calls = 0
        self._total_input_tokens = 0
        self._total_output_tokens = 0

    # ── Goja + Session Management ──────────────────────────────────

    @staticmethod
    def _kill_stale_goja(port: int) -> None:
        """Kill any stale Goja process bound to our port."""
        import subprocess as _sp
        try:
            out = _sp.check_output(
                ["lsof", "-ti", f":{port}"], text=True, timeout=5,
            ).strip()
            for pid in out.split("\n"):
                pid = pid.strip()
                if pid and pid.isdigit():
                    _sp.run(["kill", "-9", pid], timeout=5)
                    logger.info("chatgpt_killed_stale_goja", pid=int(pid), port=port)
        except Exception:
            pass

    async def _ensure_goja(self) -> None:
        """Start Goja TLS proxy if not running."""
        if self._goja_started:
            return
        # Kill any stale process on our port (from previous unclean shutdown)
        self._kill_stale_goja(self._goja.port)
        await asyncio.sleep(0.3)  # Brief wait for port release
        await self._goja.start(timeout=15)
        self._goja_started = True
        self._http = httpx.AsyncClient(
            timeout=httpx.Timeout(60.0, connect=15.0),
            verify=False,
            proxy=self._goja.socks5_url,
            follow_redirects=True,
        )
        logger.info("chatgpt_goja_started", port=self._goja.port)

    async def _init_session(self) -> None:
        """Load chatgpt.com page to get cookies + build ID."""
        if self._session_valid:
            return

        await self._ensure_goja()

        logger.info("chatgpt_initializing_session")

        # Load main page with browser-like headers
        page_headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'pragma': 'no-cache',
            'priority': 'u=0, i',
            'sec-ch-ua': _SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
            'user-agent': _USER_AGENT,
        }

        resp = await self._http.get("https://chatgpt.com/", headers=page_headers)

        if resp.status_code != 200:
            raise RuntimeError(
                f"ChatGPT page load failed: {resp.status_code} "
                f"(may need proxy or IP is flagged)"
            )

        # Extract build ID
        if 'data-build="' in resp.text:
            self._prod = resp.text.split('data-build="')[1].split('"')[0]
        else:
            self._prod = "prod-e7a7b915adec7d72efb89ce3910e416eb7d173e0"

        # Get device ID from cookies
        self._device_id = ""
        for name, value in resp.cookies.items():
            if name == 'oai-did':
                self._device_id = value
                break
        if not self._device_id:
            self._device_id = str(uuid.uuid4())

        self._start_time = int(time.time() * 1000)
        self._sid = str(uuid.uuid4())

        # Build react container IDs
        self._reacts = [
            "location",
            "__reactContainer$" + self._gen_react(),
            "_reactListening" + self._gen_react(),
        ]

        # Build VM config
        self._config = [
            4880,
            time.strftime(
                "%a %b %d %Y %H:%M:%S GMT+0000 (Coordinated Universal Time)"
            ),
            4294705152,
            1,
            _USER_AGENT,
            None,
            self._prod,
            "en-US",
            "en-US,en",
            0,
            "webkitGetUserMedia\u2212function webkitGetUserMedia() { [native code] }",
            choice(self._reacts),
            choice(_WINDOW_KEYS),
            randint(800, 1400) + random(),
            self._sid,
            "",
            20,
            self._start_time,
        ]

        self._session_valid = True
        self._conversation_id = None
        self._parent_message_id = "client-created-root"

        logger.info(
            "chatgpt_session_ready",
            build=self._prod[:30],
            device_id=self._device_id[:12],
        )

    def _invalidate_session(self) -> None:
        """Force session refresh on next call."""
        self._session_valid = False
        self._conversation_id = None
        self._parent_message_id = "client-created-root"

    @staticmethod
    def _gen_react() -> str:
        n = random()
        base36 = ''
        chars = '0123456789abcdefghijklmnopqrstuvwxyz'
        x = int(n * 36**10)
        for _ in range(10):
            x, r = divmod(x, 36)
            base36 = chars[r] + base36
        return base36

    def _api_headers(self) -> dict[str, str]:
        """Base headers for API calls."""
        return {
            'accept': '*/*',
            'accept-language': 'en-US,en;q=0.9',
            'cache-control': 'no-cache',
            'content-type': 'application/json',
            'oai-client-version': self._prod,
            'oai-device-id': self._device_id,
            'oai-language': 'en-US',
            'origin': 'https://chatgpt.com',
            'pragma': 'no-cache',
            'priority': 'u=1, i',
            'referer': 'https://chatgpt.com/',
            'sec-ch-ua': _SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors',
            'sec-fetch-site': 'same-origin',
            'user-agent': _USER_AGENT,
        }

    # ── Token Pipeline ─────────────────────────────────────────────

    async def _get_tokens(self) -> dict[str, str]:
        """Run the full 5-token challenge pipeline.

        Returns dict with keys: requirements_token, pow_token,
        turnstile_token, conduit_token.
        """
        await self._init_session()

        # 1. Generate VM token
        config = list(self._config)  # Copy
        config[3] = 1
        config[9] = round(time.time() * 1000 - self._start_time)
        vm_token = "gAAAAAC" + Challenges.encode(config)

        # 2. Get sentinel requirements
        sentinel_resp = await self._http.post(
            "https://chatgpt.com/backend-anon/sentinel/chat-requirements",
            headers=self._api_headers(),
            json={"p": vm_token},
        )

        if sentinel_resp.status_code != 200:
            self._invalidate_session()
            raise RuntimeError(
                f"Sentinel failed: {sentinel_resp.status_code} "
                f"{sentinel_resp.text[:200]}"
            )

        reqs = sentinel_resp.json()
        requirements_token = reqs.get("token", "")
        pow_data = reqs.get("proofofwork", {})
        turnstile_data = reqs.get("turnstile", {})

        force_login = reqs.get("force_login")
        if force_login:
            logger.warning("chatgpt_force_login_detected")

        logger.info(
            "chatgpt_sentinel",
            persona=reqs.get("persona"),
            pow_required=pow_data.get("required"),
            turnstile_required=turnstile_data.get("required"),
            force_login=force_login,
        )

        # 3. Solve PoW
        pow_token = ""
        if pow_data.get("required"):
            config2 = list(self._config)
            config2[3] = random()
            config2[9] = round(time.time() * 1000 - self._start_time)
            pow_token = Challenges.solve_pow(
                pow_data["seed"], pow_data["difficulty"], config2
            ) or ""
            logger.info("chatgpt_pow_solved", token_prefix=pow_token[:30])

        # 4. Decompile Turnstile bytecode
        turnstile_token = ""
        turnstile_dx = turnstile_data.get("dx", "")
        if turnstile_dx:
            ip_info = ["0.0.0.0", "Unknown", "Unknown", "0", "0"]
            turnstile_token = VM.get_turnstile(turnstile_dx, vm_token, str(ip_info))
            logger.info(
                "chatgpt_turnstile_solved",
                token_len=len(turnstile_token),
            )

        # 5. Get conduit token
        conduit_token = ""
        conduit_body = {
            'action': 'next',
            'fork_from_shared_post': False,
            'parent_message_id': self._parent_message_id,
            'model': self.model,
            'timezone_offset_min': -300,
            'timezone': 'America/New_York',
            'history_and_training_disabled': True,
            'conversation_mode': {'kind': 'primary_assistant'},
            'system_hints': [],
            'supports_buffering': True,
            'supported_encodings': ['v1'],
        }
        if self._conversation_id:
            conduit_body['conversation_id'] = self._conversation_id

        conduit_headers = {**self._api_headers(), 'x-conduit-token': 'no-token'}
        conduit_resp = await self._http.post(
            "https://chatgpt.com/backend-anon/f/conversation/prepare",
            headers=conduit_headers,
            json=conduit_body,
        )
        if conduit_resp.status_code == 200:
            try:
                cdata = conduit_resp.json()
                conduit_token = cdata.get("conduit_token", "")
            except Exception:
                pass
        if conduit_token:
            logger.info("chatgpt_conduit_token", token_prefix=conduit_token[:30])

        return {
            "requirements_token": requirements_token,
            "pow_token": pow_token,
            "turnstile_token": turnstile_token,
            "conduit_token": conduit_token,
        }

    # ── Message Conversion ─────────────────────────────────────────

    @staticmethod
    def _format_tools_instruction(tools: list[dict[str, Any]]) -> str:
        """Format tools as text instruction for ChatGPT system prompt."""
        lines = [
            "\n# CRITICAL: TOOL CALLING FORMAT",
            "",
            "You are a tool-calling agent. You CANNOT execute code yourself.",
            "You MUST call tools by outputting a JSON object on its OWN LINE.",
            "The JSON must be a SINGLE LINE (no line breaks inside the JSON).",
            "",
            "CORRECT FORMAT (copy this pattern exactly):",
            '{"name": "crawl_target", "input": {"start_url": "http://example.com", "max_pages": 30}}',
            "",
            "WRONG (DO NOT DO THESE):",
            "- Do NOT write Python/JavaScript code",
            "- Do NOT use ```json code blocks",
            "- Do NOT split JSON across multiple lines",
            "- Do NOT describe what you would do without calling a tool",
            "",
            "RULES:",
            "1. EVERY response MUST contain exactly one JSON tool call on its own line.",
            "2. You may add brief reasoning text BEFORE the JSON line.",
            "3. The JSON line must start with { and end with } on the SAME line.",
            "4. After the JSON line, do NOT add any more text.",
            "",
            "AVAILABLE TOOLS:",
        ]

        for tool in tools:
            name = tool["name"]
            desc = tool.get("description", "")[:150]
            schema = tool.get("input_schema", {})
            required = schema.get("required", [])
            props = schema.get("properties", {})

            params = []
            for pname, pdef in props.items():
                ptype = pdef.get("type", "str")
                req = "*" if pname in required else ""
                params.append(f"{pname}{req}:{ptype}")
            param_str = ", ".join(params) if params else "(none)"
            lines.append(f"- {name}({param_str}): {desc}")

        return "\n".join(lines)

    @staticmethod
    def _build_chatgpt_messages(
        system_text: str,
        messages: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Convert Anthropic-style messages to a single ChatGPT user prompt.

        ChatGPT anonymous doesn't support multi-turn conversation history
        in the same way. We flatten the conversation into the message content,
        prepending system instructions.
        """
        parts = []

        for msg in messages:
            role = msg.get("role", "user")
            content = msg.get("content", "")

            if isinstance(content, str):
                parts.append(f"[{role}]: {content}")
            elif isinstance(content, list):
                text_parts = []
                for block in content:
                    if isinstance(block, dict):
                        btype = block.get("type", "text")
                        if btype == "text":
                            text_parts.append(block.get("text", ""))
                        elif btype == "tool_use":
                            name = block.get("name", "?")
                            inp = block.get("input", {})
                            text_parts.append(
                                f"<tool_call>{json.dumps({'name': name, 'input': inp}, default=str)[:1000]}</tool_call>"
                            )
                        elif btype == "tool_result":
                            result_content = block.get("content", "")
                            if isinstance(result_content, list):
                                result_content = "\n".join(
                                    b.get("text", "") for b in result_content
                                    if isinstance(b, dict)
                                )
                            if len(result_content) > 4000:
                                result_content = result_content[:4000] + "\n... [truncated]"
                            text_parts.append(f"[Tool result]: {result_content}")
                    elif isinstance(block, str):
                        text_parts.append(block)

                if text_parts:
                    parts.append(f"[{role}]: " + "\n".join(text_parts))

        # Build the full message for ChatGPT
        full_prompt = system_text + "\n\n--- CONVERSATION ---\n\n" + "\n\n".join(parts)

        return full_prompt

    # ── Parse SSE Response ─────────────────────────────────────────

    @staticmethod
    def _parse_sse(text: str) -> str:
        """Parse ChatGPT SSE stream (v1 encoding) into response text.

        v1 encoding uses patch/append operations:
        - {"o": "patch", "v": [{"p": "/message/content/parts/0", "o": "append", "v": "text"}]}
        - {"v": [{"p": "/message/content/parts/0", "o": "append", "v": "text"}]}  (implicit patch)
        - {"o": "append", "p": "/message/content/parts/0", "v": "text"}  (direct append)
        """
        result_parts = []
        for line in text.split("\n"):
            if not line.startswith("data: "):
                continue
            ds = line[6:].strip()
            if ds == "[DONE]":
                break
            try:
                evt = json.loads(ds)
            except json.JSONDecodeError:
                continue

            # Skip non-dict events (e.g. raw strings like "v1")
            if not isinstance(evt, dict):
                continue

            # Helper: extract text from a list of operations
            def _collect_ops(ops):
                for op in ops:
                    if isinstance(op, dict) and op.get('o') == 'append':
                        p = op.get('p', '')
                        v = op.get('v', '')
                        if '/parts/' in p and isinstance(v, str):
                            result_parts.append(v)

            # Direct append at top level
            if evt.get('o') == 'append' and '/parts/' in evt.get('p', ''):
                v = evt.get('v', '')
                if isinstance(v, str):
                    result_parts.append(v)

            # Explicit patch: {"o": "patch", "v": [ops...]}
            elif evt.get('o') == 'patch' and isinstance(evt.get('v'), list):
                _collect_ops(evt['v'])

            # Implicit patch: {"v": [ops...]} (no "o" at top level)
            elif 'o' not in evt and isinstance(evt.get('v'), list):
                _collect_ops(evt['v'])

            # Non-v1 format (full message objects)
            msg = evt.get("message")
            if isinstance(msg, dict):
                parts = msg.get("content", {}).get("parts", [])
                status = msg.get("status", "")
                if parts and status == "finished_successfully":
                    return str(parts[0]) if parts[0] else ""

        return ''.join(result_parts)

    # ── Main API Call ──────────────────────────────────────────────

    async def call_with_tools(
        self,
        phase: str,
        task_tier: str,
        system_blocks: list[dict[str, Any]],
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        target: str = "",
        max_tokens: int | None = None,
        thinking_budget: int | None = None,
    ) -> ChatGPTResponse:
        """Send chat request to ChatGPT anonymous — compatible with ClaudeClient.

        Returns ChatGPTResponse mimicking Anthropic Message.
        """
        # ChatGPT anonymous gpt-4o-mini has a strict message length limit (~4K tokens / ~16K chars).
        # We must aggressively truncate the system prompt to fit.
        MAX_PROMPT_CHARS = 15000

        # Build system prompt
        system_parts = []
        for block in system_blocks:
            text = block.get("text", "")
            if text:
                system_parts.append(text)

        if tools:
            system_parts.append(self._format_tools_instruction(tools))

        system_text = "\n\n".join(system_parts)
        original_sys_len = len(system_text)

        # Truncate system text if needed (keep first section + tool instructions at end)
        max_sys = MAX_PROMPT_CHARS - 3000  # Reserve 3K for messages
        if len(system_text) > max_sys:
            # Keep the tool instructions (last system_part) and truncate the methodology
            tool_instructions = system_parts[-1] if tools else ""
            methodology = "\n\n".join(system_parts[:-1]) if tools else system_text

            available = max_sys - len(tool_instructions) - 100
            if available > 2000:
                system_text = (
                    methodology[:available]
                    + "\n\n... [methodology truncated] ...\n\n"
                    + tool_instructions
                )
            else:
                # Extreme truncation: just keep tool instructions
                system_text = tool_instructions[:max_sys]

            logger.info("chatgpt_prompt_truncated",
                        original_len=original_sys_len, truncated_len=len(system_text))

        # Build the prompt
        full_prompt = self._build_chatgpt_messages(system_text, messages)

        # Further truncate if still too long
        if len(full_prompt) > MAX_PROMPT_CHARS:
            full_prompt = full_prompt[:MAX_PROMPT_CHARS - 100] + "\n\n... [truncated]"
            logger.info("chatgpt_full_prompt_truncated", final_len=len(full_prompt))

        # Estimate input tokens
        estimated_input_tokens = len(full_prompt) // 4

        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Get fresh tokens for each attempt
                tokens = await self._get_tokens()

                # Build chat request
                time_1 = randint(6000, 9000)
                chat_headers = {
                    'accept': 'text/event-stream',
                    'accept-language': 'en-US,en;q=0.9',
                    'cache-control': 'no-cache',
                    'content-type': 'application/json',
                    'oai-client-version': self._prod,
                    'oai-device-id': self._device_id,
                    'oai-echo-logs': f'0,{time_1},1,{time_1 + randint(1000, 1200)}',
                    'oai-language': 'en-US',
                    'openai-sentinel-chat-requirements-token': tokens["requirements_token"],
                    'openai-sentinel-proof-token': tokens["pow_token"],
                    'openai-sentinel-turnstile-token': tokens["turnstile_token"],
                    'origin': 'https://chatgpt.com',
                    'pragma': 'no-cache',
                    'priority': 'u=1, i',
                    'referer': 'https://chatgpt.com/',
                    'sec-ch-ua': _SEC_CH_UA,
                    'sec-ch-ua-mobile': '?0',
                    'sec-ch-ua-platform': '"Windows"',
                    'sec-fetch-dest': 'empty',
                    'sec-fetch-mode': 'cors',
                    'sec-fetch-site': 'same-origin',
                    'user-agent': _USER_AGENT,
                }
                if tokens["conduit_token"]:
                    chat_headers['x-conduit-token'] = tokens["conduit_token"]

                chat_body = {
                    'action': 'next',
                    'messages': [{
                        'id': str(uuid.uuid4()),
                        'author': {'role': 'user'},
                        'create_time': round(time.time(), 3),
                        'content': {
                            'content_type': 'text',
                            'parts': [full_prompt],
                        },
                        'metadata': {
                            'selected_github_repos': [],
                            'selected_all_github_repos': False,
                            'serialization_metadata': {'custom_symbol_offsets': []},
                        },
                    }],
                    'parent_message_id': self._parent_message_id,
                    'model': self.model,
                    'timezone_offset_min': -300,
                    'timezone': 'America/New_York',
                    'history_and_training_disabled': True,
                    'conversation_mode': {'kind': 'primary_assistant'},
                    'enable_message_followups': True,
                    'system_hints': [],
                    'supports_buffering': True,
                    'supported_encodings': ['v1'],
                    'client_contextual_info': {
                        'is_dark_mode': True,
                        'time_since_loaded': randint(3, 6),
                        'page_height': 1219,
                        'page_width': 1920,
                        'pixel_ratio': 1,
                        'screen_height': 1080,
                        'screen_width': 1920,
                    },
                    'paragen_cot_summary_display_override': 'allow',
                    'force_parallel_switch': 'auto',
                }
                if self._conversation_id:
                    chat_body['conversation_id'] = self._conversation_id

                logger.info(
                    "chatgpt_sending",
                    model=self.model,
                    prompt_len=len(full_prompt),
                    attempt=attempt,
                )

                # Try both endpoints
                resp = None
                for ep in [
                    "https://chatgpt.com/backend-anon/f/conversation",
                    "https://chatgpt.com/backend-anon/conversation",
                ]:
                    resp = await self._http.post(
                        ep, headers=chat_headers, json=chat_body,
                    )
                    if resp.status_code == 200:
                        break
                    elif resp.status_code in (401, 403):
                        logger.warning(
                            "chatgpt_endpoint_failed",
                            endpoint=ep,
                            status=resp.status_code,
                            body=resp.text[:200],
                        )
                        continue
                    else:
                        break

                if resp.status_code != 200:
                    error_msg = resp.text[:300] if resp else "no response"
                    if attempt < max_retries - 1:
                        logger.warning(
                            "chatgpt_retrying",
                            status=resp.status_code,
                            error=error_msg,
                            attempt=attempt,
                        )
                        self._invalidate_session()
                        await asyncio.sleep(2)
                        continue
                    raise RuntimeError(f"ChatGPT {resp.status_code}: {error_msg}")

                # Parse response
                full_text = self._parse_sse(resp.text)

                # Track conversation for multi-turn
                try:
                    # Extract conversation_id from SSE data
                    for line in resp.text.split("\n"):
                        if '"conversation_id"' in line and line.startswith("data: "):
                            evt = json.loads(line[6:].strip())
                            if 'conversation_id' in evt:
                                self._conversation_id = evt['conversation_id']
                            if 'message_id' in evt:
                                self._parent_message_id = evt['message_id']
                            break
                except Exception:
                    pass

                estimated_output_tokens = len(full_text) // 4

                logger.info(
                    "chatgpt_response",
                    text_len=len(full_text),
                    output_tokens=estimated_output_tokens,
                )

                # Extract tool calls
                clean_text, tool_calls = _extract_tool_calls(full_text)

                # Build content blocks
                content: list[ChatGPTTextBlock | ChatGPTToolUseBlock] = []
                if clean_text:
                    content.append(ChatGPTTextBlock(clean_text))
                content.extend(tool_calls)

                stop_reason = "tool_use" if tool_calls else "end_turn"

                usage = ChatGPTUsage(
                    input_tokens=estimated_input_tokens,
                    output_tokens=estimated_output_tokens,
                )

                self._total_calls += 1
                self._total_input_tokens += estimated_input_tokens
                self._total_output_tokens += estimated_output_tokens

                # Record zero cost
                self.budget.record_cost(
                    phase=phase,
                    model=f"chatgpt-{self.model}",
                    input_tokens=estimated_input_tokens,
                    output_tokens=estimated_output_tokens,
                    cache_read_tokens=0,
                    cache_creation_tokens=0,
                    target=target,
                )

                return ChatGPTResponse(
                    content=content,
                    stop_reason=stop_reason,
                    usage=usage,
                )

            except Exception as e:
                if attempt < max_retries - 1:
                    logger.warning(
                        "chatgpt_error_retrying",
                        error=str(e),
                        attempt=attempt,
                    )
                    self._invalidate_session()
                    await asyncio.sleep(2)
                    continue
                raise

        # Should not reach here
        raise RuntimeError("ChatGPT: all retries exhausted")

    def select_model(self, task_tier: str) -> str:
        """Always returns the ChatGPT model."""
        return f"chatgpt-{self.model}"

    async def close(self) -> None:
        """Close HTTP client and stop Goja."""
        if self._http:
            await self._http.aclose()
        if self._goja_started:
            await self._goja.stop()
            self._goja_started = False
