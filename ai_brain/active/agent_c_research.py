"""Agent C — Deep Research Tool for pentesting agents.

A callable tool (not a standalone agent) that performs deep research
using Z.ai with web search + extended thinking. When Agent A or B
encounters an interesting situation, they call this tool with a
situation description. Agent C:

1. Takes the situation (target, tech stack, signs observed, question)
2. Builds a comprehensive research prompt with security context
3. Sends to Z.ai with web_search=True + enable_thinking=True
4. Waits for full response (can take 30-120s)
5. Returns structured research: techniques, CVEs, exploit approaches

Usage (from react agent tool call):
    deep_research(
        situation="API endpoint /api/v1/users returns GraphQL introspection...",
        target_url="https://example.com",
        tech_stack=["Node.js", "Express", "GraphQL"],
        question="What advanced GraphQL attack techniques should I try?"
    )
"""

from __future__ import annotations

import re
import time
from typing import Any

import structlog

logger = structlog.get_logger()

# Maximum response wait time (Z.ai deep research can be slow)
RESEARCH_TIMEOUT = 180  # 3 minutes

RESEARCH_SYSTEM_PROMPT = """You are an elite offensive security researcher with 15+ years of experience in bug bounty hunting, penetration testing, and vulnerability research. You have deep expertise in:

- Web application security (OWASP Top 10 and beyond)
- API security (REST, GraphQL, gRPC, WebSocket)
- Authentication/authorization bypass techniques
- Server-side vulnerabilities (SSRF, SSTI, deserialization, race conditions)
- Client-side attacks (XSS, CSRF, clickjacking, DOM clobbering)
- Cloud security (AWS, GCP, Azure misconfigurations)
- Mobile API security
- Cryptographic weaknesses
- Business logic flaws

You are being consulted by an automated pentesting agent that has encountered an interesting situation and needs your expert analysis. Your job is to provide ACTIONABLE, SPECIFIC attack techniques — not generic advice.

IMPORTANT:
- Search the web for recent CVEs, disclosed vulnerabilities, and techniques relevant to the exact technology stack
- Reference specific tools, payloads, and PoC code where applicable
- Think about chained attacks and edge cases that automated scanners miss
- Consider the SPECIFIC version numbers and configurations mentioned
- Look for known bypass techniques for the specific WAF/CDN/framework detected"""

RESEARCH_USER_TEMPLATE = """## Penetration Testing Research Request

### Target
{target_url}

### Technology Stack
{tech_stack}

### Current Situation
{situation}

### Specific Question
{question}

### What I've Already Tried
{already_tried}

### What I've Found So Far
{existing_findings}

---

Based on this situation, provide a detailed research response with:

1. **Relevant CVEs & Known Vulnerabilities**: Search for CVEs and disclosed vulnerabilities affecting the exact technologies and versions mentioned. Include CVE IDs, severity, and whether exploits are publicly available.

2. **Attack Techniques**: List 5-10 specific attack techniques I should try, ordered by likelihood of success. For each:
   - Technique name and category
   - Why it applies to this specific situation
   - Exact payload/request to try (curl commands, HTTP requests, or code snippets)
   - Expected response if vulnerable
   - Common bypasses if initial attempt fails

3. **Chained Attack Paths**: Describe 2-3 multi-step attack chains that combine findings. Example: "SSRF → internal metadata → cloud credentials → full compromise"

4. **Tool Recommendations**: Specific tools and their exact commands for this situation (nuclei templates, custom scripts, specific scanner flags)

5. **Edge Cases & Bypasses**: Unusual techniques that automated scanners miss — race conditions, parameter pollution, encoding tricks, HTTP/2 specific attacks, etc.

Be SPECIFIC and ACTIONABLE. Include exact payloads, not just descriptions."""


class AgentCResearch:
    """Deep research tool using Z.ai with web search."""

    def __init__(self, zai_client: Any = None, proxy_pool: Any = None):
        """
        Args:
            zai_client: Existing ZaiClient instance (reuses session/proxy pool)
            proxy_pool: ProxyPool for direct calls if no zai_client
        """
        self.zai_client = zai_client
        self.proxy_pool = proxy_pool
        self._call_count = 0
        self._total_time = 0.0

    async def research(
        self,
        situation: str,
        target_url: str = "",
        tech_stack: list[str] | None = None,
        question: str = "",
        already_tried: str = "",
        existing_findings: str = "",
    ) -> dict[str, Any]:
        """Perform deep research on a security situation.

        Returns:
            Dict with keys: research_text, techniques, cves, duration_s, success
        """
        start = time.time()
        self._call_count += 1

        # Build the research prompt
        prompt = RESEARCH_USER_TEMPLATE.format(
            target_url=target_url or "unknown",
            tech_stack=", ".join(tech_stack[:15]) if tech_stack else "unknown",
            situation=situation[:3000],
            question=question or "What attack techniques should I try next?",
            already_tried=already_tried[:1500] or "(none specified)",
            existing_findings=existing_findings[:1500] or "(none yet)",
        )

        logger.info("agent_c_research_start",
                     target=target_url,
                     situation_len=len(situation),
                     question=question[:100])

        try:
            if self.zai_client:
                result = await self._call_via_zai_client(prompt)
            else:
                result = {"error": "No Z.ai client configured", "success": False}
        except Exception as e:
            logger.error("agent_c_research_failed", error=str(e))
            result = {
                "error": str(e),
                "success": False,
                "research_text": "",
                "techniques": [],
                "cves": [],
            }

        duration = time.time() - start
        self._total_time += duration
        result["duration_s"] = round(duration, 1)

        logger.info("agent_c_research_complete",
                     duration=round(duration, 1),
                     text_len=len(result.get("research_text", "")),
                     techniques=len(result.get("techniques", [])),
                     success=result.get("success", False))

        return result

    async def _call_via_zai_client(self, prompt: str) -> dict[str, Any]:
        """Call Z.ai through the existing ZaiClient with web search enabled.

        Reuses ZaiClient.call_with_tools() with web_search=True so we get
        full proxy pool support, session management, and retry logic for free.
        """
        zai = self.zai_client

        # Build messages in Claude API format (ZaiClient converts internally)
        system_blocks = [{"type": "text", "text": RESEARCH_SYSTEM_PROMPT}]
        messages = [{"role": "user", "content": prompt}]

        response = await zai.call_with_tools(
            phase="research",
            task_tier="complex",
            system_blocks=system_blocks,
            messages=messages,
            tools=[],  # No tools — just text response
            target="agent_c_research",
            web_search=True,
        )

        # Extract text from ZaiResponse content blocks
        full_text = ""
        thinking_text = ""
        for block in response.content:
            if hasattr(block, "type"):
                if block.type == "text":
                    full_text += block.text
                elif block.type == "thinking":
                    thinking_text += block.thinking

        if not full_text:
            return {
                "error": "Z.ai returned empty response",
                "success": False,
                "research_text": "",
                "techniques": [],
                "cves": [],
            }

        # Extract structured data from response
        techniques = self._extract_techniques(full_text)
        cves = self._extract_cves(full_text)

        return {
            "success": True,
            "research_text": full_text,
            "thinking": thinking_text[:2000] if thinking_text else "",
            "techniques": techniques,
            "cves": cves,
            "search_results": [],
            "web_search_used": True,
        }

    def _extract_techniques(self, text: str) -> list[dict[str, str]]:
        """Extract attack techniques from research text."""
        techniques = []
        # Look for numbered lists or headers
        # Pattern: "1. **Technique Name**: description" or "### Technique Name"
        patterns = [
            r'\d+\.\s+\*\*([^*]+)\*\*[:\s-]+(.+?)(?=\n\d+\.|\n###|\n\*\*\d|\Z)',
            r'###\s+(.+?)\n(.+?)(?=\n###|\Z)',
        ]
        for pattern in patterns:
            for m in re.finditer(pattern, text, re.DOTALL):
                name = m.group(1).strip()
                desc = m.group(2).strip()[:500]
                if len(name) > 5 and len(desc) > 10:
                    techniques.append({"name": name, "description": desc})
                if len(techniques) >= 15:
                    break
            if techniques:
                break
        return techniques

    def _extract_cves(self, text: str) -> list[str]:
        """Extract CVE identifiers from research text."""
        cves = re.findall(r'CVE-\d{4}-\d{4,}', text)
        return list(set(cves))[:20]

    @property
    def stats(self) -> dict[str, Any]:
        return {
            "calls": self._call_count,
            "total_time_s": round(self._total_time, 1),
            "avg_time_s": round(self._total_time / max(self._call_count, 1), 1),
        }
