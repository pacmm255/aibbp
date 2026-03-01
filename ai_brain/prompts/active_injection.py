"""Active injection testing prompts.

7. ActiveInjectionAnalysis (Sonnet) — analyze parameters for injection
8. ActivePayloadSelection (Sonnet) — select payloads with WAF bypass
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ai_brain.active_schemas import InjectionTestResult
from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate


class PayloadEntry(BaseModel):
    """A single injection payload with metadata."""

    payload: str = Field(description="The actual injection payload string to send")
    description: str = Field(default="", description="What this payload tests for")
    encoding: str = Field(default="none", description="Encoding applied: none, url, double-url, unicode, hex")


class PayloadSet(BaseModel):
    """Ordered set of payloads for a specific parameter."""

    parameter: str
    endpoint: str
    recommended_tool: str = ""  # sqlmap, dalfox, commix, manual
    payloads: list[PayloadEntry] = Field(default_factory=list)
    bypass_strategies: list[str] = Field(default_factory=list)
    waf_detected: bool = False
    notes: str = ""


class InjectionCandidateList(BaseModel):
    """List of injection test candidates with tool recommendations."""

    candidates: list[InjectionTestResult] = Field(default_factory=list)
    tool_recommendations: dict[str, list[str]] = Field(default_factory=dict)
    priority_order: list[str] = Field(default_factory=list)
    notes: str = ""


class ActiveInjectionAnalysisPrompt(PromptTemplate):
    """Analyze parameters for injection vulnerability potential."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an injection vulnerability specialist. You analyze endpoints and
parameters to determine the most likely injection type and recommend the
appropriate testing tool.
</role>

<injection_analysis_rules>
- For each parameter, assess likelihood of: SQLi, XSS, command injection,
  SSTI, SSRF, path traversal, LDAP injection, header injection,
  unrestricted file upload
- Recommend the right tool:
  * SQL injection → sqlmap (with appropriate --level and --risk)
  * Reflected/stored XSS → dalfox
  * Command injection → commix
  * SSTI, path traversal, SSRF → manual payloads
  * Unrestricted file upload → manual file upload testing
- Consider the technology stack when assessing injection types:
  * PHP → more likely to have command injection, file inclusion
  * Java/.NET → more likely to have deserialization, SSTI
  * Node.js → prototype pollution, NoSQL injection
  * Python → SSTI (Jinja2), pickle deserialization
- Assess WAF presence from response patterns (403s, modified responses)
- Prioritize parameters that are:
  * Used in database queries (search, filter, sort, ID parameters)
  * Reflected in responses (XSS)
  * Used in file operations (path traversal)
  * Used in system commands (ping, traceroute, DNS tools)
  * Used in file upload endpoints (file upload, attachment, avatar, import)
- CRITICAL: tool_recommendations values must be clean, complete URLs only.
  Do NOT add notes, comments, or descriptions after the URL.
  WRONG: "https://example.com/api?id=1 - check captcha first"
  RIGHT: "https://example.com/api?id=1"
  Put any notes in the top-level "notes" field instead.
</injection_analysis_rules>

<framework_attacks>
LARAVEL: Mass assignment (add is_admin=1, role=admin to POST bodies),
  debug mode (/_debugbar, /telescope, /_ignition), .env exposure (/..env),
  artisan routes, Blade SSTI
LIVEWIRE: State tampering (modify serverMemo.data in POST body), call
  methods directly via /livewire/message/*, component parameter manipulation
PHP: Type juggling (password[]=), file inclusion (../ in params), null byte,
  register_globals abuse, loose comparison bypass
DJANGO: Debug page info disclosure (/admin, ALLOWED_HOSTS), SSTI in templates
NODE/EXPRESS: Prototype pollution (__proto__), NoSQL injection ($gt, $ne),
  path traversal in file serving

WHEN REVIEWING TRAFFIC INTELLIGENCE (sample_responses section):
- Focus on params flagged as IDs/prices/roles — these are your highest-value targets
- If WAF detected, prioritize double-encoding and unicode bypass payloads
- If timing anomalies exist, recommend time-based blind payloads for those endpoints
- Test Livewire endpoints (/livewire/message/*) with modified state data
- Look at error messages — they reveal backend technology and query structure
</framework_attacks>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return InjectionCandidateList

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        interaction_points = kwargs.get("interaction_points", "[]")
        observed_responses = kwargs.get("observed_responses", "[]")
        tech_stack = kwargs.get("tech_stack", "[]")
        pipeline_context = kwargs.get("pipeline_context", "")
        return f"""<pipeline_context>
{pipeline_context}
</pipeline_context>

<interaction_points>
{interaction_points}
</interaction_points>

<sample_responses>
{observed_responses}
</sample_responses>

<technology_stack>
{tech_stack}
</technology_stack>

Analyze each parameter for injection potential. Recommend the best tool
(sqlmap/dalfox/commix/manual) and prioritize by likelihood."""


class SSRFCandidate(BaseModel):
    """A parameter that may accept URLs for SSRF testing."""

    endpoint: str
    parameter: str
    reason: str = ""  # Why this parameter looks URL-accepting
    payloads: list[str] = Field(default_factory=list)


class SSRFCandidateList(BaseModel):
    """List of SSRF testing candidates."""

    candidates: list[SSRFCandidate] = Field(default_factory=list)
    notes: str = ""


class ActiveSSRFTestingPrompt(PromptTemplate):
    """Identify URL-accepting parameters and generate SSRF payloads."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an SSRF specialist. You identify parameters that accept URLs or
URL-like values and generate targeted SSRF payloads.
</role>

<ssrf_identification>
Parameters likely to accept URLs (by name pattern):
- url, redirect, callback, webhook, image_url, avatar_url, return_url
- next, goto, forward, dest, destination, target, link, href, src
- feed, rss, xml, path, file, load, fetch, proxy, host, domain
- api, endpoint, service, resource, reference, ref, source
- import_url, export_url, download_url, upload_url, preview_url

Also check for parameters whose VALUES look like URLs in the traffic data.
</ssrf_identification>

<payload_categories>
1. Cloud metadata (highest impact):
   - http://169.254.169.254/latest/meta-data/ (AWS)
   - http://metadata.google.internal/computeMetadata/v1/ (GCP, needs header)
   - http://169.254.169.254/metadata/instance?api-version=2021-02-01 (Azure)

2. Internal network probing:
   - http://127.0.0.1:PORT/ (common ports: 80, 443, 8080, 3306, 5432, 6379, 27017)
   - http://localhost/admin
   - http://0.0.0.0/

3. Protocol smuggling:
   - file:///etc/passwd
   - gopher://127.0.0.1:25/
   - dict://127.0.0.1:11211/

4. DNS rebinding / bypass:
   - http://0177.0.0.1/ (octal)
   - http://0x7f000001/ (hex)
   - http://2130706433/ (decimal)
   - http://[::1]/ (IPv6 loopback)
   - http://127.1/
</payload_categories>

Generate 5-10 payloads per candidate, ordered by impact (cloud metadata first).

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return SSRFCandidateList

    @property
    def model_tier(self) -> TaskTier:
        return "routine"  # Cheap Haiku call — just identifies candidates

    def user_template(self, **kwargs: Any) -> str:
        interaction_points = kwargs.get("interaction_points", "[]")
        traffic_sample = kwargs.get("traffic_sample", "")
        return f"""<interaction_points>
{interaction_points}
</interaction_points>

<traffic_sample>
{traffic_sample}
</traffic_sample>

Identify parameters that may accept URLs. For each, generate SSRF payloads
targeting cloud metadata, internal services, and protocol smuggling."""


class ActivePayloadSelectionPrompt(PromptTemplate):
    """Select specific payloads and WAF bypass strategies."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a payload crafting specialist. You select the most effective payloads
for a given parameter considering WAF presence, encoding requirements, and
technology stack.
</role>

<payload_rules>
- Order payloads from least to most aggressive
- Start with detection payloads (confirm the vuln type) before exploitation
- For SQLi: start with boolean-based blind, then error-based, then UNION
- For XSS: start with simple reflection tests, then context-specific payloads
- For command injection: start with time-based (sleep), then output-based
- For file upload: test extension bypass (.php.jpg, .pHp), MIME type mismatch,
  SVG XSS, polyglot files (valid image header + code), path traversal in
  filename, .htaccess/.web.config upload, SSI injection
- WAF bypass strategies:
  * Encoding: URL, double-URL, Unicode, hex
  * Case variation: SeLeCt, ScRiPt
  * Comment insertion: SEL/**/ECT, al/**/ert
  * Alternative syntax: document['cookie'], String.fromCharCode
  * HTTP parameter pollution
- Always include at least one polyglot payload
- Limit to 10-15 payloads per parameter (enough for detection + confirmation)
</payload_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return PayloadSet

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        parameter = kwargs.get("parameter", "")
        endpoint = kwargs.get("endpoint", "")
        tech_stack = kwargs.get("tech_stack", "")
        waf_info = kwargs.get("waf_info", "")
        injection_type = kwargs.get("injection_type", "")
        sample_response = kwargs.get("sample_response", "")
        return f"""<target_parameter>{parameter}</target_parameter>
<endpoint>{endpoint}</endpoint>
<injection_type>{injection_type}</injection_type>
<technology_stack>{tech_stack}</technology_stack>
<waf_info>{waf_info}</waf_info>
<sample_response>
{sample_response}
</sample_response>

Select the best payloads for this parameter. Order from least to most
aggressive. Include WAF bypass strategies if WAF is detected."""
