"""Phase 1: Reconnaissance prompts.

1.1 - Subdomain Classification (Haiku)
1.3 - JS Analysis (Haiku)
1.4 - API/Swagger Analysis (Haiku)
1.5 - Recon Correlation (Sonnet)
1.6 - Custom Wordlist Generation (Haiku, temp=0.2)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.schemas import (
    APISwaggerResult,
    CustomWordlist,
    JSAnalysisResult,
    ReconCorrelation,
    SubdomainClassificationResult,
)


class SubdomainClassificationPrompt(PromptTemplate):
    """1.1 - Classify subdomains by interest level and category."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a subdomain classification specialist for bug bounty hunting.
You categorize discovered subdomains by their likely purpose and
vulnerability potential.
</role>

<classification_categories>
- production: Main user-facing applications
- staging: Pre-production environments (often less secured)
- dev: Development environments (may expose debug info)
- admin: Administrative panels (high-value targets)
- api: API endpoints (IDOR, auth bypass potential)
- cdn: Content delivery (usually lower priority)
- internal: Internal tools exposed externally (high interest)
- mail: Email infrastructure
- docs: Documentation portals
</classification_categories>

<interest_signals>
HIGH (8-10): admin panels, staging/dev environments, API gateways,
  internal tools, CI/CD systems, monitoring dashboards
MEDIUM (4-7): Main production apps, user portals, support systems
LOW (1-3): CDN, static content, marketing pages, status pages
</interest_signals>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return SubdomainClassificationResult

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        subdomains = kwargs["subdomains"]
        httpx_data = kwargs.get("httpx_data", "")
        return f"""<discovered_subdomains>
{subdomains}
</discovered_subdomains>

<httpx_probe_results>
{httpx_data}
</httpx_probe_results>

<task>
Classify each subdomain:
1. Assign a category (production, staging, dev, admin, api, cdn, internal)
2. Rate interest level 1-10
3. Note detected technologies if visible from httpx data
4. Flag potential admin panels and API endpoints separately
5. Identify high-value targets for deeper scanning
</task>"""


class JSAnalysisPrompt(PromptTemplate):
    """1.3 - Analyze JavaScript files for endpoints and secrets."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a JavaScript analysis specialist. You extract API endpoints,
secrets, and interesting patterns from JavaScript source code found
during reconnaissance.
</role>

<patterns_to_find>
ENDPOINTS:
- fetch/axios/XMLHttpRequest URLs
- API route definitions (/api/v1/, /graphql, etc.)
- WebSocket endpoints (ws://, wss://)
- Internal service URLs

SECRETS:
- API keys (look for key=, apikey=, api_key=)
- AWS credentials (AKIA..., aws_secret)
- JWT tokens (eyJ...)
- OAuth client secrets
- Firebase/GCP/Azure credentials
- Private keys (BEGIN RSA/EC PRIVATE KEY)
- Passwords or tokens in comments

PATTERNS:
- Authentication flows
- Role/permission checks
- Debug/admin flags
- Feature flags
- Hidden endpoints or parameters
</patterns_to_find>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return JSAnalysisResult

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        js_content = kwargs["js_content"]
        source_url = kwargs.get("source_url", "unknown")
        return f"""<javascript_source url="{source_url}">
{js_content}
</javascript_source>

<task>
Analyze this JavaScript code. Extract:
1. All API endpoints with HTTP methods and parameters
2. Any potential secrets (show only first/last 4 chars for safety)
3. Detected frameworks and libraries
4. Interesting patterns (auth flows, role checks, hidden features)
5. For each secret, assess if it's likely real vs a placeholder

Mark each secret with is_likely_real based on:
- Length and format matching known credential patterns
- Context suggesting production use
- Absence of "example", "test", "placeholder" indicators
</task>"""


class APISwaggerAnalysisPrompt(PromptTemplate):
    """1.4 - Analyze API documentation and Swagger/OpenAPI specs."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an API security analyst specializing in OpenAPI/Swagger
specifications and API endpoint analysis for bug bounty hunting.
</role>

<focus_areas>
- Authentication scheme analysis (bearer, API key, OAuth2, basic)
- Endpoint enumeration with parameter types
- Rate limiting indicators
- Versioning patterns
- Interesting parameters (IDs, file paths, URLs, callbacks)
- Admin/privileged endpoints
- CRUD operations on sensitive resources
- File upload endpoints
- Redirect/callback parameters
</focus_areas>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return APISwaggerResult

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        api_spec = kwargs["api_spec"]
        base_url = kwargs.get("base_url", "")
        return f"""<api_specification base_url="{base_url}">
{api_spec}
</api_specification>

<task>
Analyze this API specification. Extract:
1. Authentication scheme and any weaknesses
2. All endpoints with methods and parameter types
3. Rate limiting information if present
4. Interesting parameters that could be vulnerable (IDs, URLs, files)
5. Privileged/admin endpoints
6. Any versioning that might allow accessing older, less-secured versions
</task>"""


class ReconCorrelationPrompt(PromptTemplate):
    """1.5 - Correlate all recon data into actionable intelligence."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a reconnaissance correlation expert. You synthesize data from
multiple recon sources (subdomain enumeration, port scanning, web
probing, JS analysis, API discovery) into a coherent attack surface
map with actionable testing priorities.
</role>

<correlation_strategy>
1. Map technology stacks across subdomains (shared frameworks, shared auth)
2. Identify shared infrastructure (same IP, same CDN, same hosting)
3. Cross-reference JS endpoints with discovered subdomains
4. Match API specs with live endpoints
5. Identify patterns suggesting vulnerability classes:
   - Sequential IDs → IDOR potential
   - JWT usage → Token manipulation
   - GraphQL → Introspection, batching
   - File upload → SSRF, path traversal
   - OAuth → Token theft, open redirect
   - CORS headers → Misconfiguration
</correlation_strategy>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ReconCorrelation

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        subdomain_data = kwargs.get("subdomain_data", "")
        port_data = kwargs.get("port_data", "")
        httpx_data = kwargs.get("httpx_data", "")
        js_analysis = kwargs.get("js_analysis", "")
        api_specs = kwargs.get("api_specs", "")
        return f"""<recon_data>
<subdomains>
{subdomain_data}
</subdomains>

<port_scan>
{port_data}
</port_scan>

<web_probe>
{httpx_data}
</web_probe>

<js_analysis>
{js_analysis}
</js_analysis>

<api_specifications>
{api_specs}
</api_specifications>
</recon_data>

<task>
Correlate all reconnaissance data. Produce:
1. Attack surface summary — what is the overall exposure?
2. High-value targets — which specific endpoints to test first
3. Technology stack mapping — what runs where
4. Shared infrastructure — what targets share resources
5. Recommended test areas — which vulnerability classes to prioritize
6. Potential vulnerability classes — based on tech stack and patterns
</task>"""


class CustomWordlistPrompt(PromptTemplate):
    """1.6 - Generate custom wordlist based on target intelligence."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a wordlist generation specialist for bug bounty hunting.
You create target-specific wordlists by analyzing the target's
technology stack, naming conventions, and discovered patterns.
</role>

<wordlist_strategy>
Generate words in these categories:
- PATHS: Common paths for the detected technology stack
- PARAMS: Parameter names seen in APIs and JS files
- SUBDOMAINS: Predicted subdomain names based on patterns
- FILES: Sensitive files for the tech stack (.env, config, backup)
- KEYWORDS: Business-specific terms from the target

Naming convention analysis:
- camelCase vs snake_case vs kebab-case
- Prefix/suffix patterns (api-, -service, -admin)
- Versioning patterns (v1, v2, version)
- Environment indicators (dev, staging, prod, test)
</wordlist_strategy>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return CustomWordlist

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    @property
    def temperature(self) -> float:
        return 0.2  # Slightly creative for wordlist generation

    def user_template(self, **kwargs: Any) -> str:
        target = kwargs["target"]
        tech_stack = kwargs.get("tech_stack", "")
        known_paths = kwargs.get("known_paths", "")
        known_params = kwargs.get("known_params", "")
        return f"""<target_intelligence>
<target>{target}</target>
<technology_stack>
{tech_stack}
</technology_stack>
<known_paths>
{known_paths}
</known_paths>
<known_parameters>
{known_params}
</known_parameters>
</target_intelligence>

<task>
Generate a custom wordlist tailored to this target. Include:
1. Path words based on the technology stack
2. Parameter names based on API patterns
3. Subdomain predictions based on naming conventions
4. Sensitive file paths for the tech stack
5. Business-specific keywords

Organize words by category. Aim for 200-500 high-quality words
that are specific to this target, not generic.
</task>"""
