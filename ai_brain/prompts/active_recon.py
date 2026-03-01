"""Active reconnaissance prompts.

3. ActiveSurfaceMapping (Haiku) — categorize pages, forms, API endpoints
4. ActiveInteractionPointDiscovery (Haiku) — identify testable parameters
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.active_schemas import ActiveReconResult, InteractionPoint
from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate


class InteractionPointList(BaseModel):
    """List of discovered interaction points."""

    points: list[InteractionPoint]
    total_params: int = 0
    high_priority_count: int = 0
    notes: str = ""


class ActiveSurfaceMappingPrompt(PromptTemplate):
    """Map the application attack surface from crawled page data."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a reconnaissance specialist mapping a web application's attack surface.
Your job is to categorize all discoverable pages, forms, API endpoints, and
interesting features from the crawled data.
</role>

<mapping_rules>
- Categorize every page: public, requires-auth, admin, API, file-upload
- Identify all forms and their purposes (login, registration, search, payment, etc.)
- Detect API endpoints from URL patterns (/api/, /v1/, /graphql)
- Note technology stack indicators as simple strings (e.g., ["Laravel", "PHP 8.1", "jQuery 3.x"])
- Flag interesting features: file upload, payment processing, user management
- Mark auth endpoints: login, register, forgot-password, OAuth callbacks
- Prioritize forms with sensitive actions (password change, profile edit, payment)
</mapping_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ActiveReconResult

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        pages = kwargs.get("pages", "[]")
        links = kwargs.get("links", "[]")
        forms = kwargs.get("forms", "[]")
        api_map = kwargs.get("api_map", "{}")
        headers = kwargs.get("headers", "{}")
        return f"""<crawled_pages>
{pages}
</crawled_pages>

<discovered_links>
{links}
</discovered_links>

<discovered_forms>
{forms}
</discovered_forms>

<api_map_from_traffic>
{api_map}
</api_map_from_traffic>

<response_headers>
{headers}
</response_headers>

Map the full attack surface. Categorize every endpoint and form."""


class ActiveInteractionPointDiscoveryPrompt(PromptTemplate):
    """Identify and prioritize testable parameters from DOM and traffic."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a parameter discovery specialist. You find every testable input
in a web application and prioritize them by vulnerability likelihood.
</role>

<discovery_rules>
- Extract all parameters from: URL query strings, POST body, JSON body,
  path segments, headers (especially custom ones), cookies
- Prioritize parameters that:
  * Accept user IDs or object references (IDOR candidates) → priority 9-10
  * Accept filenames or paths (path traversal, file inclusion) → priority 8-9
  * Accept URLs (SSRF candidates) → priority 8-9
  * Appear in search/filter operations (injection candidates) → priority 7-8
  * Accept numeric values in business logic (price manipulation) → priority 7-8
  * Are reflected in responses (XSS candidates) → priority 6-7
  * Are hidden form fields → priority 6-7
- Mark auth_required based on whether the endpoint returned 401/403 without auth
- Set param_type accurately (query, body, path, header, cookie, json, multipart)
</discovery_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return InteractionPointList

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        dom_snapshot = kwargs.get("dom_snapshot", "")
        api_map = kwargs.get("api_map", "{}")
        traffic_entries = kwargs.get("traffic_entries", "[]")
        return f"""<dom_snapshot>
{dom_snapshot}
</dom_snapshot>

<api_map>
{api_map}
</api_map>

<sample_traffic>
{traffic_entries}
</sample_traffic>

Identify all testable parameters. Assign priority 1-10 based on vulnerability
likelihood. Include param_type and auth_required for each."""
