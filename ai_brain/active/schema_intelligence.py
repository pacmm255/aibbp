"""Schema intelligence layer for API-aware testing.

- OpenAPIIngester: Parse OpenAPI 2.0/3.x specs → structured endpoints
- GraphQLSchemaManager: Schema diffing and type-aware mutation generation
- ASVSWSTGReference: Embedded ASVS/WSTG test case references

Usage:
    ingester = OpenAPIIngester()
    endpoints = await ingester.discover_and_parse(target_url)

    ref = ASVSWSTGReference()
    tests = ref.get_relevant_tests(tech_stack, "api", "sqli")
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin

import httpx

logger = logging.getLogger("schema_intelligence")


# ── OpenAPI Ingester ────────────────────────────────────────────────────

@dataclass
class SchemaEndpoint:
    """An endpoint discovered from an API spec."""

    path: str
    method: str
    params: list[dict[str, Any]] = field(default_factory=list)
    auth_requirements: list[str] = field(default_factory=list)
    request_body_schema: dict[str, Any] = field(default_factory=dict)
    responses: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    operation_id: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "method": self.method,
            "params": self.params,
            "auth_requirements": self.auth_requirements,
            "request_body_schema": self.request_body_schema,
            "tags": self.tags,
            "operation_id": self.operation_id,
            "description": self.description[:200],
        }


# Common API spec discovery paths
_SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/swagger.json", "/swagger.yaml",
    "/api-docs", "/api-docs.json",
    "/v2/api-docs", "/v3/api-docs",
    "/api/swagger.json", "/api/openapi.json",
    "/docs/api.json", "/api/v1/swagger.json",
    "/api/v2/swagger.json", "/api/v3/openapi.json",
    "/.well-known/openapi.json",
]


class OpenAPIIngester:
    """Parse OpenAPI 2.0/3.x specs into structured endpoints."""

    def __init__(self, http_client: httpx.AsyncClient | None = None) -> None:
        self._client = http_client
        self._own_client = False

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(verify=False, timeout=10)
            self._own_client = True
        return self._client

    async def close(self) -> None:
        if self._own_client and self._client:
            await self._client.aclose()
            self._client = None

    async def discover_and_parse(
        self,
        target_url: str,
        spec_url: str = "",
    ) -> list[SchemaEndpoint]:
        """Discover and parse an API spec from a target URL.

        Args:
            target_url: Base URL to probe for specs.
            spec_url: Direct URL to spec (skips discovery).

        Returns:
            List of parsed SchemaEndpoints.
        """
        client = await self._ensure_client()

        if spec_url:
            return await self._fetch_and_parse(client, spec_url)

        # Auto-discover
        for path in _SPEC_PATHS:
            url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    ct = resp.headers.get("content-type", "")
                    body = resp.text
                    if "json" in ct or body.strip().startswith("{"):
                        try:
                            spec = json.loads(body)
                            endpoints = self._parse_spec(spec)
                            if endpoints:
                                logger.info("openapi_spec_found", url=url, endpoints=len(endpoints))
                                return endpoints
                        except json.JSONDecodeError:
                            continue
                    elif "yaml" in ct or body.strip().startswith("openapi") or body.strip().startswith("swagger"):
                        try:
                            import yaml
                            spec = yaml.safe_load(body)
                            if isinstance(spec, dict):
                                endpoints = self._parse_spec(spec)
                                if endpoints:
                                    logger.info("openapi_spec_found", url=url, endpoints=len(endpoints))
                                    return endpoints
                        except Exception:
                            continue
            except Exception:
                continue

        return []

    async def _fetch_and_parse(self, client: httpx.AsyncClient, url: str) -> list[SchemaEndpoint]:
        """Fetch and parse a spec from a direct URL."""
        try:
            resp = await client.get(url)
            if resp.status_code != 200:
                return []
            spec = json.loads(resp.text)
            return self._parse_spec(spec)
        except Exception as e:
            logger.debug("spec_fetch_failed", url=url, error=str(e)[:100])
            return []

    def _parse_spec(self, spec: dict[str, Any]) -> list[SchemaEndpoint]:
        """Parse OpenAPI 2.0 or 3.x spec."""
        endpoints: list[SchemaEndpoint] = []

        # Detect version
        is_v3 = "openapi" in spec and str(spec["openapi"]).startswith("3")
        is_v2 = "swagger" in spec and str(spec["swagger"]).startswith("2")

        if not is_v3 and not is_v2:
            # Check for paths key as heuristic
            if "paths" not in spec:
                return []

        paths = spec.get("paths", {})
        if not isinstance(paths, dict):
            return []

        # Security definitions
        global_security = spec.get("security", [])

        for path, methods in paths.items():
            if not isinstance(methods, dict):
                continue
            for method, operation in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete", "head", "options"):
                    continue
                if not isinstance(operation, dict):
                    continue

                ep = SchemaEndpoint(
                    path=path,
                    method=method.upper(),
                    tags=operation.get("tags", []),
                    operation_id=operation.get("operationId", ""),
                    description=operation.get("summary", operation.get("description", ""))[:200],
                )

                # Parameters
                params = operation.get("parameters", [])
                # Include path-level parameters
                path_params = methods.get("parameters", [])
                all_params = (path_params or []) + (params or [])

                for param in all_params:
                    if isinstance(param, dict):
                        ep.params.append({
                            "name": param.get("name", ""),
                            "in": param.get("in", "query"),
                            "type": param.get("type", param.get("schema", {}).get("type", "")),
                            "required": param.get("required", False),
                        })

                # Request body (OpenAPI 3.x)
                if is_v3 and "requestBody" in operation:
                    rb = operation["requestBody"]
                    content = rb.get("content", {})
                    for ct, schema_info in content.items():
                        if isinstance(schema_info, dict) and "schema" in schema_info:
                            ep.request_body_schema = schema_info["schema"]
                            break

                # Request body (Swagger 2.x — body parameter)
                for param in all_params:
                    if isinstance(param, dict) and param.get("in") == "body":
                        ep.request_body_schema = param.get("schema", {})

                # Security requirements
                security = operation.get("security", global_security)
                if security:
                    for sec_req in security:
                        if isinstance(sec_req, dict):
                            ep.auth_requirements.extend(sec_req.keys())

                endpoints.append(ep)

        return endpoints

    def parse_spec_dict(self, spec: dict[str, Any]) -> list[SchemaEndpoint]:
        """Parse an already-loaded spec dict (public API)."""
        return self._parse_spec(spec)


# ── GraphQL Schema Manager ─────────────────────────────────────────────

class GraphQLSchemaManager:
    """Enhanced GraphQL analysis with schema diffing."""

    def __init__(self) -> None:
        self._schemas: dict[str, dict[str, Any]] = {}  # auth_context → schema

    def register_schema(self, auth_context: str, schema: dict[str, Any]) -> None:
        """Register an introspection result for an auth context."""
        self._schemas[auth_context] = schema

    def diff_schemas(self, context_a: str, context_b: str) -> dict[str, Any]:
        """Compare schemas between two auth contexts.

        Returns types/fields/mutations present in one but not the other.
        """
        schema_a = self._schemas.get(context_a, {})
        schema_b = self._schemas.get(context_b, {})

        types_a = self._extract_types(schema_a)
        types_b = self._extract_types(schema_b)

        return {
            "only_in_a": list(types_a - types_b),
            "only_in_b": list(types_b - types_a),
            "common": list(types_a & types_b),
            "context_a": context_a,
            "context_b": context_b,
        }

    def generate_mutations(self, schema: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate test mutations from schema types."""
        mutations: list[dict[str, Any]] = []

        types_data = schema.get("data", {}).get("__schema", {}).get("types", [])
        for t in types_data:
            if t.get("name") == "Mutation":
                for field_info in t.get("fields", []):
                    mutations.append({
                        "name": field_info.get("name", ""),
                        "args": [
                            {"name": a.get("name", ""), "type": self._type_name(a.get("type", {}))}
                            for a in field_info.get("args", [])
                        ],
                    })

        return mutations

    @staticmethod
    def _extract_types(schema: dict[str, Any]) -> set[str]:
        """Extract type names from introspection schema."""
        types: set[str] = set()
        types_data = schema.get("data", {}).get("__schema", {}).get("types", [])
        for t in types_data:
            name = t.get("name", "")
            if name and not name.startswith("__"):
                types.add(name)
        return types

    @staticmethod
    def _type_name(type_obj: dict[str, Any]) -> str:
        """Extract human-readable type name from GraphQL type object."""
        if isinstance(type_obj, dict):
            kind = type_obj.get("kind", "")
            if kind == "NON_NULL":
                return GraphQLSchemaManager._type_name(type_obj.get("ofType", {})) + "!"
            if kind == "LIST":
                return "[" + GraphQLSchemaManager._type_name(type_obj.get("ofType", {})) + "]"
            return type_obj.get("name", "?")
        return "?"


# ── ASVS/WSTG Reference ────────────────────────────────────────────────

# Embedded static data — no external files needed.

_ASVS_CHAPTERS: dict[str, str] = {
    "V1": "Architecture, Design and Threat Modeling",
    "V2": "Authentication",
    "V3": "Session Management",
    "V4": "Access Control",
    "V5": "Validation, Sanitization and Encoding",
    "V6": "Stored Cryptography",
    "V7": "Error Handling and Logging",
    "V8": "Data Protection",
    "V9": "Communication",
    "V10": "Malicious Code",
    "V11": "Business Logic",
    "V12": "Files and Resources",
    "V13": "API and Web Service",
    "V14": "Configuration",
}

# Representative ASVS requirements (subset of ~200)
_ASVS_REQUIREMENTS: list[dict[str, Any]] = [
    {"id": "V2.1.1", "chapter": "V2", "description": "Verify passwords are at least 12 characters", "level": 1},
    {"id": "V2.2.1", "chapter": "V2", "description": "Verify anti-automation controls against credential testing", "level": 1},
    {"id": "V2.5.1", "chapter": "V2", "description": "Verify password reset does not reveal credentials", "level": 1},
    {"id": "V3.1.1", "chapter": "V3", "description": "Verify session token is generated using approved CSPRNG", "level": 1},
    {"id": "V3.3.1", "chapter": "V3", "description": "Verify logout invalidates session token", "level": 1},
    {"id": "V3.4.1", "chapter": "V3", "description": "Verify cookie-based session tokens have Secure attribute", "level": 1},
    {"id": "V4.1.1", "chapter": "V4", "description": "Verify access controls are enforced server-side", "level": 1},
    {"id": "V4.1.3", "chapter": "V4", "description": "Verify principle of least privilege for all access", "level": 1},
    {"id": "V4.2.1", "chapter": "V4", "description": "Verify sensitive data and APIs are protected against IDOR", "level": 1},
    {"id": "V5.1.1", "chapter": "V5", "description": "Verify input validation against HTTP parameter pollution", "level": 1},
    {"id": "V5.2.1", "chapter": "V5", "description": "Verify all untrusted HTML input is properly sanitized", "level": 1},
    {"id": "V5.3.1", "chapter": "V5", "description": "Verify output encoding prevents injection", "level": 1},
    {"id": "V5.3.4", "chapter": "V5", "description": "Verify data selection or database queries use parameterized queries", "level": 1},
    {"id": "V5.5.1", "chapter": "V5", "description": "Verify serialized objects use integrity checks or encryption", "level": 1},
    {"id": "V8.3.1", "chapter": "V8", "description": "Verify sensitive data is sent to server in HTTP body, not URL", "level": 1},
    {"id": "V11.1.1", "chapter": "V11", "description": "Verify business logic flows are sequential and cannot be skipped", "level": 1},
    {"id": "V12.1.1", "chapter": "V12", "description": "Verify file upload validates file type", "level": 1},
    {"id": "V12.3.1", "chapter": "V12", "description": "Verify user-submitted filenames are sanitized for path traversal", "level": 1},
    {"id": "V13.1.1", "chapter": "V13", "description": "Verify all API responses contain correct Content-Type header", "level": 1},
    {"id": "V13.2.1", "chapter": "V13", "description": "Verify RESTful APIs validate Content-Type is expected type", "level": 1},
]

# Representative WSTG test cases (subset of ~90)
_WSTG_TESTS: list[dict[str, Any]] = [
    {"id": "WSTG-CONF-01", "name": "Test Network Infrastructure Configuration", "category": "config"},
    {"id": "WSTG-CONF-05", "name": "Enumerate Infrastructure and Application Admin Interfaces", "category": "config"},
    {"id": "WSTG-IDNT-01", "name": "Test Role Definitions", "category": "identity"},
    {"id": "WSTG-IDNT-02", "name": "Test User Registration Process", "category": "identity"},
    {"id": "WSTG-ATHN-01", "name": "Testing for Credentials Transported over Encrypted Channel", "category": "auth"},
    {"id": "WSTG-ATHN-02", "name": "Testing for Default Credentials", "category": "auth"},
    {"id": "WSTG-ATHN-03", "name": "Testing for Weak Lock Out Mechanism", "category": "auth"},
    {"id": "WSTG-ATHN-04", "name": "Testing for Bypassing Authentication Schema", "category": "auth"},
    {"id": "WSTG-ATHN-07", "name": "Testing for Weak Password Policy", "category": "auth"},
    {"id": "WSTG-ATHZ-01", "name": "Testing Directory Traversal File Include", "category": "authz"},
    {"id": "WSTG-ATHZ-02", "name": "Testing for Bypassing Authorization Schema", "category": "authz"},
    {"id": "WSTG-ATHZ-03", "name": "Testing for Privilege Escalation", "category": "authz"},
    {"id": "WSTG-ATHZ-04", "name": "Testing for Insecure Direct Object References", "category": "authz"},
    {"id": "WSTG-INPV-01", "name": "Testing for Reflected Cross Site Scripting", "category": "input"},
    {"id": "WSTG-INPV-02", "name": "Testing for Stored Cross Site Scripting", "category": "input"},
    {"id": "WSTG-INPV-05", "name": "Testing for SQL Injection", "category": "input"},
    {"id": "WSTG-INPV-07", "name": "Testing for XML Injection", "category": "input"},
    {"id": "WSTG-INPV-11", "name": "Testing for Code Injection", "category": "input"},
    {"id": "WSTG-INPV-12", "name": "Testing for Command Injection", "category": "input"},
    {"id": "WSTG-INPV-18", "name": "Testing for Server-Side Template Injection", "category": "input"},
    {"id": "WSTG-INPV-19", "name": "Testing for Server-Side Request Forgery", "category": "input"},
    {"id": "WSTG-BUSL-01", "name": "Test Business Logic Data Validation", "category": "business"},
    {"id": "WSTG-BUSL-02", "name": "Test Ability to Forge Requests", "category": "business"},
    {"id": "WSTG-BUSL-04", "name": "Test for Process Timing", "category": "business"},
    {"id": "WSTG-BUSL-06", "name": "Test Number of Times a Function Can be Used", "category": "business"},
    {"id": "WSTG-BUSL-09", "name": "Test Upload of Malicious Files", "category": "business"},
    {"id": "WSTG-SESS-01", "name": "Testing for Session Management Schema", "category": "session"},
    {"id": "WSTG-SESS-02", "name": "Testing for Cookies Attributes", "category": "session"},
    {"id": "WSTG-SESS-03", "name": "Testing for Session Fixation", "category": "session"},
    {"id": "WSTG-SESS-09", "name": "Testing for Session Hijacking", "category": "session"},
    {"id": "WSTG-CLNT-01", "name": "Testing for DOM-Based Cross Site Scripting", "category": "client"},
    {"id": "WSTG-CRYP-01", "name": "Testing for Weak Transport Layer Security", "category": "crypto"},
    {"id": "WSTG-ERRH-01", "name": "Testing for Improper Error Handling", "category": "error"},
    {"id": "WSTG-APIT-01", "name": "Testing GraphQL", "category": "api"},
]

# Vuln type → WSTG test ID mapping
_VULN_TO_WSTG: dict[str, list[str]] = {
    "xss": ["WSTG-INPV-01", "WSTG-INPV-02", "WSTG-CLNT-01"],
    "sqli": ["WSTG-INPV-05"],
    "cmdi": ["WSTG-INPV-12"],
    "ssti": ["WSTG-INPV-18"],
    "ssrf": ["WSTG-INPV-19"],
    "lfi": ["WSTG-ATHZ-01"],
    "idor": ["WSTG-ATHZ-04"],
    "bac": ["WSTG-ATHZ-02", "WSTG-ATHZ-03"],
    "auth_bypass": ["WSTG-ATHN-04"],
    "jwt": ["WSTG-ATHN-04"],
    "csrf": ["WSTG-SESS-01"],
    "file_upload": ["WSTG-BUSL-09"],
    "race_condition": ["WSTG-BUSL-04", "WSTG-BUSL-06"],
    "graphql": ["WSTG-APIT-01"],
    "xxe": ["WSTG-INPV-07"],
    "deserialization": ["WSTG-INPV-11"],
}

# Vuln type → ASVS chapter mapping
_VULN_TO_ASVS: dict[str, list[str]] = {
    "xss": ["V5"],
    "sqli": ["V5"],
    "cmdi": ["V5"],
    "ssti": ["V5"],
    "ssrf": ["V5", "V13"],
    "lfi": ["V12"],
    "idor": ["V4"],
    "bac": ["V4"],
    "auth_bypass": ["V2"],
    "jwt": ["V2", "V3"],
    "csrf": ["V3", "V13"],
    "file_upload": ["V12"],
    "race_condition": ["V11"],
    "graphql": ["V13"],
    "xxe": ["V5"],
    "deserialization": ["V5"],
    "information_disclosure": ["V7", "V8"],
}

# CAPEC mapping
_VULN_TO_CAPEC: dict[str, str] = {
    "xss": "CAPEC-86",
    "sqli": "CAPEC-66",
    "cmdi": "CAPEC-88",
    "ssti": "CAPEC-242",
    "ssrf": "CAPEC-664",
    "lfi": "CAPEC-126",
    "idor": "CAPEC-122",
    "csrf": "CAPEC-62",
    "file_upload": "CAPEC-650",
    "race_condition": "CAPEC-26",
    "xxe": "CAPEC-201",
    "deserialization": "CAPEC-586",
    "auth_bypass": "CAPEC-115",
}


class ASVSWSTGReference:
    """Embedded ASVS/WSTG/CAPEC reference for testing and reporting."""

    def get_relevant_tests(
        self,
        tech_stack: list[str] | None = None,
        endpoint_type: str = "",
        vuln_type: str = "",
    ) -> list[dict[str, Any]]:
        """Get relevant test cases based on context.

        Args:
            tech_stack: Detected technologies.
            endpoint_type: Type of endpoint (api, form, file, auth).
            vuln_type: Specific vulnerability type to look up.

        Returns:
            List of relevant WSTG/ASVS test references.
        """
        results: list[dict[str, Any]] = []

        # Vuln-type-specific tests
        if vuln_type:
            vt = vuln_type.lower().strip()
            wstg_ids = _VULN_TO_WSTG.get(vt, [])
            for wstg_id in wstg_ids:
                for test in _WSTG_TESTS:
                    if test["id"] == wstg_id:
                        results.append(test)

            asvs_chapters = _VULN_TO_ASVS.get(vt, [])
            for chapter in asvs_chapters:
                for req in _ASVS_REQUIREMENTS:
                    if req["chapter"] == chapter:
                        results.append(req)

        # Endpoint-type-specific tests
        if endpoint_type:
            et = endpoint_type.lower()
            category_map = {
                "api": "api",
                "form": "input",
                "auth": "auth",
                "file": "business",
                "session": "session",
            }
            cat = category_map.get(et, "")
            if cat:
                for test in _WSTG_TESTS:
                    if test.get("category") == cat and test not in results:
                        results.append(test)

        return results

    def get_capec_id(self, vuln_type: str) -> str:
        """Get CAPEC ID for a vulnerability type."""
        return _VULN_TO_CAPEC.get(vuln_type.lower().strip(), "")

    def get_asvs_chapter(self, chapter_id: str) -> str:
        """Get ASVS chapter name."""
        return _ASVS_CHAPTERS.get(chapter_id, "")
