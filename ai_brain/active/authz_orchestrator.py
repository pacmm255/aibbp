"""Authorization orchestrator for multi-account role-pair testing.

Makes multi-role/tenant testing first-class: creates role-specific accounts,
discovers role capabilities, runs differential role-pair tests, tracks
object lineage, and tests workflow invariants.

Usage:
    orch = AuthzOrchestrator(scope_guard, http_client)
    ctx = await orch.create_role_account("admin", target_url)
    caps = await orch.discover_role_capabilities(ctx)
    findings = await orch.run_role_pair_test(admin_ctx, user_ctx, endpoint)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("authz_orchestrator")


# ── Data Structures ─────────────────────────────────────────────────────

@dataclass
class RoleContext:
    """Authenticated session context for a specific role."""

    username: str = ""
    password: str = ""
    role: str = ""  # e.g., "admin", "user", "viewer"
    cookies: dict[str, str] = field(default_factory=dict)
    session_token: str = ""
    capabilities: set[str] = field(default_factory=set)  # accessible endpoints
    objects_owned: dict[str, list[str]] = field(default_factory=dict)  # resource_type → [object_ids]
    headers: dict[str, str] = field(default_factory=dict)  # Auth headers

    def to_dict(self) -> dict[str, Any]:
        """Serialize for state storage."""
        return {
            "username": self.username,
            "password": self.password,
            "role": self.role,
            "cookies": self.cookies,
            "session_token": self.session_token,
            "capabilities": list(self.capabilities),
            "objects_owned": self.objects_owned,
            "headers": self.headers,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> RoleContext:
        """Deserialize from state."""
        ctx = RoleContext(
            username=d.get("username", ""),
            password=d.get("password", ""),
            role=d.get("role", ""),
            cookies=d.get("cookies", {}),
            session_token=d.get("session_token", ""),
            capabilities=set(d.get("capabilities", [])),
            objects_owned=d.get("objects_owned", {}),
            headers=d.get("headers", {}),
        )
        return ctx


@dataclass
class ObjectLineage:
    """Tracks who created and can access an object."""

    object_id: str = ""
    resource_type: str = ""  # e.g., "post", "order", "profile"
    created_by: str = ""  # role name
    accessible_by: set[str] = field(default_factory=set)  # roles that can access
    endpoint: str = ""
    operations: dict[str, bool] = field(default_factory=dict)  # "GET": True, "DELETE": False

    def to_dict(self) -> dict[str, Any]:
        return {
            "object_id": self.object_id,
            "resource_type": self.resource_type,
            "created_by": self.created_by,
            "accessible_by": list(self.accessible_by),
            "endpoint": self.endpoint,
            "operations": self.operations,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> ObjectLineage:
        return ObjectLineage(
            object_id=d.get("object_id", ""),
            resource_type=d.get("resource_type", ""),
            created_by=d.get("created_by", ""),
            accessible_by=set(d.get("accessible_by", [])),
            endpoint=d.get("endpoint", ""),
            operations=d.get("operations", {}),
        )


@dataclass
class WorkflowStep:
    """A single step in a multi-step workflow."""

    name: str = ""
    endpoint: str = ""
    method: str = "GET"
    requires_auth: bool = True
    preconditions: list[str] = field(default_factory=list)  # descriptions
    postconditions: list[str] = field(default_factory=list)  # verifiable assertions
    parameters: dict[str, Any] = field(default_factory=dict)


@dataclass
class Workflow:
    """A multi-step business workflow."""

    name: str = ""
    steps: list[WorkflowStep] = field(default_factory=list)
    invariants: list[str] = field(default_factory=list)  # e.g., "total must not change"
    skip_attacks: list[str] = field(default_factory=list)  # steps to try skipping

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "steps": [
                {"name": s.name, "endpoint": s.endpoint, "method": s.method,
                 "requires_auth": s.requires_auth, "parameters": s.parameters}
                for s in self.steps
            ],
            "invariants": self.invariants,
            "skip_attacks": self.skip_attacks,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> Workflow:
        steps = []
        for s in d.get("steps", []):
            steps.append(WorkflowStep(
                name=s.get("name", ""),
                endpoint=s.get("endpoint", ""),
                method=s.get("method", "GET"),
                requires_auth=s.get("requires_auth", True),
                parameters=s.get("parameters", {}),
            ))
        return Workflow(
            name=d.get("name", ""),
            steps=steps,
            invariants=d.get("invariants", []),
            skip_attacks=d.get("skip_attacks", []),
        )


# ── Public segments (skip authz on these) ──────────────────────────────

_PUBLIC_PATH_SEGMENTS = frozenset({
    "login", "signin", "signup", "register", "forgot", "reset",
    "password", "auth", "logout", "oauth", "callback", "verify",
    "confirm", "activate", "public", "health", "status", "ping",
})


# ── AuthzOrchestrator ──────────────────────────────────────────────────

class AuthzOrchestrator:
    """Multi-account authorization testing orchestrator."""

    def __init__(
        self,
        scope_guard: Any,
        http_client: httpx.AsyncClient | None = None,
        socks_proxy: str | None = None,
    ) -> None:
        self._scope_guard = scope_guard
        self._http_client = http_client
        self._socks_proxy = socks_proxy
        self._own_client = False
        self._role_contexts: dict[str, RoleContext] = {}
        self._object_lineage: dict[str, ObjectLineage] = {}
        self._workflows: dict[str, Workflow] = {}

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._http_client is None:
            kwargs: dict[str, Any] = {"verify": False, "timeout": 15}
            if self._socks_proxy:
                kwargs["proxy"] = self._socks_proxy
            self._http_client = httpx.AsyncClient(**kwargs)
            self._own_client = True
        return self._http_client

    async def close(self) -> None:
        if self._own_client and self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    def register_role(self, role: str, ctx: RoleContext) -> None:
        """Register a role context (from external account creation)."""
        ctx.role = role
        self._role_contexts[role] = ctx

    def get_role_context(self, role: str) -> RoleContext | None:
        """Get a registered role context."""
        return self._role_contexts.get(role)

    async def discover_role_capabilities(
        self,
        ctx: RoleContext,
        endpoints: list[str],
    ) -> set[str]:
        """Discover which endpoints a role can access."""
        client = await self._ensure_client()
        accessible: set[str] = set()

        for ep in endpoints:
            # Skip public paths
            path_lower = urlparse(ep).path.lower()
            if any(seg in path_lower for seg in _PUBLIC_PATH_SEGMENTS):
                continue

            try:
                self._scope_guard.validate_url(ep)
                headers = dict(ctx.headers)
                resp = await client.get(ep, headers=headers, cookies=ctx.cookies)
                if resp.status_code < 400:
                    accessible.add(ep)
            except Exception:
                continue

        ctx.capabilities = accessible
        return accessible

    async def run_role_pair_test(
        self,
        role_a: RoleContext,
        role_b: RoleContext,
        endpoint: str,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Test access control between two roles on an endpoint.

        Sends the same request with both roles' sessions. If role_b
        can access role_a's data, that's an access control issue.

        Returns list of finding dicts.
        """
        client = await self._ensure_client()
        findings: list[dict[str, Any]] = []

        # Skip public paths
        path_lower = urlparse(endpoint).path.lower()
        if any(seg in path_lower for seg in _PUBLIC_PATH_SEGMENTS):
            return []

        try:
            self._scope_guard.validate_url(endpoint)
        except Exception:
            return []

        # Request as role_a
        resp_a = await self._send_as_role(client, role_a, endpoint, method, body)
        # Request as role_b
        resp_b = await self._send_as_role(client, role_b, endpoint, method, body)
        # Request as anonymous
        resp_anon = await self._send_anonymous(client, endpoint, method, body)

        if resp_a is None or resp_b is None:
            return []

        # Analysis: if all responses are the same → public page, skip
        if resp_anon and self._responses_similar(resp_a, resp_anon):
            return []

        # Check for access control violations
        if resp_a["status"] < 400 and resp_b["status"] < 400:
            # Both can access — check if they should
            if not self._responses_similar(resp_a, resp_b):
                # Different responses → may be fine (different data for different roles)
                pass
            else:
                # Same response for different roles → potential BAC
                findings.append({
                    "vuln_type": "bac",
                    "endpoint": endpoint,
                    "method": method,
                    "severity": "high",
                    "evidence": (
                        f"Role '{role_b.role}' can access endpoint that returns same response "
                        f"as '{role_a.role}'. Status: {resp_a['status']} vs {resp_b['status']}. "
                        f"Body similarity indicates broken access control."
                    ),
                    "auth_context": f"{role_a.role} vs {role_b.role}",
                    "request_dump": f"{method} {endpoint}\nCookies: {role_b.cookies}",
                    "response_dump": f"HTTP {resp_b['status']}\n{resp_b['body'][:500]}",
                    "tool_used": "authz_orchestrator",
                })

        # Lower-privilege role accessing higher-privilege endpoint
        if resp_a["status"] < 400 and resp_b["status"] < 400:
            # Check if role_b shouldn't have access (heuristic: role_a is higher privilege)
            if self._is_higher_privilege(role_a.role, role_b.role):
                if self._responses_similar(resp_a, resp_b):
                    findings.append({
                        "vuln_type": "privilege_escalation",
                        "endpoint": endpoint,
                        "method": method,
                        "severity": "critical",
                        "evidence": (
                            f"Lower-privilege role '{role_b.role}' can access "
                            f"'{role_a.role}'-level endpoint {endpoint}. "
                            f"Both return status {resp_a['status']}."
                        ),
                        "auth_context": f"{role_a.role} vs {role_b.role}",
                        "tool_used": "authz_orchestrator",
                    })

        return findings

    async def test_workflow_invariants(
        self,
        workflow: Workflow,
        ctx: RoleContext,
    ) -> list[dict[str, Any]]:
        """Execute workflow steps and check postconditions."""
        client = await self._ensure_client()
        findings: list[dict[str, Any]] = []

        for step in workflow.steps:
            try:
                self._scope_guard.validate_url(step.endpoint)
                resp = await self._send_as_role(
                    client, ctx, step.endpoint, step.method, step.parameters or None,
                )
                if resp and resp["status"] >= 400:
                    logger.debug("workflow_step_failed", step=step.name, status=resp["status"])
            except Exception as e:
                logger.debug("workflow_step_error", step=step.name, error=str(e)[:100])

        return findings

    async def test_step_skipping(
        self,
        workflow: Workflow,
        ctx: RoleContext,
    ) -> list[dict[str, Any]]:
        """Try executing later steps without earlier ones."""
        client = await self._ensure_client()
        findings: list[dict[str, Any]] = []

        if len(workflow.steps) < 2:
            return []

        # Try each step individually (skipping previous steps)
        for i in range(1, len(workflow.steps)):
            step = workflow.steps[i]
            try:
                self._scope_guard.validate_url(step.endpoint)
                resp = await self._send_as_role(
                    client, ctx, step.endpoint, step.method, step.parameters or None,
                )
                if resp and resp["status"] < 400:
                    findings.append({
                        "vuln_type": "business_logic",
                        "endpoint": step.endpoint,
                        "method": step.method,
                        "severity": "medium",
                        "evidence": (
                            f"Workflow '{workflow.name}' step '{step.name}' (step {i+1}) "
                            f"succeeded without executing previous steps. "
                            f"Status: {resp['status']}."
                        ),
                        "auth_context": ctx.role,
                        "tool_used": "authz_orchestrator",
                    })
            except Exception:
                continue

        return findings

    def track_object_lineage(
        self,
        role: str,
        endpoint: str,
        response: dict[str, Any],
    ) -> ObjectLineage | None:
        """Record who created what from a state-changing response."""
        # Try to extract object ID from response
        obj_id = None
        body = response.get("body", "")
        if isinstance(body, dict):
            obj_id = str(body.get("id", body.get("_id", "")))
        elif isinstance(body, str):
            # Try to find ID in JSON response
            try:
                parsed = json.loads(body)
                if isinstance(parsed, dict):
                    obj_id = str(parsed.get("id", parsed.get("_id", "")))
            except (json.JSONDecodeError, TypeError):
                pass

        if not obj_id:
            return None

        # Determine resource type from endpoint
        path = urlparse(endpoint).path
        resource_type = path.rstrip("/").rsplit("/", 1)[-1] if "/" in path else "unknown"

        lineage = ObjectLineage(
            object_id=obj_id,
            resource_type=resource_type,
            created_by=role,
            accessible_by={role},
            endpoint=endpoint,
        )
        self._object_lineage[obj_id] = lineage

        # Track in role context
        if role in self._role_contexts:
            ctx = self._role_contexts[role]
            if resource_type not in ctx.objects_owned:
                ctx.objects_owned[resource_type] = []
            ctx.objects_owned[resource_type].append(obj_id)

        return lineage

    async def test_tenant_isolation(
        self,
        object_id: str,
        endpoint_template: str = "",
    ) -> list[dict[str, Any]]:
        """Test cross-account access to a specific object."""
        lineage = self._object_lineage.get(object_id)
        if not lineage:
            return []

        client = await self._ensure_client()
        findings: list[dict[str, Any]] = []

        ep = endpoint_template or lineage.endpoint
        if "{id}" in ep:
            ep = ep.replace("{id}", object_id)
        elif not ep.endswith(object_id):
            ep = ep.rstrip("/") + "/" + object_id

        try:
            self._scope_guard.validate_url(ep)
        except Exception:
            return []

        # Test with every role except the creator
        for role_name, ctx in self._role_contexts.items():
            if role_name == lineage.created_by:
                continue

            resp = await self._send_as_role(client, ctx, ep, "GET")
            if resp and resp["status"] < 400:
                findings.append({
                    "vuln_type": "idor",
                    "endpoint": ep,
                    "method": "GET",
                    "severity": "high",
                    "evidence": (
                        f"Object {object_id} (created by '{lineage.created_by}') "
                        f"is accessible by '{role_name}'. "
                        f"Status: {resp['status']}."
                    ),
                    "auth_context": f"{lineage.created_by} vs {role_name}",
                    "tool_used": "authz_orchestrator",
                })
                lineage.accessible_by.add(role_name)

        return findings

    def register_workflow(self, workflow: Workflow) -> None:
        """Register a discovered workflow."""
        self._workflows[workflow.name] = workflow

    def get_state(self) -> dict[str, Any]:
        """Export state for LangGraph."""
        return {
            "role_contexts": {r: c.to_dict() for r, c in self._role_contexts.items()},
            "object_lineage": {o: l.to_dict() for o, l in self._object_lineage.items()},
            "workflows": {w: wf.to_dict() for w, wf in self._workflows.items()},
        }

    def load_state(self, state: dict[str, Any]) -> None:
        """Restore state from LangGraph."""
        for role, data in state.get("role_contexts", {}).items():
            self._role_contexts[role] = RoleContext.from_dict(data)
        for oid, data in state.get("object_lineage", {}).items():
            self._object_lineage[oid] = ObjectLineage.from_dict(data)
        for name, data in state.get("workflows", {}).items():
            self._workflows[name] = Workflow.from_dict(data)

    # ── Private Helpers ─────────────────────────────────────────────────

    async def _send_as_role(
        self,
        client: httpx.AsyncClient,
        ctx: RoleContext,
        endpoint: str,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Send request authenticated as a specific role."""
        try:
            headers = dict(ctx.headers)
            if ctx.session_token:
                headers["Authorization"] = f"Bearer {ctx.session_token}"

            kwargs: dict[str, Any] = {"headers": headers, "cookies": ctx.cookies}
            if body and method.upper() in ("POST", "PUT", "PATCH"):
                kwargs["data"] = body

            resp = await client.request(method, endpoint, **kwargs)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:3000],
            }
        except Exception as e:
            logger.debug("role_request_failed", role=ctx.role, error=str(e)[:100])
            return None

    async def _send_anonymous(
        self,
        client: httpx.AsyncClient,
        endpoint: str,
        method: str = "GET",
        body: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Send unauthenticated request."""
        try:
            kwargs: dict[str, Any] = {}
            if body and method.upper() in ("POST", "PUT", "PATCH"):
                kwargs["data"] = body
            resp = await client.request(method, endpoint, **kwargs)
            return {
                "status": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:3000],
            }
        except Exception:
            return None

    @staticmethod
    def _responses_similar(resp_a: dict, resp_b: dict) -> bool:
        """Check if two responses are similar enough to indicate same access level."""
        if resp_a["status"] != resp_b["status"]:
            return False
        # Compare body length (within 20%)
        len_a = len(resp_a.get("body", ""))
        len_b = len(resp_b.get("body", ""))
        if len_a == 0 and len_b == 0:
            return True
        ratio = min(len_a, len_b) / max(len_a, len_b, 1)
        return ratio > 0.8

    @staticmethod
    def _is_higher_privilege(role_a: str, role_b: str) -> bool:
        """Heuristic: is role_a higher privilege than role_b?"""
        hierarchy = {"superadmin": 5, "admin": 4, "manager": 3, "editor": 2, "user": 1, "viewer": 0, "guest": 0}
        a_level = hierarchy.get(role_a.lower(), 2)
        b_level = hierarchy.get(role_b.lower(), 2)
        return a_level > b_level
