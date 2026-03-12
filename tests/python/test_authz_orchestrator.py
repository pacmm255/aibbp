"""Exhaustive tests for ai_brain.active.authz_orchestrator."""

import json
import pytest

from ai_brain.active.authz_orchestrator import (
    RoleContext,
    ObjectLineage,
    WorkflowStep,
    Workflow,
    AuthzOrchestrator,
    _PUBLIC_PATH_SEGMENTS,
)


# ── RoleContext ────────────────────────────────────────────────────────


class TestRoleContext:
    def test_defaults(self):
        ctx = RoleContext()
        assert ctx.username == ""
        assert ctx.role == ""
        assert ctx.cookies == {}
        assert ctx.capabilities == set()
        assert ctx.objects_owned == {}

    def test_full_construction(self):
        ctx = RoleContext(
            username="admin@test.com",
            password="secret",
            role="admin",
            cookies={"session": "abc123"},
            session_token="jwt.token.here",
            capabilities={"/api/users", "/api/admin"},
            objects_owned={"post": ["1", "2"]},
            headers={"X-Custom": "value"},
        )
        assert ctx.username == "admin@test.com"
        assert len(ctx.capabilities) == 2

    def test_to_dict(self):
        ctx = RoleContext(
            username="user1",
            role="editor",
            capabilities={"/api/posts"},
            objects_owned={"post": ["5"]},
        )
        d = ctx.to_dict()
        assert d["username"] == "user1"
        assert d["role"] == "editor"
        assert "/api/posts" in d["capabilities"]
        assert d["objects_owned"]["post"] == ["5"]

    def test_from_dict_roundtrip(self):
        ctx = RoleContext(
            username="user1",
            password="pass",
            role="viewer",
            cookies={"sid": "x"},
            session_token="tok",
            capabilities={"/a", "/b"},
            objects_owned={"item": ["1"]},
            headers={"Auth": "Bearer x"},
        )
        d = ctx.to_dict()
        restored = RoleContext.from_dict(d)
        assert restored.username == "user1"
        assert restored.role == "viewer"
        assert restored.capabilities == {"/a", "/b"}
        assert restored.objects_owned == {"item": ["1"]}
        assert restored.headers == {"Auth": "Bearer x"}

    def test_from_dict_defaults(self):
        restored = RoleContext.from_dict({})
        assert restored.username == ""
        assert restored.capabilities == set()


# ── ObjectLineage ──────────────────────────────────────────────────────


class TestObjectLineage:
    def test_defaults(self):
        ol = ObjectLineage()
        assert ol.object_id == ""
        assert ol.accessible_by == set()

    def test_to_dict(self):
        ol = ObjectLineage(
            object_id="123",
            resource_type="post",
            created_by="admin",
            accessible_by={"admin", "user"},
            endpoint="/api/posts/123",
            operations={"GET": True, "DELETE": False},
        )
        d = ol.to_dict()
        assert d["object_id"] == "123"
        assert "admin" in d["accessible_by"]
        assert d["operations"]["GET"] is True

    def test_from_dict_roundtrip(self):
        ol = ObjectLineage(
            object_id="456",
            resource_type="order",
            created_by="user1",
            accessible_by={"user1"},
            endpoint="/api/orders/456",
        )
        d = ol.to_dict()
        restored = ObjectLineage.from_dict(d)
        assert restored.object_id == "456"
        assert restored.created_by == "user1"
        assert restored.accessible_by == {"user1"}


# ── WorkflowStep ──────────────────────────────────────────────────────


class TestWorkflowStep:
    def test_defaults(self):
        ws = WorkflowStep()
        assert ws.method == "GET"
        assert ws.requires_auth is True
        assert ws.parameters == {}

    def test_full(self):
        ws = WorkflowStep(
            name="add_to_cart",
            endpoint="/api/cart",
            method="POST",
            parameters={"product_id": "123"},
        )
        assert ws.name == "add_to_cart"
        assert ws.method == "POST"


# ── Workflow ───────────────────────────────────────────────────────────


class TestWorkflow:
    def test_defaults(self):
        wf = Workflow()
        assert wf.name == ""
        assert wf.steps == []
        assert wf.invariants == []

    def test_to_dict(self):
        wf = Workflow(
            name="checkout",
            steps=[
                WorkflowStep(name="cart", endpoint="/cart", method="GET"),
                WorkflowStep(name="pay", endpoint="/pay", method="POST"),
            ],
            invariants=["total must not change"],
            skip_attacks=["pay"],
        )
        d = wf.to_dict()
        assert d["name"] == "checkout"
        assert len(d["steps"]) == 2
        assert d["steps"][0]["name"] == "cart"
        assert "total must not change" in d["invariants"]

    def test_from_dict_roundtrip(self):
        wf = Workflow(
            name="registration",
            steps=[
                WorkflowStep(name="step1", endpoint="/register", method="POST"),
                WorkflowStep(name="step2", endpoint="/verify", method="POST"),
            ],
        )
        d = wf.to_dict()
        restored = Workflow.from_dict(d)
        assert restored.name == "registration"
        assert len(restored.steps) == 2
        assert restored.steps[0].name == "step1"
        assert restored.steps[1].endpoint == "/verify"

    def test_from_dict_empty(self):
        restored = Workflow.from_dict({})
        assert restored.name == ""
        assert restored.steps == []


# ── Public Path Segments ──────────────────────────────────────────────


class TestPublicPathSegments:
    def test_common_public_paths(self):
        assert "login" in _PUBLIC_PATH_SEGMENTS
        assert "register" in _PUBLIC_PATH_SEGMENTS
        assert "forgot" in _PUBLIC_PATH_SEGMENTS
        assert "health" in _PUBLIC_PATH_SEGMENTS
        assert "oauth" in _PUBLIC_PATH_SEGMENTS


# ── AuthzOrchestrator (unit tests, no network) ───────────────────────


class TestAuthzOrchestrator:
    class FakeScopeGuard:
        def validate_url(self, url):
            if "evil.com" in url:
                raise ValueError("Out of scope")

    def test_register_role(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        ctx = RoleContext(username="admin", password="pass")
        orch.register_role("admin", ctx)
        assert ctx.role == "admin"
        assert orch.get_role_context("admin") is ctx

    def test_get_role_context_missing(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        assert orch.get_role_context("nonexistent") is None

    def test_track_object_lineage_json_body(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        orch.register_role("admin", RoleContext(username="admin"))
        lineage = orch.track_object_lineage(
            "admin",
            "http://example.com/api/posts",
            {"body": json.dumps({"id": "post123", "title": "Test"})},
        )
        assert lineage is not None
        assert lineage.object_id == "post123"
        assert lineage.created_by == "admin"
        assert "admin" in lineage.accessible_by

    def test_track_object_lineage_dict_body(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        lineage = orch.track_object_lineage(
            "user",
            "http://example.com/api/orders",
            {"body": {"id": 42, "total": 99.99}},
        )
        assert lineage is not None
        assert lineage.object_id == "42"

    def test_track_object_lineage_no_id(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        lineage = orch.track_object_lineage(
            "user",
            "http://example.com/api/items",
            {"body": "not json"},
        )
        assert lineage is None

    def test_track_object_adds_to_role_context(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        ctx = RoleContext(username="admin")
        orch.register_role("admin", ctx)
        orch.track_object_lineage(
            "admin",
            "http://example.com/api/posts",
            {"body": {"id": "p1"}},
        )
        assert "p1" in ctx.objects_owned.get("posts", [])

    def test_register_workflow(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        wf = Workflow(name="checkout")
        orch.register_workflow(wf)
        assert "checkout" in orch._workflows

    def test_get_state(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        orch.register_role("admin", RoleContext(username="admin"))
        orch.register_workflow(Workflow(name="test"))
        state = orch.get_state()
        assert "role_contexts" in state
        assert "admin" in state["role_contexts"]
        assert "workflows" in state
        assert "test" in state["workflows"]

    def test_load_state_roundtrip(self):
        orch = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        orch.register_role("admin", RoleContext(username="admin", capabilities={"/api/admin"}))
        orch.register_role("user", RoleContext(username="user"))
        orch.register_workflow(Workflow(name="checkout", steps=[
            WorkflowStep(name="cart", endpoint="/cart"),
        ]))
        state = orch.get_state()

        orch2 = AuthzOrchestrator(scope_guard=self.FakeScopeGuard())
        orch2.load_state(state)
        assert orch2.get_role_context("admin") is not None
        assert orch2.get_role_context("admin").username == "admin"
        assert "/api/admin" in orch2.get_role_context("admin").capabilities
        assert "checkout" in orch2._workflows

    def test_responses_similar_same(self):
        r1 = {"status": 200, "body": "Hello World"}
        r2 = {"status": 200, "body": "Hello World"}
        assert AuthzOrchestrator._responses_similar(r1, r2)

    def test_responses_similar_different_status(self):
        r1 = {"status": 200, "body": "OK"}
        r2 = {"status": 403, "body": "Forbidden"}
        assert not AuthzOrchestrator._responses_similar(r1, r2)

    def test_responses_similar_different_length(self):
        r1 = {"status": 200, "body": "Short"}
        r2 = {"status": 200, "body": "A" * 1000}
        assert not AuthzOrchestrator._responses_similar(r1, r2)

    def test_responses_similar_both_empty(self):
        r1 = {"status": 200, "body": ""}
        r2 = {"status": 200, "body": ""}
        assert AuthzOrchestrator._responses_similar(r1, r2)

    def test_is_higher_privilege(self):
        assert AuthzOrchestrator._is_higher_privilege("admin", "user")
        assert AuthzOrchestrator._is_higher_privilege("superadmin", "admin")
        assert not AuthzOrchestrator._is_higher_privilege("user", "admin")
        assert not AuthzOrchestrator._is_higher_privilege("viewer", "manager")
        assert not AuthzOrchestrator._is_higher_privilege("user", "user")

    def test_is_higher_privilege_unknown_roles(self):
        # Unknown roles get level 2
        assert not AuthzOrchestrator._is_higher_privilege("custom_a", "custom_b")
        assert AuthzOrchestrator._is_higher_privilege("admin", "custom_role")
