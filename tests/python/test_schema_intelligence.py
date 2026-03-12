"""Exhaustive tests for ai_brain.active.schema_intelligence."""

import json
import pytest

from ai_brain.active.schema_intelligence import (
    SchemaEndpoint,
    OpenAPIIngester,
    GraphQLSchemaManager,
    ASVSWSTGReference,
    _SPEC_PATHS,
    _ASVS_CHAPTERS,
    _ASVS_REQUIREMENTS,
    _WSTG_TESTS,
    _VULN_TO_WSTG,
    _VULN_TO_ASVS,
    _VULN_TO_CAPEC,
)


# ── SchemaEndpoint ─────────────────────────────────────────────────────


class TestSchemaEndpoint:
    def test_minimal(self):
        ep = SchemaEndpoint(path="/api/users", method="GET")
        assert ep.path == "/api/users"
        assert ep.method == "GET"
        assert ep.params == []
        assert ep.auth_requirements == []

    def test_full(self):
        ep = SchemaEndpoint(
            path="/api/users/{id}",
            method="PUT",
            params=[{"name": "id", "in": "path", "type": "integer"}],
            auth_requirements=["bearerAuth"],
            request_body_schema={"type": "object"},
            tags=["users"],
            operation_id="updateUser",
            description="Update a user",
        )
        assert ep.operation_id == "updateUser"
        assert len(ep.params) == 1

    def test_to_dict(self):
        ep = SchemaEndpoint(
            path="/api/items",
            method="POST",
            tags=["items"],
            description="A" * 300,  # Should be truncated
        )
        d = ep.to_dict()
        assert d["path"] == "/api/items"
        assert d["method"] == "POST"
        assert len(d["description"]) <= 200


# ── OpenAPIIngester (spec parsing, no network) ────────────────────────


class TestOpenAPIIngesterParsing:
    def test_parse_openapi_3(self):
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {
                "/api/users": {
                    "get": {
                        "operationId": "listUsers",
                        "summary": "List all users",
                        "tags": ["users"],
                        "parameters": [
                            {"name": "page", "in": "query", "schema": {"type": "integer"}},
                        ],
                        "security": [{"bearerAuth": []}],
                        "responses": {"200": {"description": "OK"}},
                    },
                    "post": {
                        "operationId": "createUser",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"name": {"type": "string"}},
                                    }
                                }
                            }
                        },
                    },
                },
            },
        }
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert len(endpoints) == 2

        get_ep = next(ep for ep in endpoints if ep.method == "GET")
        assert get_ep.operation_id == "listUsers"
        assert len(get_ep.params) == 1
        assert get_ep.params[0]["name"] == "page"
        assert "bearerAuth" in get_ep.auth_requirements

        post_ep = next(ep for ep in endpoints if ep.method == "POST")
        assert post_ep.request_body_schema["type"] == "object"

    def test_parse_swagger_2(self):
        spec = {
            "swagger": "2.0",
            "info": {"title": "API", "version": "1.0"},
            "paths": {
                "/api/items": {
                    "get": {
                        "parameters": [
                            {"name": "q", "in": "query", "type": "string"},
                        ],
                    },
                    "post": {
                        "parameters": [
                            {"name": "body", "in": "body", "schema": {"type": "object"}},
                        ],
                    },
                },
            },
        }
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert len(endpoints) == 2

        post_ep = next(ep for ep in endpoints if ep.method == "POST")
        assert post_ep.request_body_schema["type"] == "object"

    def test_parse_empty_paths(self):
        spec = {"openapi": "3.0.0", "paths": {}}
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert endpoints == []

    def test_parse_no_paths(self):
        spec = {"openapi": "3.0.0"}
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert endpoints == []

    def test_parse_unknown_spec(self):
        spec = {"random": "data"}
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert endpoints == []

    def test_parse_global_security(self):
        spec = {
            "openapi": "3.0.0",
            "security": [{"apiKey": []}],
            "paths": {
                "/api/data": {
                    "get": {"summary": "Get data"},
                },
            },
        }
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert len(endpoints) == 1
        assert "apiKey" in endpoints[0].auth_requirements

    def test_parse_path_level_params(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/items/{id}": {
                    "parameters": [
                        {"name": "id", "in": "path", "type": "integer", "required": True},
                    ],
                    "get": {"summary": "Get item"},
                    "delete": {"summary": "Delete item"},
                },
            },
        }
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert len(endpoints) == 2
        for ep in endpoints:
            assert any(p["name"] == "id" for p in ep.params)

    def test_parse_skips_invalid_methods(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/test": {
                    "get": {"summary": "OK"},
                    "x-custom": {"summary": "Skip this"},
                    "parameters": [],
                },
            },
        }
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert len(endpoints) == 1

    def test_parse_all_http_methods(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/api/resource": {
                    "get": {},
                    "post": {},
                    "put": {},
                    "patch": {},
                    "delete": {},
                    "head": {},
                    "options": {},
                },
            },
        }
        ingester = OpenAPIIngester()
        endpoints = ingester.parse_spec_dict(spec)
        assert len(endpoints) == 7


# ── Spec Discovery Paths ─────────────────────────────────────────────


class TestSpecPaths:
    def test_common_paths_included(self):
        assert "/openapi.json" in _SPEC_PATHS
        assert "/swagger.json" in _SPEC_PATHS
        assert "/api-docs" in _SPEC_PATHS

    def test_path_count(self):
        assert len(_SPEC_PATHS) >= 10


# ── GraphQLSchemaManager ──────────────────────────────────────────────


class TestGraphQLSchemaManager:
    def _make_schema(self, type_names):
        return {
            "data": {
                "__schema": {
                    "types": [
                        {"name": t, "kind": "OBJECT", "fields": []}
                        for t in type_names
                    ]
                }
            }
        }

    def test_register_schema(self):
        mgr = GraphQLSchemaManager()
        schema = self._make_schema(["User", "Post"])
        mgr.register_schema("admin", schema)
        assert "admin" in mgr._schemas

    def test_diff_schemas(self):
        mgr = GraphQLSchemaManager()
        mgr.register_schema("admin", self._make_schema(["User", "Post", "AdminPanel"]))
        mgr.register_schema("user", self._make_schema(["User", "Post"]))
        diff = mgr.diff_schemas("admin", "user")
        assert "AdminPanel" in diff["only_in_a"]
        assert diff["only_in_b"] == []
        assert "User" in diff["common"]

    def test_diff_schemas_empty(self):
        mgr = GraphQLSchemaManager()
        diff = mgr.diff_schemas("a", "b")
        assert diff["only_in_a"] == []
        assert diff["only_in_b"] == []

    def test_diff_schemas_skips_internal_types(self):
        mgr = GraphQLSchemaManager()
        mgr.register_schema("a", {
            "data": {"__schema": {"types": [
                {"name": "__Schema", "kind": "OBJECT", "fields": []},
                {"name": "User", "kind": "OBJECT", "fields": []},
            ]}}
        })
        mgr.register_schema("b", self._make_schema(["User"]))
        diff = mgr.diff_schemas("a", "b")
        assert "__Schema" not in diff["only_in_a"]

    def test_generate_mutations(self):
        schema = {
            "data": {
                "__schema": {
                    "types": [
                        {
                            "name": "Mutation",
                            "kind": "OBJECT",
                            "fields": [
                                {
                                    "name": "createUser",
                                    "args": [
                                        {
                                            "name": "input",
                                            "type": {
                                                "kind": "NON_NULL",
                                                "name": None,
                                                "ofType": {"kind": "INPUT_OBJECT", "name": "CreateUserInput"},
                                            },
                                        },
                                    ],
                                },
                            ],
                        },
                    ],
                },
            },
        }
        mgr = GraphQLSchemaManager()
        mutations = mgr.generate_mutations(schema)
        assert len(mutations) == 1
        assert mutations[0]["name"] == "createUser"
        assert mutations[0]["args"][0]["name"] == "input"
        assert mutations[0]["args"][0]["type"] == "CreateUserInput!"

    def test_generate_mutations_empty(self):
        mgr = GraphQLSchemaManager()
        mutations = mgr.generate_mutations({})
        assert mutations == []

    def test_type_name_list(self):
        type_obj = {"kind": "LIST", "ofType": {"kind": "SCALAR", "name": "String"}}
        result = GraphQLSchemaManager._type_name(type_obj)
        assert result == "[String]"

    def test_type_name_non_null_list(self):
        type_obj = {
            "kind": "NON_NULL",
            "ofType": {"kind": "LIST", "ofType": {"kind": "SCALAR", "name": "Int"}},
        }
        result = GraphQLSchemaManager._type_name(type_obj)
        assert result == "[Int]!"

    def test_type_name_simple(self):
        assert GraphQLSchemaManager._type_name({"kind": "SCALAR", "name": "Boolean"}) == "Boolean"

    def test_type_name_invalid(self):
        assert GraphQLSchemaManager._type_name("not a dict") == "?"
        assert GraphQLSchemaManager._type_name({}) == "?"


# ── ASVS/WSTG Reference Data ──────────────────────────────────────────


class TestReferenceData:
    def test_asvs_chapters(self):
        assert len(_ASVS_CHAPTERS) >= 14
        assert "V5" in _ASVS_CHAPTERS
        assert "Validation" in _ASVS_CHAPTERS["V5"]

    def test_asvs_requirements_count(self):
        assert len(_ASVS_REQUIREMENTS) >= 18

    def test_asvs_requirements_have_ids(self):
        for req in _ASVS_REQUIREMENTS:
            assert "id" in req
            assert "chapter" in req
            assert req["id"].startswith("V")

    def test_wstg_tests_count(self):
        assert len(_WSTG_TESTS) >= 30

    def test_wstg_tests_have_ids(self):
        for test in _WSTG_TESTS:
            assert "id" in test
            assert test["id"].startswith("WSTG-")
            assert "category" in test

    def test_vuln_to_wstg_mappings(self):
        assert "xss" in _VULN_TO_WSTG
        assert "sqli" in _VULN_TO_WSTG
        assert "cmdi" in _VULN_TO_WSTG
        # XSS should map to both reflected and stored
        assert len(_VULN_TO_WSTG["xss"]) >= 2

    def test_vuln_to_asvs_mappings(self):
        assert "xss" in _VULN_TO_ASVS
        assert "V5" in _VULN_TO_ASVS["xss"]

    def test_vuln_to_capec_mappings(self):
        assert _VULN_TO_CAPEC["xss"] == "CAPEC-86"
        assert _VULN_TO_CAPEC["sqli"] == "CAPEC-66"
        assert _VULN_TO_CAPEC["cmdi"] == "CAPEC-88"


# ── ASVSWSTGReference ─────────────────────────────────────────────────


class TestASVSWSTGReference:
    def test_get_relevant_tests_by_vuln_type(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests(vuln_type="sqli")
        assert len(tests) > 0
        # Should include WSTG and ASVS
        ids = [t.get("id", "") for t in tests]
        assert any("WSTG" in i for i in ids)
        assert any(i.startswith("V5") for i in ids)

    def test_get_relevant_tests_xss(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests(vuln_type="xss")
        ids = [t.get("id", "") for t in tests]
        assert "WSTG-INPV-01" in ids  # Reflected XSS
        assert "WSTG-INPV-02" in ids  # Stored XSS

    def test_get_relevant_tests_by_endpoint_type(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests(endpoint_type="auth")
        assert len(tests) > 0
        categories = [t.get("category", "") for t in tests]
        assert "auth" in categories

    def test_get_relevant_tests_api(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests(endpoint_type="api")
        ids = [t.get("id", "") for t in tests]
        assert "WSTG-APIT-01" in ids

    def test_get_relevant_tests_combined(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests(vuln_type="idor", endpoint_type="api")
        assert len(tests) > 0

    def test_get_relevant_tests_empty(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests()
        assert tests == []

    def test_get_relevant_tests_unknown_vuln(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests(vuln_type="unknown_xyz")
        assert tests == []

    def test_get_capec_id(self):
        ref = ASVSWSTGReference()
        assert ref.get_capec_id("xss") == "CAPEC-86"
        assert ref.get_capec_id("sqli") == "CAPEC-66"
        assert ref.get_capec_id("unknown") == ""

    def test_get_capec_case_insensitive(self):
        ref = ASVSWSTGReference()
        assert ref.get_capec_id("  XSS  ") == "CAPEC-86"

    def test_get_asvs_chapter(self):
        ref = ASVSWSTGReference()
        assert ref.get_asvs_chapter("V5") == "Validation, Sanitization and Encoding"
        assert ref.get_asvs_chapter("V99") == ""

    def test_no_duplicate_results(self):
        ref = ASVSWSTGReference()
        tests = ref.get_relevant_tests(vuln_type="xss", endpoint_type="form")
        ids = [t.get("id", "") for t in tests]
        # WSTG-INPV-01 should appear only once even though it matches both vuln and category
        assert ids.count("WSTG-INPV-01") == 1
