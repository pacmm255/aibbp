"""Exhaustive tests for ai_brain.active.observation_model."""

import json
import uuid
from datetime import datetime, timezone

import pytest

from ai_brain.active.observation_model import (
    Artifact,
    FindingScore,
    Observation,
    ProofPack,
    observation_to_legacy,
    wrap_tool_result,
)


# ── Artifact ────────────────────────────────────────────────────────────


class TestArtifact:
    def test_create_minimal(self):
        a = Artifact(type="http_request")
        assert a.type == "http_request"
        assert a.content == ""
        assert a.metadata == {}
        assert isinstance(a.id, str)
        assert len(a.id) > 0

    def test_content_hash_deterministic(self):
        a1 = Artifact(type="http_response", content="HTTP 200 OK")
        a2 = Artifact(type="http_response", content="HTTP 200 OK")
        assert a1.content_hash == a2.content_hash

    def test_content_hash_different_content(self):
        a1 = Artifact(type="http_response", content="HTTP 200 OK")
        a2 = Artifact(type="http_response", content="HTTP 404 Not Found")
        assert a1.content_hash != a2.content_hash

    def test_content_hash_empty(self):
        a = Artifact(type="code", content="")
        assert len(a.content_hash) == 64  # SHA-256 hex

    def test_content_hash_unicode(self):
        a = Artifact(type="trace", content="日本語テスト 🎯")
        assert len(a.content_hash) == 64

    def test_content_hash_binary_safe(self):
        a = Artifact(type="screenshot", content="\x00\x01\x02\xff")
        assert len(a.content_hash) == 64

    def test_all_types_valid(self):
        for t in ("http_request", "http_response", "screenshot", "trace", "diff", "code"):
            a = Artifact(type=t, content="test")
            assert a.type == t

    def test_metadata_stored(self):
        a = Artifact(type="http_response", metadata={"status": 200, "source": "test"})
        assert a.metadata["status"] == 200

    def test_unique_ids(self):
        ids = {Artifact(type="code").id for _ in range(100)}
        assert len(ids) == 100

    def test_serialization_roundtrip(self):
        a = Artifact(type="http_response", content="body", metadata={"k": "v"})
        d = a.model_dump()
        a2 = Artifact(**d)
        assert a2.content == a.content
        assert a2.content_hash == a.content_hash

    def test_json_roundtrip(self):
        a = Artifact(type="http_request", content="GET /api")
        j = a.model_dump_json()
        a2 = Artifact.model_validate_json(j)
        assert a2.content == "GET /api"


# ── Observation ─────────────────────────────────────────────────────────


class TestObservation:
    def test_create_minimal(self):
        obs = Observation()
        assert obs.type == "scan_result"
        assert obs.subject == ""
        assert obs.turn == 0
        assert obs.confidence == 0.5
        assert isinstance(obs.timestamp, datetime)

    def test_all_types_valid(self):
        for t in ("http_response", "scan_result", "browser_event", "auth_event", "error", "finding_candidate"):
            obs = Observation(type=t)
            assert obs.type == t

    def test_full_construction(self):
        art = Artifact(type="http_response", content="HTTP 200")
        obs = Observation(
            type="http_response",
            subject="http://example.com/api",
            auth_context="admin",
            workflow_step="checkout_step_2",
            confidence=0.95,
            side_effect_risk=0.1,
            artifacts=[art],
            policy_decision="allowed",
            tool_name="send_http_request",
            turn=42,
        )
        assert obs.subject == "http://example.com/api"
        assert obs.auth_context == "admin"
        assert obs.workflow_step == "checkout_step_2"
        assert obs.confidence == 0.95
        assert len(obs.artifacts) == 1
        assert obs.turn == 42

    def test_to_legacy_tuple(self):
        obs = Observation(
            tool_name="test_sqli",
            raw_result={"vulnerable": True, "type": "blind_sqli"},
        )
        name, result_str = obs.to_legacy_tuple()
        assert name == "test_sqli"
        parsed = json.loads(result_str)
        assert parsed["vulnerable"] is True

    def test_raw_result_excluded_from_serialization(self):
        obs = Observation(raw_result={"secret": "data"})
        d = obs.model_dump()
        assert "raw_result" not in d

    def test_replay_recipe(self):
        obs = Observation(replay_recipe={
            "method": "POST",
            "url": "http://target.com/login",
            "body": "user=admin&pass=test",
        })
        assert obs.replay_recipe["method"] == "POST"

    def test_timestamp_is_utc(self):
        obs = Observation()
        assert obs.timestamp.tzinfo is not None


# ── ProofPack ───────────────────────────────────────────────────────────


class TestProofPack:
    def test_empty_completeness(self):
        pp = ProofPack()
        assert pp.completeness_score() == 0.0

    def test_single_component(self):
        pp = ProofPack(attack=Artifact(type="http_response", content="pwned"))
        assert pp.completeness_score() == 0.25

    def test_two_components(self):
        pp = ProofPack(
            baseline=Artifact(type="http_response", content="normal"),
            attack=Artifact(type="http_response", content="injected"),
        )
        assert pp.completeness_score() == 0.5

    def test_three_components(self):
        pp = ProofPack(
            baseline=Artifact(type="http_response", content="normal"),
            attack=Artifact(type="http_response", content="injected"),
            negative_control=Artifact(type="http_response", content="safe"),
        )
        assert pp.completeness_score() == 0.75

    def test_full_completeness(self):
        pp = ProofPack(
            baseline=Artifact(type="http_response", content="normal"),
            attack=Artifact(type="http_response", content="injected"),
            negative_control=Artifact(type="http_response", content="safe"),
            replay_confirmation=Artifact(type="http_response", content="injected_again"),
        )
        assert pp.completeness_score() == 1.0

    def test_to_jsonb(self):
        pp = ProofPack(
            finding_id="f123",
            attack=Artifact(type="http_response", content="pwned"),
            impact_statement="RCE confirmed",
        )
        d = pp.to_jsonb()
        assert d["finding_id"] == "f123"
        assert d["impact_statement"] == "RCE confirmed"
        assert "attack" in d
        # Nones should be excluded
        assert "baseline" not in d

    def test_jsonb_serializable(self):
        pp = ProofPack(
            finding_id="f1",
            attack=Artifact(type="http_response", content="data"),
            affected_objects=["obj1", "obj2"],
        )
        serialized = json.dumps(pp.to_jsonb())
        assert isinstance(serialized, str)
        parsed = json.loads(serialized)
        assert parsed["finding_id"] == "f1"

    def test_sarif_entry_empty_by_default(self):
        pp = ProofPack()
        assert pp.sarif_entry == {}


# ── FindingScore ────────────────────────────────────────────────────────


class TestFindingScore:
    def test_default_composite(self):
        fs = FindingScore()
        c = fs.compute_composite()
        assert c >= 0.0
        assert c <= 1.0
        assert fs.composite_score == c

    def test_high_cvss_high_confidence(self):
        fs = FindingScore(
            cvss_base=9.8,
            verifier_confidence=0.95,
            program_criticality=0.9,
            exploit_maturity="functional",
            duplicate_likelihood=0.1,
        )
        c = fs.compute_composite()
        assert c > 0.7

    def test_low_everything(self):
        fs = FindingScore(
            cvss_base=0.0,
            verifier_confidence=0.0,
            program_criticality=0.0,
            exploit_maturity="none",
            duplicate_likelihood=1.0,
        )
        c = fs.compute_composite()
        assert c < 0.05

    def test_maturity_weights(self):
        fs_none = FindingScore(cvss_base=7.0, verifier_confidence=0.8, exploit_maturity="none")
        fs_weapon = FindingScore(cvss_base=7.0, verifier_confidence=0.8, exploit_maturity="weaponized")
        fs_none.compute_composite()
        fs_weapon.compute_composite()
        assert fs_weapon.composite_score > fs_none.composite_score

    def test_duplicate_penalty(self):
        fs_unique = FindingScore(cvss_base=7.0, verifier_confidence=0.8, duplicate_likelihood=0.0)
        fs_dupe = FindingScore(cvss_base=7.0, verifier_confidence=0.8, duplicate_likelihood=1.0)
        fs_unique.compute_composite()
        fs_dupe.compute_composite()
        assert fs_unique.composite_score > fs_dupe.composite_score

    def test_composite_capped_at_one(self):
        fs = FindingScore(
            cvss_base=10.0,
            verifier_confidence=1.0,
            program_criticality=1.0,
            exploit_maturity="weaponized",
            duplicate_likelihood=0.0,
        )
        c = fs.compute_composite()
        assert c <= 1.0

    def test_unknown_maturity_defaults_to_none(self):
        fs = FindingScore(exploit_maturity="unknown_type")
        fs.compute_composite()
        # Should use default weight for unknown (0.1)
        assert fs.composite_score >= 0


# ── wrap_tool_result ────────────────────────────────────────────────────


class TestWrapToolResult:
    def test_basic_wrap(self):
        obs = wrap_tool_result("test_xss", {"vulnerable": True, "url": "http://x.com"})
        assert obs.tool_name == "test_xss"
        # Result has "vulnerable" but not "vuln_type"/"finding"/"vulnerability", so stays scan_result
        assert obs.type == "scan_result"
        assert obs.subject == "http://x.com"

    def test_finding_candidate_type(self):
        obs = wrap_tool_result("test_xss", {"vuln_type": "xss", "url": "http://x.com"})
        assert obs.type == "finding_candidate"

    def test_http_response_type(self):
        obs = wrap_tool_result("send_http_request", {
            "status_code": 200,
            "headers": {"content-type": "text/html"},
            "body": "<html>test</html>",
        })
        assert obs.type == "http_response"

    def test_error_type(self):
        obs = wrap_tool_result("test_sqli", {"error": "Connection refused"})
        assert obs.type == "error"
        assert obs.confidence == 0.2

    def test_vulnerable_high_confidence(self):
        obs = wrap_tool_result("test_sqli", {"vulnerable": True, "type": "union"})
        assert obs.confidence == 0.9

    def test_artifacts_extraction(self):
        obs = wrap_tool_result("send_http_request", {
            "method": "POST",
            "url": "http://target.com/api",
            "request_headers": {"Content-Type": "application/json"},
            "request_body": '{"user":"admin"}',
            "status_code": 200,
            "headers": {"Set-Cookie": "session=abc"},
            "body": "OK",
        })
        assert len(obs.artifacts) >= 2
        types = {a.type for a in obs.artifacts}
        assert "http_request" in types
        assert "http_response" in types

    def test_turn_and_auth_context(self):
        obs = wrap_tool_result("test_idor", {"result": "ok"}, turn=15, auth_context="user:bob")
        assert obs.turn == 15
        assert obs.auth_context == "user:bob"

    def test_subject_from_endpoint(self):
        obs = wrap_tool_result("test", {"endpoint": "http://api.test.com/users"})
        assert obs.subject == "http://api.test.com/users"

    def test_subject_from_target(self):
        obs = wrap_tool_result("test", {"target": "http://api.test.com"})
        assert obs.subject == "http://api.test.com"

    def test_raw_result_stored(self):
        data = {"key": "value", "nested": {"inner": [1, 2, 3]}}
        obs = wrap_tool_result("test", data)
        assert obs.raw_result == data

    def test_legacy_roundtrip(self):
        data = {"status_code": 404, "body": "not found"}
        obs = wrap_tool_result("send_http_request", data)
        legacy = observation_to_legacy(obs)
        assert legacy == data

    def test_empty_result(self):
        obs = wrap_tool_result("test", {})
        assert obs.type == "scan_result"
        assert obs.confidence == 0.5

    def test_no_artifacts_for_minimal_result(self):
        obs = wrap_tool_result("test", {"message": "no results"})
        # Should not crash, may or may not have artifacts
        assert isinstance(obs.artifacts, list)

    def test_large_body_truncated_in_artifact(self):
        large_body = "X" * 10000
        obs = wrap_tool_result("test", {"body": large_body, "status_code": 200})
        for art in obs.artifacts:
            assert len(art.content) <= 5000  # Should be truncated
