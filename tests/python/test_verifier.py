"""Exhaustive tests for ai_brain.active.verifier."""

import pytest

from ai_brain.active.verifier import Verifier
from ai_brain.active.observation_model import (
    Artifact,
    Observation,
    ProofPack,
    FindingScore,
)


# ── Verifier._is_injection_type ───────────────────────────────────────


class TestIsInjectionType:
    def test_injection_types(self):
        injection = [
            "xss", "sqli", "nosqli", "cmdi", "ssti", "xxe", "lfi",
            "ssrf", "redirect", "path_traversal", "command_injection",
            "sql_injection", "reflected_xss", "stored_xss",
            "server_side_template_injection", "xml_external_entity",
        ]
        for vt in injection:
            assert Verifier._is_injection_type(vt), f"{vt} should be injection type"

    def test_non_injection_types(self):
        non_injection = ["idor", "bac", "race_condition", "jwt", "csrf", "info_disc"]
        for vt in non_injection:
            assert not Verifier._is_injection_type(vt), f"{vt} should NOT be injection type"

    def test_case_insensitive(self):
        assert Verifier._is_injection_type("XSS")
        assert Verifier._is_injection_type("  SQLI  ")


# ── Verifier._find_attack_observation ─────────────────────────────────


class TestFindAttackObservation:
    def _make_verifier(self):
        class FakeScopeGuard:
            def validate_url(self, url): pass
        return Verifier(scope_guard=FakeScopeGuard())

    def test_match_by_tool_and_endpoint(self):
        v = self._make_verifier()
        obs = Observation(
            tool_name="test_sqli",
            subject="http://example.com/api/users",
        )
        finding = {"tool_used": "test_sqli", "endpoint": "http://example.com/api/users"}
        result = v._find_attack_observation(finding, [obs])
        assert result is obs

    def test_match_by_endpoint_path(self):
        v = self._make_verifier()
        obs = Observation(
            tool_name="other_tool",
            subject="http://example.com/api/users?id=1",
        )
        finding = {"tool_used": "different_tool", "endpoint": "http://example.com/api/users"}
        result = v._find_attack_observation(finding, [obs])
        assert result is obs

    def test_match_exploit_tool_fallback(self):
        v = self._make_verifier()
        obs = Observation(
            tool_name="send_http_request",
            subject="http://example.com/other",
        )
        finding = {"tool_used": "no_match", "endpoint": "http://no-match.com"}
        result = v._find_attack_observation(finding, [obs])
        assert result is obs

    def test_no_match(self):
        v = self._make_verifier()
        obs = Observation(tool_name="scan_info_disclosure", subject="http://x.com")
        finding = {"tool_used": "test_sqli", "endpoint": "http://y.com/api"}
        result = v._find_attack_observation(finding, [obs])
        assert result is None

    def test_empty_observations(self):
        v = self._make_verifier()
        finding = {"tool_used": "test_sqli", "endpoint": "http://x.com"}
        result = v._find_attack_observation(finding, [])
        assert result is None

    def test_prefers_most_recent(self):
        v = self._make_verifier()
        obs_old = Observation(
            tool_name="test_sqli",
            subject="http://example.com/api",
        )
        obs_new = Observation(
            tool_name="test_sqli",
            subject="http://example.com/api",
        )
        finding = {"tool_used": "test_sqli", "endpoint": "http://example.com/api"}
        result = v._find_attack_observation(finding, [obs_old, obs_new])
        assert result is obs_new  # reversed() makes latest first


# ── Verifier._compute_finding_score ───────────────────────────────────


class TestComputeFindingScore:
    def _make_verifier(self):
        class FakeScopeGuard:
            def validate_url(self, url): pass
        return Verifier(scope_guard=FakeScopeGuard())

    def test_basic_score(self):
        v = self._make_verifier()
        finding = {"vuln_type": "xss"}
        pack = ProofPack()
        score = v._compute_finding_score(finding, pack)
        assert score.cvss_base > 0
        assert 0 <= score.composite_score <= 1.0

    def test_score_with_proof(self):
        v = self._make_verifier()
        finding = {"vuln_type": "sqli"}
        pack = ProofPack(
            attack=Artifact(type="http_response", content="data"),
            replay_confirmation=Artifact(type="http_response", content="replayed"),
        )
        score = v._compute_finding_score(finding, pack)
        assert score.exploit_maturity == "functional"  # Has replay
        assert score.composite_score > 0

    def test_score_poc_only(self):
        v = self._make_verifier()
        finding = {"vuln_type": "rce"}
        pack = ProofPack(
            attack=Artifact(type="http_response", content="pwned"),
        )
        score = v._compute_finding_score(finding, pack)
        assert score.exploit_maturity == "poc"

    def test_score_no_proof(self):
        v = self._make_verifier()
        finding = {"vuln_type": "xss"}
        pack = ProofPack()
        score = v._compute_finding_score(finding, pack)
        assert score.exploit_maturity == "none"

    def test_score_with_evidence_score(self):
        v = self._make_verifier()
        finding = {"vuln_type": "xss", "evidence_score": 5}
        pack = ProofPack()
        score = v._compute_finding_score(finding, pack)
        assert score.verifier_confidence >= 1.0  # 5/5 = 1.0

    def test_score_with_policy_manifest(self):
        v = self._make_verifier()
        from ai_brain.active.policy import PolicyManifest, AssetRule
        manifest = PolicyManifest(
            asset_criticality={"example.com": 0.95},
        )
        finding = {"vuln_type": "sqli", "endpoint": "https://example.com/api"}
        pack = ProofPack()
        score = v._compute_finding_score(finding, pack, policy_manifest=manifest)
        assert score.program_criticality == 0.95

    def test_score_auth_context_adjusts_cvss(self):
        v = self._make_verifier()
        finding_noauth = {"vuln_type": "sqli"}
        finding_auth = {"vuln_type": "sqli", "auth_context": "user"}
        pack = ProofPack()
        score_noauth = v._compute_finding_score(finding_noauth, pack)
        score_auth = v._compute_finding_score(finding_auth, pack)
        # Auth required should lower CVSS (PR goes up)
        assert score_auth.cvss_base <= score_noauth.cvss_base


# ── Verifier._build_impact_statement ──────────────────────────────────


class TestBuildImpactStatement:
    def _make_verifier(self):
        class FakeScopeGuard:
            def validate_url(self, url): pass
        return Verifier(scope_guard=FakeScopeGuard())

    def test_high_completeness(self):
        v = self._make_verifier()
        finding = {"vuln_type": "sqli", "endpoint": "http://x.com/api"}
        pack = ProofPack(
            baseline=Artifact(type="http_response", content="a"),
            attack=Artifact(type="http_response", content="b"),
            negative_control=Artifact(type="http_response", content="c"),
            replay_confirmation=Artifact(type="http_response", content="d"),
        )
        stmt = v._build_impact_statement(finding, pack)
        assert "Verified" in stmt
        assert "100%" in stmt
        assert "Replay confirmed" in stmt

    def test_medium_completeness(self):
        v = self._make_verifier()
        finding = {"vuln_type": "xss", "endpoint": "http://x.com"}
        pack = ProofPack(
            baseline=Artifact(type="http_response", content="a"),
            attack=Artifact(type="http_response", content="b"),
        )
        stmt = v._build_impact_statement(finding, pack)
        assert "Partially verified" in stmt

    def test_low_completeness(self):
        v = self._make_verifier()
        finding = {"vuln_type": "ssrf", "endpoint": "http://x.com"}
        pack = ProofPack()
        stmt = v._build_impact_statement(finding, pack)
        assert "Candidate" in stmt
        assert "manual verification" in stmt


# ── Verifier.verify (sync parts, no network) ─────────────────────────


class TestVerifierVerify:
    def _make_verifier(self):
        class FakeScopeGuard:
            def validate_url(self, url): pass
        return Verifier(scope_guard=FakeScopeGuard())

    @pytest.mark.asyncio
    async def test_verify_minimal(self):
        v = self._make_verifier()
        finding = {"vuln_type": "idor", "endpoint": "http://x.com/api/users/1"}
        pack = await v.verify(finding, [])
        assert isinstance(pack, ProofPack)
        assert pack.impact_statement != ""

    @pytest.mark.asyncio
    async def test_verify_with_matching_observation(self):
        v = self._make_verifier()
        obs = Observation(
            tool_name="test_idor",
            subject="http://x.com/api/users/1",
            artifacts=[Artifact(type="http_response", content="HTTP 200\nuser data")],
        )
        finding = {
            "vuln_type": "idor",
            "endpoint": "http://x.com/api/users/1",
            "tool_used": "test_idor",
        }
        pack = await v.verify(finding, [obs])
        assert pack.attack is not None
        assert pack.attack.content == "HTTP 200\nuser data"

    @pytest.mark.asyncio
    async def test_verify_non_injection_skips_differential(self):
        v = self._make_verifier()
        finding = {"vuln_type": "idor", "endpoint": "http://x.com/api"}
        pack = await v.verify(finding, [])
        # IDOR is not injection type, so no differential testing
        assert pack.baseline is None
        assert pack.negative_control is None

    @pytest.mark.asyncio
    async def test_verify_sets_triager_score(self):
        v = self._make_verifier()
        finding = {"vuln_type": "xss"}
        pack = await v.verify(finding, [])
        assert pack.triager_score >= 0.0

    @pytest.mark.asyncio
    async def test_verify_sets_auth_context(self):
        v = self._make_verifier()
        finding = {"vuln_type": "sqli", "auth_context": "admin", "workflow_step": "checkout"}
        pack = await v.verify(finding, [])
        assert pack.auth_context == "admin"
        assert pack.workflow_context == "checkout"

    @pytest.mark.asyncio
    async def test_verify_sets_finding_id(self):
        v = self._make_verifier()
        finding = {"vuln_type": "xss", "finding_id": "f-123"}
        pack = await v.verify(finding, [])
        assert pack.finding_id == "f-123"
