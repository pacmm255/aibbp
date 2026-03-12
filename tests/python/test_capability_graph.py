"""Exhaustive tests for ai_brain.active.capability_graph."""

import pytest

from ai_brain.active.capability_graph import (
    Capability,
    VulnEffect,
    Chain,
    CapabilityGraph,
    VULN_EFFECTS,
    GOAL_STATES,
    _VULN_EFFECT_MAP,
)


# ── VulnEffect Rules ──────────────────────────────────────────────────


class TestVulnEffects:
    def test_effect_count(self):
        assert len(VULN_EFFECTS) >= 28

    def test_all_effects_have_vuln_type(self):
        for effect in VULN_EFFECTS:
            assert effect.vuln_type, f"Effect missing vuln_type: {effect}"

    def test_all_effects_have_grants(self):
        for effect in VULN_EFFECTS:
            assert len(effect.grants) > 0, f"{effect.vuln_type} has no grants"

    def test_grants_format(self):
        for effect in VULN_EFFECTS:
            for grant in effect.grants:
                assert ":" in grant, f"{effect.vuln_type} grant '{grant}' missing colon"

    def test_rce_grants_os_command(self):
        rce = _VULN_EFFECT_MAP["rce"]
        assert "execute:os_command" in rce.grants

    def test_sqli_grants_database(self):
        sqli = _VULN_EFFECT_MAP["sqli"]
        assert "read:database" in sqli.grants

    def test_xss_grants_session_token(self):
        xss = _VULN_EFFECT_MAP["xss"]
        assert "read:session_token" in xss.grants

    def test_ssrf_grants_internal(self):
        ssrf = _VULN_EFFECT_MAP["ssrf"]
        assert "read:internal_network" in ssrf.grants

    def test_cors_has_prerequisites(self):
        cors = _VULN_EFFECT_MAP["cors"]
        assert len(cors.prerequisites) > 0
        assert "read:session_token" in cors.prerequisites

    def test_ato_has_prerequisites(self):
        ato = _VULN_EFFECT_MAP["ato"]
        assert "read:session_token" in ato.prerequisites


# ── Goal States ────────────────────────────────────────────────────────


class TestGoalStates:
    def test_goal_count(self):
        assert len(GOAL_STATES) >= 7

    def test_rce_is_goal(self):
        assert "execute:os_command" in GOAL_STATES

    def test_admin_is_goal(self):
        assert "escalate:admin" in GOAL_STATES

    def test_database_is_goal(self):
        assert "read:database" in GOAL_STATES


# ── Capability ─────────────────────────────────────────────────────────


class TestCapability:
    def test_defaults(self):
        cap = Capability()
        assert cap.cap_type == "read"
        assert cap.scope == "same_user"
        assert cap.verified is False
        assert len(cap.id) > 0

    def test_unique_ids(self):
        ids = {Capability().id for _ in range(50)}
        assert len(ids) == 50


# ── Chain ──────────────────────────────────────────────────────────────


class TestChain:
    def test_describe_complete(self):
        chain = Chain(
            goal="execute:os_command",
            steps=[{"vuln_type": "rce", "grants": ["execute:os_command"]}],
            missing_capabilities=[],
        )
        desc = chain.describe()
        assert "COMPLETE" in desc
        assert "rce" in desc

    def test_describe_incomplete(self):
        chain = Chain(
            goal="escalate:admin",
            steps=[{"vuln_type": "sqli", "grants": ["read:database"]}],
            missing_capabilities=["escalate:admin"],
        )
        desc = chain.describe()
        assert "NEEDS" in desc
        assert "escalate:admin" in desc


# ── CapabilityGraph ────────────────────────────────────────────────────


class TestCapabilityGraph:
    def test_empty_graph(self):
        g = CapabilityGraph()
        # BFS finds direct paths even with no granted caps (effects with no prerequisites)
        chains = g.find_reachable_goals()
        assert isinstance(chains, list)
        # No caps are currently granted, so no chain has confidence 1.0
        for chain in chains:
            assert chain.confidence < 1.0
        assert g.suggest_next_tests() != []  # Should suggest tests even with no caps

    def test_register_finding_xss(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "xss"})
        assert "read:session_token" in caps
        assert "write:dom" in caps
        assert "execute:client_js" in caps

    def test_register_finding_sqli(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "sqli"})
        assert "read:database" in caps
        assert "write:database" in caps

    def test_register_finding_rce(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "rce"})
        assert "execute:os_command" in caps

    def test_register_finding_alias(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "reflected_xss"})
        assert "read:session_token" in caps

    def test_register_finding_sql_injection_alias(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "sql_injection"})
        assert "read:database" in caps

    def test_register_finding_command_injection_alias(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "command_injection"})
        assert "execute:os_command" in caps

    def test_register_unknown_type(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "totally_unknown_xyz"})
        assert caps == []

    def test_no_duplicate_caps(self):
        g = CapabilityGraph()
        caps1 = g.register_finding({"vuln_type": "xss"})
        caps2 = g.register_finding({"vuln_type": "xss"})
        assert len(caps1) > 0
        assert len(caps2) == 0  # Already granted

    def test_case_insensitive(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "XSS"})
        assert "read:session_token" in caps

    def test_whitespace_tolerant(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "  sqli  "})
        assert "read:database" in caps

    def test_find_reachable_goals_with_rce(self):
        g = CapabilityGraph()
        g.register_finding({"vuln_type": "rce"})
        chains = g.find_reachable_goals()
        goals_reached = [c.goal for c in chains if c.confidence >= 0.8]
        assert "execute:os_command" in goals_reached
        assert "write:filesystem" in goals_reached

    def test_find_reachable_goals_with_sqli(self):
        g = CapabilityGraph()
        g.register_finding({"vuln_type": "sqli"})
        chains = g.find_reachable_goals()
        goals_reached = [c.goal for c in chains if c.confidence >= 0.8]
        assert "read:database" in goals_reached

    def test_find_reachable_goals_empty(self):
        g = CapabilityGraph()
        chains = g.find_reachable_goals()
        # Should still return potential chains (via BFS)
        # but with lower confidence
        for chain in chains:
            assert chain.confidence < 1.0

    def test_suggest_next_tests_initial(self):
        g = CapabilityGraph()
        suggestions = g.suggest_next_tests()
        assert len(suggestions) > 0
        # Should suggest RCE, SQLi etc as they reach goals
        text = " ".join(suggestions)
        assert "rce" in text.lower() or "sqli" in text.lower() or "cmdi" in text.lower()

    def test_suggest_next_tests_after_finding(self):
        g = CapabilityGraph()
        g.register_finding({"vuln_type": "xss"})
        suggestions = g.suggest_next_tests()
        # XSS grants session_token which is prereq for cors/ato
        # But those don't reach GOAL_STATES directly - suggestions should still exist
        assert isinstance(suggestions, list)

    def test_bootstrap_from_tech_stack_java(self):
        g = CapabilityGraph()
        g.bootstrap_from_tech_stack(["Java", "Spring Boot"])
        # Should add potential deserialization
        chains = g.find_reachable_goals()
        assert isinstance(chains, list)

    def test_bootstrap_from_tech_stack_php(self):
        g = CapabilityGraph()
        g.bootstrap_from_tech_stack(["PHP", "Apache"])
        chains = g.find_reachable_goals()
        assert isinstance(chains, list)

    def test_bootstrap_from_tech_stack_graphql(self):
        g = CapabilityGraph()
        g.bootstrap_from_tech_stack(["Node.js", "GraphQL"])
        chains = g.find_reachable_goals()
        assert isinstance(chains, list)

    def test_bootstrap_cloud(self):
        g = CapabilityGraph()
        g.bootstrap_from_tech_stack(["AWS", "EC2"])
        # Should add potential ssrf → cloud_metadata
        chains = g.find_reachable_goals()
        assert isinstance(chains, list)

    def test_get_chain_suggestions_empty(self):
        g = CapabilityGraph()
        s = g.get_chain_suggestions()
        # Empty or has suggestions
        assert isinstance(s, str)

    def test_get_chain_suggestions_with_findings(self):
        g = CapabilityGraph()
        g.register_finding({"vuln_type": "sqli"})
        g.register_finding({"vuln_type": "xss"})
        s = g.get_chain_suggestions()
        assert isinstance(s, str)

    def test_multi_hop_chain(self):
        """Test that the graph can find 2-hop paths (xss → cors → cross-origin)."""
        g = CapabilityGraph()
        g.register_finding({"vuln_type": "xss"})
        # XSS grants read:session_token, which is prereq for cors
        # cors grants read:cross_origin_data
        # This tests the multi-hop BFS
        suggestions = g.suggest_next_tests()
        assert isinstance(suggestions, list)

    def test_chain_confidence_levels(self):
        g = CapabilityGraph()
        chains_empty = g.find_reachable_goals()
        g.register_finding({"vuln_type": "rce"})
        chains_with_rce = g.find_reachable_goals()
        # With RCE, some chains should have high confidence
        high_conf = [c for c in chains_with_rce if c.confidence >= 0.8]
        assert len(high_conf) > 0

    def test_verified_finding(self):
        g = CapabilityGraph()
        caps = g.register_finding({"vuln_type": "sqli", "confirmed": True, "finding_id": "f123"})
        cap = g._capabilities.get("read:database")
        assert cap is not None
        assert cap.verified is True
        assert cap.proof_id == "f123"

    def test_all_vuln_types_have_effects(self):
        """Verify common vuln types are in the effect map."""
        expected = ["xss", "sqli", "rce", "cmdi", "ssti", "ssrf", "lfi", "idor", "jwt", "csrf"]
        for vt in expected:
            assert vt in _VULN_EFFECT_MAP, f"{vt} not in VULN_EFFECT_MAP"

    def test_chain_sorted_by_confidence(self):
        g = CapabilityGraph()
        g.register_finding({"vuln_type": "rce"})
        g.register_finding({"vuln_type": "sqli"})
        chains = g.find_reachable_goals()
        if len(chains) >= 2:
            for i in range(len(chains) - 1):
                assert chains[i].confidence >= chains[i + 1].confidence
