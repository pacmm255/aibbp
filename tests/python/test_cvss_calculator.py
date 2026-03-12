"""Exhaustive tests for ai_brain.active.cvss_calculator."""

import pytest

from ai_brain.active.cvss_calculator import (
    VULN_TYPE_CVSS_PROFILES,
    compute_cvss_vector,
    severity_from_score,
    _apply_context_adjustments,
    _build_vector_string,
    _heuristic_score,
)


class TestCVSSProfiles:
    def test_all_profiles_have_required_keys(self):
        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        for vuln_type, profile in VULN_TYPE_CVSS_PROFILES.items():
            assert set(profile.keys()) == required, f"{vuln_type} missing keys"

    def test_all_metric_values_valid(self):
        valid_values = {
            "AV": {"N", "A", "L", "P"},
            "AC": {"L", "H"},
            "PR": {"N", "L", "H"},
            "UI": {"N", "R"},
            "S": {"U", "C"},
            "C": {"N", "L", "H"},
            "I": {"N", "L", "H"},
            "A": {"N", "L", "H"},
        }
        for vuln_type, profile in VULN_TYPE_CVSS_PROFILES.items():
            for metric, value in profile.items():
                assert value in valid_values[metric], f"{vuln_type}.{metric}={value} invalid"

    def test_rce_is_critical(self):
        s, _ = compute_cvss_vector("rce")
        assert s >= 9.0

    def test_cmdi_is_critical(self):
        s, _ = compute_cvss_vector("cmdi")
        assert s >= 9.0

    def test_ssti_is_critical(self):
        s, _ = compute_cvss_vector("ssti")
        assert s >= 9.0

    def test_sqli_is_high(self):
        s, _ = compute_cvss_vector("sqli")
        assert s >= 7.0

    def test_xss_is_medium(self):
        s, _ = compute_cvss_vector("xss")
        assert 4.0 <= s < 9.0

    def test_info_disclosure_is_low(self):
        s, _ = compute_cvss_vector("information_disclosure")
        assert s < 7.0

    def test_profile_count(self):
        assert len(VULN_TYPE_CVSS_PROFILES) >= 27


class TestComputeCvssVector:
    def test_returns_tuple(self):
        result = compute_cvss_vector("xss")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_score_is_float(self):
        s, v = compute_cvss_vector("sqli")
        assert isinstance(s, float)

    def test_vector_string_format(self):
        _, v = compute_cvss_vector("sqli")
        assert v.startswith("CVSS:3.1/")
        assert "/AV:" in v
        assert "/AC:" in v
        assert "/PR:" in v
        assert "/UI:" in v
        assert "/S:" in v
        assert "/C:" in v
        assert "/I:" in v
        assert "/A:" in v

    def test_score_range(self):
        for vt in VULN_TYPE_CVSS_PROFILES:
            s, _ = compute_cvss_vector(vt)
            assert 0.0 <= s <= 10.0, f"{vt} score {s} out of range"

    def test_alias_mapping(self):
        s1, _ = compute_cvss_vector("sql_injection")
        s2, _ = compute_cvss_vector("sqli")
        assert s1 == s2

        s1, _ = compute_cvss_vector("reflected_xss")
        s2, _ = compute_cvss_vector("xss")
        assert s1 == s2

        s1, _ = compute_cvss_vector("command_injection")
        s2, _ = compute_cvss_vector("cmdi")
        assert s1 == s2

        s1, _ = compute_cvss_vector("server_side_request_forgery")
        s2, _ = compute_cvss_vector("ssrf")
        assert s1 == s2

    def test_all_aliases(self):
        aliases = [
            "reflected_xss", "stored_xss", "cross_site_scripting",
            "sql_injection", "blind_sqli", "union_sqli",
            "command_injection", "os_command_injection",
            "server_side_request_forgery",
            "open_redirect", "url_redirect",
            "cors_misconfiguration",
            "account_takeover",
            "path_traversal", "directory_traversal", "local_file_inclusion",
            "nosql_injection",
            "broken_access_control",
            "authentication_bypass",
            "remote_code_execution",
            "template_injection", "server_side_template_injection",
            "xml_external_entity",
            "prototype_pollution",
            "insecure_deserialization",
        ]
        for alias in aliases:
            s, v = compute_cvss_vector(alias)
            assert s > 0, f"Alias '{alias}' returned 0 score"

    def test_unknown_vuln_type_defaults(self):
        s, v = compute_cvss_vector("totally_unknown_vuln_type_xyz")
        assert s >= 0  # Should use default profile, not crash
        assert "CVSS:3.1/" in v

    def test_case_insensitive(self):
        s1, _ = compute_cvss_vector("XSS")
        s2, _ = compute_cvss_vector("xss")
        assert s1 == s2

    def test_whitespace_tolerant(self):
        s1, _ = compute_cvss_vector("  sqli  ")
        s2, _ = compute_cvss_vector("sqli")
        assert s1 == s2


class TestContextAdjustments:
    def test_auth_required_elevates_pr(self):
        s_noauth, _ = compute_cvss_vector("sqli", {})
        s_auth, _ = compute_cvss_vector("sqli", {"auth_required": True})
        assert s_auth <= s_noauth

    def test_user_interaction_sets_ui(self):
        base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
        adjusted = _apply_context_adjustments(base, {"user_interaction": True})
        assert adjusted["UI"] == "R"

    def test_scope_change(self):
        base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
        adjusted = _apply_context_adjustments(base, {"scope_change": True})
        assert adjusted["S"] == "C"

    def test_high_complexity(self):
        base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
        adjusted = _apply_context_adjustments(base, {"high_complexity": True})
        assert adjusted["AC"] == "H"

    def test_admin_required(self):
        base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
        adjusted = _apply_context_adjustments(base, {"admin_required": True})
        assert adjusted["PR"] == "H"

    def test_pii_exposed(self):
        base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"}
        adjusted = _apply_context_adjustments(base, {"pii_exposed": True})
        assert adjusted["C"] == "H"

    def test_no_context_no_change(self):
        base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
        adjusted = _apply_context_adjustments(base, {})
        assert adjusted == base

    def test_original_not_mutated(self):
        base = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"}
        original = dict(base)
        _apply_context_adjustments(base, {"auth_required": True, "high_complexity": True})
        assert base == original  # Original dict unchanged


class TestHeuristicScore:
    def test_all_none_impact_zero(self):
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "N", "I": "N", "A": "N"}
        assert _heuristic_score(metrics) == 0.0

    def test_max_metrics_high_score(self):
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
        score = _heuristic_score(metrics)
        assert score >= 8.0

    def test_physical_av_low_score(self):
        metrics = {"AV": "P", "AC": "H", "PR": "H", "UI": "R", "S": "U", "C": "L", "I": "N", "A": "N"}
        score = _heuristic_score(metrics)
        assert score < 3.0

    def test_scope_changed_higher(self):
        m_unchanged = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "L", "A": "N"}
        m_changed = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "L", "I": "L", "A": "N"}
        assert _heuristic_score(m_changed) >= _heuristic_score(m_unchanged)


class TestBuildVectorString:
    def test_format(self):
        metrics = {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"}
        v = _build_vector_string(metrics)
        assert v == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestSeverityFromScore:
    def test_critical(self):
        assert severity_from_score(9.0) == "critical"
        assert severity_from_score(10.0) == "critical"

    def test_high(self):
        assert severity_from_score(7.0) == "high"
        assert severity_from_score(8.9) == "high"

    def test_medium(self):
        assert severity_from_score(4.0) == "medium"
        assert severity_from_score(6.9) == "medium"

    def test_low(self):
        assert severity_from_score(0.1) == "low"
        assert severity_from_score(3.9) == "low"

    def test_info(self):
        assert severity_from_score(0.0) == "info"
