"""Exhaustive tests for ai_brain.active.policy."""

import os
import tempfile
import pytest

from ai_brain.active.policy import (
    AssetRule,
    AuthRules,
    RateLimitRule,
    PolicyManifest,
    PolicyCompiler,
)


# ── AssetRule ──────────────────────────────────────────────────────────


class TestAssetRule:
    def test_frozen(self):
        r = AssetRule(pattern="example.com")
        with pytest.raises(AttributeError):
            r.pattern = "other.com"

    def test_defaults(self):
        r = AssetRule(pattern="*.example.com")
        assert r.asset_type == "domain"
        assert r.criticality == 0.5
        assert r.notes == ""

    def test_custom_values(self):
        r = AssetRule(pattern="10.0.0.0/8", asset_type="cidr", criticality=0.9, notes="internal")
        assert r.asset_type == "cidr"
        assert r.criticality == 0.9


# ── AuthRules ──────────────────────────────────────────────────────────


class TestAuthRules:
    def test_defaults(self):
        ar = AuthRules()
        assert ar.test_accounts_provided is False
        assert ar.self_registration_allowed is True
        assert ar.mfa_required is False
        assert ar.required_credentials == {}

    def test_frozen(self):
        ar = AuthRules(test_accounts_provided=True, mfa_required=True)
        with pytest.raises(AttributeError):
            ar.mfa_required = False


# ── RateLimitRule ──────────────────────────────────────────────────────


class TestRateLimitRule:
    def test_defaults(self):
        rl = RateLimitRule(action="http_request")
        assert rl.max_per_minute == 60
        assert rl.max_per_second == 2.0


# ── PolicyManifest ─────────────────────────────────────────────────────


class TestPolicyManifest:

    # -- is_asset_in_scope --

    def test_in_scope_exact_domain(self):
        m = PolicyManifest(allowed_assets=[AssetRule(pattern="example.com")])
        assert m.is_asset_in_scope("https://example.com/path")

    def test_in_scope_wildcard(self):
        m = PolicyManifest(allowed_assets=[AssetRule(pattern="*.example.com")])
        assert m.is_asset_in_scope("https://sub.example.com/api")
        assert m.is_asset_in_scope("https://example.com/api")  # suffix match

    def test_out_of_scope_excluded(self):
        m = PolicyManifest(
            allowed_assets=[AssetRule(pattern="*.example.com")],
            excluded_assets=[AssetRule(pattern="admin.example.com")],
        )
        assert not m.is_asset_in_scope("https://admin.example.com")
        assert m.is_asset_in_scope("https://app.example.com")

    def test_no_allowed_means_all_in_scope(self):
        m = PolicyManifest()
        assert m.is_asset_in_scope("https://anything.com")

    def test_excluded_takes_precedence(self):
        m = PolicyManifest(
            excluded_assets=[AssetRule(pattern="evil.com")],
        )
        assert not m.is_asset_in_scope("https://evil.com/path")
        assert m.is_asset_in_scope("https://good.com")

    def test_bare_domain_url(self):
        m = PolicyManifest(allowed_assets=[AssetRule(pattern="example.com")])
        assert m.is_asset_in_scope("example.com")

    def test_empty_url(self):
        m = PolicyManifest(allowed_assets=[AssetRule(pattern="example.com")])
        assert not m.is_asset_in_scope("")

    def test_cidr_rule(self):
        # Simplified CIDR: splits on / then rsplit('.', 1) → prefix "10.0.0"
        # hostname.startswith("10.0.0") is True for 10.0.0.x but not 10.0.1.x
        m = PolicyManifest(allowed_assets=[AssetRule(pattern="10.0.0.0/8", asset_type="cidr")])
        assert m.is_asset_in_scope("http://10.0.0.5/api")
        # Broader CIDR needs broader pattern
        m2 = PolicyManifest(allowed_assets=[AssetRule(pattern="10.0.0.0/16", asset_type="cidr")])
        assert m2.is_asset_in_scope("http://10.0.0.5/api")

    def test_app_id_rule(self):
        m = PolicyManifest(allowed_assets=[AssetRule(pattern="myapp", asset_type="app_id")])
        assert m.is_asset_in_scope("https://myapp.example.com/v1")

    # -- is_test_allowed --

    def test_default_prohibited(self):
        m = PolicyManifest()
        assert not m.is_test_allowed("dos")
        assert not m.is_test_allowed("ddos")
        assert not m.is_test_allowed("social_engineering")
        assert not m.is_test_allowed("physical_access")
        assert not m.is_test_allowed("supply_chain")
        assert not m.is_test_allowed("third_party_services")

    def test_custom_prohibited(self):
        m = PolicyManifest(prohibited_tests=frozenset({"sqli", "rce"}))
        assert not m.is_test_allowed("sqli")
        assert not m.is_test_allowed("rce")
        assert m.is_test_allowed("xss")

    def test_case_insensitive_technique(self):
        m = PolicyManifest(prohibited_tests=frozenset({"sqli"}))
        assert not m.is_test_allowed("  SQLI  ")

    def test_test_allowed_checks_scope(self):
        m = PolicyManifest(
            allowed_assets=[AssetRule(pattern="example.com")],
        )
        assert m.is_test_allowed("xss", "https://example.com/api")
        assert not m.is_test_allowed("xss", "https://other.com/api")

    def test_test_allowed_no_asset(self):
        m = PolicyManifest()
        assert m.is_test_allowed("xss")

    # -- get_rate_limit --

    def test_rate_limit_found(self):
        m = PolicyManifest(rate_limits=[RateLimitRule(action="login", max_per_minute=5)])
        rl = m.get_rate_limit("login")
        assert rl is not None
        assert rl.max_per_minute == 5

    def test_rate_limit_not_found(self):
        m = PolicyManifest()
        assert m.get_rate_limit("anything") is None

    # -- get_asset_criticality --

    def test_criticality_from_mapping(self):
        m = PolicyManifest(asset_criticality={"api.example.com": 0.95})
        assert m.get_asset_criticality("https://api.example.com/v1") == 0.95

    def test_criticality_from_allowed_assets(self):
        m = PolicyManifest(
            allowed_assets=[AssetRule(pattern="example.com", criticality=0.7)],
        )
        assert m.get_asset_criticality("https://example.com") == 0.7

    def test_criticality_default(self):
        m = PolicyManifest()
        assert m.get_asset_criticality("https://unknown.com") == 0.5

    def test_criticality_wildcard_mapping(self):
        m = PolicyManifest(asset_criticality={"*.prod.example.com": 0.9})
        assert m.get_asset_criticality("https://api.prod.example.com") == 0.9

    # -- summary --

    def test_summary_basic(self):
        m = PolicyManifest(mode="ctf", program_name="TestCTF")
        s = m.summary()
        assert "ctf" in s
        assert "TestCTF" in s

    def test_summary_with_scope(self):
        m = PolicyManifest(
            allowed_assets=[AssetRule(pattern="example.com")],
            excluded_assets=[AssetRule(pattern="admin.example.com")],
        )
        s = m.summary()
        assert "example.com" in s
        assert "admin.example.com" in s

    def test_summary_custom_prohibited(self):
        m = PolicyManifest(prohibited_tests=frozenset({"sqli", "dos"}))
        s = m.summary()
        assert "sqli" in s

    def test_summary_severity_cap(self):
        m = PolicyManifest(severity_cap="medium")
        s = m.summary()
        assert "medium" in s

    def test_summary_high_value_targets(self):
        m = PolicyManifest(asset_criticality={"api.example.com": 0.9})
        s = m.summary()
        assert "api.example.com" in s

    # -- _extract_hostname --

    def test_extract_hostname_https(self):
        assert PolicyManifest._extract_hostname("https://example.com/path") == "example.com"

    def test_extract_hostname_bare(self):
        assert PolicyManifest._extract_hostname("example.com") == "example.com"

    def test_extract_hostname_empty(self):
        assert PolicyManifest._extract_hostname("") == ""

    def test_extract_hostname_with_port(self):
        assert PolicyManifest._extract_hostname("https://example.com:8080/api") == "example.com"

    # -- _matches_rule --

    def test_matches_exact_domain(self):
        rule = AssetRule(pattern="example.com")
        assert PolicyManifest._matches_rule("example.com", "", rule)
        assert not PolicyManifest._matches_rule("other.com", "", rule)

    def test_matches_wildcard_domain(self):
        rule = AssetRule(pattern="*.example.com")
        assert PolicyManifest._matches_rule("sub.example.com", "", rule)
        assert PolicyManifest._matches_rule("example.com", "", rule)
        assert not PolicyManifest._matches_rule("other.com", "", rule)

    def test_matches_app_id(self):
        rule = AssetRule(pattern="myapp", asset_type="app_id")
        assert PolicyManifest._matches_rule("", "https://myapp.example.com", rule)
        assert not PolicyManifest._matches_rule("", "https://other.example.com", rule)


# ── PolicyCompiler ─────────────────────────────────────────────────────


class TestPolicyCompilerFromCliArgs:
    class FakeArgs:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)

    def test_target_auto_adds_allowed(self):
        args = self.FakeArgs(target="https://example.com", budget=15.0)
        m = PolicyCompiler.from_cli_args(args)
        assert m.is_asset_in_scope("https://example.com/api")
        assert m.is_asset_in_scope("https://sub.example.com/api")

    def test_ctf_auto_detection(self):
        args = self.FakeArgs(target="http://ctf.local", budget=3.0, max_turns=100)
        m = PolicyCompiler.from_cli_args(args)
        assert m.mode == "ctf"

    def test_non_ctf_mode(self):
        args = self.FakeArgs(target="http://target.com", budget=20.0, max_turns=200)
        m = PolicyCompiler.from_cli_args(args)
        assert m.mode == "public_bounty"

    def test_explicit_mode(self):
        args = self.FakeArgs(target="http://target.com", mode="cooperative", budget=3.0, max_turns=100)
        m = PolicyCompiler.from_cli_args(args)
        assert m.mode == "cooperative"

    def test_allowed_domains_string(self):
        args = self.FakeArgs(allowed_domains="a.com, b.com", target="", budget=10.0)
        m = PolicyCompiler.from_cli_args(args)
        assert m.is_asset_in_scope("https://a.com")
        assert m.is_asset_in_scope("https://b.com")

    def test_allowed_domains_list(self):
        args = self.FakeArgs(allowed_domains=["a.com", "b.com"], target="", budget=10.0)
        m = PolicyCompiler.from_cli_args(args)
        assert m.is_asset_in_scope("https://a.com")

    def test_out_of_scope_string(self):
        args = self.FakeArgs(out_of_scope="admin.example.com", target="https://example.com", budget=10.0)
        m = PolicyCompiler.from_cli_args(args)
        assert not m.is_asset_in_scope("https://admin.example.com")

    def test_prohibited_tests_string(self):
        args = self.FakeArgs(prohibited_tests="sqli,rce", target="http://x.com", budget=10.0)
        m = PolicyCompiler.from_cli_args(args)
        assert not m.is_test_allowed("sqli")
        assert not m.is_test_allowed("rce")

    def test_empty_args(self):
        args = self.FakeArgs()
        m = PolicyCompiler.from_cli_args(args)
        assert m.mode == "public_bounty"


class TestPolicyCompilerFromYaml:
    def test_basic_yaml(self, tmp_path):
        yaml_content = """
program_name: TestProgram
platform: hackerone
mode: cooperative
allowed_assets:
  - example.com
  - pattern: "*.staging.example.com"
    type: domain
    criticality: 0.9
    notes: "staging environment"
excluded_assets:
  - admin.example.com
prohibited_tests:
  - dos
  - social_engineering
rate_limits:
  - action: http_request
    max_per_minute: 120
    max_per_second: 5.0
asset_criticality:
  "api.example.com": 0.95
reward_eligibility: 0.8
severity_cap: low
hazard_classes:
  - pii
  - financial
"""
        f = tmp_path / "policy.yaml"
        f.write_text(yaml_content)
        m = PolicyCompiler.from_yaml(str(f))

        assert m.program_name == "TestProgram"
        assert m.platform == "hackerone"
        assert m.mode == "cooperative"
        assert len(m.allowed_assets) == 2
        assert m.allowed_assets[1].criticality == 0.9
        assert len(m.excluded_assets) == 1
        assert "dos" in m.prohibited_tests
        assert len(m.rate_limits) == 1
        assert m.rate_limits[0].max_per_minute == 120
        assert m.asset_criticality["api.example.com"] == 0.95
        assert m.reward_eligibility == 0.8
        assert m.severity_cap == "low"
        assert "pii" in m.hazard_classes

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            PolicyCompiler.from_yaml("/nonexistent/path.yaml")

    def test_invalid_yaml(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("- just a list")
        with pytest.raises(ValueError):
            PolicyCompiler.from_yaml(str(f))

    def test_auth_rules(self, tmp_path):
        yaml_content = """
auth_rules:
  test_accounts_provided: true
  self_registration_allowed: false
  mfa_required: true
  required_credentials:
    admin: admin123
"""
        f = tmp_path / "auth.yaml"
        f.write_text(yaml_content)
        m = PolicyCompiler.from_yaml(str(f))
        assert m.auth_rules.test_accounts_provided is True
        assert m.auth_rules.self_registration_allowed is False
        assert m.auth_rules.mfa_required is True
        assert m.auth_rules.required_credentials["admin"] == "admin123"

    def test_minimal_yaml(self, tmp_path):
        f = tmp_path / "min.yaml"
        f.write_text("{}")
        m = PolicyCompiler.from_yaml(str(f))
        assert m.program_name == ""
        assert m.mode == "public_bounty"


class TestPolicyCompilerForCtf:
    def test_ctf_manifest(self):
        m = PolicyCompiler.for_ctf("http://ctf.example.com:8080")
        assert m.mode == "ctf"
        assert m.platform == "ctf"
        assert m.program_name == "CTF"
        assert m.reward_eligibility == 0.0
        assert m.is_asset_in_scope("http://ctf.example.com:8080/flag")
        assert len(m.allowed_assets) == 2

    def test_ctf_no_prohibited(self):
        m = PolicyCompiler.for_ctf("http://localhost:8080")
        assert m.is_test_allowed("sqli")
        assert m.is_test_allowed("rce")
        # Only default prohibitions apply
        assert not m.is_test_allowed("dos")


class TestPolicyCompilerStubs:
    def test_hackerone_not_implemented(self):
        with pytest.raises(NotImplementedError):
            PolicyCompiler.from_hackerone("test-program")

    def test_bugcrowd_not_implemented(self):
        with pytest.raises(NotImplementedError):
            PolicyCompiler.from_bugcrowd("https://bugcrowd.com/test")
