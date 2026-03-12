"""Policy manifest and compiler for scope/rules/rate-limit enforcement.

PolicyManifest captures the program rules (scope, prohibited tests, rate limits,
asset criticality, etc.) in a structured format. PolicyCompiler builds manifests
from CLI args, YAML files, or platform APIs.

Usage:
    # From CLI args (zero-friction, backward compatible)
    manifest = PolicyCompiler.from_cli_args(args)

    # From YAML policy file
    manifest = PolicyCompiler.from_yaml("policy.yaml")

    # CTF mode (permissive)
    manifest = PolicyCompiler.for_ctf("http://target.com")
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse


# ── Data Structures ─────────────────────────────────────────────────────

@dataclass(frozen=True)
class AssetRule:
    """Scope rule for an asset (domain, CIDR, or app ID)."""

    pattern: str
    asset_type: Literal["domain", "cidr", "app_id"] = "domain"
    criticality: float = 0.5  # 0.0–1.0
    notes: str = ""


@dataclass(frozen=True)
class AuthRules:
    """Authentication rules for the testing engagement."""

    test_accounts_provided: bool = False
    self_registration_allowed: bool = True
    required_credentials: dict[str, str] = field(default_factory=dict)
    mfa_required: bool = False


@dataclass
class RateLimitRule:
    """Rate limit for a specific action type."""

    action: str  # e.g., "http_request", "login_attempt", "exploit"
    max_per_minute: int = 60
    max_per_second: float = 2.0


@dataclass
class PolicyManifest:
    """Complete policy for a testing engagement.

    Captures scope, auth rules, prohibited tests, rate limits,
    asset criticality, and engagement mode.
    """

    program_name: str = ""
    platform: str = ""  # "hackerone", "bugcrowd", "synack", "direct", "ctf"
    allowed_assets: list[AssetRule] = field(default_factory=list)
    excluded_assets: list[AssetRule] = field(default_factory=list)
    auth_rules: AuthRules = field(default_factory=AuthRules)
    prohibited_tests: frozenset[str] = field(default_factory=frozenset)
    rate_limits: list[RateLimitRule] = field(default_factory=list)
    reward_eligibility: float = 1.0  # 0.0 = ineligible, 1.0 = full eligibility
    asset_criticality: dict[str, float] = field(default_factory=dict)  # pattern → criticality
    mode: Literal["public_bounty", "ctf", "cooperative"] = "public_bounty"
    hazard_classes: frozenset[str] = field(default_factory=frozenset)  # e.g., {"pii", "financial"}
    noisy_actions: frozenset[str] = field(default_factory=frozenset)
    severity_cap: str = ""  # e.g., "medium" — don't report below this

    # Default prohibited tests for safety
    _DEFAULT_PROHIBITED: frozenset[str] = frozenset({
        "dos", "ddos", "social_engineering", "physical_access",
        "supply_chain", "third_party_services",
    })

    def is_asset_in_scope(self, url: str) -> bool:
        """Check if a URL is within the allowed scope."""
        hostname = self._extract_hostname(url)
        if not hostname:
            return False

        # Check exclusions first
        for rule in self.excluded_assets:
            if self._matches_rule(hostname, url, rule):
                return False

        # If no allowed assets defined, everything is in scope
        if not self.allowed_assets:
            return True

        # Check allowed assets
        for rule in self.allowed_assets:
            if self._matches_rule(hostname, url, rule):
                return True

        return False

    def is_test_allowed(self, technique: str, asset: str = "") -> bool:
        """Check if a testing technique is allowed by policy."""
        technique_lower = technique.lower().strip()

        # Check default prohibited
        if technique_lower in self._DEFAULT_PROHIBITED:
            return False

        # Check policy prohibited
        if technique_lower in self.prohibited_tests:
            return False

        # If asset provided, check scope
        if asset and not self.is_asset_in_scope(asset):
            return False

        return True

    def get_rate_limit(self, action: str) -> RateLimitRule | None:
        """Get rate limit for an action type."""
        for rl in self.rate_limits:
            if rl.action == action:
                return rl
        return None

    def get_asset_criticality(self, url: str) -> float:
        """Get criticality multiplier for an asset (0.0–1.0)."""
        hostname = self._extract_hostname(url)

        # Check explicit criticality mappings
        for pattern, crit in self.asset_criticality.items():
            if fnmatch.fnmatch(hostname, pattern):
                return crit

        # Check allowed_assets for criticality
        for rule in self.allowed_assets:
            if self._matches_rule(hostname, url, rule):
                return rule.criticality

        return 0.5  # Default

    def summary(self) -> str:
        """Build a human-readable policy summary for the brain prompt."""
        lines = [f"Mode: {self.mode}"]

        if self.program_name:
            lines.append(f"Program: {self.program_name}")

        if self.allowed_assets:
            scope_list = ", ".join(r.pattern for r in self.allowed_assets[:10])
            lines.append(f"In-scope: {scope_list}")

        if self.excluded_assets:
            excl_list = ", ".join(r.pattern for r in self.excluded_assets[:10])
            lines.append(f"Excluded: {excl_list}")

        if self.prohibited_tests - self._DEFAULT_PROHIBITED:
            custom = self.prohibited_tests - self._DEFAULT_PROHIBITED
            lines.append(f"Prohibited tests: {', '.join(sorted(custom))}")

        if self.severity_cap:
            lines.append(f"Severity cap: {self.severity_cap}")

        high_value = [
            (p, c) for p, c in self.asset_criticality.items() if c >= 0.8
        ]
        if high_value:
            hv_list = ", ".join(f"{p} ({c:.1f})" for p, c in high_value[:5])
            lines.append(f"High-value targets: {hv_list}")

        return "\n".join(lines)

    @staticmethod
    def _extract_hostname(url: str) -> str:
        """Extract hostname from URL, handling bare domains."""
        if "://" not in url:
            url = f"https://{url}"
        try:
            return (urlparse(url).hostname or "").lower().strip(".")
        except Exception:
            return ""

    @staticmethod
    def _matches_rule(hostname: str, url: str, rule: AssetRule) -> bool:
        """Check if hostname/URL matches an asset rule."""
        pattern = rule.pattern.lower().strip(".")

        if rule.asset_type == "domain":
            # Wildcard domain matching
            if pattern.startswith("*."):
                suffix = pattern[2:]
                return hostname == suffix or hostname.endswith("." + suffix)
            return hostname == pattern or hostname.endswith("." + pattern)

        if rule.asset_type == "cidr":
            # Basic IP range check (simplified — no full CIDR math)
            return hostname.startswith(pattern.split("/")[0].rsplit(".", 1)[0])

        if rule.asset_type == "app_id":
            return pattern in url.lower()

        return False


# ── Policy Compiler ─────────────────────────────────────────────────────

class PolicyCompiler:
    """Builds PolicyManifest from various sources."""

    @staticmethod
    def from_cli_args(args: Any) -> PolicyManifest:
        """Build manifest from existing CLI arguments.

        Backward compatible — works with the current --allowed-domains,
        --out-of-scope, --budget flags. No new flags required.
        """
        allowed: list[AssetRule] = []
        excluded: list[AssetRule] = []

        # Parse allowed domains
        allowed_domains = getattr(args, "allowed_domains", []) or []
        if isinstance(allowed_domains, str):
            allowed_domains = [d.strip() for d in allowed_domains.split(",") if d.strip()]
        for d in allowed_domains:
            d = d.strip()
            if d:
                allowed.append(AssetRule(pattern=d))

        # Parse excluded domains
        out_of_scope = getattr(args, "out_of_scope", []) or []
        if isinstance(out_of_scope, str):
            out_of_scope = [d.strip() for d in out_of_scope.split(",") if d.strip()]
        for d in out_of_scope:
            d = d.strip()
            if d:
                excluded.append(AssetRule(pattern=d))

        # Auto-add target domain if no allowed domains specified
        target = getattr(args, "target", "")
        if target and not allowed:
            hostname = PolicyManifest._extract_hostname(target)
            if hostname:
                allowed.append(AssetRule(pattern=hostname, criticality=0.8))
                # Also allow wildcard subdomains
                allowed.append(AssetRule(pattern=f"*.{hostname}", criticality=0.5))

        # Detect CTF mode
        budget = getattr(args, "budget", 15.0)
        max_turns = getattr(args, "max_turns", 150)
        is_ctf = budget <= 5.0 and max_turns <= 150

        # Parse prohibited tests
        prohibited = set()
        raw_prohibited = getattr(args, "prohibited_tests", []) or []
        if isinstance(raw_prohibited, str):
            raw_prohibited = [t.strip() for t in raw_prohibited.split(",") if t.strip()]
        prohibited.update(raw_prohibited)

        # Parse mode
        mode_str = getattr(args, "mode", "")
        if mode_str in ("public_bounty", "ctf", "cooperative"):
            mode = mode_str
        elif is_ctf:
            mode = "ctf"
        else:
            mode = "public_bounty"

        # Parse policy YAML if provided
        policy_path = getattr(args, "policy", "")
        if policy_path:
            return PolicyCompiler.from_yaml(policy_path)

        return PolicyManifest(
            allowed_assets=allowed,
            excluded_assets=excluded,
            prohibited_tests=frozenset(prohibited),
            mode=mode,
        )

    @staticmethod
    def from_yaml(path: str) -> PolicyManifest:
        """Load full policy from YAML file."""
        import yaml

        p = Path(path)
        if not p.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        data = yaml.safe_load(p.read_text())
        if not isinstance(data, dict):
            raise ValueError(f"Policy file must be a YAML dict: {path}")

        # Parse allowed assets
        allowed = []
        for item in data.get("allowed_assets", []):
            if isinstance(item, str):
                allowed.append(AssetRule(pattern=item))
            elif isinstance(item, dict):
                allowed.append(AssetRule(
                    pattern=item["pattern"],
                    asset_type=item.get("type", "domain"),
                    criticality=float(item.get("criticality", 0.5)),
                    notes=item.get("notes", ""),
                ))

        # Parse excluded assets
        excluded = []
        for item in data.get("excluded_assets", []):
            if isinstance(item, str):
                excluded.append(AssetRule(pattern=item))
            elif isinstance(item, dict):
                excluded.append(AssetRule(
                    pattern=item["pattern"],
                    asset_type=item.get("type", "domain"),
                ))

        # Parse auth rules
        auth_data = data.get("auth_rules", {})
        auth_rules = AuthRules(
            test_accounts_provided=auth_data.get("test_accounts_provided", False),
            self_registration_allowed=auth_data.get("self_registration_allowed", True),
            required_credentials=auth_data.get("required_credentials", {}),
            mfa_required=auth_data.get("mfa_required", False),
        )

        # Parse rate limits
        rate_limits = []
        for rl in data.get("rate_limits", []):
            if isinstance(rl, dict):
                rate_limits.append(RateLimitRule(
                    action=rl.get("action", "http_request"),
                    max_per_minute=rl.get("max_per_minute", 60),
                    max_per_second=float(rl.get("max_per_second", 2.0)),
                ))

        # Parse asset criticality
        asset_crit = {}
        for pattern, crit in data.get("asset_criticality", {}).items():
            asset_crit[pattern] = float(crit)

        return PolicyManifest(
            program_name=data.get("program_name", ""),
            platform=data.get("platform", ""),
            allowed_assets=allowed,
            excluded_assets=excluded,
            auth_rules=auth_rules,
            prohibited_tests=frozenset(data.get("prohibited_tests", [])),
            rate_limits=rate_limits,
            reward_eligibility=float(data.get("reward_eligibility", 1.0)),
            asset_criticality=asset_crit,
            mode=data.get("mode", "public_bounty"),
            hazard_classes=frozenset(data.get("hazard_classes", [])),
            noisy_actions=frozenset(data.get("noisy_actions", [])),
            severity_cap=data.get("severity_cap", ""),
        )

    @staticmethod
    def for_ctf(target_url: str) -> PolicyManifest:
        """Build permissive CTF manifest.

        No prohibited tests (except DoS), no rate limits, maximum
        tool availability from turn 0.
        """
        hostname = PolicyManifest._extract_hostname(target_url)
        allowed = []
        if hostname:
            allowed.append(AssetRule(pattern=hostname, criticality=1.0))
            allowed.append(AssetRule(pattern=f"*.{hostname}", criticality=0.8))

        return PolicyManifest(
            program_name="CTF",
            platform="ctf",
            allowed_assets=allowed,
            mode="ctf",
            reward_eligibility=0.0,  # No bounty
            severity_cap="",  # Report everything
        )

    @staticmethod
    def from_hackerone(handle: str, token: str = "") -> PolicyManifest:
        """Build manifest from HackerOne program API.

        TODO: Implement in Sprint 4 — requires HackerOne API v1 access.
        """
        raise NotImplementedError("HackerOne API integration planned for Sprint 4")

    @staticmethod
    def from_bugcrowd(url: str) -> PolicyManifest:
        """Build manifest from Bugcrowd program page.

        TODO: Implement in Sprint 4 — requires scope page scraping.
        """
        raise NotImplementedError("Bugcrowd scraping planned for Sprint 4")
