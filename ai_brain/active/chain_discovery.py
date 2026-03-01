"""Automatic vulnerability chain discovery and adversarial reasoning engine.

Evaluates finding combinations for escalation potential and generates
novel hypotheses from observed behavior. Zero LLM cost for chain
evaluation; uses heuristic rules for chain scoring.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import time
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger()


# ── Chain Templates ─────────────────────────────────────────────────────

@dataclass
class ChainTemplate:
    """A known vulnerability chain pattern."""
    name: str
    steps: list[str]  # vuln_type sequence
    combined_severity: str  # critical, high, medium
    description: str
    real_world_impact: str


# Known chain patterns that turn low/medium findings into critical impact
CHAIN_TEMPLATES = [
    ChainTemplate(
        name="Info Disclosure → SSRF → RCE",
        steps=["info_disclosure", "ssrf", "rce"],
        combined_severity="critical",
        description="Leaked internal URLs enable SSRF to access internal services, leading to RCE",
        real_world_impact="Full server compromise via chained information leak",
    ),
    ChainTemplate(
        name="XSS → Account Takeover",
        steps=["xss", "session_theft"],
        combined_severity="critical",
        description="XSS steals session cookies or tokens, enabling account takeover",
        real_world_impact="Account takeover via stored/reflected XSS",
    ),
    ChainTemplate(
        name="IDOR → Data Exfiltration",
        steps=["idor", "data_exposure"],
        combined_severity="high",
        description="IDOR enables access to other users' data at scale",
        real_world_impact="Mass PII theft via sequential ID enumeration",
    ),
    ChainTemplate(
        name="SQLi → Auth Bypass → Admin Access",
        steps=["sqli", "auth_bypass"],
        combined_severity="critical",
        description="SQL injection extracts admin credentials or bypasses auth",
        real_world_impact="Full admin access via SQL injection",
    ),
    ChainTemplate(
        name="Open Redirect → OAuth Token Theft",
        steps=["open_redirect", "oauth_theft"],
        combined_severity="critical",
        description="Open redirect in OAuth flow leaks authorization tokens",
        real_world_impact="Account takeover via OAuth redirect manipulation",
    ),
    ChainTemplate(
        name="CORS + XSS → Cross-Origin Data Theft",
        steps=["cors_misconfiguration", "xss"],
        combined_severity="high",
        description="CORS misconfiguration combined with XSS enables cross-origin data theft",
        real_world_impact="Sensitive data exfiltration cross-origin",
    ),
    ChainTemplate(
        name="Mass Assignment → Privilege Escalation",
        steps=["mass_assignment", "privilege_escalation"],
        combined_severity="critical",
        description="Mass assignment sets admin flag, enabling privilege escalation",
        real_world_impact="User to admin escalation via hidden parameter",
    ),
    ChainTemplate(
        name="File Upload → Webshell → RCE",
        steps=["file_upload", "rce"],
        combined_severity="critical",
        description="Unrestricted file upload allows webshell deployment",
        real_world_impact="Remote code execution via uploaded webshell",
    ),
    ChainTemplate(
        name="SSRF → Cloud Metadata → AWS Keys",
        steps=["ssrf", "cloud_metadata", "credential_theft"],
        combined_severity="critical",
        description="SSRF accesses cloud metadata service to steal IAM credentials",
        real_world_impact="AWS/GCP/Azure account compromise",
    ),
    ChainTemplate(
        name="Race Condition → Double Spend",
        steps=["race_condition", "financial_impact"],
        combined_severity="high",
        description="Race condition on financial endpoint enables double-spending",
        real_world_impact="Financial loss via concurrent request exploitation",
    ),
    ChainTemplate(
        name="SSTI → RCE",
        steps=["ssti", "rce"],
        combined_severity="critical",
        description="Server-side template injection escalates to code execution",
        real_world_impact="Full server compromise via template injection",
    ),
    ChainTemplate(
        name="Path Traversal → Source Code → Hardcoded Creds",
        steps=["path_traversal", "source_disclosure", "credential_theft"],
        combined_severity="critical",
        description="Path traversal reads source code containing hardcoded credentials",
        real_world_impact="Credential theft via source code exposure",
    ),
    ChainTemplate(
        name="User Enumeration → Credential Stuffing",
        steps=["user_enumeration", "brute_force"],
        combined_severity="medium",
        description="Username enumeration enables targeted credential attacks",
        real_world_impact="Account compromise via targeted credential stuffing",
    ),
    ChainTemplate(
        name="JWT Weakness → Admin Impersonation",
        steps=["jwt_vulnerability", "privilege_escalation"],
        combined_severity="critical",
        description="JWT algorithm confusion or weak secret enables token forging",
        real_world_impact="Admin access via forged JWT token",
    ),
    ChainTemplate(
        name="IDOR + CSRF → Account Modification",
        steps=["idor", "csrf"],
        combined_severity="high",
        description="IDOR with missing CSRF enables modifying other users' accounts",
        real_world_impact="Cross-user data modification",
    ),
]

# Severity escalation rules
SEVERITY_HIERARCHY = {
    "informational": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Vulnerability type compatibility (which types can chain together)
CHAIN_COMPATIBILITY: dict[str, list[str]] = {
    "xss": ["session_theft", "account_takeover", "phishing", "cors_misconfiguration"],
    "sqli": ["data_exposure", "auth_bypass", "credential_theft", "rce"],
    "ssrf": ["cloud_metadata", "internal_access", "rce", "data_exposure", "credential_theft"],
    "idor": ["data_exposure", "privilege_escalation", "account_takeover"],
    "open_redirect": ["oauth_theft", "phishing", "xss"],
    "cors_misconfiguration": ["xss", "data_exposure"],
    "mass_assignment": ["privilege_escalation", "auth_bypass"],
    "file_upload": ["rce", "xss", "path_traversal"],
    "path_traversal": ["source_disclosure", "data_exposure", "credential_theft", "rce"],
    "ssti": ["rce", "data_exposure"],
    "command_injection": ["rce", "data_exposure", "credential_theft"],
    "race_condition": ["financial_impact", "privilege_escalation", "data_exposure"],
    "jwt_vulnerability": ["privilege_escalation", "account_takeover", "auth_bypass"],
    "csrf": ["account_takeover", "privilege_escalation"],
    "user_enumeration": ["brute_force", "credential_stuffing"],
    "info_disclosure": ["ssrf", "sqli", "credential_theft", "path_traversal"],
    "header_injection": ["cache_poisoning", "xss", "open_redirect"],
    "prototype_pollution": ["rce", "privilege_escalation", "auth_bypass"],
    "http_smuggling": ["cache_poisoning", "auth_bypass", "xss"],
    "broken_access_control": ["data_exposure", "privilege_escalation"],
}


# ── Chain Discovery Engine ──────────────────────────────────────────────

class ChainDiscoveryEngine:
    """Automatically discovers vulnerability chains from findings.

    After each new finding, evaluates all combinations to find
    chains that escalate impact. Uses heuristic rules, not LLM calls.
    """

    def __init__(self):
        self._findings: list[dict[str, Any]] = []
        self._discovered_chains: list[dict[str, Any]] = []
        self._chain_hashes: set[str] = set()

    def add_finding(self, finding: dict[str, Any]) -> list[dict[str, Any]]:
        """Add a new finding and check for chain opportunities.

        Returns newly discovered chains (may be empty).
        """
        self._findings.append(finding)
        new_chains = self._evaluate_chains(finding)
        return new_chains

    def get_chains(self) -> list[dict[str, Any]]:
        """Get all discovered chains."""
        return self._discovered_chains

    def get_chain_suggestions(self) -> list[str]:
        """Get suggestions for what to test next based on current findings."""
        suggestions: list[str] = []

        for finding in self._findings:
            vuln_type = finding.get("vuln_type", "")
            endpoint = finding.get("endpoint", "")

            compatible = CHAIN_COMPATIBILITY.get(vuln_type, [])

            for target_type in compatible:
                # Check if we already have this chain
                already_found = any(
                    f.get("vuln_type") == target_type
                    for f in self._findings
                )
                if not already_found:
                    suggestions.append(
                        f"Finding '{vuln_type}' at {endpoint} can chain with "
                        f"'{target_type}'. Test for {target_type} on related endpoints."
                    )

        return suggestions[:10]

    def _evaluate_chains(self, new_finding: dict[str, Any]) -> list[dict[str, Any]]:
        """Evaluate if new finding creates chains with existing findings."""
        new_chains: list[dict[str, Any]] = []
        new_type = new_finding.get("vuln_type", "")

        # Check pairwise chains
        for existing in self._findings:
            if existing is new_finding:
                continue

            existing_type = existing.get("vuln_type", "")

            # Check if these types can chain
            chain = self._check_chain_pair(new_finding, existing)
            if chain:
                chain_hash = self._hash_chain(chain)
                if chain_hash not in self._chain_hashes:
                    self._chain_hashes.add(chain_hash)
                    self._discovered_chains.append(chain)
                    new_chains.append(chain)

        # Check against known templates
        template_chains = self._match_templates()
        for tc in template_chains:
            chain_hash = self._hash_chain(tc)
            if chain_hash not in self._chain_hashes:
                self._chain_hashes.add(chain_hash)
                self._discovered_chains.append(tc)
                new_chains.append(tc)

        if new_chains:
            logger.info(
                "chain_discovery",
                new_chains=len(new_chains),
                total_chains=len(self._discovered_chains),
                finding_type=new_type,
            )

        return new_chains

    def _check_chain_pair(
        self,
        finding_a: dict[str, Any],
        finding_b: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Check if two findings can form a chain."""
        type_a = finding_a.get("vuln_type", "")
        type_b = finding_b.get("vuln_type", "")

        # Check compatibility both ways
        a_chains_to = CHAIN_COMPATIBILITY.get(type_a, [])
        b_chains_to = CHAIN_COMPATIBILITY.get(type_b, [])

        chain = None

        # A enables B
        if type_b in a_chains_to:
            chain = self._build_chain(finding_a, finding_b, f"{type_a} → {type_b}")
        # B enables A
        elif type_a in b_chains_to:
            chain = self._build_chain(finding_b, finding_a, f"{type_b} → {type_a}")
        # Same endpoint, different types — potential interaction
        elif finding_a.get("endpoint") == finding_b.get("endpoint"):
            if type_a != type_b:
                chain = {
                    "chain_name": f"Co-located: {type_a} + {type_b}",
                    "steps": [finding_a, finding_b],
                    "combined_severity": self._escalate_severity(
                        finding_a.get("severity", "medium"),
                        finding_b.get("severity", "medium"),
                    ),
                    "description": (
                        f"Two vulnerabilities ({type_a}, {type_b}) on same endpoint "
                        f"{finding_a.get('endpoint')} may interact for higher impact."
                    ),
                    "auto_discovered": True,
                }

        return chain

    def _build_chain(
        self,
        step1: dict[str, Any],
        step2: dict[str, Any],
        chain_name: str,
    ) -> dict[str, Any]:
        """Build a chain descriptor from two findings."""
        # Look for matching template
        type1 = step1.get("vuln_type", "")
        type2 = step2.get("vuln_type", "")

        template_match = None
        for template in CHAIN_TEMPLATES:
            if type1 in template.steps and type2 in template.steps:
                template_match = template
                break

        return {
            "chain_name": chain_name,
            "steps": [step1, step2],
            "combined_severity": (
                template_match.combined_severity if template_match
                else self._escalate_severity(
                    step1.get("severity", "medium"),
                    step2.get("severity", "medium"),
                )
            ),
            "description": (
                template_match.description if template_match
                else f"Chain: {type1} at {step1.get('endpoint', '')} → {type2} at {step2.get('endpoint', '')}"
            ),
            "real_world_impact": (
                template_match.real_world_impact if template_match
                else f"Combined impact of {type1} + {type2}"
            ),
            "template": template_match.name if template_match else None,
            "auto_discovered": True,
        }

    def _match_templates(self) -> list[dict[str, Any]]:
        """Match current findings against known chain templates."""
        chains: list[dict[str, Any]] = []
        finding_types = {f.get("vuln_type", "") for f in self._findings}

        for template in CHAIN_TEMPLATES:
            # Check if we have findings matching the template steps
            matched_steps = [t for t in template.steps if t in finding_types]
            if len(matched_steps) >= 2:
                # We have enough findings to form this chain
                step_findings = []
                for step_type in matched_steps:
                    for f in self._findings:
                        if f.get("vuln_type") == step_type:
                            step_findings.append(f)
                            break

                chains.append({
                    "chain_name": template.name,
                    "steps": step_findings,
                    "combined_severity": template.combined_severity,
                    "description": template.description,
                    "real_world_impact": template.real_world_impact,
                    "template": template.name,
                    "auto_discovered": True,
                })

        return chains

    @staticmethod
    def _escalate_severity(sev_a: str, sev_b: str) -> str:
        """Escalate severity when chaining two findings."""
        level_a = SEVERITY_HIERARCHY.get(sev_a, 2)
        level_b = SEVERITY_HIERARCHY.get(sev_b, 2)
        combined = min(level_a + level_b, 4)  # Cap at critical
        # Chains always escalate by at least 1 level
        combined = max(combined, max(level_a, level_b) + 1)
        combined = min(combined, 4)
        for name, level in SEVERITY_HIERARCHY.items():
            if level == combined:
                return name
        return "high"

    @staticmethod
    def _hash_chain(chain: dict[str, Any]) -> str:
        """Generate a dedup hash for a chain."""
        steps = chain.get("steps", [])
        key = "|".join(
            f"{s.get('vuln_type', '')}:{s.get('endpoint', '')}"
            for s in steps
        )
        return hashlib.md5(key.encode()).hexdigest()


# ── Adversarial Reasoning Engine ────────────────────────────────────────

class AdversarialReasoningEngine:
    """Generates novel hypotheses from tool results and behavioral observations.

    After each tool execution, analyzes what the result implies about the
    target system and generates new attack hypotheses. Zero LLM cost.
    """

    def __init__(self):
        self._observations: list[dict[str, Any]] = []
        self._hypotheses: list[dict[str, Any]] = []
        self._hypothesis_hashes: set[str] = set()

    def analyze_tool_result(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_result: str,
        current_findings: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Analyze a tool result and generate new hypotheses.

        Returns list of new hypotheses to test.
        """
        new_hypotheses: list[dict[str, Any]] = []

        # Parse result
        try:
            result_data = json.loads(tool_result) if isinstance(tool_result, str) else tool_result
        except (json.JSONDecodeError, TypeError):
            result_data = {"raw": str(tool_result)[:2000]}

        # Record observation
        observation = {
            "tool": tool_name,
            "input": tool_input,
            "result_summary": str(result_data)[:500],
            "timestamp": time.time(),
        }
        self._observations.append(observation)

        # Apply reasoning rules
        rules = [
            self._reason_about_errors,
            self._reason_about_status_codes,
            self._reason_about_technology,
            self._reason_about_parameters,
            self._reason_about_auth,
            self._reason_about_timing,
            self._reason_about_file_exposure,
        ]

        for rule in rules:
            try:
                hypotheses = rule(tool_name, tool_input, result_data)
                for h in hypotheses:
                    h_hash = hashlib.md5(
                        f"{h['hypothesis']}:{h.get('endpoint', '')}".encode()
                    ).hexdigest()
                    if h_hash not in self._hypothesis_hashes:
                        self._hypothesis_hashes.add(h_hash)
                        self._hypotheses.append(h)
                        new_hypotheses.append(h)
            except Exception:
                continue

        return new_hypotheses

    def get_hypotheses(self, status: str = "pending") -> list[dict[str, Any]]:
        """Get hypotheses by status."""
        return [h for h in self._hypotheses if h.get("status") == status]

    def _reason_about_errors(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Errors reveal internal implementation details."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result).lower()

        # Stack trace → technology identification + potential injection
        if any(kw in result_str for kw in ["traceback", "stack trace", "exception"]):
            endpoint = tool_input.get("url", tool_input.get("target", ""))
            hypotheses.append({
                "hypothesis": f"Error messages at {endpoint} reveal internal implementation. "
                    "Try extracting database schema, file paths, or credentials from verbose errors.",
                "endpoint": endpoint,
                "suggested_tool": "response_diff_analyze",
                "priority": "high",
                "status": "pending",
                "reasoning": "Verbose error messages indicate weak error handling, which often "
                    "correlates with other security weaknesses like SQLi or path traversal.",
            })

        # SQL error → SQLi likely
        if any(kw in result_str for kw in ["sql", "mysql", "postgres", "sqlite", "ora-"]):
            endpoint = tool_input.get("url", "")
            hypotheses.append({
                "hypothesis": f"SQL error at {endpoint} suggests injection point. "
                    "Test with UNION-based and blind extraction.",
                "endpoint": endpoint,
                "suggested_tool": "test_sqli",
                "priority": "critical",
                "status": "pending",
                "reasoning": "Database errors in response body confirm the parameter reaches SQL engine.",
            })

        return hypotheses

    def _reason_about_status_codes(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Status code patterns reveal access control logic."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result)

        # 403 means resource EXISTS but is protected
        if "403" in result_str and tool_name in ("navigate_and_extract", "send_http_request", "systematic_fuzz"):
            endpoint = tool_input.get("url", "")
            hypotheses.append({
                "hypothesis": f"403 Forbidden at {endpoint} — resource exists but is protected. "
                    "Try auth bypass: header spoofing, verb tampering, path mutations.",
                "endpoint": endpoint,
                "suggested_tool": "test_auth_bypass",
                "priority": "high",
                "status": "pending",
                "reasoning": "403 confirms the endpoint exists. 404 would mean it doesn't. "
                    "Many WAFs and access controls can be bypassed via HTTP tricks.",
            })

        # 500 means parameter reaches backend code
        if "500" in result_str:
            endpoint = tool_input.get("url", "")
            hypotheses.append({
                "hypothesis": f"500 Internal Server Error at {endpoint} — input reaches backend "
                    "and causes unhandled exception. Likely injection point.",
                "endpoint": endpoint,
                "suggested_tool": "response_diff_analyze",
                "priority": "high",
                "status": "pending",
                "reasoning": "500 errors from user input indicate insufficient input validation.",
            })

        return hypotheses

    def _reason_about_technology(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Technology fingerprints suggest specific attack vectors."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result).lower()

        tech_attacks = {
            "laravel": "Test for .env exposure, mass assignment (is_admin=1), debug mode at /_ignition",
            "django": "Test for debug page at /admin, SSTI in templates, settings.SECRET_KEY exposure",
            "express": "Test for prototype pollution via __proto__, NoSQL injection, path traversal",
            "spring": "Test for actuator endpoints (/actuator/env, /actuator/heapdump), SSTI, SpEL injection",
            "wordpress": "Test for wp-config.php.bak, xmlrpc.php attacks, plugin vulnerabilities",
            "php": "Test for type juggling, LFI via php://filter, file upload bypasses (.phtml, .php5)",
            "graphql": "Test for introspection, field-level auth bypass, batching attacks, nested query DoS",
            "jwt": "Test for alg:none bypass, weak secret brute-force, algorithm confusion (RS256→HS256)",
            "nginx": "Test for ..;/ path traversal, off-by-slash misconfiguration, alias traversal",
            "apache": "Test for .htaccess upload, mod_proxy SSRF, server-status/server-info exposure",
        }

        for tech, attack_suggestion in tech_attacks.items():
            if tech in result_str:
                hypotheses.append({
                    "hypothesis": f"Technology '{tech}' detected. {attack_suggestion}",
                    "endpoint": tool_input.get("url", tool_input.get("target", "")),
                    "suggested_tool": "systematic_fuzz",
                    "priority": "medium",
                    "status": "pending",
                    "reasoning": f"Framework-specific vulnerabilities for {tech} are well-documented.",
                })

        return hypotheses

    def _reason_about_parameters(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Parameter patterns suggest specific vulnerability types."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result).lower()

        # ID parameters → IDOR
        id_patterns = ["user_id", "account_id", "order_id", "profile_id", "document_id"]
        for pattern in id_patterns:
            if pattern in result_str:
                hypotheses.append({
                    "hypothesis": f"Parameter '{pattern}' found — test for IDOR by changing "
                        "the ID value to access other users' resources.",
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "test_idor",
                    "priority": "high",
                    "status": "pending",
                    "reasoning": f"Sequential or guessable {pattern} values are a classic IDOR pattern.",
                })
                break

        # URL/redirect parameters → SSRF/Open Redirect
        url_params = ["url", "redirect", "callback", "next", "return", "goto", "dest", "forward"]
        for param in url_params:
            if f'"{param}"' in result_str or f"'{param}'" in result_str or f"name=\"{param}\"" in result_str:
                hypotheses.append({
                    "hypothesis": f"URL-accepting parameter '{param}' found. "
                        "Test for SSRF (internal network access) and open redirect.",
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "send_http_request",
                    "priority": "high",
                    "status": "pending",
                    "reasoning": "URL parameters are high-value targets for SSRF and redirect attacks.",
                })
                break

        # File parameters → Upload vulnerabilities
        if "type=\"file\"" in result_str or "multipart" in result_str:
            hypotheses.append({
                "hypothesis": "File upload field detected. Test for unrestricted file upload "
                    "(webshell, SVG XSS, path traversal in filename).",
                "endpoint": tool_input.get("url", ""),
                "suggested_tool": "test_file_upload",
                "priority": "high",
                "status": "pending",
                "reasoning": "File upload is a common RCE vector if validation is weak.",
            })

        return hypotheses

    def _reason_about_auth(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Authentication patterns suggest bypass opportunities."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result).lower()

        # JWT token found
        if "eyj" in result_str:  # Base64 JWT prefix
            hypotheses.append({
                "hypothesis": "JWT token detected in response. Test for algorithm confusion "
                    "(alg:none), weak secret, and claim manipulation.",
                "endpoint": tool_input.get("url", ""),
                "suggested_tool": "test_jwt",
                "priority": "high",
                "status": "pending",
                "reasoning": "JWT implementation flaws are extremely common and high-impact.",
            })

        # Different error messages for auth → enumeration
        if tool_name in ("send_http_request", "navigate_and_extract"):
            if any(kw in result_str for kw in ["invalid username", "user not found", "no such user"]):
                hypotheses.append({
                    "hypothesis": "User enumeration possible — different error messages for "
                        "valid vs invalid usernames. Enumerate users, then target specific accounts.",
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "systematic_fuzz",
                    "priority": "medium",
                    "status": "pending",
                    "reasoning": "Differential error messages reveal valid usernames.",
                })

        return hypotheses

    def _reason_about_timing(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Timing variations suggest blind injection or side channels."""
        hypotheses: list[dict[str, Any]] = []

        if isinstance(result, dict):
            elapsed = result.get("elapsed_ms", result.get("elapsed_seconds", 0))
            if isinstance(elapsed, (int, float)) and elapsed > 5000:
                hypotheses.append({
                    "hypothesis": f"Slow response ({elapsed}ms) suggests time-based blind injection "
                        "or heavy backend processing. Test with sleep-based payloads.",
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "blind_sqli_extract",
                    "priority": "high",
                    "status": "pending",
                    "reasoning": "Responses >5s may indicate the payload triggered a SLEEP() or similar.",
                })

        return hypotheses

    def _reason_about_file_exposure(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """File/path exposure suggests further enumeration."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result)

        # Source code or config file exposed
        sensitive_patterns = [
            ("<?php", "PHP source code exposed — check for hardcoded credentials, SQL queries"),
            ("DB_PASSWORD", "Database credentials exposed in configuration"),
            ("SECRET_KEY", "Application secret key exposed — enables session forgery"),
            ("api_key", "API key exposed — test for privilege escalation"),
            ("password", "Password or credential reference found"),
            (".git/", "Git repository exposed — download full source with git-dumper"),
        ]

        for pattern, description in sensitive_patterns:
            if pattern in result_str:
                hypotheses.append({
                    "hypothesis": description,
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "send_http_request",
                    "priority": "critical",
                    "status": "pending",
                    "reasoning": f"Pattern '{pattern}' found in response indicates sensitive data exposure.",
                })
                break

        return hypotheses
