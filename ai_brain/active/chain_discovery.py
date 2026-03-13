"""Automatic vulnerability chain discovery and adversarial reasoning engine.

Evaluates finding combinations for escalation potential and generates
novel hypotheses from observed behavior. Zero LLM cost for chain
evaluation; uses heuristic rules for chain scoring.

The AdversarialReasoningEngine dynamically generates testable hypotheses
from actual observations (endpoints, findings, tech stack, traffic
intelligence) rather than relying solely on static pattern matching.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import re
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


# ── Impact weights for hypothesis prioritization ──────────────────────

_IMPACT_WEIGHTS: dict[str, int] = {
    "rce": 10,
    "sqli": 9,
    "ssrf": 8,
    "auth_bypass": 8,
    "credential_theft": 8,
    "privilege_escalation": 7,
    "account_takeover": 7,
    "idor": 6,
    "ssti": 7,
    "file_upload": 6,
    "path_traversal": 6,
    "command_injection": 9,
    "xss": 5,
    "open_redirect": 4,
    "user_enumeration": 3,
    "info_disclosure": 3,
    "csrf": 4,
    "race_condition": 5,
    "jwt_vulnerability": 7,
    "mass_assignment": 6,
    "prototype_pollution": 6,
    "http_smuggling": 7,
    "cors_misconfiguration": 3,
    "header_injection": 4,
    "broken_access_control": 7,
}

# Testability scores: how easy is it to verify this hypothesis?
_TESTABILITY: dict[str, int] = {
    "send_http_request": 9,  # Simple HTTP request — easy
    "systematic_fuzz": 8,    # Automated fuzzing — easy
    "test_sqli": 8,
    "test_xss": 7,
    "test_idor": 7,
    "test_jwt": 7,
    "test_file_upload": 6,
    "test_auth_bypass": 6,
    "response_diff_analyze": 8,
    "blind_sqli_extract": 5,  # Time-based — harder to confirm
    "run_custom_exploit": 4,  # Requires manual script — least testable
    "navigate_and_extract": 7,
}


# ── Adversarial Reasoning Engine ────────────────────────────────────────

class AdversarialReasoningEngine:
    """Generates novel hypotheses from tool results and behavioral observations.

    After each tool execution, analyzes what the result implies about the
    target system and generates new attack hypotheses. Zero LLM cost.

    Enhanced with:
    - ``generate_hypotheses(state)`` — derives testable hypotheses from full
      pentesting state (endpoints, findings, tech stack, traffic intel)
    - ``prioritize_hypotheses()`` — ranks by testability, impact, novelty
    - ``update_hypothesis_status()`` — lifecycle tracking
    - Dynamic rule generation from cross-referencing observations
    """

    def __init__(self) -> None:
        self._observations: list[dict[str, Any]] = []
        self._hypotheses: list[dict[str, Any]] = []
        self._hypothesis_hashes: set[str] = set()
        # Track which observation-derived rules have already fired,
        # keyed by a short descriptor so we don't repeat ourselves.
        self._fired_dynamic_rules: set[str] = set()

    # ── Public API ──────────────────────────────────────────────────

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
        # Cap observations to prevent unbounded memory growth
        if len(self._observations) > 500:
            self._observations = self._observations[-400:]

        # Apply per-result reasoning rules
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
                new_hypotheses.extend(self._dedupe_and_store(hypotheses))
            except Exception:
                continue

        # Cross-observation dynamic rules (fires across accumulated data)
        try:
            dynamic = self._generate_dynamic_rules(current_findings)
            new_hypotheses.extend(self._dedupe_and_store(dynamic))
        except Exception:
            pass

        return new_hypotheses

    def generate_hypotheses(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Generate testable hypotheses from the full pentesting state.

        Called periodically (e.g. from the compressor node) to derive
        hypotheses from the accumulated knowledge — endpoints, findings,
        tech stack, traffic intelligence, accounts — rather than from
        a single tool result.

        Returns only *new* hypotheses (already-seen ones are deduped).
        """
        new_hypotheses: list[dict[str, Any]] = []

        generators = [
            self._hypothesize_from_endpoints,
            self._hypothesize_from_findings,
            self._hypothesize_from_tech_stack,
            self._hypothesize_from_traffic_intel,
            self._hypothesize_from_api_versions,
            self._hypothesize_from_auth_gaps,
            self._hypothesize_from_error_patterns,
        ]

        for gen in generators:
            try:
                new_hypotheses.extend(self._dedupe_and_store(gen(state)))
            except Exception:
                continue

        if new_hypotheses:
            logger.info(
                "adversarial_state_hypotheses",
                new=len(new_hypotheses),
                total=len(self._hypotheses),
            )
        return new_hypotheses

    def prioritize_hypotheses(
        self,
        hypotheses: list[dict[str, Any]] | None = None,
    ) -> list[dict[str, Any]]:
        """Rank hypotheses by testability * impact * novelty.

        If *hypotheses* is ``None``, operates on all internal pending hypotheses.
        Returns a new list sorted best-first (does **not** mutate the input).
        """
        candidates = hypotheses if hypotheses is not None else self.get_hypotheses("untested")
        if not candidates:
            candidates = self.get_hypotheses("pending")

        scored: list[tuple[float, dict[str, Any]]] = []
        seen_vuln_types: set[str] = set()

        for h in candidates:
            impact = _IMPACT_WEIGHTS.get(h.get("vuln_type", ""), 5)
            testability = _TESTABILITY.get(h.get("suggested_tool", ""), 5)
            # Novelty bonus: first time we see this vuln_type gets 1.5x
            vuln_type = h.get("vuln_type", h.get("suggested_tool", "unknown"))
            novelty = 1.5 if vuln_type not in seen_vuln_types else 1.0
            seen_vuln_types.add(vuln_type)
            # Priority bonus
            prio_bonus = {"critical": 2.0, "high": 1.5, "medium": 1.0, "low": 0.5}.get(
                h.get("priority", "medium"), 1.0,
            )
            score = impact * testability * novelty * prio_bonus
            scored.append((score, h))

        scored.sort(key=lambda x: x[0], reverse=True)
        return [h for _, h in scored]

    def update_hypothesis_status(
        self,
        hypothesis_id: str,
        status: str,
        evidence: str = "",
    ) -> bool:
        """Update the status of a hypothesis.

        *status* must be one of: ``untested``, ``pending``, ``confirmed``,
        ``rejected``.

        Returns ``True`` if a matching hypothesis was found and updated.
        """
        for h in self._hypotheses:
            if h.get("id") == hypothesis_id:
                h["status"] = status
                if evidence:
                    h["evidence"] = evidence
                h["updated_at"] = time.time()
                return True
        return False

    def get_hypotheses(self, status: str = "pending") -> list[dict[str, Any]]:
        """Get hypotheses filtered by status."""
        return [h for h in self._hypotheses if h.get("status") == status]

    def get_all_hypotheses(self) -> list[dict[str, Any]]:
        """Return every hypothesis regardless of status."""
        return list(self._hypotheses)

    def get_hypothesis_summary(self, max_items: int = 15) -> str:
        """Return a compact text summary suitable for prompt injection.

        Shows at most *max_items* total, sorted by priority score.
        """
        if not self._hypotheses:
            return ""

        prioritized = self.prioritize_hypotheses(self._hypotheses)
        lines: list[str] = []
        shown = 0
        for h in prioritized:
            if shown >= max_items:
                remaining = len(prioritized) - shown
                if remaining > 0:
                    lines.append(f"  ... and {remaining} more")
                break
            status = h.get("status", "pending")
            prio = h.get("priority", "?")
            desc = h.get("hypothesis", "?")
            # Truncate long descriptions
            if len(desc) > 120:
                desc = desc[:117] + "..."
            lines.append(f"  [{status}|{prio}] {desc}")
            shown += 1
        return "\n".join(lines)

    # ── Internal helpers ────────────────────────────────────────────

    def _dedupe_and_store(self, hypotheses: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Deduplicate hypotheses, assign IDs, store internally. Return new ones."""
        new: list[dict[str, Any]] = []
        for h in hypotheses:
            h_hash = hashlib.md5(
                f"{h.get('hypothesis', '')}:{h.get('endpoint', '')}".encode()
            ).hexdigest()
            if h_hash not in self._hypothesis_hashes:
                self._hypothesis_hashes.add(h_hash)
                h.setdefault("id", f"hyp_{h_hash[:8]}")
                h.setdefault("status", "untested")
                h.setdefault("created_at", time.time())
                self._hypotheses.append(h)
                new.append(h)
        return new

    # ── Per-result reasoning rules (unchanged public interface) ────

    def _reason_about_errors(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Errors reveal internal implementation details."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result).lower()

        # Stack trace -> technology identification + potential injection
        if any(kw in result_str for kw in ["traceback", "stack trace", "exception"]):
            endpoint = tool_input.get("url", tool_input.get("target", ""))
            hypotheses.append({
                "hypothesis": f"Error messages at {endpoint} reveal internal implementation. "
                    "Try extracting database schema, file paths, or credentials from verbose errors.",
                "endpoint": endpoint,
                "suggested_tool": "response_diff_analyze",
                "priority": "high",
                "status": "untested",
                "vuln_type": "info_disclosure",
                "reasoning": "Verbose error messages indicate weak error handling, which often "
                    "correlates with other security weaknesses like SQLi or path traversal.",
            })

        # SQL error -> SQLi likely
        if any(kw in result_str for kw in ["sql", "mysql", "postgres", "sqlite", "ora-"]):
            endpoint = tool_input.get("url", "")
            hypotheses.append({
                "hypothesis": f"SQL error at {endpoint} suggests injection point. "
                    "Test with UNION-based and blind extraction.",
                "endpoint": endpoint,
                "suggested_tool": "test_sqli",
                "priority": "critical",
                "status": "untested",
                "vuln_type": "sqli",
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
                "status": "untested",
                "vuln_type": "auth_bypass",
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
                "status": "untested",
                "vuln_type": "sqli",
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
            "laravel": ("Test for .env exposure, mass assignment (is_admin=1), debug mode at /_ignition", "mass_assignment"),
            "django": ("Test for debug page at /admin, SSTI in templates, settings.SECRET_KEY exposure", "ssti"),
            "express": ("Test for prototype pollution via __proto__, NoSQL injection, path traversal", "prototype_pollution"),
            "spring": ("Test for actuator endpoints (/actuator/env, /actuator/heapdump), SSTI, SpEL injection", "ssti"),
            "wordpress": ("Test for wp-config.php.bak, xmlrpc.php attacks, plugin vulnerabilities", "rce"),
            "php": ("Test for type juggling, LFI via php://filter, file upload bypasses (.phtml, .php5)", "path_traversal"),
            "graphql": ("Test for introspection, field-level auth bypass, batching attacks, nested query DoS", "broken_access_control"),
            "jwt": ("Test for alg:none bypass, weak secret brute-force, algorithm confusion (RS256->HS256)", "jwt_vulnerability"),
            "nginx": ("Test for ..;/ path traversal, off-by-slash misconfiguration, alias traversal", "path_traversal"),
            "apache": ("Test for .htaccess upload, mod_proxy SSRF, server-status/server-info exposure", "ssrf"),
        }

        for tech, (attack_suggestion, vuln_type) in tech_attacks.items():
            if tech in result_str:
                hypotheses.append({
                    "hypothesis": f"Technology '{tech}' detected. {attack_suggestion}",
                    "endpoint": tool_input.get("url", tool_input.get("target", "")),
                    "suggested_tool": "systematic_fuzz",
                    "priority": "medium",
                    "status": "untested",
                    "vuln_type": vuln_type,
                    "reasoning": f"Framework-specific vulnerabilities for {tech} are well-documented.",
                })

        return hypotheses

    def _reason_about_parameters(
        self, tool_name: str, tool_input: dict, result: Any,
    ) -> list[dict[str, Any]]:
        """Parameter patterns suggest specific vulnerability types."""
        hypotheses: list[dict[str, Any]] = []
        result_str = str(result).lower()

        # ID parameters -> IDOR
        id_patterns = ["user_id", "account_id", "order_id", "profile_id", "document_id"]
        for pattern in id_patterns:
            if pattern in result_str:
                hypotheses.append({
                    "hypothesis": f"Parameter '{pattern}' found — test for IDOR by changing "
                        "the ID value to access other users' resources.",
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "test_idor",
                    "priority": "high",
                    "status": "untested",
                    "vuln_type": "idor",
                    "reasoning": f"Sequential or guessable {pattern} values are a classic IDOR pattern.",
                })
                break

        # URL/redirect parameters -> SSRF/Open Redirect
        url_params = ["url", "redirect", "callback", "next", "return", "goto", "dest", "forward"]
        for param in url_params:
            if f'"{param}"' in result_str or f"'{param}'" in result_str or f"name=\"{param}\"" in result_str:
                hypotheses.append({
                    "hypothesis": f"URL-accepting parameter '{param}' found. "
                        "Test for SSRF (internal network access) and open redirect.",
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "send_http_request",
                    "priority": "high",
                    "status": "untested",
                    "vuln_type": "ssrf",
                    "reasoning": "URL parameters are high-value targets for SSRF and redirect attacks.",
                })
                break

        # File parameters -> Upload vulnerabilities
        if "type=\"file\"" in result_str or "multipart" in result_str:
            hypotheses.append({
                "hypothesis": "File upload field detected. Test for unrestricted file upload "
                    "(webshell, SVG XSS, path traversal in filename).",
                "endpoint": tool_input.get("url", ""),
                "suggested_tool": "test_file_upload",
                "priority": "high",
                "status": "untested",
                "vuln_type": "file_upload",
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
                "status": "untested",
                "vuln_type": "jwt_vulnerability",
                "reasoning": "JWT implementation flaws are extremely common and high-impact.",
            })

        # Different error messages for auth -> enumeration
        if tool_name in ("send_http_request", "navigate_and_extract"):
            if any(kw in result_str for kw in ["invalid username", "user not found", "no such user"]):
                hypotheses.append({
                    "hypothesis": "User enumeration possible — different error messages for "
                        "valid vs invalid usernames. Enumerate users, then target specific accounts.",
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "systematic_fuzz",
                    "priority": "medium",
                    "status": "untested",
                    "vuln_type": "user_enumeration",
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
                    "status": "untested",
                    "vuln_type": "sqli",
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
            ("<?php", "PHP source code exposed — check for hardcoded credentials, SQL queries", "info_disclosure"),
            ("DB_PASSWORD", "Database credentials exposed in configuration", "credential_theft"),
            ("SECRET_KEY", "Application secret key exposed — enables session forgery", "credential_theft"),
            ("api_key", "API key exposed — test for privilege escalation", "credential_theft"),
            ("password", "Password or credential reference found", "credential_theft"),
            (".git/", "Git repository exposed — download full source with git-dumper", "info_disclosure"),
        ]

        for pattern, description, vuln_type in sensitive_patterns:
            if pattern in result_str:
                hypotheses.append({
                    "hypothesis": description,
                    "endpoint": tool_input.get("url", ""),
                    "suggested_tool": "send_http_request",
                    "priority": "critical",
                    "status": "untested",
                    "vuln_type": vuln_type,
                    "reasoning": f"Pattern '{pattern}' found in response indicates sensitive data exposure.",
                })
                break

        return hypotheses

    # ── State-based hypothesis generators ───────────────────────────

    def _hypothesize_from_endpoints(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Derive hypotheses from discovered endpoints."""
        hypotheses: list[dict[str, Any]] = []
        endpoints = state.get("endpoints", {})
        tested = state.get("tested_techniques", {})

        for url, info in list(endpoints.items())[:100]:  # Cap iteration
            method = info.get("method", "GET")
            auth_required = info.get("auth_required", False)

            # Admin/sensitive endpoint accessible without auth
            if not auth_required and any(
                seg in url.lower()
                for seg in ["/admin", "/dashboard", "/manage", "/internal", "/debug", "/config"]
            ):
                hypotheses.append({
                    "hypothesis": f"Sensitive endpoint {url} appears accessible without auth. "
                        "Verify access control and test for privilege escalation.",
                    "endpoint": url,
                    "suggested_tool": "send_http_request",
                    "priority": "critical",
                    "status": "untested",
                    "vuln_type": "broken_access_control",
                    "reasoning": "Admin/internal endpoints without auth are high-severity by definition.",
                })

            # POST/PUT/DELETE without tested CSRF
            if method in ("POST", "PUT", "DELETE", "PATCH"):
                csrf_key = f"{url}::csrf"
                if csrf_key not in tested:
                    hypotheses.append({
                        "hypothesis": f"State-changing {method} endpoint {url} — test for CSRF.",
                        "endpoint": url,
                        "suggested_tool": "send_http_request",
                        "priority": "medium",
                        "status": "untested",
                        "vuln_type": "csrf",
                        "reasoning": f"{method} endpoints that modify data are CSRF targets if missing tokens.",
                    })

            # Endpoint with ID-like path segments
            if re.search(r'/\d+(/|$)', url) or re.search(r'/[a-f0-9-]{36}(/|$)', url):
                idor_key = f"{url}::idor"
                if idor_key not in tested:
                    hypotheses.append({
                        "hypothesis": f"Endpoint {url} has an ID in the path — test IDOR "
                            "by substituting other IDs.",
                        "endpoint": url,
                        "suggested_tool": "test_idor",
                        "priority": "high",
                        "status": "untested",
                        "vuln_type": "idor",
                        "reasoning": "Numeric or UUID path segments often map to object IDs.",
                    })

        return hypotheses

    def _hypothesize_from_findings(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Derive follow-up hypotheses from existing findings."""
        hypotheses: list[dict[str, Any]] = []
        findings = state.get("findings", {})

        for _fid, fdata in findings.items():
            vuln_type = fdata.get("vuln_type", "")
            endpoint = fdata.get("endpoint", "")
            confirmed = fdata.get("confirmed", False)

            # If we have a confirmed XSS, check if cookies lack HttpOnly
            if vuln_type == "xss" and confirmed:
                hypotheses.append({
                    "hypothesis": f"Confirmed XSS at {endpoint} — check if session cookies "
                        "lack HttpOnly flag for account takeover via cookie theft.",
                    "endpoint": endpoint,
                    "suggested_tool": "send_http_request",
                    "priority": "critical",
                    "status": "untested",
                    "vuln_type": "account_takeover",
                    "reasoning": "XSS + missing HttpOnly = ATO chain (critical on HackerOne).",
                })

            # If we have SQLi, try to extract credentials
            if vuln_type == "sqli":
                hypotheses.append({
                    "hypothesis": f"SQLi at {endpoint} — attempt to extract user table "
                        "(usernames, password hashes) for credential theft.",
                    "endpoint": endpoint,
                    "suggested_tool": "blind_sqli_extract",
                    "priority": "critical",
                    "status": "untested",
                    "vuln_type": "credential_theft",
                    "reasoning": "SQLi -> credential extraction is a standard escalation path.",
                })

            # If we have SSRF, try cloud metadata
            if vuln_type == "ssrf":
                hypotheses.append({
                    "hypothesis": f"SSRF at {endpoint} — probe cloud metadata endpoints "
                        "(169.254.169.254, metadata.google.internal) for IAM credentials.",
                    "endpoint": endpoint,
                    "suggested_tool": "send_http_request",
                    "priority": "critical",
                    "status": "untested",
                    "vuln_type": "credential_theft",
                    "reasoning": "SSRF -> cloud metadata is the most common critical chain.",
                })

            # If we have path traversal, try reading sensitive files
            if vuln_type == "path_traversal":
                hypotheses.append({
                    "hypothesis": f"Path traversal at {endpoint} — read /etc/passwd, "
                        ".env, config files for credential harvesting.",
                    "endpoint": endpoint,
                    "suggested_tool": "send_http_request",
                    "priority": "critical",
                    "status": "untested",
                    "vuln_type": "credential_theft",
                    "reasoning": "Path traversal -> config read -> credential theft is a proven chain.",
                })

        return hypotheses

    def _hypothesize_from_tech_stack(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Derive hypotheses from the detected technology stack."""
        hypotheses: list[dict[str, Any]] = []
        tech_stack = state.get("tech_stack", [])
        if not tech_stack:
            return hypotheses

        tech_lower = " ".join(tech_stack).lower()
        target_url = state.get("target_url", "")

        # JWT in tech stack
        if "jwt" in tech_lower:
            hypotheses.append({
                "hypothesis": "JWT detected in tech stack. Test for alg:none bypass, "
                    "weak secret brute-force, and RS256->HS256 algorithm confusion.",
                "endpoint": target_url,
                "suggested_tool": "test_jwt",
                "priority": "high",
                "status": "untested",
                "vuln_type": "jwt_vulnerability",
                "reasoning": "JWT is in the tech stack, so it's used for auth. Weak implementations are common.",
            })

        # GraphQL in tech stack
        if "graphql" in tech_lower:
            hypotheses.append({
                "hypothesis": "GraphQL detected. Test introspection query, field-level "
                    "authorization bypass, and batched query attacks.",
                "endpoint": target_url,
                "suggested_tool": "send_http_request",
                "priority": "high",
                "status": "untested",
                "vuln_type": "broken_access_control",
                "reasoning": "GraphQL introspection often leaks the full schema including private fields.",
            })

        # File upload capability
        if any("upload" in t.lower() for t in tech_stack):
            hypotheses.append({
                "hypothesis": "File upload capability in tech stack. Test for unrestricted "
                    "upload (webshell, polyglot, path traversal in filename).",
                "endpoint": target_url,
                "suggested_tool": "test_file_upload",
                "priority": "high",
                "status": "untested",
                "vuln_type": "file_upload",
                "reasoning": "File upload -> RCE is a high-impact chain.",
            })

        return hypotheses

    def _hypothesize_from_traffic_intel(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Derive hypotheses from traffic intelligence analysis."""
        hypotheses: list[dict[str, Any]] = []
        ti = state.get("traffic_intelligence", {})
        if not ti:
            return hypotheses

        target_url = state.get("target_url", "")

        # Missing security headers
        gaps = ti.get("security_header_gaps", [])
        if any(g.lower() == "x-frame-options" for g in gaps):
            hypotheses.append({
                "hypothesis": "Missing X-Frame-Options header — test for clickjacking on "
                    "sensitive actions (password change, payment, settings).",
                "endpoint": target_url,
                "suggested_tool": "send_http_request",
                "priority": "medium",
                "status": "untested",
                "vuln_type": "csrf",
                "reasoning": "Clickjacking can be chained with CSRF for high-impact attacks.",
            })

        # ID parameters detected in traffic
        id_params = ti.get("id_params", [])
        for param in id_params[:5]:
            hypotheses.append({
                "hypothesis": f"ID parameter '{param}' observed in traffic — test IDOR "
                    "by modifying the value.",
                "endpoint": target_url,
                "suggested_tool": "test_idor",
                "priority": "high",
                "status": "untested",
                "vuln_type": "idor",
                "reasoning": f"Traffic analysis found '{param}' used as an object reference.",
            })

        # Cookie issues
        cookie_issues = ti.get("cookie_issues", [])
        if cookie_issues:
            hypotheses.append({
                "hypothesis": "Cookie security issues detected: "
                    f"{', '.join(str(c) for c in cookie_issues[:3])}. "
                    "Test for session fixation and cookie theft.",
                "endpoint": target_url,
                "suggested_tool": "send_http_request",
                "priority": "medium",
                "status": "untested",
                "vuln_type": "account_takeover",
                "reasoning": "Insecure cookies enable session theft especially when combined with XSS.",
            })

        # WAF detected -> suggest bypass techniques
        if ti.get("waf_detected"):
            waf_type = ti.get("waf_type", "unknown")
            hypotheses.append({
                "hypothesis": f"WAF detected ({waf_type}). Use encoding tricks, HTTP/2 "
                    "downgrade, chunked transfer, and case variations to bypass.",
                "endpoint": target_url,
                "suggested_tool": "systematic_fuzz",
                "priority": "medium",
                "status": "untested",
                "vuln_type": "sqli",
                "reasoning": f"WAF ({waf_type}) blocks naive payloads but bypass techniques exist.",
            })

        return hypotheses

    def _hypothesize_from_api_versions(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Detect API versioning and hypothesize about older versions."""
        hypotheses: list[dict[str, Any]] = []
        endpoints = state.get("endpoints", {})

        versions_seen: dict[str, set[str]] = {}  # base_path -> set of versions
        for url in endpoints:
            match = re.search(r'/(v\d+)/', url)
            if match:
                version = match.group(1)
                # Replace version segment with placeholder for grouping
                base = url[:match.start()] + "/{VERSION}/" + url[match.end():]
                versions_seen.setdefault(base, set()).add(version)

        for base, versions in versions_seen.items():
            version_nums = sorted(
                [int(v[1:]) for v in versions if v[1:].isdigit()],
            )
            if version_nums:
                latest = version_nums[-1]
                # Suggest testing older versions
                for v in range(1, latest):
                    if v not in version_nums:
                        old_url = base.replace("{VERSION}", f"v{v}")
                        rule_key = f"api_version_v{v}_{base}"
                        if rule_key not in self._fired_dynamic_rules:
                            self._fired_dynamic_rules.add(rule_key)
                            hypotheses.append({
                                "hypothesis": f"API v{latest} exists — test if v{v} is still "
                                    "accessible and lacks security patches.",
                                "endpoint": old_url,
                                "suggested_tool": "send_http_request",
                                "priority": "high",
                                "status": "untested",
                                "vuln_type": "broken_access_control",
                                "reasoning": f"Older API versions (v{v}) often lack auth or validation "
                                    "that was added in newer versions.",
                            })

        return hypotheses

    def _hypothesize_from_auth_gaps(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Identify endpoints that might have auth inconsistencies."""
        hypotheses: list[dict[str, Any]] = []
        endpoints = state.get("endpoints", {})
        accounts = state.get("accounts", {})

        # If we have accounts but some endpoints are marked auth_required
        # and we haven't tested them with different roles
        if not accounts:
            return hypotheses

        roles_available = {info.get("role", "user") for info in accounts.values()}
        auth_endpoints = [
            url for url, info in endpoints.items()
            if info.get("auth_required")
        ]

        if len(roles_available) >= 2 and auth_endpoints:
            rule_key = "multi_role_authz"
            if rule_key not in self._fired_dynamic_rules:
                self._fired_dynamic_rules.add(rule_key)
                hypotheses.append({
                    "hypothesis": f"Multiple roles available ({', '.join(roles_available)}). "
                        f"Test {len(auth_endpoints)} auth-required endpoints for horizontal/vertical "
                        "privilege escalation by replaying requests across roles.",
                    "endpoint": auth_endpoints[0] if auth_endpoints else "",
                    "suggested_tool": "send_http_request",
                    "priority": "critical",
                    "status": "untested",
                    "vuln_type": "privilege_escalation",
                    "reasoning": "Cross-role request replay is the most reliable way to find BAC bugs.",
                })

        return hypotheses

    def _hypothesize_from_error_patterns(self, state: dict[str, Any]) -> list[dict[str, Any]]:
        """Cross-reference error observations to find differential behavior."""
        hypotheses: list[dict[str, Any]] = []

        # Group observations by endpoint and look for status code variation
        endpoint_status: dict[str, set[str]] = {}
        for obs in self._observations[-200:]:
            url = obs.get("input", {}).get("url", "")
            if not url:
                continue
            summary = obs.get("result_summary", "")
            for code in ["200", "301", "302", "400", "401", "403", "404", "500"]:
                if code in summary:
                    endpoint_status.setdefault(url, set()).add(code)

        for url, codes in endpoint_status.items():
            # 200 + 500 on same endpoint means some inputs crash it
            if "200" in codes and "500" in codes:
                rule_key = f"diff_500_{url}"
                if rule_key not in self._fired_dynamic_rules:
                    self._fired_dynamic_rules.add(rule_key)
                    hypotheses.append({
                        "hypothesis": f"Endpoint {url} returns both 200 and 500 for different inputs — "
                            "differential behavior suggests injection point. "
                            "Use response_diff_analyze to map input->error boundaries.",
                        "endpoint": url,
                        "suggested_tool": "response_diff_analyze",
                        "priority": "high",
                        "status": "untested",
                        "vuln_type": "sqli",
                        "reasoning": "Inconsistent status codes for the same endpoint indicate "
                            "certain inputs reach unprotected code paths.",
                    })

            # 403 on some requests, 200 on others -> incomplete access control
            if "403" in codes and "200" in codes:
                rule_key = f"diff_403_{url}"
                if rule_key not in self._fired_dynamic_rules:
                    self._fired_dynamic_rules.add(rule_key)
                    hypotheses.append({
                        "hypothesis": f"Endpoint {url} returns both 403 and 200 — access control "
                            "is inconsistent. Test with different HTTP methods and headers.",
                        "endpoint": url,
                        "suggested_tool": "test_auth_bypass",
                        "priority": "high",
                        "status": "untested",
                        "vuln_type": "broken_access_control",
                        "reasoning": "Inconsistent access control (403+200) often means "
                            "the check can be bypassed via verb tampering or header manipulation.",
                    })

        return hypotheses

    # ── Cross-observation dynamic rules ─────────────────────────────

    def _generate_dynamic_rules(
        self, current_findings: list[dict[str, Any]] | None,
    ) -> list[dict[str, Any]]:
        """Generate rules by cross-referencing accumulated observations.

        Unlike the per-result rules above, these look at *patterns across
        multiple observations* to find things a single-result rule would miss.
        """
        hypotheses: list[dict[str, Any]] = []
        if len(self._observations) < 3:
            return hypotheses

        # 1. Detect endpoints that reflect user input (potential XSS/SSTI)
        for obs in self._observations[-20:]:  # Only recent observations
            summary = obs.get("result_summary", "").lower()
            tool_input = obs.get("input", {})
            # Check if any input value appears in the output
            for _key, val in tool_input.items():
                if isinstance(val, str) and len(val) > 3 and val.lower() in summary:
                    endpoint = tool_input.get("url", "")
                    rule_key = f"reflection_{endpoint}_{val[:20]}"
                    if rule_key not in self._fired_dynamic_rules:
                        self._fired_dynamic_rules.add(rule_key)
                        hypotheses.append({
                            "hypothesis": f"Input value '{val[:50]}' reflected in response from "
                                f"{endpoint}. Test for XSS and SSTI.",
                            "endpoint": endpoint,
                            "suggested_tool": "test_xss",
                            "priority": "high",
                            "status": "untested",
                            "vuln_type": "xss",
                            "reasoning": "Input reflection without encoding is the root cause of XSS.",
                        })
                    break  # One reflection hypothesis per observation

        # 2. Detect redirect chains (multiple 302s)
        redirect_endpoints: list[str] = []
        for obs in self._observations:
            summary = obs.get("result_summary", "")
            if "302" in summary or "301" in summary:
                endpoint = obs.get("input", {}).get("url", "")
                if endpoint:
                    redirect_endpoints.append(endpoint)

        if len(redirect_endpoints) >= 2:
            rule_key = "redirect_chain"
            if rule_key not in self._fired_dynamic_rules:
                self._fired_dynamic_rules.add(rule_key)
                hypotheses.append({
                    "hypothesis": f"Multiple redirect endpoints found ({len(redirect_endpoints)}). "
                        "Test for open redirect and OAuth token theft via redirect manipulation.",
                    "endpoint": redirect_endpoints[0],
                    "suggested_tool": "send_http_request",
                    "priority": "high",
                    "status": "untested",
                    "vuln_type": "open_redirect",
                    "reasoning": "Applications with many redirects often have at least one open redirect.",
                })

        # 3. Detect consistent auth patterns -> test for bypass
        auth_observed = set()
        for obs in self._observations:
            summary = obs.get("result_summary", "").lower()
            if "401" in summary or "login" in summary or "unauthorized" in summary:
                endpoint = obs.get("input", {}).get("url", "")
                if endpoint:
                    auth_observed.add(endpoint)

        if len(auth_observed) >= 3:
            rule_key = "many_auth_endpoints"
            if rule_key not in self._fired_dynamic_rules:
                self._fired_dynamic_rules.add(rule_key)
                hypotheses.append({
                    "hypothesis": f"{len(auth_observed)} endpoints require auth. "
                        "Test if any share a common auth middleware that can be bypassed "
                        "with X-Original-URL, X-Rewrite-URL, or path prefix tricks.",
                    "endpoint": list(auth_observed)[0],
                    "suggested_tool": "test_auth_bypass",
                    "priority": "high",
                    "status": "untested",
                    "vuln_type": "auth_bypass",
                    "reasoning": "Centralized auth middleware often has bypass routes.",
                })

        return hypotheses
