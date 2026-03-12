"""Independent finding verifier that produces ProofPacks.

Runs inside tool_executor_node (no new LangGraph nodes). Takes a finding
candidate + recent Observations, sends baseline/negative-control/replay
requests, and optionally calls Claude Haiku for ambiguous cases.

Replaces the inline _auto_differential_test() + _claude_validate_finding()
+ _score_evidence() pipeline with a unified proof-oriented workflow.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import time
from typing import Any
from urllib.parse import urlparse, urlencode

import httpx

from ai_brain.active.observation_model import (
    Artifact,
    FindingScore,
    Observation,
    ProofPack,
)
from ai_brain.active.cvss_calculator import compute_cvss_vector

logger = logging.getLogger("verifier")


class Verifier:
    """Produces ProofPacks for finding candidates.

    Pipeline:
    1. Find matching attack Observation from recent observations
    2. Send baseline request (benign param value)
    3. Send negative control (similar non-exploiting request)
    4. Replay attack to confirm reproducibility
    5. Claude Haiku validation ONLY if completeness_score < 0.75
    6. Compute triager_score from pack quality + CVSS
    """

    def __init__(
        self,
        scope_guard: Any,
        claude_client: Any | None = None,
        http_client: httpx.AsyncClient | None = None,
        socks_proxy: str | None = None,
    ) -> None:
        self._scope_guard = scope_guard
        self._claude_client = claude_client
        self._http_client = http_client
        self._socks_proxy = socks_proxy
        self._own_client = False

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client."""
        if self._http_client is None:
            kwargs: dict[str, Any] = {"verify": False, "timeout": 10}
            if self._socks_proxy:
                kwargs["proxy"] = self._socks_proxy
            self._http_client = httpx.AsyncClient(**kwargs)
            self._own_client = True
        return self._http_client

    async def close(self) -> None:
        """Close owned HTTP client."""
        if self._own_client and self._http_client:
            await self._http_client.aclose()
            self._http_client = None

    async def verify(
        self,
        finding: dict[str, Any],
        observations: list[Observation],
        policy_manifest: Any | None = None,
    ) -> ProofPack:
        """Verify a finding candidate and produce a ProofPack.

        Args:
            finding: Finding dict with vuln_type, endpoint, parameter, evidence, etc.
            observations: Recent Observations from tool results.
            policy_manifest: Optional PolicyManifest for criticality scoring.

        Returns:
            ProofPack with completeness_score indicating proof quality.
        """
        pack = ProofPack(
            finding_id=finding.get("finding_id", ""),
            auth_context=finding.get("auth_context", ""),
            workflow_context=finding.get("workflow_step", ""),
        )

        endpoint = finding.get("endpoint", "")
        parameter = finding.get("parameter", "")
        vuln_type = finding.get("vuln_type", "")
        method = finding.get("method", "GET").upper()

        # Step 1: Find matching attack Observation
        attack_obs = self._find_attack_observation(finding, observations)
        if attack_obs:
            # Use the HTTP response artifact as the attack proof
            for art in attack_obs.artifacts:
                if art.type == "http_response":
                    pack.attack = art
                    break
            if not pack.attack and attack_obs.artifacts:
                pack.attack = attack_obs.artifacts[0]

        # Steps 2-4: Differential testing (only for injection-type findings)
        if endpoint and self._is_injection_type(vuln_type):
            try:
                self._scope_guard.validate_url(endpoint)
                baseline, negative, replay = await self._differential_test(
                    endpoint, parameter, method, finding, attack_obs,
                )
                pack.baseline = baseline
                pack.negative_control = negative
                pack.replay_confirmation = replay
            except Exception as e:
                logger.debug("differential_test_failed", error=str(e)[:200])

        # Step 5: Claude Haiku validation for incomplete proofs
        if pack.completeness_score() < 0.75 and self._claude_client is not None:
            haiku_result = await self._claude_validate(finding, pack)
            if haiku_result is not None:
                pack.impact_statement = haiku_result.get("assessment", "")
                if haiku_result.get("is_valid") is False:
                    pack.triager_score = 0.0
                    return pack

        # Step 6: Compute scores
        score = self._compute_finding_score(finding, pack, policy_manifest)
        pack.triager_score = score.composite_score

        # Build impact statement if not set
        if not pack.impact_statement:
            pack.impact_statement = self._build_impact_statement(finding, pack)

        return pack

    def _find_attack_observation(
        self,
        finding: dict[str, Any],
        observations: list[Observation],
    ) -> Observation | None:
        """Find the Observation that produced this finding candidate."""
        endpoint = finding.get("endpoint", "")
        tool_used = finding.get("tool_used", "")
        parameter = finding.get("parameter", "")

        # Pass 1: Match by tool + endpoint
        for obs in reversed(observations):
            if obs.tool_name == tool_used and endpoint and endpoint in obs.subject:
                return obs

        # Pass 2: Match by endpoint only
        if endpoint:
            ep_path = urlparse(endpoint).path
            for obs in reversed(observations):
                if ep_path and ep_path in obs.subject:
                    return obs

        # Pass 3: Match any exploit tool result
        _exploit_tools = {
            "send_http_request", "test_sqli", "test_xss", "test_ssrf",
            "test_ssti", "test_idor", "run_custom_exploit", "systematic_fuzz",
            "response_diff_analyze", "test_file_upload",
        }
        for obs in reversed(observations):
            if obs.tool_name in _exploit_tools:
                return obs

        return None

    async def _differential_test(
        self,
        endpoint: str,
        parameter: str,
        method: str,
        finding: dict[str, Any],
        attack_obs: Observation | None,
    ) -> tuple[Artifact | None, Artifact | None, Artifact | None]:
        """Send baseline, negative control, and replay requests."""
        client = await self._ensure_client()
        baseline_art = None
        negative_art = None
        replay_art = None

        parsed = urlparse(endpoint)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

        # Baseline: benign value
        try:
            if method == "GET":
                resp = await client.get(base_url, params={parameter: "test123"} if parameter else None)
            else:
                resp = await client.request(method, base_url, data={parameter: "test123"} if parameter else None)
            baseline_art = Artifact(
                type="http_response",
                content=f"HTTP {resp.status_code}\n{dict(resp.headers)}\n\n{resp.text[:2000]}",
                metadata={"role": "baseline", "status": resp.status_code},
            )
        except Exception as e:
            logger.debug("baseline_request_failed", error=str(e)[:100])

        # Negative control: similar non-exploiting value
        try:
            control_value = "harmless<>test" if "xss" in finding.get("vuln_type", "").lower() else "1 OR 0"
            if method == "GET":
                resp = await client.get(base_url, params={parameter: control_value} if parameter else None)
            else:
                resp = await client.request(method, base_url, data={parameter: control_value} if parameter else None)
            negative_art = Artifact(
                type="http_response",
                content=f"HTTP {resp.status_code}\n{dict(resp.headers)}\n\n{resp.text[:2000]}",
                metadata={"role": "negative_control", "status": resp.status_code},
            )
        except Exception as e:
            logger.debug("negative_control_failed", error=str(e)[:100])

        # Replay: re-send attack payload
        if attack_obs and attack_obs.replay_recipe:
            try:
                recipe = attack_obs.replay_recipe
                resp = await client.request(
                    recipe.get("method", method),
                    recipe.get("url", endpoint),
                    headers=recipe.get("headers"),
                    data=recipe.get("body"),
                )
                replay_art = Artifact(
                    type="http_response",
                    content=f"HTTP {resp.status_code}\n{dict(resp.headers)}\n\n{resp.text[:2000]}",
                    metadata={"role": "replay_confirmation", "status": resp.status_code},
                )
            except Exception as e:
                logger.debug("replay_failed", error=str(e)[:100])
        elif attack_obs:
            # Try to replay from attack observation raw_result
            raw = attack_obs.raw_result
            payload = raw.get("payload", raw.get("payload_used", ""))
            if payload and parameter:
                try:
                    if method == "GET":
                        resp = await client.get(base_url, params={parameter: payload})
                    else:
                        resp = await client.request(method, base_url, data={parameter: payload})
                    replay_art = Artifact(
                        type="http_response",
                        content=f"HTTP {resp.status_code}\n{dict(resp.headers)}\n\n{resp.text[:2000]}",
                        metadata={"role": "replay_confirmation", "status": resp.status_code},
                    )
                except Exception as e:
                    logger.debug("replay_from_payload_failed", error=str(e)[:100])

        return baseline_art, negative_art, replay_art

    async def _claude_validate(
        self,
        finding: dict[str, Any],
        pack: ProofPack,
    ) -> dict[str, Any] | None:
        """Call Claude Haiku to validate ambiguous findings."""
        if self._claude_client is None:
            return None

        evidence = str(finding.get("evidence", ""))[:3000]
        vuln_type = finding.get("vuln_type", "")
        endpoint = finding.get("endpoint", "")

        # Build proof summary
        proof_parts = []
        if pack.baseline:
            proof_parts.append(f"BASELINE:\n{pack.baseline.content[:500]}")
        if pack.attack:
            proof_parts.append(f"ATTACK:\n{pack.attack.content[:500]}")
        if pack.negative_control:
            proof_parts.append(f"NEGATIVE CONTROL:\n{pack.negative_control.content[:500]}")
        if pack.replay_confirmation:
            proof_parts.append(f"REPLAY:\n{pack.replay_confirmation.content[:500]}")
        proof_summary = "\n\n".join(proof_parts) if proof_parts else "No proof artifacts available."

        prompt = f"""Validate this vulnerability finding. Answer ONLY with JSON.

Vuln type: {vuln_type}
Endpoint: {endpoint}
Evidence: {evidence[:1500]}

Proof artifacts:
{proof_summary}

Respond with: {{"is_valid": true/false, "assessment": "1-2 sentence explanation", "confidence": 0.0-1.0}}
Only mark is_valid:true if the evidence demonstrates real exploitable impact."""

        try:
            response = await self._claude_client.call_claude(
                messages=[{"role": "user", "content": prompt}],
                model_tier="routine",
                phase="validation",
                max_tokens=300,
            )
            text = response.text if hasattr(response, "text") else str(response)
            # Extract JSON from response
            match = re.search(r'\{[^{}]+\}', text)
            if match:
                return json.loads(match.group())
        except Exception as e:
            logger.debug("claude_validation_failed", error=str(e)[:200])

        return None

    def _compute_finding_score(
        self,
        finding: dict[str, Any],
        pack: ProofPack,
        policy_manifest: Any | None = None,
    ) -> FindingScore:
        """Compute composite score for a finding."""
        vuln_type = finding.get("vuln_type", "")

        # CVSS from vuln type
        cvss_score, cvss_vector = compute_cvss_vector(vuln_type, {
            "auth_required": bool(finding.get("auth_context")),
        })

        # Verifier confidence from proof completeness + evidence quality
        evidence_score = finding.get("evidence_score", 0) or 0
        verifier_confidence = max(
            pack.completeness_score(),
            min(evidence_score / 5.0, 1.0),
        )

        # Program criticality from policy
        program_crit = 0.5
        if policy_manifest:
            endpoint = finding.get("endpoint", "")
            program_crit = policy_manifest.get_asset_criticality(endpoint)

        # Exploit maturity
        maturity = "none"
        if pack.replay_confirmation:
            maturity = "functional"
        elif pack.attack:
            maturity = "poc"

        score = FindingScore(
            cvss_base=cvss_score,
            cvss_vector=cvss_vector,
            program_criticality=program_crit,
            verifier_confidence=verifier_confidence,
            exploit_maturity=maturity,
            duplicate_likelihood=0.5,
        )
        score.compute_composite()
        return score

    def _build_impact_statement(self, finding: dict[str, Any], pack: ProofPack) -> str:
        """Build impact statement from finding and proof."""
        vuln_type = finding.get("vuln_type", "")
        endpoint = finding.get("endpoint", "")
        completeness = pack.completeness_score()

        if completeness >= 0.75:
            return (
                f"Verified {vuln_type} at {endpoint} with "
                f"{int(completeness * 100)}% proof completeness. "
                f"Replay confirmed reproducibility."
            )
        elif completeness >= 0.5:
            return (
                f"Partially verified {vuln_type} at {endpoint}. "
                f"Attack response captured but missing full differential proof."
            )
        else:
            return (
                f"Candidate {vuln_type} at {endpoint} with limited proof. "
                f"Requires manual verification."
            )

    @staticmethod
    def _is_injection_type(vuln_type: str) -> bool:
        """Check if vuln type is injection-based (benefits from differential testing)."""
        injection_types = {
            "xss", "sqli", "nosqli", "cmdi", "ssti", "xxe", "lfi",
            "ssrf", "redirect", "path_traversal", "command_injection",
            "sql_injection", "reflected_xss", "stored_xss",
            "server_side_template_injection", "xml_external_entity",
        }
        return vuln_type.lower().strip().replace(" ", "_") in injection_types
