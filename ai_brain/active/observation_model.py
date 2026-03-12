"""Observation envelope and proof-of-concept data models.

Core types for structured evidence collection:
- Artifact: Immutable evidence item (HTTP request/response, screenshot, etc.)
- Observation: Wrapped tool result with context (auth, workflow, confidence)
- ProofPack: Complete proof-of-concept bundle for a finding
- FindingScore: Composite scoring with CVSS, verifier confidence, etc.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, computed_field


# ── Artifact ────────────────────────────────────────────────────────────

ArtifactType = Literal[
    "http_request", "http_response", "screenshot", "trace", "diff", "code",
]


class Artifact(BaseModel):
    """Immutable evidence item with content-addressable hash."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ArtifactType
    content: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def content_hash(self) -> str:
        """SHA-256 of content for dedup and integrity."""
        return hashlib.sha256(self.content.encode(errors="replace")).hexdigest()


# ── Observation ─────────────────────────────────────────────────────────

ObservationType = Literal[
    "http_response", "scan_result", "browser_event", "auth_event",
    "error", "finding_candidate",
]


class Observation(BaseModel):
    """Wrapped tool result with full context.

    Every tool result flows through this envelope before being stored
    or fed back to the brain. The brain still sees the raw JSON string;
    this is the structured backing store.
    """

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: ObservationType = "scan_result"
    subject: str = ""  # URL or resource under test
    auth_context: str = ""  # e.g. "admin", "anonymous", "user:bob"
    workflow_step: str = ""  # e.g. "checkout_step_3"
    confidence: float = 0.5  # 0.0–1.0
    side_effect_risk: float = 0.0  # 0.0 = read-only, 1.0 = destructive
    artifacts: list[Artifact] = Field(default_factory=list)
    policy_decision: str = ""  # "allowed" / "blocked" / ""
    canonical_fingerprint: str = ""  # dedup fingerprint
    replay_recipe: dict[str, Any] = Field(default_factory=dict)
    tool_name: str = ""
    turn: int = 0
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    raw_result: dict[str, Any] = Field(default_factory=dict, exclude=True)

    def to_legacy_tuple(self) -> tuple[str, str]:
        """Convert to (tool_name, result_json_str) for backward compat."""
        import json
        return (self.tool_name, json.dumps(self.raw_result, default=str))


# ── ProofPack ───────────────────────────────────────────────────────────

class ProofPack(BaseModel):
    """Complete proof-of-concept bundle for a single finding.

    Contains baseline, attack, negative control, and replay confirmation
    artifacts that together prove (or disprove) exploitability.
    """

    finding_id: str = ""
    baseline: Artifact | None = None  # Benign request/response
    attack: Artifact | None = None  # Exploit request/response
    negative_control: Artifact | None = None  # Similar non-exploiting request
    replay_confirmation: Artifact | None = None  # Replay of attack for reproducibility
    auth_context: str = ""
    workflow_context: str = ""
    affected_objects: list[str] = Field(default_factory=list)
    impact_statement: str = ""
    triager_score: float = 0.0  # 0.0–1.0 quality score
    sarif_entry: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def completeness_score(self) -> float:
        """Fraction of proof components present (0.0–1.0)."""
        components = [self.baseline, self.attack, self.negative_control, self.replay_confirmation]
        present = sum(1 for c in components if c is not None)
        return present / 4.0

    def to_jsonb(self) -> dict[str, Any]:
        """Serialize for PostgreSQL JSONB storage."""
        return self.model_dump(mode="json", exclude_none=True)


# ── FindingScore ────────────────────────────────────────────────────────

class FindingScore(BaseModel):
    """Composite vulnerability score combining multiple signals."""

    cvss_base: float = 0.0
    cvss_vector: str = ""
    program_criticality: float = 0.5  # 0.0–1.0 from policy manifest
    verifier_confidence: float = 0.0  # 0.0–1.0 from evidence scoring
    exploit_maturity: str = "none"  # none, poc, functional, weaponized
    duplicate_likelihood: float = 0.5  # 0.0 = unique, 1.0 = certain dupe
    epss_signal: float | None = None  # EPSS score if available
    kev_listed: bool = False  # Known Exploited Vulnerabilities catalog
    composite_score: float = 0.0

    _MATURITY_WEIGHTS: dict[str, float] = {
        "none": 0.1,
        "poc": 0.5,
        "functional": 0.8,
        "weaponized": 1.0,
    }

    def compute_composite(self) -> float:
        """Weighted composite score for triager ranking.

        Formula:
            composite = (cvss_norm * 0.30
                       + verifier_confidence * 0.30
                       + program_criticality * 0.15
                       + maturity_weight * 0.15
                       + uniqueness * 0.10)
        """
        cvss_norm = min(self.cvss_base / 10.0, 1.0)
        maturity_w = self._MATURITY_WEIGHTS.get(self.exploit_maturity, 0.1)
        uniqueness = 1.0 - self.duplicate_likelihood

        self.composite_score = (
            cvss_norm * 0.30
            + self.verifier_confidence * 0.30
            + self.program_criticality * 0.15
            + maturity_w * 0.15
            + uniqueness * 0.10
        )
        return self.composite_score


# ── Adapter Functions ───────────────────────────────────────────────────

def wrap_tool_result(
    tool_name: str,
    result_dict: dict[str, Any],
    turn: int = 0,
    auth_context: str = "",
    subject: str = "",
) -> Observation:
    """Wrap a legacy tool result dict into an Observation envelope.

    Backward-compatible: tools keep returning dicts, this wraps them
    for structured storage without changing tool code.
    """
    # Determine observation type from result content
    obs_type: ObservationType = "scan_result"
    if "status_code" in result_dict or "headers" in result_dict:
        obs_type = "http_response"
    elif "error" in result_dict:
        obs_type = "error"
    elif any(k in result_dict for k in ("vuln_type", "finding", "vulnerability")):
        obs_type = "finding_candidate"

    # Extract subject URL from result
    if not subject:
        subject = (
            result_dict.get("url", "")
            or result_dict.get("endpoint", "")
            or result_dict.get("target", "")
        )

    # Build artifacts from HTTP data
    artifacts: list[Artifact] = []

    # HTTP request artifact
    req_parts: list[str] = []
    method = result_dict.get("method", "")
    url = result_dict.get("url", result_dict.get("endpoint", ""))
    if method or url:
        req_parts.append(f"{method} {url}")
    req_headers = result_dict.get("request_headers", {})
    if isinstance(req_headers, dict):
        for k, v in list(req_headers.items())[:15]:
            req_parts.append(f"{k}: {v}")
    req_body = result_dict.get("request_body", result_dict.get("payload", ""))
    if req_body:
        req_parts.append(f"\n{str(req_body)[:2000]}")
    if req_parts:
        artifacts.append(Artifact(type="http_request", content="\n".join(req_parts)))

    # HTTP response artifact
    resp_parts: list[str] = []
    status = result_dict.get("status_code", result_dict.get("status", ""))
    if status:
        resp_parts.append(f"HTTP {status}")
    resp_headers = result_dict.get("headers", result_dict.get("response_headers", {}))
    if isinstance(resp_headers, dict):
        for k, v in list(resp_headers.items())[:15]:
            resp_parts.append(f"{k}: {v}")
    body = result_dict.get("body", result_dict.get("stdout", result_dict.get("output", "")))
    if body:
        resp_parts.append(f"\n{str(body)[:4000]}")
    if resp_parts:
        artifacts.append(Artifact(type="http_response", content="\n".join(resp_parts)))

    # Confidence from result
    confidence = 0.5
    if result_dict.get("vulnerable") or result_dict.get("injectable"):
        confidence = 0.9
    elif result_dict.get("error"):
        confidence = 0.2

    return Observation(
        type=obs_type,
        subject=subject,
        auth_context=auth_context,
        confidence=confidence,
        artifacts=artifacts,
        tool_name=tool_name,
        turn=turn,
        raw_result=result_dict,
    )


def observation_to_legacy(obs: Observation) -> dict[str, Any]:
    """Convert Observation back to legacy dict format."""
    return obs.raw_result
