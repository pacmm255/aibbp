"""CVSS 3.1 calculator with vulnerability-type-aware profiles.

Maps 27 canonical vuln types to CVSS base metric values with context-aware
adjustments (auth required → PR:L, user interaction → UI:R, etc.).

Uses the `cvss` PyPI library for score computation from vector strings.
"""

from __future__ import annotations

from typing import Any

try:
    from cvss import CVSS3
except ImportError:
    CVSS3 = None  # type: ignore[assignment, misc]


# CVSS 3.1 base metrics:
# AV: Network(N), Adjacent(A), Local(L), Physical(P)
# AC: Low(L), High(H)
# PR: None(N), Low(L), High(H)
# UI: None(N), Required(R)
# S:  Unchanged(U), Changed(C)
# C:  None(N), Low(L), High(H)
# I:  None(N), Low(L), High(H)
# A:  None(N), Low(L), High(H)

VULN_TYPE_CVSS_PROFILES: dict[str, dict[str, str]] = {
    # ── Critical ────────────────────────────────────
    "rce": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "cmdi": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "deserialization": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "ssti": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},

    # ── High ────────────────────────────────────────
    "sqli": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "nosqli": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "ssrf": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "N", "A": "N"},
    "lfi": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "auth_bypass": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "ato": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "file_upload": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
    "xxe": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
    "jwt": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "idor": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "L", "A": "N"},
    "bac": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},
    "privilege_escalation": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "N"},

    # ── Medium ──────────────────────────────────────
    "xss": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "csrf": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "U", "C": "N", "I": "L", "A": "N"},
    "race_condition": {"AV": "N", "AC": "H", "PR": "L", "UI": "N", "S": "U", "C": "N", "I": "H", "A": "N"},
    "cors": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "U", "C": "L", "I": "L", "A": "N"},
    "redirect": {"AV": "N", "AC": "L", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
    "mass_assignment": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "L", "I": "H", "A": "N"},
    "graphql": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},

    # ── Low ─────────────────────────────────────────
    "information_disclosure": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
    "subdomain_takeover": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "C", "C": "L", "I": "L", "A": "N"},
    "user_enumeration": {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
    "http_smuggling": {"AV": "N", "AC": "H", "PR": "N", "UI": "N", "S": "C", "C": "H", "I": "H", "A": "N"},
    "cache_poisoning": {"AV": "N", "AC": "H", "PR": "N", "UI": "R", "S": "C", "C": "L", "I": "L", "A": "N"},
}


def _apply_context_adjustments(
    metrics: dict[str, str],
    context: dict[str, Any],
) -> dict[str, str]:
    """Adjust CVSS metrics based on finding context."""
    m = dict(metrics)  # Copy

    # Auth required → elevate PR
    if context.get("auth_required"):
        if m["PR"] == "N":
            m["PR"] = "L"

    # User interaction needed
    if context.get("user_interaction"):
        m["UI"] = "R"

    # Scope change (e.g., XSS in iframe, SSRF to internal)
    if context.get("scope_change"):
        m["S"] = "C"

    # Data sensitivity boost
    if context.get("pii_exposed") or context.get("credentials_exposed"):
        m["C"] = "H"

    # Write access demonstrated
    if context.get("write_access"):
        m["I"] = "H"

    # Availability impact demonstrated
    if context.get("availability_impact"):
        m["A"] = "H"

    # High complexity (e.g., race condition, multi-step)
    if context.get("high_complexity"):
        m["AC"] = "H"

    # Admin privileges required
    if context.get("admin_required"):
        m["PR"] = "H"

    return m


def _build_vector_string(metrics: dict[str, str]) -> str:
    """Build CVSS 3.1 vector string from metric dict."""
    return (
        f"CVSS:3.1/AV:{metrics['AV']}/AC:{metrics['AC']}"
        f"/PR:{metrics['PR']}/UI:{metrics['UI']}/S:{metrics['S']}"
        f"/C:{metrics['C']}/I:{metrics['I']}/A:{metrics['A']}"
    )


def compute_cvss_vector(
    vuln_type: str,
    finding_context: dict[str, Any] | None = None,
) -> tuple[float, str]:
    """Compute CVSS 3.1 base score and vector string.

    Args:
        vuln_type: Canonical vulnerability type (e.g., 'xss', 'sqli').
        finding_context: Optional context for adjustments (auth_required,
            user_interaction, scope_change, pii_exposed, etc.).

    Returns:
        (score, vector_string) tuple. Score is 0.0–10.0.
        Falls back to heuristic calculation if cvss library unavailable.
    """
    ctx = finding_context or {}

    # Canonicalize vuln type
    vt = vuln_type.lower().strip().replace(" ", "_").replace("-", "_")

    # Alias mapping
    _aliases: dict[str, str] = {
        "reflected_xss": "xss", "stored_xss": "xss", "cross_site_scripting": "xss",
        "sql_injection": "sqli", "blind_sqli": "sqli", "union_sqli": "sqli",
        "command_injection": "cmdi", "os_command_injection": "cmdi",
        "server_side_request_forgery": "ssrf",
        "open_redirect": "redirect", "url_redirect": "redirect",
        "cors_misconfiguration": "cors",
        "account_takeover": "ato",
        "path_traversal": "lfi", "directory_traversal": "lfi",
        "local_file_inclusion": "lfi",
        "nosql_injection": "nosqli",
        "broken_access_control": "bac",
        "authentication_bypass": "auth_bypass",
        "remote_code_execution": "rce",
        "template_injection": "ssti",
        "server_side_template_injection": "ssti",
        "xml_external_entity": "xxe",
        "prototype_pollution": "mass_assignment",
        "insecure_deserialization": "deserialization",
    }
    vt = _aliases.get(vt, vt)

    # Get base profile or default to info disclosure
    profile = VULN_TYPE_CVSS_PROFILES.get(
        vt,
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "L", "I": "N", "A": "N"},
    )

    # Apply context adjustments
    metrics = _apply_context_adjustments(profile, ctx)

    # Build vector string
    vector = _build_vector_string(metrics)

    # Compute score
    if CVSS3 is not None:
        try:
            c = CVSS3(vector)
            score = c.base_score
            return (score, vector)
        except Exception:
            pass

    # Fallback: heuristic scoring based on metrics
    score = _heuristic_score(metrics)
    return (score, vector)


def _heuristic_score(metrics: dict[str, str]) -> float:
    """Approximate CVSS 3.1 base score without the cvss library.

    Not perfectly accurate but close enough for ranking.
    """
    # Impact sub-score components
    c_val = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics["C"], 0.0)
    i_val = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics["I"], 0.0)
    a_val = {"N": 0.0, "L": 0.22, "H": 0.56}.get(metrics["A"], 0.0)

    iss = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    if metrics["S"] == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    # Exploitability sub-score
    av_val = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}.get(metrics["AV"], 0.85)
    ac_val = {"L": 0.77, "H": 0.44}.get(metrics["AC"], 0.77)
    pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}
    pr_map = pr_map_c if metrics["S"] == "C" else pr_map_u
    pr_val = pr_map.get(metrics["PR"], 0.85)
    ui_val = {"N": 0.85, "R": 0.62}.get(metrics["UI"], 0.85)

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0:
        return 0.0

    if metrics["S"] == "U":
        score = min(impact + exploitability, 10.0)
    else:
        score = min(1.08 * (impact + exploitability), 10.0)

    # Round up to one decimal
    return round(score * 10) / 10


def severity_from_score(score: float) -> str:
    """Map CVSS score to severity label."""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 0.1:
        return "low"
    return "info"
