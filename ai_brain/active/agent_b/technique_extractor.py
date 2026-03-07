"""Extract technique cards from HackerOne reports and security writeups.

Processes raw H1 JSON reports into structured technique cards suitable
for the LanceDB knowledge base. Uses a fast heuristic extraction
(no LLM needed) for the bulk pipeline, with optional LLM enrichment.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

import structlog

logger = structlog.get_logger()

# ── Vulnerability class mapping ──────────────────────────────────

# Map H1 weakness names to normalized vuln classes
WEAKNESS_MAP = {
    "cross-site scripting": "xss",
    "xss": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom-based xss": "xss",
    "sql injection": "sqli",
    "sqli": "sqli",
    "blind sql injection": "sqli",
    "server-side request forgery": "ssrf",
    "ssrf": "ssrf",
    "insecure direct object reference": "idor",
    "idor": "idor",
    "broken access control": "idor",
    "cross-site request forgery": "csrf",
    "csrf": "csrf",
    "remote code execution": "rce",
    "rce": "rce",
    "command injection": "cmdi",
    "os command injection": "cmdi",
    "path traversal": "path_traversal",
    "directory traversal": "path_traversal",
    "local file inclusion": "lfi",
    "remote file inclusion": "rfi",
    "file upload": "file_upload",
    "unrestricted upload": "file_upload",
    "xml external entity": "xxe",
    "xxe": "xxe",
    "server side template injection": "ssti",
    "ssti": "ssti",
    "open redirect": "open_redirect",
    "url redirection": "open_redirect",
    "information disclosure": "info_disclosure",
    "information exposure": "info_disclosure",
    "sensitive data exposure": "info_disclosure",
    "authentication bypass": "auth_bypass",
    "improper authentication": "auth_bypass",
    "privilege escalation": "privesc",
    "business logic": "business_logic",
    "business logic errors": "business_logic",
    "race condition": "race_condition",
    "time-of-check time-of-use": "race_condition",
    "deserialization": "deserialization",
    "insecure deserialization": "deserialization",
    "subdomain takeover": "subdomain_takeover",
    "crlf injection": "crlf",
    "http response splitting": "crlf",
    "clickjacking": "clickjacking",
    "denial of service": "dos",
    "regular expression dos": "redos",
    "mass assignment": "mass_assignment",
    "prototype pollution": "prototype_pollution",
    "jwt": "jwt",
    "graphql": "graphql",
    "oauth": "oauth",
    "cors misconfiguration": "cors",
    "host header injection": "host_header",
    "cache poisoning": "cache_poisoning",
    "http request smuggling": "http_smuggling",
    "websocket": "websocket",
    "nosql injection": "nosqli",
}

# CWE to vuln class mapping
CWE_VULN_MAP = {
    "79": "xss", "89": "sqli", "918": "ssrf", "639": "idor",
    "352": "csrf", "94": "rce", "78": "cmdi", "22": "path_traversal",
    "98": "lfi", "434": "file_upload", "611": "xxe", "1336": "ssti",
    "601": "open_redirect", "200": "info_disclosure", "287": "auth_bypass",
    "269": "privesc", "362": "race_condition", "502": "deserialization",
    "113": "crlf", "1021": "clickjacking", "400": "dos",
}


def _normalize_vuln_class(weakness_name: str, cwe_id: str = "") -> str:
    """Normalize a weakness name to a standard vuln class."""
    if weakness_name:
        lower = weakness_name.lower().strip()
        for key, val in WEAKNESS_MAP.items():
            if key in lower:
                return val
    if cwe_id:
        cwe_num = re.sub(r'\D', '', cwe_id)
        if cwe_num in CWE_VULN_MAP:
            return CWE_VULN_MAP[cwe_num]
    return "other"


def _extract_tech_stack(report: dict) -> list[str]:
    """Infer target technology stack from report content."""
    techs = set()
    # From structured data
    team = report.get("team", {})
    if isinstance(team, dict):
        team_name = (team.get("name", "") or "").lower()
        # Known platform mappings
        platform_hints = {
            "ruby": ["ruby", "rails"], "python": ["python", "django", "flask"],
            "php": ["php", "laravel", "wordpress"], "java": ["java", "spring"],
            "node": ["node", "express", "next"], "go": ["golang"],
        }
        for lang, keywords in platform_hints.items():
            for kw in keywords:
                if kw in team_name:
                    techs.add(lang)

    # From vulnerability details text
    vuln_info = json.dumps(report.get("vulnerability_information", ""))
    text = f"{report.get('title', '')} {vuln_info}"
    text_lower = text.lower()

    tech_keywords = {
        "graphql": "graphql", "rest api": "rest_api", "jwt": "jwt",
        "oauth": "oauth", "saml": "saml", "ldap": "ldap",
        "mysql": "mysql", "postgresql": "postgresql", "mongodb": "mongodb",
        "redis": "redis", "elasticsearch": "elasticsearch",
        "nginx": "nginx", "apache": "apache", "iis": "iis",
        "aws": "aws", "s3": "aws_s3", "lambda": "aws_lambda",
        "docker": "docker", "kubernetes": "kubernetes",
        "wordpress": "wordpress", "drupal": "drupal", "joomla": "joomla",
        "react": "react", "angular": "angular", "vue": "vue",
        "laravel": "laravel", "django": "django", "flask": "flask",
        "spring": "spring", "express": "express", "rails": "rails",
        "cloudflare": "cloudflare", "akamai": "akamai",
        "websocket": "websocket", "grpc": "grpc",
    }
    for keyword, tech in tech_keywords.items():
        if keyword in text_lower:
            techs.add(tech)

    return sorted(techs)


def _extract_severity(report: dict) -> str:
    """Extract severity from report."""
    sev = report.get("severity_rating", "")
    if sev:
        return sev.lower()
    # Infer from CVSS
    severity = report.get("severity", {})
    if isinstance(severity, dict):
        rating = severity.get("rating", "")
        if rating:
            return rating.lower()
    return "medium"


def _extract_cwe(report: dict) -> str:
    """Extract CWE ID from report."""
    weakness = report.get("weakness", {})
    if isinstance(weakness, dict):
        cwe_id = weakness.get("external_id", "")
        if cwe_id:
            return cwe_id
    return ""


def _compute_confidence(report: dict) -> float:
    """Compute confidence score based on report quality signals."""
    score = 0.5
    # Bounty paid = confirmed real
    bounties = report.get("bounties", [])
    if bounties:
        score += 0.2
        total_bounty = sum(float(b.get("amount", 0)) for b in bounties if b.get("amount"))
        if total_bounty >= 1000:
            score += 0.1
    # Resolved state
    substate = report.get("readable_substate", "").lower()
    if substate in ("resolved", "triaged"):
        score += 0.1
    elif substate in ("informative", "duplicate"):
        score -= 0.1
    # Has structured severity
    if report.get("severity_rating"):
        score += 0.05
    # Upvotes
    vote_count = report.get("vote_count", 0)
    if vote_count and vote_count > 10:
        score += 0.05
    return min(max(score, 0.1), 1.0)


def extract_technique_card(report: dict) -> dict | None:
    """Extract a technique card from a single H1 report.

    Uses heuristic extraction — no LLM needed. Fast enough for
    bulk processing of 8000+ reports.
    """
    report_id = str(report.get("id", ""))
    title = report.get("title", "")
    if not title:
        return None

    # Skip non-actionable reports
    substate = (report.get("readable_substate", "") or "").lower()
    if substate in ("spam", "not applicable", ""):
        return None

    # Weakness / vuln class
    weakness = report.get("weakness", {})
    weakness_name = ""
    if isinstance(weakness, dict):
        weakness_name = weakness.get("name", "")
    cwe_id = _extract_cwe(report)
    vuln_class = _normalize_vuln_class(weakness_name, cwe_id)

    # Severity
    severity = _extract_severity(report)

    # Tech stack
    tech_stack = _extract_tech_stack(report)

    # Bounty
    bounties = report.get("bounties", [])
    bounty_amount = sum(float(b.get("amount", 0)) for b in bounties if b.get("amount"))

    # Extract vulnerability information as the core narrative
    vuln_info = report.get("vulnerability_information", "")
    if isinstance(vuln_info, dict):
        vuln_info = json.dumps(vuln_info)
    vuln_info = str(vuln_info or "")

    # Build heuristic from title + weakness
    heuristic = f"When testing for {weakness_name or vuln_class}: {title}"

    # Build reasoning from vulnerability info (truncate for embedding)
    reasoning = vuln_info[:2000] if vuln_info else title

    # Extract attack steps from structured summaries if available
    summaries = report.get("summaries", [])
    attack_steps = []
    if summaries:
        for s in summaries:
            if isinstance(s, dict):
                content = s.get("content", "")
                if content:
                    attack_steps.append(content[:500])

    # Build technique card
    card_id = f"h1-{report_id}"
    card = {
        "id": card_id,
        "title": title,
        "vuln_class": vuln_class,
        "target_tech": ",".join(tech_stack) if tech_stack else "",
        "preconditions": [],  # Would need LLM to extract properly
        "heuristic": heuristic,
        "reasoning_chain": reasoning[:1500],
        "attack_steps": attack_steps,
        "variations": [],
        "cwe_ids": cwe_id,
        "difficulty": "medium",
        "severity": severity,
        "source_id": report_id,
        "source_url": report.get("url", f"https://hackerone.com/reports/{report_id}"),
        "bounty_amount": bounty_amount,
        "confidence": _compute_confidence(report),
    }
    return card


def process_h1_reports_dir(
    reports_dir: str,
    batch_size: int = 100,
    min_confidence: float = 0.3,
) -> list[dict]:
    """Process all H1 report JSON files in a directory.

    Returns list of technique cards.
    """
    reports_path = Path(reports_dir)
    if not reports_path.exists():
        logger.error("h1_reports_dir_not_found", path=reports_dir)
        return []

    json_files = sorted(reports_path.glob("*.json"))
    logger.info("processing_h1_reports", total=len(json_files))

    cards = []
    skipped = 0
    errors = 0

    for i, f in enumerate(json_files):
        try:
            with open(f) as fh:
                report = json.load(fh)
            card = extract_technique_card(report)
            if card and card["confidence"] >= min_confidence:
                cards.append(card)
            else:
                skipped += 1
        except Exception as e:
            errors += 1
            if errors <= 5:
                logger.warning("h1_report_parse_error", file=f.name, error=str(e))

        if (i + 1) % 1000 == 0:
            logger.info("h1_processing_progress", processed=i + 1,
                        cards=len(cards), skipped=skipped, errors=errors)

    logger.info("h1_processing_complete",
                total=len(json_files), cards=len(cards),
                skipped=skipped, errors=errors)
    return cards


def vuln_class_stats(cards: list[dict]) -> dict[str, int]:
    """Count technique cards by vulnerability class."""
    from collections import Counter
    return dict(Counter(c["vuln_class"] for c in cards).most_common())
