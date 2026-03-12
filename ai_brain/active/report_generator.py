"""Multi-format professional report generator for AIBBP findings.

Supports Markdown (HackerOne-style), HTML (styled), and JSON (enriched).
Adds CWE mapping, deterministic CVSS 3.1 scoring, and remediation guidance.
"""

from __future__ import annotations

import json
import time
from typing import Any

import structlog

from ai_brain.active.cvss_calculator import compute_cvss_vector, severity_from_score
from ai_brain.active.schema_intelligence import ASVSWSTGReference

logger = structlog.get_logger()

# ── CWE Mapping ─────────────────────────────────────────────────────

CWE_MAP: dict[str, str] = {
    "xss": "CWE-79",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "cmdi": "CWE-78",
    "command_injection": "CWE-78",
    "ssrf": "CWE-918",
    "xxe": "CWE-611",
    "nosql_injection": "CWE-943",
    "insecure_deserialization": "CWE-502",
    "denial_of_service": "CWE-400",
    "csrf": "CWE-352",
    "path_traversal": "CWE-22",
    "lfi": "CWE-98",
    "ssti": "CWE-1336",
    "idor": "CWE-639",
    "broken_access_control": "CWE-284",
    "jwt_vulnerability": "CWE-347",
    "open_redirect": "CWE-601",
    "crlf_injection": "CWE-93",
    "host_header_injection": "CWE-644",
    "file_upload": "CWE-434",
    "information_disclosure": "CWE-200",
    "default_credentials": "CWE-798",
    "race_condition": "CWE-362",
    "http_smuggling": "CWE-444",
    "cache_poisoning": "CWE-349",
    "prototype_pollution": "CWE-1321",
}

# ── Remediation Guidance ─────────────────────────────────────────────

REMEDIATION_MAP: dict[str, str] = {
    "CWE-79": "Implement context-aware output encoding for all user-controlled data. Use Content-Security-Policy headers. Consider using a templating engine with auto-escaping enabled.",
    "CWE-89": "Use parameterized queries or prepared statements exclusively. Never concatenate user input into SQL. Implement an ORM or query builder with proper escaping.",
    "CWE-78": "Avoid passing user input to system commands. Use language-specific APIs instead of shell commands. If unavoidable, use strict allowlists for permitted characters.",
    "CWE-918": "Implement URL allowlists for outbound requests. Block requests to internal IP ranges (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 169.254.0.0/16). Validate URL schemes to http/https only.",
    "CWE-611": "Disable external entity processing in XML parsers. Use JSON instead of XML where possible. Configure parsers with DTD loading disabled and external entity resolution turned off.",
    "CWE-943": "Sanitize user input before passing to NoSQL queries. Use parameterized queries or explicit type casting. Reject input containing MongoDB operators ($ne, $gt, $regex, etc.).",
    "CWE-502": "Avoid deserializing untrusted data. Use safe serialization formats (JSON) instead. Implement integrity checks (HMAC) on serialized data. Use allowlists for permitted classes.",
    "CWE-400": "Implement request rate limiting and input size validation. Set timeouts for regex evaluation. Limit recursion depth for JSON/XML parsers. Use GraphQL query depth/complexity limits.",
    "CWE-352": "Implement anti-CSRF tokens (synchronized token pattern or double-submit cookies). Use SameSite=Strict cookies. Verify Origin/Referer headers on state-changing requests.",
    "CWE-22": "Validate and sanitize file paths. Use a canonicalized base directory with path joining. Reject inputs containing ../ or path separators. Use allowlists for permitted filenames.",
    "CWE-1336": "Do not render user input in templates. Use sandboxed template engines. Escape template syntax characters in user data. Separate template logic from user content.",
    "CWE-639": "Implement proper authorization checks for all object references. Use indirect references (random UUIDs) instead of sequential IDs. Verify user owns the requested resource server-side.",
    "CWE-347": "Use strong JWT signing algorithms (RS256/ES256). Validate alg header against expected value. Reject none algorithm. Use long, random secrets for HMAC. Enforce token expiration.",
    "CWE-601": "Use relative URLs for redirects. Maintain an allowlist of permitted redirect destinations. Validate redirect URLs against the application domain. Reject external URLs.",
    "CWE-93": "Strip or encode CR (\\r) and LF (\\n) characters from HTTP header values. Use framework-provided header setting functions that handle encoding automatically.",
    "CWE-644": "Do not trust Host or X-Forwarded-Host headers for generating URLs. Configure the server's canonical hostname explicitly. Validate Host against an allowlist.",
    "CWE-434": "Validate file content type (not just extension). Store uploads outside the webroot. Use random filenames. Scan uploaded files for malicious content. Limit file sizes.",
    "CWE-200": "Remove debug endpoints and error details from production. Disable directory listing. Configure proper error pages. Review HTTP headers for information leakage.",
    "CWE-798": "Remove or change all default credentials before deployment. Enforce strong password policies. Use secrets management for credentials. Implement MFA.",
    "CWE-362": "Use database-level locking or atomic operations for critical sections. Implement idempotency keys for financial operations. Use optimistic locking with version checks.",
    "CWE-284": "Implement role-based access control with least-privilege principles. Verify authorization on every request server-side. Do not rely on client-side access control.",
    "CWE-98": "Same as path traversal: validate file paths, use allowlists, canonicalize paths before access.",
    "CWE-444": "Normalize HTTP request parsing. Reject ambiguous requests. Use HTTP/2 where possible. Ensure front-end and back-end servers agree on request boundaries.",
    "CWE-349": "Use unique cache keys that include user-specific data when appropriate. Implement cache-control headers correctly. Validate Vary headers.",
    "CWE-1321": "Freeze prototype objects. Validate object keys before assignment. Use Map instead of plain objects for user-controlled keys. Sanitize __proto__ and constructor inputs.",
}

# ── CVSS 3.1 Scoring ────────────────────────────────────────────────

_SEVERITY_TO_CVSS: dict[str, tuple[float, str]] = {
    "critical": (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    "high": (8.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"),
    "medium": (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"),
    "low": (3.1, "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N"),
    "info": (0.0, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:N"),
}


class ReportGenerator:
    """Generate professional vulnerability reports in multiple formats."""

    @staticmethod
    def generate_cvss_vector(finding: dict[str, Any]) -> tuple[float, str]:
        """Generate deterministic CVSS 3.1 score from vuln_type + severity."""
        severity = finding.get("severity", "medium").lower()
        return _SEVERITY_TO_CVSS.get(severity, _SEVERITY_TO_CVSS["medium"])

    @staticmethod
    def _enrich_finding(finding: dict[str, Any]) -> dict[str, Any]:
        """Add CWE, CVSS, and remediation to a finding."""
        enriched = dict(finding)
        vuln_type = finding.get("vuln_type", "").lower()

        # CWE
        cwe = CWE_MAP.get(vuln_type, "CWE-000")
        enriched["cwe"] = cwe

        # CVSS — prefer real computation, fall back to severity table
        if vuln_type:
            cvss_score, cvss_vector = compute_cvss_vector(vuln_type, {
                "auth_required": bool(finding.get("auth_context")),
            })
            enriched["cvss_score"] = cvss_score
            enriched["cvss_vector"] = cvss_vector
        else:
            score, vector = ReportGenerator.generate_cvss_vector(finding)
            enriched["cvss_score"] = score
            enriched["cvss_vector"] = vector

        # ASVS/WSTG/CAPEC references
        if vuln_type:
            ref = ASVSWSTGReference()
            enriched["capec_id"] = ref.get_capec_id(vuln_type)
            relevant_tests = ref.get_relevant_tests(vuln_type=vuln_type)
            if relevant_tests:
                enriched["asvs_wstg_refs"] = [
                    {"id": t.get("id", ""), "name": t.get("name", t.get("description", ""))}
                    for t in relevant_tests[:5]
                ]

        # Remediation
        enriched["remediation"] = REMEDIATION_MAP.get(cwe, "Review and apply security best practices for this vulnerability class.")

        return enriched

    def generate(
        self,
        findings: dict[str, dict[str, Any]],
        target_url: str,
        tech_stack: list[str] | None = None,
        attack_chains: dict[str, dict[str, Any]] | None = None,
        format: str = "md",
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Generate report in specified format (md, html, json)."""
        # Enrich all findings
        enriched = {fid: self._enrich_finding(info) for fid, info in findings.items()}

        ctx = {
            "target_url": target_url,
            "tech_stack": tech_stack or [],
            "attack_chains": attack_chains or {},
            "findings": enriched,
            "metadata": metadata or {},
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        }

        if format == "sarif":
            return self._generate_sarif(ctx)
        elif format == "html":
            return self._generate_html(ctx)
        elif format == "json":
            return self._generate_json(ctx)
        else:
            return self._generate_markdown(ctx)

    def _generate_markdown(self, ctx: dict) -> str:
        """Generate HackerOne-style Markdown report."""
        lines: list[str] = []
        findings = ctx["findings"]

        lines.append(f"# Vulnerability Assessment Report")
        lines.append(f"")
        lines.append(f"**Target:** {ctx['target_url']}")
        lines.append(f"**Date:** {ctx['generated_at']}")
        if ctx["tech_stack"]:
            lines.append(f"**Tech Stack:** {', '.join(ctx['tech_stack'])}")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append("")

        # Summary table
        severity_counts: dict[str, int] = {}
        for info in findings.values():
            sev = info.get("severity", "medium")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        lines.append("## Executive Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            if sev in severity_counts:
                lines.append(f"| {sev.upper()} | {severity_counts[sev]} |")
        lines.append("")

        # Attack chain diagram
        if ctx["attack_chains"]:
            lines.append("## Attack Chains")
            lines.append("")
            mermaid = self._build_chain_mermaid(ctx["attack_chains"])
            if mermaid:
                lines.append("```mermaid")
                lines.append(mermaid)
                lines.append("```")
                lines.append("")

        # Individual findings
        lines.append("## Findings")
        lines.append("")

        # Sort by severity
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings.items(),
            key=lambda x: sev_order.get(x[1].get("severity", "medium"), 5),
        )

        for i, (fid, info) in enumerate(sorted_findings, 1):
            sev = info.get("severity", "medium").upper()
            vuln_type = info.get("vuln_type", "Unknown")
            endpoint = info.get("endpoint", "N/A")
            cwe = info.get("cwe", "N/A")
            cvss = info.get("cvss_score", 0)

            lines.append(f"### {i}. [{sev}] {vuln_type} — {cwe}")
            lines.append("")
            lines.append(f"**Endpoint:** `{endpoint}`")
            if info.get("parameter"):
                lines.append(f"**Parameter:** `{info['parameter']}`")
            lines.append(f"**CVSS:** {cvss} ({info.get('cvss_vector', '')})")
            lines.append(f"**Confirmed:** {'Yes' if info.get('confirmed') else 'No'}")
            lines.append("")

            # Evidence
            lines.append("#### Evidence")
            lines.append("")
            evidence = info.get("evidence", "")
            lines.append(f"```")
            lines.append(evidence[:1000])
            lines.append(f"```")
            lines.append("")

            # Request/Response
            if info.get("request_dump"):
                lines.append("#### Request")
                lines.append("")
                lines.append("```http")
                lines.append(info["request_dump"][:500])
                lines.append("```")
                lines.append("")

            if info.get("response_dump"):
                lines.append("#### Response")
                lines.append("")
                lines.append("```http")
                lines.append(info["response_dump"][:500])
                lines.append("```")
                lines.append("")

            # Remediation
            lines.append("#### Remediation")
            lines.append("")
            lines.append(info.get("remediation", "Apply security best practices."))
            lines.append("")
            lines.append("---")
            lines.append("")

        lines.append("")
        lines.append("---")
        lines.append(f"*Generated by AIBBP — {ctx['generated_at']}*")

        return "\n".join(lines)

    def _generate_html(self, ctx: dict) -> str:
        """Generate styled HTML report."""
        findings = ctx["findings"]

        sev_colors = {
            "critical": "#dc3545", "high": "#fd7e14",
            "medium": "#ffc107", "low": "#28a745", "info": "#17a2b8",
        }

        rows = []
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_findings = sorted(
            findings.items(),
            key=lambda x: sev_order.get(x[1].get("severity", "medium"), 5),
        )

        for fid, info in sorted_findings:
            sev = info.get("severity", "medium")
            color = sev_colors.get(sev, "#6c757d")
            rows.append(f"""
            <tr>
                <td><span style="background:{color};color:white;padding:2px 8px;border-radius:4px">{sev.upper()}</span></td>
                <td>{info.get('vuln_type', 'Unknown')}</td>
                <td><code>{info.get('endpoint', 'N/A')}</code></td>
                <td>{info.get('cwe', 'N/A')}</td>
                <td>{info.get('cvss_score', 0)}</td>
                <td>{'Yes' if info.get('confirmed') else 'No'}</td>
            </tr>""")

        details = []
        for i, (fid, info) in enumerate(sorted_findings, 1):
            sev = info.get("severity", "medium")
            details.append(f"""
            <div style="border:1px solid #ddd;border-radius:8px;padding:16px;margin:16px 0">
                <h3>{i}. [{sev.upper()}] {info.get('vuln_type', '')} — {info.get('cwe', '')}</h3>
                <p><strong>Endpoint:</strong> <code>{info.get('endpoint', '')}</code></p>
                <p><strong>CVSS:</strong> {info.get('cvss_score', 0)}</p>
                <h4>Evidence</h4>
                <pre style="background:#f8f9fa;padding:12px;border-radius:4px;overflow-x:auto">{info.get('evidence', '')[:1000]}</pre>
                <h4>Remediation</h4>
                <p>{info.get('remediation', '')}</p>
            </div>""")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AIBBP Vulnerability Report — {ctx['target_url']}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }}
table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
th, td {{ padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }}
th {{ background: #f8f9fa; }}
code {{ background: #f1f1f1; padding: 2px 6px; border-radius: 3px; }}
pre {{ white-space: pre-wrap; word-break: break-all; }}
</style>
</head>
<body>
<h1>Vulnerability Assessment Report</h1>
<p><strong>Target:</strong> {ctx['target_url']}</p>
<p><strong>Date:</strong> {ctx['generated_at']}</p>
<p><strong>Total Findings:</strong> {len(findings)}</p>

<h2>Summary</h2>
<table>
<tr><th>Severity</th><th>Type</th><th>Endpoint</th><th>CWE</th><th>CVSS</th><th>Confirmed</th></tr>
{''.join(rows)}
</table>

<h2>Finding Details</h2>
{''.join(details)}

<hr>
<p><em>Generated by AIBBP — {ctx['generated_at']}</em></p>
</body>
</html>"""

    def _generate_json(self, ctx: dict) -> str:
        """Generate enriched JSON report."""
        output = {
            "report_version": "1.0",
            "target_url": ctx["target_url"],
            "generated_at": ctx["generated_at"],
            "tech_stack": ctx["tech_stack"],
            "metadata": ctx["metadata"],
            "summary": {
                "total_findings": len(ctx["findings"]),
                "by_severity": {},
                "by_cwe": {},
            },
            "findings": [],
            "attack_chains": ctx["attack_chains"],
        }

        sev_counts: dict[str, int] = {}
        cwe_counts: dict[str, int] = {}

        for fid, info in ctx["findings"].items():
            sev = info.get("severity", "medium")
            cwe = info.get("cwe", "CWE-000")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

            output["findings"].append({
                "id": fid,
                **info,
            })

        output["summary"]["by_severity"] = sev_counts
        output["summary"]["by_cwe"] = cwe_counts

        return json.dumps(output, indent=2, default=str)

    def _generate_sarif(self, ctx: dict) -> str:
        """Generate SARIF 2.1.0 output from findings."""
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "AIBBP",
                        "version": "0.1.0",
                        "informationUri": "https://github.com/aibbp",
                        "rules": [],
                    }
                },
                "results": [],
            }],
        }
        run = sarif["runs"][0]
        rules_seen: set[str] = set()

        for finding in ctx.get("findings", {}).values():
            vuln_type = finding.get("vuln_type", "unknown")
            rule_id = f"AIBBP-{vuln_type.upper()}"

            if rule_id not in rules_seen:
                rules_seen.add(rule_id)
                run["tool"]["driver"]["rules"].append({
                    "id": rule_id,
                    "name": vuln_type,
                    "shortDescription": {"text": finding.get("title", vuln_type)},
                    "helpUri": f"https://owasp.org/www-community/attacks/{vuln_type}",
                })

            result = {
                "ruleId": rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}.get(finding.get("severity", "info"), "note"),
                "message": {"text": finding.get("description", finding.get("title", ""))[:500]},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": finding.get("endpoint", "")},
                    }
                }],
            }

            # Add proof pack references if available
            if finding.get("proof_pack"):
                result["fingerprints"] = {"proof_completeness": str(finding["proof_pack"].get("completeness", 0))}

            run["results"].append(result)

        return json.dumps(sarif, indent=2)

    @staticmethod
    def _build_chain_mermaid(chains: dict[str, dict[str, Any]]) -> str:
        """Convert attack chains to Mermaid flowchart."""
        if not chains:
            return ""
        lines = ["graph LR"]
        for chain_id, chain in chains.items():
            steps = chain.get("steps", [])
            if not steps:
                continue
            for i, step in enumerate(steps):
                node_id = f"{chain_id}_{i}"
                desc = step.get("description", f"Step {i}")[:40]
                status = step.get("status", "pending")
                style = ":::done" if status == "completed" else ""
                lines.append(f"    {node_id}[\"{desc}\"]")
                if i > 0:
                    prev = f"{chain_id}_{i-1}"
                    lines.append(f"    {prev} --> {node_id}")
        if len(lines) <= 1:
            return ""
        return "\n".join(lines)
