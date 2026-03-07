#!/usr/bin/env python3
"""Validate ALL findings using Claude Opus 4.6 and write reports for confirmed ones.

Usage: python validate_findings.py [--dry-run] [--domain DOMAIN] [--severity critical,high,medium]

Pulls findings from PostgreSQL, deduplicates, sends each to Opus for validation,
writes professional bug bounty reports for confirmed findings to /reports/.
Resumable — saves progress after each batch.
"""

import asyncio
import hashlib
import json
import os
import pathlib
import re
import sys
import time
from datetime import datetime

import asyncpg
import structlog

logger = structlog.get_logger()

# ── Config ───────────────────────────────────────────────────────────────
DB_DSN = "postgresql://aibbp:aibbp_dev@localhost:5433/aibbp"
REPORTS_DIR = pathlib.Path("/root/aibbp/reports")
PROGRESS_FILE = pathlib.Path("/root/aibbp/reports/.validation_progress.json")
MODEL = "claude-opus-4-6"
MAX_CONCURRENT = 3  # parallel Opus calls
COST_PER_FINDING_EST = 0.05  # ~$0.05 per validation call

# FP heuristics — skip these patterns without LLM validation
FP_EVIDENCE_PATTERNS = [
    r"FALSE POSITIVE",
    r"NOT a real production secret",
    r"DEMO DATA",
    r"demo/test",
]

FP_TITLE_PATTERNS = [
    r"^Final Assessment$",
    r"^Penetration Test Complete",
    r"^Complete Assessment$",
    r"^Final Report$",
    r"^Session \d+ Complete$",
    r"^Authentication Security$",
    r"^Penetration Test Final$",
    r"^Final Critical Assessment$",
]

# Vuln types that are summary entries, not actual findings
SUMMARY_TYPES = {
    "info", "complete_assessment", "penetration_test_complete",
    "complete_penetration_test", "penetration_test_complete_verified",
    "multiple_critical_confirmed", "multiple_critical",
    "multiple_vulnerabilities", "multiple_critical_vulnerabilities",
    "comprehensive", "final_assessment",
}

VALIDATION_SYSTEM_PROMPT = """You are an expert bug bounty validator with 15+ years of experience. Your job is to analyze vulnerability findings from an automated pentesting agent and determine if they are REAL or FALSE POSITIVES.

Be EXTREMELY strict and skeptical. Automated agents produce many false positives. Apply these rules:

AUTOMATIC FALSE POSITIVE:
- HTTP 500 errors alone do NOT prove exploitation. A 500 means the server errored — could be input validation, WAF, or generic error handling. You need PROOF: data extracted, behavior changed, timing delta confirmed.
- "Returns 200 OK" on admin/internal endpoints does NOT prove access control bypass — many apps return 200 with a login page, redirect, or empty body.
- "Accepted without validation" needs proof the OAuth flow actually completes and delivers tokens/codes to attacker.
- Reflected values in Location headers are open redirects at most, not SSRF or token theft, unless the actual token/code appears in the redirect to attacker domain.
- "Response changed" or "length diff" doesn't prove prototype pollution without demonstrated code execution or privilege escalation.
- Rate limiting absence is informational, not a vulnerability.
- Subdomain takeover claims need: (1) dangling CNAME confirmed, (2) hosting service returns unclaimed page, (3) attacker can register.
- "NoSQL injection causes 500" is NOT confirmed without data extraction or auth bypass proof.
- JWT alg:none returning 500 does NOT mean the token was accepted — it means the server crashed parsing it.
- "Scope escalation" on OAuth endpoints needs proof the elevated scope actually grants the claimed access, not just that the parameter is echoed.

CONFIRMED VULNERABILITY requires:
- SSTI: Mathematical evaluation ({{7*7}}=49) with ACTUAL response body showing the computed result
- XSS: Payload reflected unencoded in an HTML context that would execute (not in JSON, not URL-encoded in a header)
- SQLi: Data extracted, time-based delay with measured timing diff, or UNION results visible
- SSRF: Actual internal data returned (metadata, internal HTML, etc.)
- Auth bypass: Actual protected content/functionality demonstrated (not just a non-401 status code)
- Credential exposure: Keys/tokens shown AND verified functional (API calls succeed)
- RCE: Actual command output in response
- IDOR: Actual other-user data accessed
- Host header injection: Only critical if password reset email provably uses the poisoned host (not just "200 OK returned")
- Open redirect: Low severity unless chained with demonstrated token theft

SEVERITY GUIDELINES:
- critical: RCE, account takeover with full proof, working credential theft, verified SSTI with code execution
- high: Verified XSS in main app, verified SQLi with data, verified SSRF with internal data, verified auth bypass with access to protected data
- medium: Open redirect, info disclosure of non-critical data, unverified but plausible injection, CSRF
- low: Missing headers, informational findings, theoretical attacks without proof
- none: False positive, not exploitable

Respond with EXACTLY this JSON (no other text):
{
  "verdict": "CONFIRMED" | "FALSE_POSITIVE" | "LIKELY_FP" | "NEEDS_MANUAL",
  "confidence": 0-100,
  "reasoning": "Brief explanation",
  "actual_severity": "critical|high|medium|low|info|none",
  "actual_vuln_type": "corrected vulnerability type",
  "reportable": true or false,
  "report_title": "Clean title for bug bounty report if reportable"
}"""

VALIDATION_USER_TEMPLATE = """Validate this automated scanner finding:

Domain: {domain}
Reported Severity: {severity}
Reported Type: {vuln_type}
Title: {title}
Endpoint: {endpoint}
Evidence: {evidence}
PoC Code: {poc_code}
Tool Used: {tool_used}

Is this a real, exploitable vulnerability or a false positive? Be strict and skeptical."""

REPORT_TEMPLATE = """# {title}

**Domain:** {domain}
**Severity:** {severity}
**CVSS:** {cvss}
**Type:** {vuln_type}
**Endpoint:** `{endpoint}`
**Discovered:** {discovered_at}
**Validated:** {validated_at}

---

## Summary

{summary}

## Steps to Reproduce

{steps}

## Evidence

{evidence}

## Impact

{impact}

## Remediation

{remediation}

---

*Validated by Claude Opus 4.6 — manual verification recommended before submission.*
"""

REPORT_GEN_SYSTEM = """You are writing a professional bug bounty report for submission to a security program. Given the validated finding, generate a complete report. Be precise and factual — only include what the evidence actually shows.

Respond in JSON with these keys:
- "summary": 2-3 sentence executive summary
- "steps": Numbered reproduction steps with exact curl commands or URLs
- "evidence": The actual proof — HTTP responses, computed results, data returned
- "impact": What an attacker could achieve, affected users, business impact
- "remediation": Specific technical fix recommendations
- "cvss": CVSS 3.1 base score as string (e.g. "8.6")"""


async def get_anthropic_client():
    """Create Anthropic client using OAuth credentials."""
    import anthropic

    creds_path = pathlib.Path.home() / ".claude" / ".credentials.json"
    if creds_path.exists():
        data = json.loads(creds_path.read_text())
        oauth = data.get("claudeAiOauth", {})
        token = oauth.get("accessToken", "")
        if token and oauth.get("expiresAt", 0) > time.time() * 1000:
            return anthropic.AsyncAnthropic(
                api_key=token,
                default_headers={"anthropic-beta": "oauth-2025-04-20"},
            )

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if api_key:
        return anthropic.AsyncAnthropic(api_key=api_key)

    raise RuntimeError("No Anthropic credentials found")


async def call_opus(client, system: str, user_msg: str, max_tokens: int = 4096) -> str:
    """Call Opus 4.6 with thinking enabled. Auto-refreshes OAuth on 401."""
    global _CLIENT
    if _CLIENT is not None:
        client = _CLIENT
    for attempt in range(3):
        try:
            response = await client.messages.create(
                model=MODEL,
                max_tokens=max(max_tokens, 16384),
                thinking={"type": "enabled", "budget_tokens": 8000},
                system=system,
                messages=[{"role": "user", "content": user_msg}],
            )
            for block in response.content:
                if hasattr(block, "text"):
                    return block.text
            return ""
        except Exception as e:
            err_str = str(e)
            is_auth = "401" in err_str or "authentication_error" in err_str
            if is_auth and attempt < 2:
                logger.warning("opus_auth_refresh", attempt=attempt)
                await asyncio.sleep(5)
                try:
                    new_client = await get_anthropic_client()
                    _CLIENT = new_client
                    client = new_client
                except Exception:
                    pass
                continue
            if attempt < 2:
                wait = 5 * (attempt + 1)
                logger.warning("opus_retry", attempt=attempt, error=err_str, wait=wait)
                await asyncio.sleep(wait)
            else:
                raise
    return ""

_CLIENT = None


def is_auto_fp(finding: dict) -> str | None:
    """Check if finding is an automatic false positive. Returns reason or None."""
    evidence = str(finding.get("evidence", ""))
    title = str(finding.get("title", ""))
    vuln_type = str(finding.get("vuln_type", ""))

    for pat in FP_EVIDENCE_PATTERNS:
        if re.search(pat, evidence, re.IGNORECASE):
            return f"Evidence self-identifies as FP: {pat}"

    for pat in FP_TITLE_PATTERNS:
        if re.search(pat, title, re.IGNORECASE):
            return f"Summary/assessment entry, not individual finding"

    if vuln_type in SUMMARY_TYPES:
        return f"Summary vuln_type: {vuln_type}"

    # 500-only evidence (no proof of exploitation)
    if re.search(r"(returns?\s+500|status\s+500|500\s+(instead|rather|error|response))", evidence, re.IGNORECASE):
        has_proof = re.search(
            r"(returns?\s+200|data\s+returned|confirmed|verified|extract|output|49|alert\(|"
            r"success.*true|password|hash|key\s*[:=]|token\s*[:=]|admin|dashboard)",
            evidence, re.IGNORECASE
        )
        if not has_proof:
            return "Only evidence is HTTP 500 — no proof of exploitation"

    return None


def dedup_key(f: dict) -> str:
    raw = f"{f.get('domain','')}|{f.get('vuln_type','')}|{(f.get('endpoint') or '')[:80]}"
    return hashlib.md5(raw.encode()).hexdigest()


def load_progress() -> dict:
    if PROGRESS_FILE.exists():
        try:
            return json.loads(PROGRESS_FILE.read_text())
        except Exception:
            pass
    return {"validated": {}, "stats": {"total": 0, "confirmed": 0, "fp": 0, "manual": 0, "auto_fp": 0}}


def save_progress(progress: dict):
    PROGRESS_FILE.write_text(json.dumps(progress, indent=2, default=str))


def sanitize_filename(s: str) -> str:
    s = re.sub(r'[^\w\s-]', '', s.lower())
    s = re.sub(r'[-\s]+', '_', s).strip('_')
    return s[:60]


async def fetch_findings(pool: asyncpg.Pool, severity_filter: list[str] | None = None,
                         domain_filter: str | None = None) -> list[dict]:
    """Fetch all confirmed findings from DB, deduplicated."""
    query = """
        SELECT DISTINCT ON (domain, vuln_type, LEFT(COALESCE(endpoint,''), 80))
            id, domain, severity, vuln_type, title, endpoint,
            evidence::text as evidence, poc_code, tool_used,
            description, method, parameter, discovered_at
        FROM findings
        WHERE confirmed = true
    """
    params = []
    idx = 1

    if severity_filter:
        query += f" AND severity = ANY(${idx}::text[])"
        params.append(severity_filter)
        idx += 1

    if domain_filter:
        query += f" AND domain ILIKE ${idx}"
        params.append(f"%{domain_filter}%")
        idx += 1

    query += " ORDER BY domain, vuln_type, LEFT(COALESCE(endpoint,''), 80), discovered_at DESC"

    rows = await pool.fetch(query, *params)
    return [dict(r) for r in rows]


async def validate_finding(client, finding: dict, semaphore: asyncio.Semaphore) -> dict:
    """Validate a single finding with Opus."""
    async with semaphore:
        evidence = str(finding.get("evidence", ""))
        try:
            ev_data = json.loads(evidence)
            if isinstance(ev_data, dict):
                evidence = ev_data.get("raw", json.dumps(ev_data))
        except (json.JSONDecodeError, TypeError):
            pass

        user_msg = VALIDATION_USER_TEMPLATE.format(
            domain=finding.get("domain") or "?",
            severity=finding.get("severity") or "?",
            vuln_type=finding.get("vuln_type") or "?",
            title=finding.get("title") or "?",
            endpoint=finding.get("endpoint") or "?",
            evidence=evidence[:3000],
            poc_code=(finding.get("poc_code") or "(none)")[:1000],
            tool_used=finding.get("tool_used") or "(unknown)",
        )

        try:
            raw = await call_opus(client, VALIDATION_SYSTEM_PROMPT, user_msg, max_tokens=2048)
            # Extract JSON — find balanced braces containing "verdict"
            result = None
            # Try parsing raw first (might be pure JSON)
            stripped = raw.strip()
            if stripped.startswith("```"):
                # Remove markdown code fences
                stripped = re.sub(r'^```(?:json)?\s*', '', stripped)
                stripped = re.sub(r'\s*```$', '', stripped)
            try:
                result = json.loads(stripped)
            except json.JSONDecodeError:
                # Find the JSON object by balanced brace matching
                start = raw.find("{")
                if start >= 0:
                    depth = 0
                    for i in range(start, len(raw)):
                        if raw[i] == "{":
                            depth += 1
                        elif raw[i] == "}":
                            depth -= 1
                            if depth == 0:
                                try:
                                    result = json.loads(raw[start:i+1])
                                except json.JSONDecodeError:
                                    pass
                                break
            if not result:
                result = {
                    "verdict": "NEEDS_MANUAL",
                    "confidence": 0,
                    "reasoning": raw[:300] if raw else "Empty response",
                    "reportable": False,
                }
        except Exception as e:
            logger.warning("validation_parse_error", domain=finding.get("domain"),
                          title=finding.get("title"), error=str(e))
            result = {
                "verdict": "NEEDS_MANUAL",
                "confidence": 0,
                "reasoning": f"Parse error: {e}",
                "reportable": False,
            }

        result["finding_id"] = str(finding.get("id", ""))
        result["domain"] = finding.get("domain", "")
        result["title"] = finding.get("title", "")
        result["original_severity"] = finding.get("severity", "")
        return result


async def generate_report(client, finding: dict, validation: dict,
                          report_num: int, semaphore: asyncio.Semaphore) -> str | None:
    """Generate a professional bug bounty report for a confirmed finding."""
    async with semaphore:
        evidence = str(finding.get("evidence", ""))
        try:
            ev_data = json.loads(evidence)
            if isinstance(ev_data, dict):
                evidence = ev_data.get("raw", json.dumps(ev_data))
        except (json.JSONDecodeError, TypeError):
            pass

        user_msg = f"""Generate a bug bounty report for this confirmed vulnerability:

Domain: {finding.get('domain', '?')}
Severity: {validation.get('actual_severity', finding.get('severity', '?'))}
Type: {validation.get('actual_vuln_type', finding.get('vuln_type', '?'))}
Title: {validation.get('report_title', finding.get('title', '?'))}
Endpoint: {finding.get('endpoint', '?')}
Method: {finding.get('method', '?')}
Parameter: {finding.get('parameter', '?')}
Evidence: {evidence[:4000]}
PoC: {(finding.get('poc_code') or '(none)')[:2000]}
Validator Notes: {validation.get('reasoning', '')}"""

        try:
            raw = await call_opus(client, REPORT_GEN_SYSTEM, user_msg, max_tokens=4096)
            m = re.search(r'\{.*\}', raw, re.DOTALL)
            if not m:
                return None
            report_data = json.loads(m.group())
        except Exception as e:
            logger.warning("report_gen_error", domain=finding.get("domain"),
                          title=finding.get("title"), error=str(e))
            return None

        severity = validation.get("actual_severity", finding.get("severity", "medium"))
        report = REPORT_TEMPLATE.format(
            title=validation.get("report_title", finding.get("title", "Unknown")),
            domain=finding.get("domain", "?"),
            severity=severity.upper(),
            cvss=report_data.get("cvss", "N/A"),
            vuln_type=validation.get("actual_vuln_type", finding.get("vuln_type", "?")),
            endpoint=finding.get("endpoint", "?"),
            discovered_at=str(finding.get("discovered_at", "?"))[:19],
            validated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
            summary=report_data.get("summary", ""),
            steps=report_data.get("steps", ""),
            evidence=report_data.get("evidence", ""),
            impact=report_data.get("impact", ""),
            remediation=report_data.get("remediation", ""),
        )

        domain_safe = sanitize_filename(finding.get("domain", "unknown"))
        title_safe = sanitize_filename(
            validation.get("report_title", finding.get("title", "unknown"))
        )
        sev_prefix = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4"}.get(severity, "P5")
        filename = f"{sev_prefix}_{report_num:03d}_{domain_safe}_{title_safe}.md"
        filepath = REPORTS_DIR / filename

        filepath.write_text(report)
        return str(filepath)


async def main():
    import argparse
    parser = argparse.ArgumentParser(description="Validate findings with Opus 4.6")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--domain", type=str, default=None)
    parser.add_argument("--severity", type=str, default="critical,high,medium,low",
                       help="Severity filter (comma-separated, default: critical,high,medium,low)")
    parser.add_argument("--limit", type=int, default=0, help="Max findings to validate (0=all)")
    parser.add_argument("--reset", action="store_true", help="Reset progress and start fresh")
    args = parser.parse_args()

    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    if args.reset and PROGRESS_FILE.exists():
        PROGRESS_FILE.unlink()
        print("[*] Progress reset")

    severity_filter = [s.strip() for s in args.severity.split(",") if s.strip()]
    print(f"[*] Connecting to DB...")
    pool = await asyncpg.create_pool(DB_DSN)

    print(f"[*] Fetching findings (severity={severity_filter}, domain={args.domain})...")
    findings = await fetch_findings(pool, severity_filter, args.domain)
    print(f"[*] Fetched {len(findings)} unique findings from DB")

    progress = load_progress()
    already_done = set(progress["validated"].keys())

    to_validate = []
    auto_fp_count = 0
    skipped_count = 0

    for f in findings:
        dk = dedup_key(f)
        if dk in already_done:
            skipped_count += 1
            continue

        fp_reason = is_auto_fp(f)
        if fp_reason:
            progress["validated"][dk] = {
                "verdict": "AUTO_FP",
                "reasoning": fp_reason,
                "domain": f.get("domain"),
                "title": f.get("title"),
            }
            progress["stats"]["auto_fp"] = progress["stats"].get("auto_fp", 0) + 1
            auto_fp_count += 1
            continue

        to_validate.append(f)

    if args.limit > 0:
        to_validate = to_validate[:args.limit]

    save_progress(progress)

    print(f"\n{'='*60}")
    print(f"  Already validated:   {skipped_count}")
    print(f"  Auto-FP (filtered):  {auto_fp_count}")
    print(f"  To validate (Opus):  {len(to_validate)}")
    print(f"  Estimated cost:      ~${len(to_validate) * COST_PER_FINDING_EST:.2f}")
    print(f"{'='*60}\n")

    if args.dry_run:
        print("[DRY RUN] Would validate:")
        for i, f in enumerate(to_validate[:30]):
            print(f"  {i+1}. [{f['severity']}] {f['domain']}: {f['title']} ({f['vuln_type']})")
        if len(to_validate) > 30:
            print(f"  ... and {len(to_validate) - 30} more")
        await pool.close()
        return

    if not to_validate:
        print("[*] Nothing to validate — all findings already processed!")
        await pool.close()
        return

    print(f"[*] Initializing Claude Opus 4.6...")
    global _CLIENT
    client = await get_anthropic_client()
    _CLIENT = client

    semaphore = asyncio.Semaphore(MAX_CONCURRENT)
    confirmed_findings = []

    # Process in batches
    batch_size = 15
    for batch_start in range(0, len(to_validate), batch_size):
        batch = to_validate[batch_start:batch_start + batch_size]
        batch_num = batch_start // batch_size + 1
        total_batches = (len(to_validate) + batch_size - 1) // batch_size

        print(f"\n── Batch {batch_num}/{total_batches} ({len(batch)} findings) ──")

        async def _safe_validate(finding):
            try:
                return await validate_finding(client, finding, semaphore)
            except Exception as e:
                import traceback
                logger.error("validation_error", error=str(e),
                           domain=finding.get("domain"), title=finding.get("title"),
                           tb=traceback.format_exc()[-500:])
                return e

        tasks = [_safe_validate(f) for f in batch]
        results = await asyncio.gather(*tasks)

        for f, result in zip(batch, results):
            dk = dedup_key(f)
            if isinstance(result, Exception):
                logger.error("validation_error", error=str(result))
                progress["validated"][dk] = {
                    "verdict": "ERROR", "reasoning": str(result),
                    "domain": f.get("domain"), "title": f.get("title"),
                }
                continue

            verdict = result.get("verdict", "NEEDS_MANUAL")
            confidence = result.get("confidence", 0)
            reportable = result.get("reportable", False)
            actual_sev = result.get("actual_severity", f.get("severity"))

            progress["stats"]["total"] = progress["stats"].get("total", 0) + 1
            if verdict == "CONFIRMED":
                progress["stats"]["confirmed"] = progress["stats"].get("confirmed", 0) + 1
                sym = "✓"
            elif verdict in ("FALSE_POSITIVE", "LIKELY_FP"):
                progress["stats"]["fp"] = progress["stats"].get("fp", 0) + 1
                sym = "✗"
            else:
                progress["stats"]["manual"] = progress["stats"].get("manual", 0) + 1
                sym = "?"

            short_reason = result.get("reasoning", "")[:120]
            print(f"  {sym} [{actual_sev:8s}] {f.get('domain',''):30s} {f.get('title','')[:40]:40s} [{verdict}]")
            if verdict == "CONFIRMED":
                print(f"    ↳ {short_reason}")

            progress["validated"][dk] = {
                "verdict": verdict,
                "confidence": confidence,
                "reasoning": result.get("reasoning", ""),
                "actual_severity": actual_sev,
                "reportable": reportable,
                "report_title": result.get("report_title", ""),
                "actual_vuln_type": result.get("actual_vuln_type", ""),
                "domain": f.get("domain"),
                "title": f.get("title"),
                "finding_id": str(f.get("id", "")),
            }

            if verdict == "CONFIRMED" and reportable:
                confirmed_findings.append((f, result))

        save_progress(progress)
        s = progress["stats"]
        print(f"  [progress: {s.get('confirmed',0)} confirmed, {s.get('fp',0)} FP, {s.get('manual',0)} manual]")

    # Generate reports
    if confirmed_findings:
        print(f"\n{'='*60}")
        print(f"  Generating {len(confirmed_findings)} reports...")
        print(f"{'='*60}\n")

        # Get next report number
        existing_reports = list(REPORTS_DIR.glob("P?_*.md"))
        next_num = len(existing_reports) + 1

        for i, (f, v) in enumerate(confirmed_findings):
            rnum = next_num + i
            filepath = await generate_report(client, f, v, rnum, semaphore)
            if filepath:
                print(f"  ✓ {pathlib.Path(filepath).name}")

    # Mark FPs in DB
    print(f"\n[*] Updating DB...")
    update_count = 0
    async with pool.acquire() as conn:
        for dk, vdata in progress["validated"].items():
            if vdata.get("verdict") in ("FALSE_POSITIVE", "LIKELY_FP", "AUTO_FP"):
                fid = vdata.get("finding_id")
                if fid and fid != "None":
                    try:
                        await conn.execute(
                            "UPDATE findings SET is_false_positive=true, fp_reason=$1, validated_at=NOW() WHERE id=$2::uuid",
                            vdata.get("reasoning", "")[:500],
                            fid,
                        )
                        update_count += 1
                    except Exception:
                        pass

    await pool.close()

    stats = progress["stats"]
    print(f"\n{'='*60}")
    print(f"  VALIDATION COMPLETE")
    print(f"{'='*60}")
    print(f"  Opus-validated:  {stats.get('total', 0)}")
    print(f"  Auto-FP:         {stats.get('auto_fp', 0)}")
    print(f"  Confirmed real:  {stats.get('confirmed', 0)}")
    print(f"  False positive:  {stats.get('fp', 0)}")
    print(f"  Needs manual:    {stats.get('manual', 0)}")
    print(f"  DB updated:      {update_count} FPs marked")
    print(f"  Reports:         {REPORTS_DIR}/")
    print(f"{'='*60}")


if __name__ == "__main__":
    asyncio.run(main())
