#!/usr/bin/env python3
"""Bulk active validator for all findings across all targets."""

import asyncio
import hashlib
import json
import glob
import subprocess
import time
import ssl
from collections import defaultdict
from urllib.parse import urlparse

import httpx

# ── Load & deduplicate findings ──────────────────────────────────────────────

def load_findings():
    deduped = {}
    for f in sorted(glob.glob("/root/.aibbp/targets/*/memory.json")):
        data = json.load(open(f))
        domain = data.get("domain", "")
        target_url = data.get("target_url", "")
        for fid, fd in data.get("findings", {}).items():
            ep = fd.get("endpoint", "")
            vt = fd.get("vuln_type", "")
            sev = fd.get("severity", "unknown").lower()
            key = f"{domain}|{vt}|{ep}".lower()
            h = hashlib.md5(key.encode()).hexdigest()
            if h not in deduped:
                deduped[h] = {
                    "domain": domain, "target_url": target_url,
                    "vuln_type": vt, "endpoint": ep, "severity": sev,
                    "finding_ids": [fid], "evidence": fd.get("evidence", {}),
                    "fid_primary": fid,
                }
            else:
                deduped[h]["finding_ids"].append(fid)
    return deduped


def _extract_url(endpoint, domain, target_url):
    if not endpoint:
        return ""
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        url = endpoint.split(" and ")[0].split(" AND ")[0].strip()
        for sep in [" -", " (", " →", " |", " –", " +"]:
            if sep in url:
                url = url.split(sep)[0].strip()
        return url
    if endpoint.startswith("/"):
        base = target_url.rstrip("/") if target_url else f"https://{domain}"
        return f"{base}{endpoint}"
    if " " in endpoint and "/" not in endpoint:
        return ""
    if "." in endpoint and not endpoint.startswith("."):
        return f"https://{endpoint}"
    if domain:
        return f"https://{domain}/{endpoint}"
    return ""


# ── Validators ───────────────────────────────────────────────────────────────

async def _check_get(client, url):
    return await client.get(url, follow_redirects=True)

async def _check_post(client, url, **kw):
    return await client.post(url, follow_redirects=True, **kw)

async def _try_request(client, url):
    try:
        return await _check_get(client, url)
    except:
        try:
            return await _check_post(client, url)
        except:
            return None

async def validate_finding(client, finding):
    domain = finding["domain"]
    vt = finding["vuln_type"].lower()
    ep = finding["endpoint"]
    evidence = finding["evidence"]
    detail = evidence.get("detail", "") if isinstance(evidence, dict) else str(evidence)

    result = {**finding, "validation_status": "UNKNOWN", "validation_detail": "",
              "http_status": None, "response_size": None}

    try:
        url = _extract_url(ep, domain, finding.get("target_url", ""))
        if not url:
            result["validation_status"] = "SKIP"
            result["validation_detail"] = "No testable URL"
            return result

        # Skip summary/assessment findings
        if any(x in vt for x in ["assessment", "summary", "report", "multiple", "final"]):
            if any(x in ep.lower() for x in ["ecosystem", "penetration", "complete"]) or vt in ("multiple",):
                result["validation_status"] = "SKIP"
                result["validation_detail"] = "Summary finding"
                return result

        # Route by vuln type
        if "sqs" in vt or "message_injection" in vt:
            r = await _check_post(client, url, headers={"Content-Type": "application/json"},
                                  content=json.dumps({"event": "val_test", "ts": int(time.time())}))
            result["http_status"] = r.status_code
            result["response_size"] = len(r.content)
            if "SendMessageResponse" in r.text or "MessageId" in r.text:
                result["validation_status"] = "CONFIRMED"
                result["validation_detail"] = "SQS XML with MessageId returned"
            elif r.status_code == 404:
                result["validation_status"] = "FALSE_POSITIVE"
                result["validation_detail"] = "404"
            else:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = f"HTTP {r.status_code}"
            return result

        if any(x in vt for x in ["rpc", "json_rpc"]) or "rpc." in url:
            r = await _check_post(client, url, json={"jsonrpc":"2.0","method":"eth_accounts","params":[],"id":1})
            result["http_status"] = r.status_code
            result["response_size"] = len(r.content)
            try:
                body = r.json()
            except:
                body = {}
            accts = body.get("result", [])
            err = body.get("error", {}).get("message", "")
            if isinstance(accts, list) and len(accts) > 0:
                result["validation_status"] = "CONFIRMED"
                result["validation_detail"] = f"eth_accounts: {accts[0]}"
            elif "does not exist" in err:
                result["validation_status"] = "FALSE_POSITIVE"
                result["validation_detail"] = "Method disabled"
            else:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = f"RPC exists: {err[:60] or str(accts)[:60]}"
            return result

        if any(x in vt for x in ["cors"]):
            r = await client.options(url, headers={"Origin": "https://evil.com",
                                                    "Access-Control-Request-Method": "GET"},
                                     follow_redirects=True)
            result["http_status"] = r.status_code
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "")
            if acao == "https://evil.com" and acac.lower() == "true":
                result["validation_status"] = "CONFIRMED"
                result["validation_detail"] = f"CORS reflects origin with credentials"
            elif acao == "*":
                result["validation_status"] = "LOW_VALUE"
                result["validation_detail"] = "CORS wildcard (no creds)"
            elif acao == "https://evil.com":
                result["validation_status"] = "LIKELY_REAL"
                result["validation_detail"] = "CORS reflects origin (no creds header)"
            elif r.status_code == 404:
                result["validation_status"] = "FALSE_POSITIVE"
                result["validation_detail"] = "404"
            else:
                result["validation_status"] = "FALSE_POSITIVE"
                result["validation_detail"] = f"CORS safe: ACAO={acao or 'none'}"
            return result

        if any(x in vt for x in ["subdomain_takeover"]):
            parsed = urlparse(url)
            hostname = parsed.hostname or url
            try:
                dig = subprocess.run(["dig", "+short", "CNAME", hostname],
                                     capture_output=True, text=True, timeout=5)
                cname = dig.stdout.strip()
            except:
                cname = ""
            try:
                r = await _check_get(client, url)
                result["http_status"] = r.status_code
                result["response_size"] = len(r.content)
                body = r.text
                sigs = ["NoSuchBucket", "There isn't a GitHub Pages", "Heroku | No such app",
                        "is not a registered namespace", "Domain is not connected"]
                found = [s for s in sigs if s.lower() in body.lower()]
                if found:
                    result["validation_status"] = "LIKELY_REAL"
                    result["validation_detail"] = f"Takeover sig: {found[0]}, CNAME={cname}"
                elif not cname:
                    result["validation_status"] = "FALSE_POSITIVE"
                    result["validation_detail"] = "No CNAME, not claimable"
                else:
                    result["validation_status"] = "NEEDS_MANUAL"
                    result["validation_detail"] = f"CNAME={cname}, HTTP {r.status_code}"
            except httpx.ConnectError:
                try:
                    dig2 = subprocess.run(["dig", "+short", hostname],
                                          capture_output=True, text=True, timeout=5)
                    has_a = bool(dig2.stdout.strip())
                except:
                    has_a = False
                if not has_a and not cname:
                    result["validation_status"] = "FALSE_POSITIVE"
                    result["validation_detail"] = "DNS doesn't resolve"
                elif cname:
                    result["validation_status"] = "NEEDS_MANUAL"
                    result["validation_detail"] = f"CNAME={cname}, unreachable"
                else:
                    result["validation_status"] = "FALSE_POSITIVE"
                    result["validation_detail"] = "Unreachable, no CNAME"
            return result

        if any(x in vt for x in ["open_redirect"]):
            r = await client.get(url, follow_redirects=False)
            result["http_status"] = r.status_code
            result["response_size"] = len(r.content)
            if r.status_code == 404:
                result["validation_status"] = "FALSE_POSITIVE"
                result["validation_detail"] = "404"
            elif r.status_code in (301, 302, 307, 308):
                loc = r.headers.get("location", "")
                if any(x in loc.lower() for x in ["evil.com", "attacker", "example.com"]):
                    result["validation_status"] = "LIKELY_REAL"
                    result["validation_detail"] = f"Redirects to: {loc[:60]}"
                else:
                    result["validation_status"] = "NEEDS_MANUAL"
                    result["validation_detail"] = f"Redirect to {loc[:60]}"
            else:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = f"HTTP {r.status_code}"
            return result

        if any(x in vt for x in ["rate_limit", "brute_force", "no_rate"]):
            result["validation_status"] = "LOW_VALUE"
            result["validation_detail"] = "Rate limit issues typically low severity"
            return result

        # ── Generic: just check if endpoint exists ──
        r = await _try_request(client, url)
        if r is None:
            result["validation_status"] = "UNREACHABLE"
            result["validation_detail"] = "Connection failed"
            return result

        result["http_status"] = r.status_code
        result["response_size"] = len(r.content)
        body = r.text

        if r.status_code == 404:
            # Check if it's a Cloudflare challenge page
            if "Attention Required" in body or "cf-browser-verification" in body:
                result["validation_status"] = "BLOCKED"
                result["validation_detail"] = "Cloudflare challenge page"
            else:
                result["validation_status"] = "FALSE_POSITIVE"
                result["validation_detail"] = "Endpoint returns 404"
            return result

        if r.status_code == 403:
            if "cloudflare" in body.lower() or "incapsula" in body.lower() or "akamai" in body.lower():
                result["validation_status"] = "BLOCKED"
                result["validation_detail"] = "WAF blocking"
            else:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = "403 - may be auth or WAF"
            return result

        if r.status_code in (401,):
            result["validation_status"] = "NEEDS_MANUAL"
            result["validation_detail"] = "401 - auth required"
            return result

        # Check for Cloudflare challenge on 200
        if r.status_code == 200 and ("Attention Required" in body or "cf-browser-verification" in body):
            result["validation_status"] = "BLOCKED"
            result["validation_detail"] = "Cloudflare challenge"
            return result

        # Auth bypass check
        if any(x in vt for x in ["auth_bypass", "broken_auth", "access_control"]):
            if r.status_code == 200:
                if "__NEXT_DATA__" in body and '"nextExport":true' in body:
                    result["validation_status"] = "FALSE_POSITIVE"
                    result["validation_detail"] = "Static Next.js export"
                else:
                    result["validation_status"] = "NEEDS_MANUAL"
                    result["validation_detail"] = f"200 ({len(body)} bytes), verify real data"
            elif r.status_code == 500:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = "500 - may process without auth"
            return result

        # XSS check
        if any(x in vt for x in ["xss", "stored_xss"]):
            xss_sigs = ["<script>", "<svg", "onerror=", "onload=", "javascript:", "alert("]
            found = [s for s in xss_sigs if s.lower() in body.lower()]
            if found:
                result["validation_status"] = "LIKELY_REAL"
                result["validation_detail"] = f"XSS indicators: {', '.join(found[:3])}"
            else:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = f"HTTP {r.status_code}, no XSS indicators"
            return result

        # Info disclosure
        if any(x in vt for x in ["info_disclosure", "sensitive_data", "api_key", "credential",
                                   "key_exposure", "token_exposure", "config_exposure"]):
            pats = ["api_key", "apikey", "secret", "password", "AKIA", "private_key",
                    "-----BEGIN", "postgres://", "mysql://", "mongodb://"]
            found = [p for p in pats if p.lower() in body.lower()]
            if "NEXT_PUBLIC_" in body and found:
                result["validation_status"] = "LOW_VALUE"
                result["validation_detail"] = f"NEXT_PUBLIC_ keys (intentionally client-side)"
            elif found:
                result["validation_status"] = "LIKELY_REAL"
                result["validation_detail"] = f"Sensitive: {', '.join(found[:3])}"
            else:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = f"HTTP {r.status_code}, check content"
            return result

        # Segment keys
        if "segment" in vt:
            if "WRITE_KEY" in body or "writeKey" in body:
                result["validation_status"] = "LIKELY_REAL"
                result["validation_detail"] = "Segment write key found in response"
            else:
                result["validation_status"] = "NEEDS_MANUAL"
                result["validation_detail"] = f"HTTP {r.status_code}"
            return result

        # Default
        result["validation_status"] = "NEEDS_MANUAL"
        result["validation_detail"] = f"HTTP {r.status_code} ({len(body)} bytes)"

    except httpx.ConnectError:
        result["validation_status"] = "UNREACHABLE"
        result["validation_detail"] = "Connection failed"
    except httpx.ConnectTimeout:
        result["validation_status"] = "UNREACHABLE"
        result["validation_detail"] = "Timeout"
    except httpx.ReadTimeout:
        result["validation_status"] = "TIMEOUT"
        result["validation_detail"] = "Read timeout"
    except ssl.SSLError as e:
        result["validation_status"] = "UNREACHABLE"
        result["validation_detail"] = f"SSL: {str(e)[:60]}"
    except Exception as e:
        result["validation_status"] = "ERROR"
        result["validation_detail"] = f"{type(e).__name__}: {str(e)[:80]}"

    return result


# ── Runner ───────────────────────────────────────────────────────────────────

async def main():
    import warnings
    warnings.filterwarnings("ignore")

    print("Loading findings...")
    deduped = load_findings()
    findings = list(deduped.values())
    print(f"  {len(findings)} unique findings to validate")

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "unknown": 5}
    findings.sort(key=lambda f: sev_order.get(f["severity"], 5))

    print(f"\nStarting validation (15 concurrent requests)...")
    print("=" * 70)

    sem = asyncio.Semaphore(15)
    start = time.time()
    done = 0

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(12.0, connect=6.0),
        verify=False, follow_redirects=False,
        headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
    ) as client:
        async def _run(f):
            nonlocal done
            async with sem:
                r = await validate_finding(client, f)
                done += 1
                if done % 50 == 0:
                    print(f"  Progress: {done}/{len(findings)}")
                return r

        results = await asyncio.gather(*[_run(f) for f in findings], return_exceptions=True)

    elapsed = time.time() - start
    processed = []
    for r in results:
        if isinstance(r, Exception):
            processed.append({"validation_status": "ERROR", "validation_detail": str(r)[:80],
                              "domain": "?", "vuln_type": "?", "endpoint": "?", "severity": "?"})
        else:
            processed.append(r)

    # ── Results ──
    cats = defaultdict(list)
    for r in processed:
        cats[r["validation_status"]].append(r)

    print(f"\n{'=' * 70}")
    print(f"VALIDATION COMPLETE — {len(processed)} findings in {elapsed:.1f}s")
    print(f"{'=' * 70}")
    print(f"\n{'STATUS':<20} {'COUNT':>5}")
    print("-" * 30)
    for s in ["CONFIRMED", "LIKELY_REAL", "NEEDS_MANUAL", "LOW_VALUE", "BLOCKED",
              "FALSE_POSITIVE", "SKIP", "UNREACHABLE", "TIMEOUT", "ERROR", "UNKNOWN"]:
        if s in cats:
            print(f"  {s:<18} {len(cats[s]):>5}")
    print(f"  {'TOTAL':<18} {len(processed):>5}")

    for status in ["CONFIRMED", "LIKELY_REAL"]:
        if status in cats:
            print(f"\n{'=' * 70}")
            print(f"  {status} FINDINGS ({len(cats[status])})")
            print(f"{'=' * 70}")
            for r in cats[status]:
                sev = r.get("severity", "?").upper()
                dupes = len(r.get("finding_ids", []))
                print(f"\n  [{sev}] {r['domain']} — {r['vuln_type']}")
                print(f"    Endpoint: {r['endpoint'][:90]}")
                print(f"    HTTP {r.get('http_status','?')} | {r.get('response_size','?')} bytes | {dupes} dupes")
                print(f"    → {r['validation_detail']}")

    if "FALSE_POSITIVE" in cats:
        print(f"\n{'=' * 70}")
        print(f"  FALSE POSITIVES ({len(cats['FALSE_POSITIVE'])})")
        print(f"{'=' * 70}")
        fp_dom = defaultdict(list)
        for r in cats["FALSE_POSITIVE"]:
            fp_dom[r["domain"]].append(r)
        for dom in sorted(fp_dom, key=lambda d: len(fp_dom[d]), reverse=True):
            items = fp_dom[dom]
            print(f"\n  {dom} ({len(items)} FP):")
            for r in items[:5]:
                print(f"    - {r['vuln_type']}: {r['validation_detail']}")
            if len(items) > 5:
                print(f"    ... and {len(items)-5} more")

    # Save JSON
    output = {
        "timestamp": time.time(),
        "elapsed": elapsed,
        "total": len(processed),
        "summary": {s: len(v) for s, v in cats.items()},
        "confirmed": [{k: v for k, v in r.items() if k != "evidence"} for r in cats.get("CONFIRMED", [])],
        "likely_real": [{k: v for k, v in r.items() if k != "evidence"} for r in cats.get("LIKELY_REAL", [])],
        "false_positives": [{"domain": r["domain"], "vuln_type": r["vuln_type"],
                             "endpoint": r["endpoint"][:100], "detail": r["validation_detail"]}
                            for r in cats.get("FALSE_POSITIVE", [])],
        "needs_manual": [{"domain": r["domain"], "vuln_type": r["vuln_type"],
                          "endpoint": r["endpoint"][:100], "severity": r["severity"],
                          "detail": r["validation_detail"], "http": r.get("http_status")}
                         for r in cats.get("NEEDS_MANUAL", [])],
    }
    with open("/root/aibbp/validation_results.json", "w") as f:
        json.dump(output, f, indent=2, default=str)
    print(f"\nResults saved: /root/aibbp/validation_results.json")


if __name__ == "__main__":
    asyncio.run(main())
