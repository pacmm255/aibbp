# Stored XSS in BitMEX Testnet Chat Channels

## Summary

Multiple BitMEX testnet chat channels contain stored XSS payloads that are returned by the API without sanitization. The `/api/v1/chat` endpoint returns user-submitted messages containing raw HTML and JavaScript that, if rendered by the client without proper escaping, would execute in users' browsers.

## Severity

**High**

## Affected Endpoint

- `GET https://testnet.bitmex.com/api/v1/chat?channelID={id}&reverse=true`

## Reproduction Steps

### Step 1: Retrieve chat messages from channel 6

```bash
curl -s "https://testnet.bitmex.com/api/v1/chat?count=5&channelID=6&reverse=true"
```

### Step 2: Observe XSS payloads in message content

Response contains messages with raw HTML/JavaScript:

```
<svg/onload="&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x64;&#x6F;&#x63;&#x75;&#x6D;&#x65;&#x6E;&#x74;&#x2E;&#x64;&#x6F;&#x6D;&#x61;&#x69;&#x6E;&#x29;">
```

```
<script>if("x\xEE\xA9\x93".length==2) { javascript:alert(1);}</script>
```

```
<style></style\x0A<img src="about:blank" onerror=javascript:alert(1)//></style>
```

### Step 3: Verify payloads exist across multiple channels

```bash
# Channel 2
curl -s "https://testnet.bitmex.com/api/v1/chat?count=5&channelID=2&reverse=true"
# Contains: <h1> tags, <img> tags, <br /> injection

# Channel 6
curl -s "https://testnet.bitmex.com/api/v1/chat?count=5&channelID=6&reverse=true"
# Contains: <svg/onload>, <script>, <style> injection
```

## Impact

- XSS payloads stored permanently in chat messages
- Any user viewing these channels in a client that doesn't properly escape HTML will have JavaScript executed in their browser context
- Potential for session hijacking, cookie theft, or account takeover via the BitMEX testnet interface
- The testnet uses the same UI framework as production — if the rendering vulnerability exists on testnet, it likely exists on mainnet

## Remediation

1. Sanitize all chat message content server-side before storage (strip HTML tags)
2. Ensure the chat rendering client uses proper HTML escaping / Content Security Policy
3. Remove existing malicious payloads from chat history
