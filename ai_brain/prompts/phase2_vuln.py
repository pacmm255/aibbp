"""Phase 2: Vulnerability Detection prompts.

2.1 - IDOR Detection (Haiku)
2.2 - Auth Flow Analysis (Haiku)
2.3 - Business Logic Detection (Sonnet)
2.4 - CORS Detection (Haiku)
2.5 - GraphQL Detection (Haiku)
2.6 - Mass Assignment Detection (Haiku)
2.7 - SSRF Detection (Haiku)
2.8 - JWT/OAuth Detection (Haiku)
2.9 - Error Message Analysis (Haiku)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.schemas import (
    AuthBypassFinding,
    BusinessLogicFinding,
    CORSFinding,
    ErrorMessageFinding,
    GraphQLFinding,
    IDORScanResult,
    JWTOAuthFinding,
    MassAssignmentFinding,
    SSRFFinding,
)


class IDORDetectionPrompt(PromptTemplate):
    """2.1 - Detect IDOR/BOLA vulnerabilities from endpoint data."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an IDOR (Insecure Direct Object Reference) and BOLA (Broken
Object Level Authorization) detection specialist.
</role>

<idor_patterns>
SEQUENTIAL IDs:
- /api/users/123 → Try /api/users/124
- /orders/1001 → Try /orders/1002
- /invoice/download?id=5 → Try id=6

UUID-BASED:
- /api/documents/550e8400-e29b-41d4-a716-446655440000
- Even UUIDs can be leaked in other responses

ENCODED IDs:
- Base64-encoded: /api/resource/MTIz (base64 of "123")
- Hash-based: Check if predictable hashes

ACCESS PATTERNS:
- Direct: Change ID in URL/parameter
- Indirect: Change reference in request body
- Via related object: Access parent to reach child

CRITICAL SIGNALS:
- Endpoints returning different data for different ID values
- Missing or inconsistent authorization checks
- ID values visible in responses (helps guess other IDs)
- Predictable ID patterns (auto-increment, timestamp-based)
</idor_patterns>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return IDORScanResult

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        endpoints = kwargs["endpoints"]
        request_data = kwargs.get("request_data", "")
        return f"""<endpoint_data>
{endpoints}
</endpoint_data>

<request_response_samples>
{request_data}
</request_response_samples>

<task>
Analyze these endpoints for IDOR/BOLA vulnerabilities:
1. Identify endpoints with object references (IDs, UUIDs, encoded values)
2. Classify the ID type (sequential, uuid, encoded)
3. Determine the access pattern (direct, indirect)
4. Assess evidence strength for each candidate
5. For confirmed findings, provide severity and impact assessment

Focus on endpoints that:
- Accept user-controlled IDs in URL or parameters
- Return user-specific data
- Perform state-changing operations on referenced objects
</task>"""


class AuthFlowAnalysisPrompt(PromptTemplate):
    """2.2 - Analyze authentication flows for bypasses."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an authentication bypass specialist. You analyze authentication
mechanisms, session management, and authorization flows to find
security weaknesses.
</role>

<bypass_techniques>
TOKEN MANIPULATION:
- JWT algorithm confusion (none, HS256→RS256)
- Token reuse across accounts
- Token expiration bypass
- Missing signature verification

PATH TRAVERSAL:
- /admin → 403, /ADMIN → 200
- /api/admin/users → 403, /api/./admin/users → 200
- URL encoding bypass: %2Fadmin

ROLE ESCALATION:
- Modifying role claim in JWT
- Parameter tampering: role=admin, isAdmin=true
- Vertical: user → admin
- Horizontal: user_A → user_B

SESSION WEAKNESSES:
- Predictable session tokens
- Session fixation
- Missing session invalidation on password change
- Concurrent session limits bypass

AUTHENTICATION LOGIC:
- Registration: email verification bypass
- Password reset: token prediction, race conditions
- MFA bypass: backup codes, missing enforcement
- OAuth: state parameter missing, redirect_uri manipulation
</bypass_techniques>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return AuthBypassFinding

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        auth_data = kwargs["auth_data"]
        return f"""<authentication_data>
{auth_data}
</authentication_data>

<task>
Analyze this authentication flow for bypass vulnerabilities:
1. Identify the authentication mechanism (JWT, session, OAuth)
2. Check for token manipulation weaknesses
3. Analyze authorization enforcement
4. Check for role escalation vectors
5. Assess session management security

For each finding, specify:
- The bypass technique
- The authentication mechanism affected
- Affected roles
- Evidence from the data
</task>"""


class BusinessLogicDetectionPrompt(PromptTemplate):
    """2.3 - Detect business logic vulnerabilities."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a business logic vulnerability specialist. You identify
flaws in application workflows that allow users to manipulate
business processes for unintended outcomes.
</role>

<business_logic_patterns>
PAYMENT/CHECKOUT:
- Price manipulation (changing price client-side)
- Quantity manipulation (negative quantities for refunds)
- Currency confusion
- Race conditions in payment processing
- Coupon/discount stacking or reuse
- Gift card balance manipulation

REGISTRATION/ACCOUNT:
- Email verification bypass
- Account takeover via password reset flaws
- Privilege escalation during registration
- Duplicate account exploitation

WORKFLOW BYPASS:
- Skipping steps in multi-step processes
- Replaying completed steps
- Accessing future steps directly
- State machine violations

RATE/LIMIT BYPASS:
- Rate limit circumvention
- Feature limit bypass (free tier → premium features)
- Referral system abuse
- Trial period extension

DATA MANIPULATION:
- Mass operations beyond authorization
- Bulk export of other users' data
- Import functionality exploitation
</business_logic_patterns>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return BusinessLogicFinding

    @property
    def model_tier(self) -> TaskTier:
        return "complex"  # Business logic needs deeper reasoning

    def user_template(self, **kwargs: Any) -> str:
        workflow_data = kwargs["workflow_data"]
        endpoint_data = kwargs.get("endpoint_data", "")
        return f"""<workflow_data>
{workflow_data}
</workflow_data>

<endpoint_data>
{endpoint_data}
</endpoint_data>

<task>
Analyze this application workflow for business logic vulnerabilities:
1. Map the intended workflow steps
2. Identify points where the flow can be manipulated
3. Check for missing server-side validation
4. Assess race condition potential
5. For each finding, provide step-by-step exploitation

Focus on high-impact scenarios: payment manipulation, privilege
escalation, and data access beyond authorization.
</task>"""


class CORSDetectionPrompt(PromptTemplate):
    """2.4 - Detect CORS misconfiguration vulnerabilities."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a CORS (Cross-Origin Resource Sharing) security analyst.
You identify CORS misconfigurations that could allow cross-origin
data theft.
</role>

<cors_vulnerability_types>
REFLECTED ORIGIN:
- ACAO reflects any Origin header → Critical
- Indicates no origin validation

WILDCARD WITH CREDENTIALS:
- ACAO: * with ACAC: true → Critical
- Browsers block this but indicates poor understanding

NULL ORIGIN:
- ACAO: null with ACAC: true → High
- Exploitable via sandboxed iframes

SUBDOMAIN TRUST:
- *.example.com trusted → Medium-High
- If any subdomain has XSS, CORS can be exploited

PREFIX/SUFFIX MATCHING:
- example.com.evil.com accepted → High
- evilexample.com accepted → High
- Indicates regex/matching bugs in origin validation

HEADERS:
- Access-Control-Allow-Origin (ACAO)
- Access-Control-Allow-Credentials (ACAC)
- Access-Control-Allow-Methods
- Access-Control-Allow-Headers
- Access-Control-Expose-Headers
</cors_vulnerability_types>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return CORSFinding

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        cors_data = kwargs["cors_data"]
        return f"""<cors_test_results>
{cors_data}
</cors_test_results>

<task>
Analyze these CORS configurations:
1. Check each endpoint's ACAO and ACAC headers
2. Identify the CORS policy type (reflected, wildcard, null, subdomain)
3. Assess exploitability based on credentials support
4. Rate severity based on the data accessible cross-origin
5. For exploitable findings, describe the attack scenario
</task>"""


class GraphQLDetectionPrompt(PromptTemplate):
    """2.5 - Detect GraphQL security issues."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a GraphQL security specialist. You identify security issues
in GraphQL implementations including information disclosure,
authorization bypasses, and denial of service vectors.
</role>

<graphql_vulnerability_types>
INTROSPECTION:
- Schema exposed via __schema query → Info disclosure
- Type/field enumeration reveals internal structure
- May expose admin-only types and mutations

AUTHORIZATION:
- Missing field-level authorization
- Nested object access bypassing parent checks
- Mutation authorization gaps

BATCHING/DoS:
- Query batching for brute force
- Deeply nested queries (resource exhaustion)
- Missing query depth limits
- Missing query complexity limits

INJECTION:
- SQL injection via GraphQL variables
- NoSQL injection
- SSRF via custom scalar types

DATA EXPOSURE:
- Overfetching: requesting fields beyond authorization
- Suggestions/typo hints leaking field names
- Error messages revealing schema structure
</graphql_vulnerability_types>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return GraphQLFinding

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        graphql_data = kwargs["graphql_data"]
        return f"""<graphql_analysis_data>
{graphql_data}
</graphql_analysis_data>

<task>
Analyze this GraphQL endpoint:
1. Check if introspection is enabled
2. Identify interesting types and mutations
3. Check for query depth/complexity limits
4. Assess batching capability for brute force
5. Look for authorization gaps in field access
6. Identify data exposure risks
</task>"""


class MassAssignmentDetectionPrompt(PromptTemplate):
    """2.6 - Detect mass assignment vulnerabilities."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a mass assignment vulnerability specialist. You identify
cases where applications bind user input directly to internal
data models, allowing attackers to modify protected fields.
</role>

<mass_assignment_patterns>
COMMON PROTECTED FIELDS:
- role, isAdmin, is_admin, admin, permissions
- verified, email_verified, is_verified
- balance, credits, subscription_tier
- created_at, updated_at (timestamp manipulation)
- id, user_id (object reference manipulation)
- password_hash, secret (direct credential access)
- status, active, disabled

DETECTION SIGNALS:
- PUT/PATCH endpoints accepting full object payloads
- Response includes fields not in the request
- Registration endpoints accepting extra fields
- Profile update accepting role/permission fields
- API documentation showing writable vs read-only mismatch

COMMON VULNERABLE FRAMEWORKS:
- Rails (strong params bypass)
- Django REST Framework (serializer misconfiguration)
- Express.js (no input filtering)
- Spring Boot (auto-binding)
</mass_assignment_patterns>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return MassAssignmentFinding

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        endpoint_data = kwargs["endpoint_data"]
        return f"""<endpoint_data>
{endpoint_data}
</endpoint_data>

<task>
Analyze these endpoints for mass assignment vulnerabilities:
1. Identify PUT/PATCH/POST endpoints with object payloads
2. Compare request fields with response fields
3. Check for protected fields that might be writable
4. Assess the framework and its default binding behavior
5. For each finding, list the specific writable and protected fields
</task>"""


class SSRFDetectionPrompt(PromptTemplate):
    """2.7 - Detect SSRF vulnerabilities."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an SSRF (Server-Side Request Forgery) detection specialist.
You identify endpoints where user-controlled input influences
server-side HTTP requests.
</role>

<ssrf_patterns>
INJECTION POINTS:
- URL parameters: ?url=, ?link=, ?redirect=, ?callback=
- Request body: webhook URLs, import URLs, avatar URLs
- Headers: X-Forwarded-For, Referer (less common)
- File upload: SVG with external references, XML with entities

SSRF TYPES:
- Full SSRF: Attacker can read response → Critical
- Blind SSRF: No response but server makes request → High
- Partial SSRF: Limited to specific protocols/ports → Medium

BYPASS TECHNIQUES:
- IP encoding: 0x7f000001, 2130706433, 0177.0.0.1
- DNS rebinding
- URL encoding
- Redirect chains
- IPv6 addressing: [::1], [0:0:0:0:0:ffff:127.0.0.1]

TARGETS:
- Cloud metadata: 169.254.169.254 (AWS/GCP/Azure)
- Internal services: localhost:6379 (Redis), :9200 (Elasticsearch)
- Internal network scanning: 10.x.x.x, 192.168.x.x
</ssrf_patterns>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return SSRFFinding

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        endpoint_data = kwargs["endpoint_data"]
        return f"""<endpoint_data>
{endpoint_data}
</endpoint_data>

<task>
Analyze these endpoints for SSRF vulnerabilities:
1. Identify parameters that accept URLs or domain names
2. Classify the SSRF type (full, blind, partial)
3. Determine the injection point (url_param, header, body, file_upload)
4. Assess what protocols might be accessible
5. Check for internal network access potential
6. Note any bypass techniques that might be needed
</task>"""


class JWTOAuthDetectionPrompt(PromptTemplate):
    """2.8 - Detect JWT and OAuth vulnerabilities."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a JWT and OAuth security specialist. You identify
vulnerabilities in token-based authentication and authorization
implementations.
</role>

<jwt_vulnerabilities>
ALGORITHM ATTACKS:
- none algorithm acceptance
- HS256/RS256 confusion (using public key as HMAC secret)
- Weak HMAC secrets (brute-forceable)

TOKEN ISSUES:
- Missing expiration (exp claim)
- Long expiration windows
- Missing audience (aud) validation
- Missing issuer (iss) validation
- Token not invalidated on logout/password change
- Sensitive data in payload (not encrypted)

KEY MANAGEMENT:
- JWK/JKWS injection
- Key ID (kid) manipulation (path traversal, SQL injection)
- x5u/x5c header injection
</jwt_vulnerabilities>

<oauth_vulnerabilities>
AUTHORIZATION:
- Missing state parameter (CSRF)
- Open redirect via redirect_uri
- Authorization code reuse
- Scope escalation

TOKEN:
- Token leakage in URL fragments
- Implicit flow token theft
- Refresh token rotation missing
- Token revocation not implemented

CLIENT:
- Client secret exposure
- PKCE not enforced for public clients
</oauth_vulnerabilities>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return JWTOAuthFinding

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        token_data = kwargs["token_data"]
        return f"""<token_analysis_data>
{token_data}
</token_analysis_data>

<task>
Analyze this JWT/OAuth implementation:
1. Identify the token type (JWT, OAuth2 bearer, API key)
2. For JWT: decode header and payload, check algorithm, expiration, claims
3. For OAuth: check authorization flow, state parameter, redirect_uri
4. Identify specific weaknesses and their exploitability
5. Assess the impact of token compromise
</task>"""


class ErrorMessageAnalysisPrompt(PromptTemplate):
    """2.9 - Analyze error messages for information disclosure."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an information disclosure specialist. You analyze error
messages, debug output, and verbose responses to identify
security-relevant information leakage.
</role>

<disclosure_types>
STACK TRACES:
- Framework and language version
- Internal file paths
- Database query structure
- Third-party library versions

DEBUG INFO:
- Debug mode indicators (DEBUG=True, RAILS_ENV=development)
- Verbose error messages with SQL queries
- Memory dumps or variable dumps
- Request/response logging

VERSION LEAKS:
- Server headers (Apache/2.4.41, nginx/1.18.0)
- X-Powered-By headers
- Framework version in HTML comments
- JavaScript library versions in sources

PATH DISCLOSURE:
- Absolute file paths (/var/www/, C:\\inetpub\\)
- Internal hostnames and IPs
- Database connection strings
- Environment variable names

SENSITIVE DATA:
- API keys in error responses
- Internal IP addresses
- Database table/column names
- User data in error contexts
</disclosure_types>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ErrorMessageFinding

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        error_data = kwargs["error_data"]
        return f"""<error_response_data>
{error_data}
</error_response_data>

<task>
Analyze these error responses for information disclosure:
1. Classify the error type (stack_trace, debug_info, version_leak, path_disclosure)
2. List all specific information leaked
3. Assess exploitability (direct, indirect, informational)
4. Determine if the information aids other attacks
5. Rate severity based on the sensitivity of leaked data
</task>"""
