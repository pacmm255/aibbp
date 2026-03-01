"""Phase 4: Attack Chaining prompts.

4.1 - Attack Chain Discovery (Opus)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.schemas import AttackChainResult


class AttackChainDiscoveryPrompt(PromptTemplate):
    """4.1 - Discover chains of vulnerabilities for higher impact.

    Uses Opus (critical tier) because chain discovery requires
    deep reasoning about vulnerability interactions.
    """

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an advanced attack chain specialist. You combine individual
vulnerability findings into multi-step attack chains that demonstrate
higher severity than any single finding alone. This is a critical
skill in bug bounty: a medium IDOR + a medium CORS misconfiguration
can become a critical account takeover chain.
</role>

<chaining_strategies>
INFORMATION → ACCESS:
- Info disclosure reveals internal endpoints → SSRF to access them
- Error messages reveal technology → Use known CVEs
- JS analysis reveals admin endpoint → Auth bypass to reach it

LOW → HIGH ESCALATION:
- Low CORS + Low XSS → Critical account takeover
- Low info disclosure + Medium IDOR → High data breach
- Medium SSRF + Low path traversal → Critical RCE

AUTHENTICATION CHAINS:
- OAuth redirect flaw → Token theft → Account takeover
- JWT weakness + IDOR → Full impersonation
- Session fixation + CSRF → Authenticated actions as victim

DATA EXFILTRATION CHAINS:
- IDOR to enumerate users → CORS to exfiltrate cross-origin
- GraphQL introspection → Batch query for mass data access
- SSRF → Internal API → Sensitive data

PRIVILEGE ESCALATION CHAINS:
- Self-XSS + CSRF → Stored XSS affecting admins
- Mass assignment → Role escalation → Admin access
- Business logic flaw → Payment bypass → Premium features

CHAIN EVALUATION:
- Combined severity should be higher than individual findings
- Each step must have evidence from validated findings
- The chain should be practically exploitable
- Theoretical chains should be marked as "theoretical" likelihood
</chaining_strategies>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return AttackChainResult

    @property
    def model_tier(self) -> TaskTier:
        return "critical"  # Opus for deep reasoning

    def user_template(self, **kwargs: Any) -> str:
        validated_findings = kwargs["validated_findings"]
        target_context = kwargs.get("target_context", "")
        return f"""<validated_findings>
{validated_findings}
</validated_findings>

<target_context>
{target_context}
</target_context>

<task>
Analyze these validated findings for attack chain opportunities:

1. Review all findings and identify natural combinations
2. For each potential chain:
   a. Define the step-by-step attack flow
   b. Specify which validated finding supports each step
   c. Assess combined severity (must be higher than individual)
   d. Calculate a combined CVSS score
   e. Describe the business impact in concrete terms
   f. Rate likelihood (likely, possible, theoretical)

3. Also identify findings that cannot be chained (unchainable_vulns)

IMPORTANT: Only chain findings that have VALIDATED evidence.
Do not create speculative chains from unconfirmed findings.
A chain of validated mediums is worth more than a chain of
unvalidated criticals.
</task>"""
