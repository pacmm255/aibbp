"""Phase 5: Reporting prompts.

5.1 - Report Generation (Opus)
5.2 - CVSS Scoring (Sonnet)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.schemas import CVSSScore, VulnReport


class ReportGenerationPrompt(PromptTemplate):
    """5.1 - Generate HackerOne-ready vulnerability report.

    Uses Opus (critical tier) because reports must be precise,
    well-structured, and convincing for triagers.
    """

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an expert bug bounty report writer. You produce
HackerOne/Bugcrowd-ready vulnerability reports that maximize
acceptance rates and bounty payouts. Your reports are clear,
evidence-based, and follow platform best practices.
</role>

<report_structure>
TITLE:
- Clear, specific, actionable
- Format: "[Vuln Type] in [Component] allows [Impact]"
- Example: "IDOR in /api/users/:id allows accessing other users' PII"

SEVERITY:
- Based on real impact, not theoretical maximum
- Matches CVSS score assessment

WEAKNESS TYPE:
- CWE identifier (CWE-639 for IDOR, CWE-287 for auth bypass, etc.)

SUMMARY:
- 2-3 sentences explaining the vulnerability
- What it is, where it is, what an attacker can do

DESCRIPTION:
- Technical details of the vulnerability
- Root cause analysis
- Affected components and endpoints
- Attack vector explanation

STEPS TO REPRODUCE:
- Numbered steps anyone can follow
- Include exact URLs, headers, parameters
- Include curl commands or browser steps
- Must be 100% reproducible

IMPACT:
- Concrete business impact
- What data is exposed or what actions are possible
- Number of affected users if estimable
- Compliance implications (GDPR, PCI-DSS)

REMEDIATION:
- Specific fix recommendations
- Code-level suggestions where possible
- Industry best practices reference

SUPPORTING MATERIAL:
- Screenshots, request/response captures
- PoC scripts or commands
</report_structure>

<quality_standards>
- Every claim must be backed by evidence
- Steps must be reproducible by a triager
- Impact must be realistic, not exaggerated
- Remediation must be actionable
- Avoid jargon; be clear and precise
</quality_standards>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return VulnReport

    @property
    def model_tier(self) -> TaskTier:
        return "critical"  # Opus for high-quality reports

    def user_template(self, **kwargs: Any) -> str:
        finding = kwargs["finding"]
        evidence = kwargs.get("evidence", "")
        cvss = kwargs.get("cvss", "")
        return f"""<validated_finding>
{finding}
</validated_finding>

<evidence>
{evidence}
</evidence>

<cvss_assessment>
{cvss}
</cvss_assessment>

<task>
Generate a HackerOne-ready vulnerability report for this finding:

1. Write a clear, specific title
2. Assign severity based on evidence
3. Identify the CWE weakness type
4. Write a concise summary
5. Provide detailed technical description
6. Write step-by-step reproduction instructions (must be copy-pasteable)
7. Describe concrete business impact
8. Provide specific remediation steps
9. List supporting material references

The report should be ready to submit directly to a bug bounty platform.
A triager should be able to reproduce the issue in under 5 minutes
by following your steps.
</task>"""


class CVSSScoringPrompt(PromptTemplate):
    """5.2 - Calculate CVSS v3.1 score for a vulnerability."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a CVSS v3.1 scoring specialist. You calculate accurate
CVSS scores based on vulnerability characteristics, ensuring
scores match the evidence provided.
</role>

<cvss_v31_metrics>
ATTACK VECTOR (AV):
- Network (N): Remotely exploitable
- Adjacent (A): Requires adjacent network
- Local (L): Requires local access
- Physical (P): Requires physical access

ATTACK COMPLEXITY (AC):
- Low (L): No special conditions needed
- High (H): Requires specific conditions/preparation

PRIVILEGES REQUIRED (PR):
- None (N): No authentication needed
- Low (L): Basic user privileges
- High (H): Admin/elevated privileges

USER INTERACTION (UI):
- None (N): No user interaction needed
- Required (R): Requires user action (clicking link, etc.)

SCOPE (S):
- Unchanged (U): Vuln only affects the vulnerable component
- Changed (C): Vuln impacts resources beyond its scope

CONFIDENTIALITY (C):
- None (N): No confidentiality impact
- Low (L): Limited data exposure
- High (H): Total information disclosure

INTEGRITY (I):
- None (N): No integrity impact
- Low (L): Limited data modification
- High (H): Total data modification possible

AVAILABILITY (A):
- None (N): No availability impact
- Low (L): Degraded performance
- High (H): Total denial of service
</cvss_v31_metrics>

<scoring_guidelines>
- Be conservative: score based on demonstrated impact, not theoretical
- IDOR to other users' data: typically 6.5-7.5 (High)
- Auth bypass: typically 8.0-9.8 (Critical) depending on scope
- CORS with credentials: typically 5.0-7.0 (Medium-High)
- Information disclosure: typically 3.0-5.0 (Low-Medium)
- Business logic: varies widely based on impact
</scoring_guidelines>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return CVSSScore

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        finding = kwargs["finding"]
        return f"""<vulnerability_finding>
{finding}
</vulnerability_finding>

<task>
Calculate the CVSS v3.1 score for this vulnerability:

1. Evaluate each metric (AV, AC, PR, UI, S, C, I, A)
2. Justify each metric choice with specific evidence
3. Calculate the final score
4. Generate the CVSS vector string
5. Map score to severity (None/Low/Medium/High/Critical)

Be conservative: base scoring on demonstrated evidence,
not theoretical maximum impact.
</task>"""
