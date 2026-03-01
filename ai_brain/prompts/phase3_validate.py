"""Phase 3: Validation prompts.

3.1 - False Positive Filter (Sonnet)
3.2 - Differential Analysis (Haiku)
3.3 - Exploitability Assessment (Sonnet)
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.schemas import (
    DifferentialAnalysis,
    ExploitabilityAssessment,
    FalsePositiveFilterResult,
)


class FalsePositiveFilterPrompt(PromptTemplate):
    """3.1 - Filter false positives from vulnerability findings."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a vulnerability validation expert specializing in false
positive identification. You critically assess reported findings
to separate real vulnerabilities from noise.
</role>

<false_positive_indicators>
IDOR FALSE POSITIVES:
- Different responses due to missing data, not missing authorization
- 404 vs 403 distinction (not found != forbidden)
- Public data accessible to all users by design
- Response differences due to caching, not authorization

AUTH FALSE POSITIVES:
- Token validation working correctly but misinterpreted
- Role-based access working as designed
- Redirect-based auth working correctly

CORS FALSE POSITIVES:
- CORS on public APIs (no sensitive data)
- Preflight-only CORS without credential support
- CORS on CDN/static resources

INFORMATION DISCLOSURE FALSE POSITIVES:
- Intentionally public version information
- Generic error messages (no actual data leak)
- Documentation or help text containing technical terms

GENERAL FALSE POSITIVE SIGNALS:
- Finding based on assumptions rather than evidence
- Confidence below 40 from detection phase
- Missing actual impact demonstration
- Expected behavior misidentified as vulnerability
</false_positive_indicators>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return FalsePositiveFilterResult

    @property
    def model_tier(self) -> TaskTier:
        return "complex"  # Needs careful reasoning

    def user_template(self, **kwargs: Any) -> str:
        findings = kwargs["findings"]
        return f"""<vulnerability_findings>
{findings}
</vulnerability_findings>

<task>
Review each vulnerability finding for false positives:
1. Examine the evidence quality for each finding
2. Check for common false positive indicators
3. Assess whether the behavior is actually a vulnerability or expected
4. Adjust confidence scores based on evidence strength
5. List any additional evidence needed to confirm/deny

For each finding, provide:
- is_false_positive: true/false
- fp_reason: Why you believe it's a false positive (if applicable)
- adjusted_confidence: New confidence score (0-100)
- additional_evidence_needed: What else would confirm/deny this
</task>"""


class DifferentialAnalysisPrompt(PromptTemplate):
    """3.2 - Compare baseline vs attack responses for validation."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a differential analysis specialist. You compare normal
(baseline) application behavior with attack behavior to validate
vulnerability findings through observable differences.
</role>

<analysis_methodology>
COMPARISON POINTS:
- HTTP status codes (200 vs 403 vs 500)
- Response body length differences
- Response body content differences
- Response headers differences
- Response timing differences
- Error messages vs success messages
- Data presence vs absence

MEANINGFUL vs NOISE:
MEANINGFUL DIFFERENCES:
- Different data returned for different user contexts
- Error code changes suggesting injection worked
- Response size changes indicating data leakage
- New headers appearing (CORS, auth)
- Redirect behavior changes

NOISE (NOT MEANINGFUL):
- CSRF token changes (expected)
- Timestamp differences (expected)
- Request ID changes (expected)
- Minor formatting differences
- Cache header differences
</analysis_methodology>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return DifferentialAnalysis

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        baseline = kwargs["baseline"]
        attack = kwargs["attack"]
        vuln_type = kwargs.get("vuln_type", "unknown")
        return f"""<differential_data>
<vulnerability_type>{vuln_type}</vulnerability_type>

<baseline_response>
{baseline}
</baseline_response>

<attack_response>
{attack}
</attack_response>
</differential_data>

<task>
Compare the baseline and attack responses:
1. Identify all differences between baseline and attack
2. Classify each difference as meaningful or noise
3. Assess whether the differences indicate a real vulnerability
4. Rate evidence quality (strong, moderate, weak, inconclusive)
5. Determine if the target is_vulnerable based on the analysis
</task>"""


class ExploitabilityAssessmentPrompt(PromptTemplate):
    """3.3 - Assess real-world exploitability of validated findings."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an exploitability assessment expert. You evaluate validated
vulnerability findings to determine their real-world impact and
exploitation feasibility for bug bounty reporting.
</role>

<assessment_criteria>
EXPLOIT COMPLEXITY:
- Low: Single request, no special conditions
- Medium: Multiple steps, some prerequisites
- High: Requires specific conditions, chaining, or timing

PREREQUISITES:
- Authenticated vs unauthenticated access
- Specific user role required
- Network position requirements
- Browser/client requirements
- Timing or race condition requirements

REAL-WORLD IMPACT:
- Data confidentiality: What data can be accessed?
- Data integrity: What data can be modified?
- Availability: Can service be disrupted?
- Account takeover potential
- Financial impact
- Compliance implications (PII exposure)

PROOF OF CONCEPT:
- Can a working PoC be demonstrated?
- What are the exact steps?
- Is it reproducible?
- What tools are needed?
</assessment_criteria>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return ExploitabilityAssessment

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        finding = kwargs["finding"]
        validation_data = kwargs.get("validation_data", "")
        return f"""<validated_finding>
{finding}
</validated_finding>

<validation_evidence>
{validation_data}
</validation_evidence>

<task>
Assess the exploitability of this validated vulnerability:
1. Determine exploit complexity (low, medium, high)
2. List all prerequisites for exploitation
3. Describe the real-world impact in concrete terms
4. Provide step-by-step proof of concept
5. Assess if this is reportable as a bug bounty finding

A finding is reportable if it has:
- Clear evidence of the vulnerability
- Demonstrable impact
- Reproducible steps
</task>"""
