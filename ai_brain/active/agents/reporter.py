"""Active reporting agent.

Takes verified findings and generates HackerOne-format reports
with CVSS scoring.
"""

from __future__ import annotations

import json
from typing import Any

import structlog

from ai_brain.active.agents.base import BaseActiveAgent
from ai_brain.active_schemas import ActiveTestReport, ActiveValidationResult
from ai_brain.prompts.active_report import ActiveFindingReportPrompt

logger = structlog.get_logger()


class ActiveReporterAgent(BaseActiveAgent):
    """Generates professional vulnerability reports from verified findings."""

    @property
    def agent_type(self) -> str:
        return "reporter"

    # Severity downgrade map for BLOCKED_BY_SECURITY verdicts
    _SEVERITY_DOWNGRADE = {
        "critical": "high",
        "high": "medium",
        "medium": "low",
        "low": "info",
        "info": "info",
    }

    async def execute(self, state: dict[str, Any]) -> dict[str, Any]:
        target_url = state["target_url"]
        validated: list[ActiveValidationResult] = state.get("validated_findings", [])
        reports: list[ActiveTestReport] = []
        errors: list[str] = []

        # Filter by verdict: only EXPLOITED and BLOCKED_BY_SECURITY are reportable
        # Backward compat: also include verified=True without a verdict field
        reportable = []
        for v in validated:
            verdict = getattr(v, "verdict", None)
            if verdict in ("EXPLOITED", "BLOCKED_BY_SECURITY"):
                reportable.append(v)
            elif verdict is None and getattr(v, "verified", False):
                reportable.append(v)

        if not reportable:
            return {"reports": [], "errors": ["No reportable findings (all FALSE_POSITIVE or OUT_OF_SCOPE)"]}

        for validation in reportable:
            self._check_kill_switch()

            try:
                report: ActiveTestReport = await self._call_claude(
                    ActiveFindingReportPrompt(),
                    target=target_url,
                    finding=json.dumps(validation.model_dump(), default=str)[:5000],
                    poc=validation.poc_code[:3000] if validation.poc_code else "",
                    evidence=(
                        validation.verification_evidence
                        or validation.original_evidence
                        or ""
                    )[:3000],
                    target_info=target_url,
                )

                # Downgrade severity for BLOCKED_BY_SECURITY findings
                if getattr(validation, "verdict", None) == "BLOCKED_BY_SECURITY":
                    original_sev = report.severity
                    report.severity = self._SEVERITY_DOWNGRADE.get(report.severity, report.severity)
                    if report.severity != original_sev:
                        report.description += (
                            f"\n\nNote: Severity downgraded from {original_sev} to "
                            f"{report.severity} because exploitation is blocked by "
                            f"{validation.blocked_by or 'a security control'}."
                        )

                reports.append(report)

            except Exception as e:
                error_msg = f"Report generation failed for {validation.finding_id}: {e}"
                logger.warning("report_error", error=error_msg)
                errors.append(error_msg)

        self._log_step(
            "generate_reports",
            input_data={"reportable_findings": len(reportable)},
            output_data={"reports_generated": len(reports)},
        )

        return {"reports": reports, "errors": errors}
