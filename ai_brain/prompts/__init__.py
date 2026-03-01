"""AI Brain prompt templates.

Complete library of 30+ prompt templates covering all phases:
- Phase 0: Program analysis (scope, prioritization)
- Phase 1: Reconnaissance (subdomain, JS, API, correlation, wordlist)
- Phase 2: Vulnerability detection (IDOR, auth, business logic, CORS, etc.)
- Phase 3: Validation (false positive filter, differential, exploitability)
- Phase 4: Attack chain discovery
- Phase 5: Reporting (HackerOne reports, CVSS scoring)
- Phase 6: Strategy (continue vs move on)
- Active: Orchestration, recon, auth, injection, business logic, validation, reporting
"""

from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate
from ai_brain.prompts.phase0_program import (
    ProgramScopeAnalysisPrompt,
    TargetPrioritizationPrompt,
)
from ai_brain.prompts.phase1_recon import (
    APISwaggerAnalysisPrompt,
    CustomWordlistPrompt,
    JSAnalysisPrompt,
    ReconCorrelationPrompt,
    SubdomainClassificationPrompt,
)
from ai_brain.prompts.phase2_vuln import (
    AuthFlowAnalysisPrompt,
    BusinessLogicDetectionPrompt,
    CORSDetectionPrompt,
    ErrorMessageAnalysisPrompt,
    GraphQLDetectionPrompt,
    IDORDetectionPrompt,
    JWTOAuthDetectionPrompt,
    MassAssignmentDetectionPrompt,
    SSRFDetectionPrompt,
)
from ai_brain.prompts.phase3_validate import (
    DifferentialAnalysisPrompt,
    ExploitabilityAssessmentPrompt,
    FalsePositiveFilterPrompt,
)
from ai_brain.prompts.phase4_chain import AttackChainDiscoveryPrompt
from ai_brain.prompts.phase5_report import (
    CVSSScoringPrompt,
    ReportGenerationPrompt,
)
from ai_brain.prompts.phase6_strategy import ContinueVsMoveOnPrompt

# Active testing prompts
from ai_brain.prompts.active_auth import (
    ActiveAccountStrategyPrompt,
    ActiveAuthFlowAnalysisPrompt,
)
from ai_brain.prompts.active_business_logic import (
    ActiveBusinessExploitDesignPrompt,
    ActiveStateAnalysisPrompt,
    ActiveWorkflowMappingPrompt,
)
from ai_brain.prompts.active_injection import (
    ActiveInjectionAnalysisPrompt,
    ActivePayloadSelectionPrompt,
)
from ai_brain.prompts.active_orchestrator import (
    ActiveNextStepPrompt,
    ActiveTestPlanningPrompt,
)
from ai_brain.prompts.active_recon import (
    ActiveInteractionPointDiscoveryPrompt,
    ActiveSurfaceMappingPrompt,
)
from ai_brain.prompts.active_report import ActiveFindingReportPrompt
from ai_brain.prompts.active_validate import (
    ActiveFindingVerificationPrompt,
    ActivePoCGenerationPrompt,
)

__all__ = [
    "ANTI_HALLUCINATION_CLAUSE",
    "PromptTemplate",
    # Phase 0
    "ProgramScopeAnalysisPrompt",
    "TargetPrioritizationPrompt",
    # Phase 1
    "SubdomainClassificationPrompt",
    "JSAnalysisPrompt",
    "APISwaggerAnalysisPrompt",
    "ReconCorrelationPrompt",
    "CustomWordlistPrompt",
    # Phase 2
    "IDORDetectionPrompt",
    "AuthFlowAnalysisPrompt",
    "BusinessLogicDetectionPrompt",
    "CORSDetectionPrompt",
    "GraphQLDetectionPrompt",
    "MassAssignmentDetectionPrompt",
    "SSRFDetectionPrompt",
    "JWTOAuthDetectionPrompt",
    "ErrorMessageAnalysisPrompt",
    # Phase 3
    "FalsePositiveFilterPrompt",
    "DifferentialAnalysisPrompt",
    "ExploitabilityAssessmentPrompt",
    # Phase 4
    "AttackChainDiscoveryPrompt",
    # Phase 5
    "ReportGenerationPrompt",
    "CVSSScoringPrompt",
    # Phase 6
    "ContinueVsMoveOnPrompt",
    # Active testing
    "ActiveTestPlanningPrompt",
    "ActiveNextStepPrompt",
    "ActiveSurfaceMappingPrompt",
    "ActiveInteractionPointDiscoveryPrompt",
    "ActiveAuthFlowAnalysisPrompt",
    "ActiveAccountStrategyPrompt",
    "ActiveInjectionAnalysisPrompt",
    "ActivePayloadSelectionPrompt",
    "ActiveWorkflowMappingPrompt",
    "ActiveStateAnalysisPrompt",
    "ActiveBusinessExploitDesignPrompt",
    "ActiveFindingVerificationPrompt",
    "ActivePoCGenerationPrompt",
    "ActiveFindingReportPrompt",
]
