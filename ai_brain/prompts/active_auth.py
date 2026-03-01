"""Active auth flow prompts.

4. ActiveAuthDiscovery (Haiku) — discover auth endpoints via AI
5. ActiveAuthFlowAnalysis (Sonnet) — analyze registration/login pages
6. ActiveAccountStrategy (Sonnet) — plan which accounts to create
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from ai_brain.active_schemas import AuthFlowResult, TestAccount
from ai_brain.models import TaskTier
from ai_brain.prompts.base import ANTI_HALLUCINATION_CLAUSE, PromptTemplate


class AuthDiscoveryResult(BaseModel):
    """Discovered auth endpoint URLs from page analysis."""

    login_url: str = Field(default="", description="Full URL of the login page")
    register_url: str = Field(default="", description="Full URL of the registration page")
    password_reset_url: str = Field(default="", description="Full URL of the password reset page")
    other_auth_urls: list[str] = Field(default_factory=list, description="Other auth-related URLs found")
    notes: str = ""


class ActiveAuthDiscoveryPrompt(PromptTemplate):
    """Discover auth endpoints (login, register, password reset) from page content.

    Uses AI to intelligently find auth-related links and buttons in any language,
    instead of relying on hardcoded keyword lists.
    """

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are a web application analyst. Your task is to find authentication-related
URLs on a web page: login, registration/signup, and password reset pages.
</role>

<discovery_rules>
- Analyze ALL links, buttons, and navigation elements on the page
- Look for auth-related text in ANY language (English, Persian/Farsi, Arabic, etc.)
- Common patterns to look for:
  * Login/Sign in: "login", "sign in", "log in", "ورود", "تسجيل دخول", "connexion", "anmelden"
  * Register/Sign up: "register", "sign up", "create account", "ثبت نام", "إنشاء حساب"
  * Password reset: "forgot password", "reset password", "بازیابی رمز", "نسيت كلمة المرور"
- Check both visible link text AND href URL patterns
- Auth links are typically in: header/nav, top-right corner, or prominent page sections
- If a page has a password field in a form, it's likely a login or register page
- Return full absolute URLs (with https://), not relative paths
- If you're not sure about a URL, include it in other_auth_urls
- Return empty string "" for any endpoint not found — do NOT guess or hallucinate
</discovery_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return AuthDiscoveryResult

    @property
    def model_tier(self) -> TaskTier:
        return "routine"

    def user_template(self, **kwargs: Any) -> str:
        page_url = kwargs.get("page_url", "")
        links = kwargs.get("links", "[]")
        buttons = kwargs.get("buttons", "[]")
        forms = kwargs.get("forms", "[]")
        text_snippet = kwargs.get("text_snippet", "")
        return f"""<current_page_url>{page_url}</current_page_url>

<page_links>
{links}
</page_links>

<page_buttons>
{buttons}
</page_buttons>

<page_forms>
{forms}
</page_forms>

<visible_text_snippet>
{text_snippet}
</visible_text_snippet>

Find all authentication-related URLs on this page: login, registration/signup,
and password reset. Return full absolute URLs. Return empty string if not found."""


class AccountStrategyResult(BaseModel):
    """Recommended accounts and privilege escalation test plan."""

    accounts_to_create: list[dict[str, str]] = Field(default_factory=list)
    privilege_escalation_tests: list[str] = Field(default_factory=list)
    session_tests: list[str] = Field(default_factory=list)
    mfa_bypass_possible: bool = False
    notes: str = ""


class ActiveAuthFlowAnalysisPrompt(PromptTemplate):
    """Analyze auth pages and observed traffic to plan account creation."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an authentication and session management specialist. You analyze
login/registration pages and auth traffic to understand how the application
handles authentication, and you create test accounts via browser automation.
</role>

<auth_analysis_rules>
- Identify the login mechanism: form-based, API-based, OAuth/SSO, magic link
- Determine session mechanism: cookies, JWT, bearer tokens, API keys
- Note MFA requirements and types (email, SMS, TOTP, hardware keys)
- Map the registration flow step by step (form fields, email verification, etc.)
- Identify password policies (length, complexity, common password blocking)
- Note CSRF protection mechanisms (tokens, referer checks)
- Check for rate limiting on login endpoints
- Flag session management issues: predictable tokens, missing secure/httponly flags
- Provide exact browser automation steps to create an account
</auth_analysis_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return AuthFlowResult

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        login_page = kwargs.get("login_page", "{}")
        register_page = kwargs.get("register_page", "{}")
        auth_traffic = kwargs.get("auth_traffic", "[]")
        cookies = kwargs.get("cookies", "[]")
        return f"""<login_page_info>
{login_page}
</login_page_info>

<registration_page_info>
{register_page}
</registration_page_info>

<observed_auth_traffic>
{auth_traffic}
</observed_auth_traffic>

<cookies_observed>
{cookies}
</cookies_observed>

Analyze the authentication flow. Determine the exact steps needed to create
a test account and log in. Identify session mechanism and security controls."""


class ActiveAccountStrategyPrompt(PromptTemplate):
    """Plan which accounts to create and what privilege escalation to test."""

    @property
    def system_prompt(self) -> str:
        return f"""<role>
You are an access control testing specialist. You plan which accounts to create
and what privilege escalation attacks to test based on discovered roles and
endpoints.
</role>

<strategy_rules>
- Always create at least 2 regular user accounts (for IDOR testing: A accesses B's resources)
- If admin endpoints discovered, attempt admin account creation or role escalation
- Test horizontal privilege escalation: user A accessing user B's data
- Test vertical privilege escalation: user accessing admin endpoints
- Plan session tests: fixation, token reuse, concurrent sessions, logout effectiveness
- Consider MFA bypass if MFA is present but might be flawed
- Minimize account creation — only create accounts needed for testing
</strategy_rules>

{ANTI_HALLUCINATION_CLAUSE}"""

    @property
    def output_schema(self) -> type[BaseModel]:
        return AccountStrategyResult

    @property
    def model_tier(self) -> TaskTier:
        return "complex"

    def user_template(self, **kwargs: Any) -> str:
        existing_accounts = kwargs.get("existing_accounts", "[]")
        roles_discovered = kwargs.get("roles_discovered", "[]")
        auth_endpoints = kwargs.get("auth_endpoints", "[]")
        admin_endpoints = kwargs.get("admin_endpoints", "[]")
        return f"""<existing_accounts>
{existing_accounts}
</existing_accounts>

<roles_discovered>
{roles_discovered}
</roles_discovered>

<auth_required_endpoints>
{auth_endpoints}
</auth_required_endpoints>

<admin_endpoints>
{admin_endpoints}
</admin_endpoints>

Plan which accounts to create and what privilege escalation tests to run.
Minimize the number of accounts while maximizing test coverage."""
