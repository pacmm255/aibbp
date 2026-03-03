"""Configuration for the AI Brain using Pydantic Settings."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class ModelConfig(BaseSettings):
    """Claude model IDs for each tier."""

    routine: str = "claude-haiku-4-5"  # compression, vision
    complex: str = "claude-sonnet-4-5"  # worker brain (routine pentesting turns)
    critical: str = "claude-opus-4-6"  # manager brain (strategy, validation, pivots)


class APIRateLimits(BaseSettings):
    """Anthropic API rate limits."""

    requests_per_minute: int = 50
    input_tokens_per_minute: int = 100_000
    max_retries: int = 3
    base_retry_delay: float = 1.0


class BudgetConfig(BaseSettings):
    """Token budget configuration."""

    total_dollars: float = 50.0
    emergency_reserve_pct: int = 15
    per_target_max_dollars: float = 10.0

    # Phase allocation percentages
    phase_program_analysis: int = 5
    phase_recon: int = 25
    phase_vuln_detection: int = 35
    phase_validation: int = 15
    phase_chain_discovery: int = 8
    phase_reporting: int = 7
    phase_strategy: int = 5

    # Pricing per 1M tokens
    haiku_input: float = 1.0
    haiku_output: float = 5.0
    sonnet_input: float = 3.0
    sonnet_output: float = 15.0
    opus_input: float = 5.0
    opus_output: float = 25.0
    cache_read_multiplier: float = 0.1


class NATSConfig(BaseSettings):
    """NATS connection settings."""

    url: str = "nats://localhost:4222"
    max_reconnect: int = 60
    reconnect_wait: int = 2


class DatabaseConfig(BaseSettings):
    """PostgreSQL connection settings."""

    host: str = "localhost"
    port: int = 5432
    name: str = "aibbp"
    user: str = "aibbp"
    password: str = "aibbp_dev"

    @property
    def dsn(self) -> str:
        return f"postgresql://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"

    @property
    def async_dsn(self) -> str:
        return f"postgresql+asyncpg://{self.user}:{self.password}@{self.host}:{self.port}/{self.name}"


class ActiveTestingConfig(BaseSettings):
    """Active testing engine configuration."""

    enabled: bool = False
    browser_headless: bool = True
    proxy_port: int = 8085
    email_domain: str = "inbox.lt"
    email_mode: str = "imap"  # "local" (aiosmtpd) or "imap"
    imap_host: str = "mail.inbox.lt"
    imap_user: str = "hunter255@inbox.lt"
    imap_password: str = "7J8PbJbSs6"
    max_accounts: int = 5
    request_delay_ms: int = 1000  # Delay between browser actions (1s to avoid WAF)
    max_requests_per_target: int = 5000
    kill_switch_check_interval: int = 10  # seconds
    dry_run: bool = False
    sqlmap_api_url: str = "http://localhost:8775"
    tools_timeout: int = 600  # seconds per tool invocation
    max_crawl_depth: int = 5
    max_crawl_pages: int = 200
    screenshot_on_action: bool = False
    email_plus_addressing: bool = False  # Disabled: always use imap_user directly
    redis_url: str = "redis://localhost:6382"
    captcha_api_key: str = ""  # 2captcha.com API key for reCAPTCHA/hCaptcha/Turnstile
    captcha_api_url: str = "https://2captcha.com"  # or rucaptcha.com, capsolver.com
    upstream_proxy: str = ""  # External SOCKS5/HTTP proxy (e.g. socks5://127.0.0.1:9054)


class AIBrainConfig(BaseSettings):
    """Root configuration for the AI Brain."""

    model_config_dict: dict = {"env_prefix": "AIBBP_"}

    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    anthropic_auth_token: str = Field(default="", alias="ANTHROPIC_AUTH_TOKEN")
    demo_mode: bool = False

    models: ModelConfig = ModelConfig()
    rate_limits: APIRateLimits = APIRateLimits()
    budget: BudgetConfig = BudgetConfig()
    nats: NATSConfig = NATSConfig()
    database: DatabaseConfig = DatabaseConfig()
    active_testing: ActiveTestingConfig = ActiveTestingConfig()

    # Defaults
    default_temperature: float = 0.0
    wordlist_temperature: float = 0.2
    default_max_tokens: int = 8192
    thinking_type: str = "adaptive"

    # Run settings
    max_duration_hours: int = 12
    checkpoint_interval_seconds: int = 30
    concurrent_solvers: int = 2
