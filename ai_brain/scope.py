"""Deterministic scope enforcer - NOT LLM-based.

All scope decisions use compiled regex, ipaddress stdlib, and domain matching.
No AI is involved in scope enforcement to prevent prompt injection attacks.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlparse


class ScopeViolation(Exception):
    """Raised when an action would go out of scope."""

    def __init__(self, message: str, action: str = "", target: str = ""):
        self.action = action
        self.target = target
        super().__init__(message)


@dataclass
class ScopeEnforcer:
    """Deterministic scope validation for all scanning actions.

    This is the safety layer that prevents the AI brain from:
    - Scanning out-of-scope domains/IPs
    - Executing destructive payloads
    - Accessing prohibited ports
    - Making requests to internal networks
    """

    allowed_domains: list[str] = field(default_factory=list)
    allowed_cidrs: list[str] = field(default_factory=list)
    out_of_scope_domains: list[str] = field(default_factory=list)
    allowed_ports: set[int] = field(default_factory=lambda: set(range(1, 65536)))
    max_rps: int = 10

    # Compiled patterns for destructive payloads
    _blocked_patterns: list[re.Pattern[str]] = field(init=False, repr=False)
    _allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(
        init=False, repr=False
    )

    # Internal/private ranges that should never be targeted
    _PRIVATE_RANGES = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
    ]

    def __post_init__(self) -> None:
        # Compile destructive payload patterns
        self._blocked_patterns = [
            re.compile(p, re.IGNORECASE)
            for p in [
                r"rm\s+-rf",
                r"shutdown",
                r"reboot",
                r"mkfs",
                r"dd\s+if=",
                r":(){ :\|:& };:",  # Fork bomb
                r"DROP\s+TABLE",
                r"DROP\s+DATABASE",
                r"DELETE\s+FROM\s+\w+\s*;?\s*$",  # DELETE without WHERE
                r"TRUNCATE\s+TABLE",
                r"UPDATE\s+\w+\s+SET\s+.*;\s*$",  # UPDATE without WHERE
                r">\s*/dev/sd",
                r"format\s+[a-z]:",
                r"net\s+stop",
                r"taskkill\s+/f",
                r"wget.*\|\s*sh",
                r"curl.*\|\s*sh",
                r"curl.*\|\s*bash",
                r"python.*-c.*import\s+os.*system",
                r"eval\s*\(",
                r"exec\s*\(",
                r"__import__",
            ]
        ]

        # Parse allowed CIDRs
        self._allowed_networks = []
        for cidr in self.allowed_cidrs:
            try:
                self._allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError:
                pass

    def validate_action(self, action: str, target: str, payload: str = "") -> None:
        """Validate a scanning action before execution.

        Args:
            action: The type of action (scan, request, fuzz, etc.)
            target: The target URL, domain, or IP
            payload: Optional payload being sent

        Raises:
            ScopeViolation: If the action would violate scope.
        """
        self._validate_target(target)
        if payload:
            self._validate_payload(payload)

    def _validate_target(self, target: str) -> None:
        """Validate that a target is in scope."""
        if not target:
            raise ScopeViolation("Empty target", target=target)

        # Parse URL if provided
        parsed = urlparse(target)
        hostname = parsed.hostname or target
        hostname = hostname.lower().strip(".")

        # Check if it's an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            self._validate_ip(ip, target)
            return
        except ValueError:
            pass

        # Domain validation
        self._validate_domain(hostname, target)

        # Port validation
        if parsed.port:
            self._validate_port(parsed.port, target)

    def _validate_domain(self, hostname: str, original_target: str) -> None:
        """Check domain against allowed/blocked lists."""
        # Check out-of-scope first (explicit deny)
        for oos in self.out_of_scope_domains:
            oos = oos.lower().strip(".")
            if hostname == oos or hostname.endswith("." + oos):
                raise ScopeViolation(
                    f"Domain {hostname} is explicitly out of scope",
                    target=original_target,
                )

        # If no allowed domains configured, allow all (open scope)
        if not self.allowed_domains:
            return

        # Check allowed domains (wildcard support)
        for allowed in self.allowed_domains:
            allowed = allowed.lower().strip(".")

            # Wildcard: *.example.com matches sub.example.com
            if allowed.startswith("*."):
                base = allowed[2:]
                if hostname == base or hostname.endswith("." + base):
                    return
            elif hostname == allowed or hostname.endswith("." + allowed):
                # Match exact domain AND subdomains (e.g., "robinhood.com"
                # matches both "robinhood.com" and "api.robinhood.com")
                return

        raise ScopeViolation(
            f"Domain {hostname} is not in scope. Allowed: {self.allowed_domains}",
            target=original_target,
        )

    def _validate_ip(
        self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address, target: str
    ) -> None:
        """Check IP against allowed CIDRs and block private ranges."""
        # Always block private/internal ranges
        for private_cidr in self._PRIVATE_RANGES:
            network = ipaddress.ip_network(private_cidr, strict=False)
            if ip in network:
                raise ScopeViolation(
                    f"IP {ip} is in a private/internal range ({private_cidr})",
                    target=target,
                )

        # If allowed CIDRs configured, check membership
        if self._allowed_networks:
            for network in self._allowed_networks:
                if ip in network:
                    return
            raise ScopeViolation(
                f"IP {ip} is not in any allowed CIDR range",
                target=target,
            )

    def _validate_port(self, port: int, target: str) -> None:
        """Validate port is in allowed range."""
        if port not in self.allowed_ports:
            raise ScopeViolation(
                f"Port {port} is not in allowed ports",
                target=target,
            )

    def _validate_payload(self, payload: str) -> None:
        """Check payload for destructive patterns."""
        for pattern in self._blocked_patterns:
            if pattern.search(payload):
                raise ScopeViolation(
                    f"Payload contains blocked pattern: {pattern.pattern}",
                    action="payload_check",
                    target=payload[:100],
                )

    def validate_command(self, command: str) -> None:
        """Validate a shell command before execution."""
        self._validate_payload(command)
