"""Active testing engine for autonomous web application security testing.

This package provides the "hands" that let the AI brain actively interact
with live web applications — browsing, clicking, registering, testing, and
writing exploits like a senior bug bounty hunter.
"""

from ai_brain.active.scope_guard import ActiveScopeGuard
from ai_brain.active.kill_switch import KillSwitch

__all__ = ["ActiveScopeGuard", "KillSwitch"]
