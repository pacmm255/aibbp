"""Passive subdomain enumeration inspired by ReconEngine's GetSubDomains().

Uses multiple sources (subfinder + crt.sh API) to discover subdomains.
NO port scanning -- only passive enumeration and DNS resolution.

Available tools: subfinder, dig, curl
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import structlog

from ai_brain.active.scope_guard import ActiveScopeGuard

logger = structlog.get_logger()

# Hard cap on returned subdomains to avoid blowup on large targets.
_MAX_SUBDOMAINS = 500

# Timeout for individual DNS resolution per domain (seconds).
_DIG_TIMEOUT = 10


class SubdomainEnumerator:
    """Passive subdomain enumeration using subfinder + crt.sh.

    Replicates ReconEngine's key passive recon patterns using CLI tools
    available on this system. Zero port scanning -- only passive enumeration
    and DNS A-record resolution.
    """

    def __init__(
        self,
        scope_guard: ActiveScopeGuard | None,
        timeout: int = 120,
    ) -> None:
        self._scope_guard = scope_guard
        self._timeout = timeout

    # ── Public API ────────────────────────────────────────────────

    async def enumerate(self, domain: str) -> dict[str, Any]:
        """Run all passive subdomain sources, deduplicate, return results.

        Returns:
            {subdomains: [...], sources: {source: [subs]}, count: N}
        """
        self._validate_domain(domain)

        # Run sources concurrently
        subfinder_task = asyncio.create_task(self._run_subfinder(domain))
        crtsh_task = asyncio.create_task(self._query_crtsh(domain))

        subfinder_results = await subfinder_task
        crtsh_results = await crtsh_task

        # Deduplicate across all sources
        all_subs: set[str] = set()
        sources: dict[str, list[str]] = {}

        if subfinder_results:
            sources["subfinder"] = sorted(subfinder_results)
            all_subs |= subfinder_results
        if crtsh_results:
            sources["crt.sh"] = sorted(crtsh_results)
            all_subs |= crtsh_results

        # Filter to in-scope subdomains and cap
        filtered = self._filter_scope(sorted(all_subs))[:_MAX_SUBDOMAINS]

        logger.info(
            "subdomain_enumeration_complete",
            domain=domain,
            total=len(filtered),
            sources={k: len(v) for k, v in sources.items()},
        )

        return {
            "subdomains": filtered,
            "sources": {k: v[:100] for k, v in sources.items()},
            "count": len(filtered),
        }

    async def resolve_domains(self, subdomains: list[str]) -> dict[str, Any]:
        """DNS A-record resolution using dig. No port scanning.

        Args:
            subdomains: List of subdomains to resolve (capped at 100).

        Returns:
            {resolved: {sub: [ips]}, unresolved: [...], count: N}
        """
        capped = subdomains[:100]
        resolved: dict[str, list[str]] = {}
        unresolved: list[str] = []

        # Resolve in batches of 20 to avoid overwhelming DNS
        batch_size = 20
        for i in range(0, len(capped), batch_size):
            batch = capped[i : i + batch_size]
            tasks = [self._dig_resolve(sub) for sub in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for sub, result in zip(batch, results):
                if isinstance(result, Exception):
                    unresolved.append(sub)
                elif result:
                    resolved[sub] = result
                else:
                    unresolved.append(sub)

        logger.info(
            "dns_resolution_complete",
            resolved=len(resolved),
            unresolved=len(unresolved),
        )

        return {
            "resolved": resolved,
            "unresolved": unresolved,
            "resolved_count": len(resolved),
            "unresolved_count": len(unresolved),
        }

    # ── Private: Sources ──────────────────────────────────────────

    async def _run_subfinder(self, domain: str) -> set[str]:
        """Run subfinder with -silent flag, parse line-delimited output."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "subfinder", "-d", domain, "-silent", "-timeout", str(self._timeout),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self._timeout + 10,
            )

            if proc.returncode != 0:
                logger.warning(
                    "subfinder_error",
                    returncode=proc.returncode,
                    stderr=stderr.decode(errors="replace")[:500],
                )

            subs: set[str] = set()
            for line in stdout.decode(errors="replace").splitlines():
                cleaned = line.strip().lower()
                if cleaned and "." in cleaned:
                    subs.add(cleaned)

            logger.info("subfinder_complete", domain=domain, found=len(subs))
            return subs

        except asyncio.TimeoutError:
            logger.warning("subfinder_timeout", domain=domain, timeout=self._timeout)
            return set()
        except FileNotFoundError:
            logger.warning("subfinder_not_installed")
            return set()
        except Exception as e:
            logger.error("subfinder_error", error=str(e))
            return set()

    async def _query_crtsh(self, domain: str) -> set[str]:
        """Query crt.sh certificate transparency API via curl."""
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            proc = await asyncio.create_subprocess_exec(
                "curl", "-s", "-m", str(min(self._timeout, 60)),
                "--max-filesize", "10485760",  # 10MB cap
                url,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=min(self._timeout, 65),
            )

            if proc.returncode != 0 or not stdout:
                logger.warning("crtsh_empty_response", domain=domain)
                return set()

            raw = stdout.decode(errors="replace")
            entries = json.loads(raw)

            subs: set[str] = set()
            for entry in entries:
                name = entry.get("name_value", "")
                # crt.sh name_value can contain newline-separated names
                for part in name.split("\n"):
                    cleaned = part.strip().lower()
                    # Skip wildcards and empty
                    if cleaned and "." in cleaned and not cleaned.startswith("*"):
                        subs.add(cleaned)

            logger.info("crtsh_complete", domain=domain, found=len(subs))
            return subs

        except (asyncio.TimeoutError, json.JSONDecodeError) as e:
            logger.warning("crtsh_error", domain=domain, error=str(e))
            return set()
        except Exception as e:
            logger.error("crtsh_error", domain=domain, error=str(e))
            return set()

    # ── Private: DNS Resolution ───────────────────────────────────

    async def _dig_resolve(self, subdomain: str) -> list[str]:
        """Resolve a single subdomain to IP addresses using dig +short."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "dig", "+short", "+time=5", "+tries=2", subdomain, "A",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await asyncio.wait_for(
                proc.communicate(), timeout=_DIG_TIMEOUT,
            )

            ips: list[str] = []
            for line in stdout.decode(errors="replace").splitlines():
                stripped = line.strip()
                # Only keep IP addresses (skip CNAMEs)
                if stripped and _is_ip(stripped):
                    ips.append(stripped)
            return ips

        except (asyncio.TimeoutError, Exception):
            return []

    # ── Private: Validation ───────────────────────────────────────

    def _validate_domain(self, domain: str) -> None:
        """Validate domain is in scope before enumeration."""
        if self._scope_guard is not None:
            self._scope_guard.validate_url(f"https://{domain}")

    def _filter_scope(self, subdomains: list[str]) -> list[str]:
        """Filter subdomains to only those in scope."""
        if self._scope_guard is None:
            return subdomains

        filtered: list[str] = []
        for sub in subdomains:
            try:
                self._scope_guard.validate_url(f"https://{sub}")
                filtered.append(sub)
            except Exception:
                pass  # Out of scope
        return filtered


def _is_ip(text: str) -> bool:
    """Check if text looks like an IPv4 address."""
    parts = text.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
