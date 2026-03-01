"""Email manager for account registration and verification during active testing.

Supports two modes:
- Local mode: Runs an aiosmtpd catch-all server for receiving verification emails
- IMAP mode: Polls an external IMAP inbox for emails (supports plus addressing)
"""

from __future__ import annotations

import asyncio
import email
import html
import imaplib
import re
import secrets
import string
import time
from email.message import Message
from typing import Any

import structlog

from ai_brain.active.errors import AccountCreationFailed
from ai_brain.config import ActiveTestingConfig

logger = structlog.get_logger()

# Patterns for extracting verification links from emails
_LINK_PATTERNS = [
    re.compile(r'href=["\']?(https?://[^"\'>\s]+(?:verify|confirm|activate|validate|token)[^"\'>\s]*)', re.IGNORECASE),
    re.compile(r'(https?://\S+(?:verify|confirm|activate|validate|token)\S*)', re.IGNORECASE),
    re.compile(r'href=["\']?(https?://[^"\'>\s]+)', re.IGNORECASE),
]

# Patterns for extracting verification codes
_CODE_PATTERNS = [
    re.compile(r'(?:code|pin|otp|token)\s*(?:is|:)\s*(\d{4,8})', re.IGNORECASE),
    re.compile(r'\b(\d{6})\b'),  # Standalone 6-digit code (most common OTP length)
    re.compile(r'(?:verification|confirmation)\s*(?:code|number)\s*(?:is|:)\s*(\w{4,8})', re.IGNORECASE),
]


class EmailManager:
    """Manages email accounts for test registration and verification.

    Generates unique email addresses, waits for incoming emails,
    and extracts verification links/codes from email content.
    """

    def __init__(self, config: ActiveTestingConfig) -> None:
        self._config = config
        self._domain = config.email_domain
        self._mode = config.email_mode
        self._local_inbox: dict[str, list[dict[str, str]]] = {}
        self._smtp_server: Any = None

    @property
    def is_configured(self) -> bool:
        """Check if email is configured (either catch-all domain or IMAP)."""
        if self._domain:
            return True
        if self._config.imap_host and self._config.imap_user:
            return True
        return False

    async def start(self) -> None:
        """Start email services based on configured mode."""
        if self._config.dry_run:
            logger.info("email_dry_run", msg="Email services skipped (dry run)")
            return

        if self._mode == "local":
            await self.start_local_server()
        elif self._mode == "imap":
            if not self._config.imap_host:
                logger.warning("imap_not_configured", msg="IMAP host not set")
                return
            try:
                mail = imaplib.IMAP4_SSL(self._config.imap_host)
                mail.login(self._config.imap_user, self._config.imap_password)
                mail.logout()
                logger.info(
                    "imap_connected",
                    host=self._config.imap_host,
                    user=self._config.imap_user,
                )
            except Exception as e:
                logger.error("imap_connection_failed", error=str(e))

    def generate_email(self, prefix: str | None = None) -> str:
        """Generate a unique email address.

        In plus addressing mode (email_plus_addressing=True with imap_user set),
        generates addresses like user+tag@domain from a single inbox.
        Otherwise uses catch-all domain mode: random@domain.

        Args:
            prefix: Optional prefix/tag for the email. If None, generates random.

        Returns:
            Email address string.
        """
        # Plus addressing mode: user+tag@domain
        if self._config.email_plus_addressing and self._config.imap_user:
            if "@" not in self._config.imap_user:
                raise AccountCreationFailed(
                    "imap_user must be a full email address for plus addressing",
                    step="generate_email",
                )
            base_user, domain = self._config.imap_user.split("@", 1)
            tag = prefix or ("test" + "".join(
                secrets.choice(string.ascii_lowercase + string.digits)
                for _ in range(8)
            ))
            safe_tag = re.sub(r"[^a-zA-Z0-9._-]", "", tag)
            addr = f"{base_user}+{safe_tag}@{domain}"
            logger.info("email_generated", address=addr, mode="plus_addressing")
            return addr

        # Catch-all domain mode
        if not self._domain:
            raise AccountCreationFailed(
                "No email domain configured", step="generate_email"
            )

        if prefix:
            safe_prefix = re.sub(r"[^a-zA-Z0-9._-]", "", prefix)
        else:
            safe_prefix = "test" + "".join(
                secrets.choice(string.ascii_lowercase + string.digits) for _ in range(8)
            )

        addr = f"{safe_prefix}@{self._domain}"
        logger.info("email_generated", address=addr)
        return addr

    async def start_local_server(self, host: str = "127.0.0.1", port: int = 1025) -> None:
        """Start a local aiosmtpd catch-all SMTP server.

        Only used in local mode. Captures all incoming emails to the in-memory inbox.
        """
        if self._config.dry_run:
            logger.info("email_dry_run", msg="Local SMTP server skipped (dry run)")
            return

        if self._mode != "local":
            return

        try:
            from aiosmtpd.controller import Controller
            from aiosmtpd.handlers import Message as SMTPMessage

            class _CatchAllHandler:
                def __init__(self, inbox: dict[str, list[dict[str, str]]]):
                    self._inbox = inbox

                async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
                    for rcpt in envelope.rcpt_tos:
                        rcpt_lower = rcpt.lower()
                        if rcpt_lower not in self._inbox:
                            self._inbox[rcpt_lower] = []

                        msg = email.message_from_bytes(envelope.content)
                        body = _extract_body(msg)

                        self._inbox[rcpt_lower].append({
                            "from": envelope.mail_from,
                            "to": rcpt,
                            "subject": msg.get("Subject", ""),
                            "body": body,
                            "timestamp": str(time.time()),
                        })
                        logger.info(
                            "email_received",
                            to=rcpt,
                            subject=msg.get("Subject", ""),
                        )
                    return "250 OK"

            handler = _CatchAllHandler(self._local_inbox)
            controller = Controller(handler, hostname=host, port=port)
            controller.start()
            self._smtp_server = controller
            logger.info("local_smtp_started", host=host, port=port)

        except ImportError:
            logger.warning("aiosmtpd_not_available", msg="aiosmtpd not installed")

    async def stop(self) -> None:
        """Stop the local SMTP server if running."""
        if self._smtp_server:
            try:
                self._smtp_server.stop()
            except Exception:
                pass
            self._smtp_server = None

    async def wait_for_email(
        self,
        address: str,
        timeout: int = 60,
        subject_filter: str | None = None,
    ) -> dict[str, str]:
        """Wait for an email to arrive at the specified address.

        Args:
            address: Email address to check.
            timeout: Maximum seconds to wait.
            subject_filter: Optional substring to match in subject line.

        Returns:
            Dict with from, to, subject, body keys.

        Raises:
            AccountCreationFailed: If no email arrives within timeout.
        """
        if self._config.dry_run:
            return {
                "from": "noreply@example.com",
                "to": address,
                "subject": "[dry run] Verification",
                "body": "Your verification link: https://example.com/verify?token=dryrun123",
            }

        if self._mode == "local":
            return await self._wait_local(address, timeout, subject_filter)
        else:
            return await self._wait_imap(address, timeout, subject_filter)

    async def _wait_local(
        self, address: str, timeout: int, subject_filter: str | None
    ) -> dict[str, str]:
        """Wait for email in the local inbox."""
        addr_lower = address.lower()
        deadline = time.monotonic() + timeout

        while time.monotonic() < deadline:
            if addr_lower in self._local_inbox:
                for msg in self._local_inbox[addr_lower]:
                    if subject_filter and subject_filter.lower() not in msg.get("subject", "").lower():
                        continue
                    return msg

            await asyncio.sleep(2)

        raise AccountCreationFailed(
            f"No email received at {address} within {timeout}s",
            step="wait_for_email",
        )

    async def _wait_imap(
        self, address: str, timeout: int, subject_filter: str | None
    ) -> dict[str, str]:
        """Wait for email via IMAP polling.

        For plus-addressed emails (user+tag@domain), uses a two-phase search:
        1. Search by exact TO address
        2. Fallback: search UNSEEN emails and filter client-side by To header
           (some providers deliver plus-addressed mail but don't support TO search for it)
        """
        if not self._config.imap_host:
            raise AccountCreationFailed("IMAP not configured", step="wait_for_email")

        deadline = time.monotonic() + timeout
        is_plus_addr = "+" in address.split("@")[0]

        while time.monotonic() < deadline:
            try:
                mail = imaplib.IMAP4_SSL(self._config.imap_host)
                mail.login(self._config.imap_user, self._config.imap_password)
                mail.select("INBOX")

                # Phase 1: Search by exact TO address (no SUBJECT filter in IMAP
                # to avoid encoding issues with non-ASCII and regex patterns)
                search_criteria = f'TO "{address}"'

                _, data = mail.search(None, search_criteria)
                mail_ids = data[0].split()

                # Phase 2: Fallback for plus addressing — search UNSEEN and filter client-side
                if not mail_ids and is_plus_addr:
                    fallback_criteria = "UNSEEN"

                    _, data = mail.search(None, fallback_criteria)
                    unseen_ids = data[0].split()

                    # Check recent unseen emails (last 20) for matching To header
                    for mid in reversed(unseen_ids[-20:]):
                        _, msg_data = mail.fetch(mid, "(RFC822)")
                        raw = msg_data[0][1]  # type: ignore[index]
                        msg = email.message_from_bytes(raw)
                        to_header = msg.get("To", "").lower()

                        if address.lower() in to_header:
                            body = _extract_body(msg)
                            mail.logout()
                            return {
                                "from": msg.get("From", ""),
                                "to": address,
                                "subject": msg.get("Subject", ""),
                                "body": body,
                            }

                if mail_ids:
                    # Get the latest matching email, apply client-side subject filter
                    for mid in reversed(mail_ids[-10:]):
                        _, msg_data = mail.fetch(mid, "(RFC822)")
                        raw = msg_data[0][1]  # type: ignore[index]
                        msg = email.message_from_bytes(raw)

                        # Client-side subject filter (supports | for OR patterns)
                        if subject_filter:
                            subject = (msg.get("Subject", "") or "").lower()
                            filter_parts = [p.strip().lower() for p in subject_filter.split("|")]
                            if not any(p in subject for p in filter_parts):
                                continue

                        body = _extract_body(msg)
                        mail.logout()
                        return {
                            "from": msg.get("From", ""),
                            "to": address,
                            "subject": msg.get("Subject", ""),
                            "body": body,
                        }

                mail.logout()
            except Exception as e:
                logger.debug("imap_poll_error", error=str(e))

            await asyncio.sleep(5)

        raise AccountCreationFailed(
            f"No email received at {address} within {timeout}s",
            step="wait_for_email",
        )

    @staticmethod
    def extract_verification_link(email_body: str) -> str | None:
        """Extract a verification/confirmation link from email body.

        Tries multiple patterns, preferring links with verification-related keywords.

        Returns:
            The URL string, or None if not found.
        """
        for pattern in _LINK_PATTERNS:
            matches = pattern.findall(email_body)
            if matches:
                # Return the first match (most specific patterns checked first)
                url = matches[0]
                # Clean up HTML entities
                url = html.unescape(url)
                return url.rstrip(".,;>")
        return None

    @staticmethod
    def extract_code(email_body: str) -> str | None:
        """Extract a verification/OTP code from email body.

        Returns:
            The code string, or None if not found.
        """
        for pattern in _CODE_PATTERNS:
            match = pattern.search(email_body)
            if match:
                return match.group(1)
        return None


def _extract_body(msg: Message) -> str:
    """Extract text body from an email message."""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace")
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode("utf-8", errors="replace")
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            return payload.decode("utf-8", errors="replace")
    return ""
