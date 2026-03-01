"""Vulnerability playbooks for the ReAct pentesting agent.

Contains distilled mutation/bypass reasoning from deadend-cli's 31KB playbook,
condensed into actionable context for the system prompt + a full reference
available via the get_playbook tool.

Source: https://github.com/xoxruns/deadend-cli (78% XBOW score)
"""

from __future__ import annotations

# ── Condensed Playbook (injected into system prompt) ──────────────────

CONDENSED_PLAYBOOK = """\
## Payload Mutation & Bypass Framework

When a payload is blocked, reason about WHY and systematically transform it:

**7-Step Fallback Chain:**
1. Try original payload
2. Encoding: URL-encode → double-URL → HTML entity → Unicode → UTF-8 overlong
3. Case: MiXeD cAsE (parsers case-insensitive, filters often case-sensitive)
4. Semantic alternatives: Different syntax, same effect (see below)
5. Fragmentation: Split keywords with comments (SE/**/LECT, <scr<!---->ipt>)
6. Parser confusion: Exploit filter vs executor interpretation differences
7. Compound mutations: Combine 2-3 techniques from above

**Parser Differential Model:**
INPUT → [Filter/WAF] → [Backend] → [Execution Engine]
Goal: Filter sees SAFE, execution engine sees MALICIOUS.

**Quick Reference — Semantic Equivalents:**
- JS exec: eval()→Function()(), setTimeout(), [].constructor.constructor()()
- JS alert: alert(1)→alert`1`, [1].map(alert), Reflect.apply(alert,null,[1])
- SQL concat: MySQL 'a' 'b', PostgreSQL 'a'||'b', MSSQL 'a'+'b'
- SQL comment: MySQL # or --, PostgreSQL --, both /* */
- SQL space: /**/, %09, %0a, %0d, +, %a0, /*!*/
- Shell space: ${IFS}, $IFS, {,}, TAB, <>, \\t
- SSTI traverse: __class__.__mro__[X].__subclasses__()[Y] or __globals__['os']
- Path traversal: ../ → ..%2f → %2e%2e%2f → ..%c0%af → ..;/ (Tomcat)

**XSS When <script> Blocked:**
<img src=x onerror=X>, <svg onload=X>, <input onfocus=X autofocus>,
<details open ontoggle=X>, <body onload=X>, <audio src=x onerror=X>

**Filter Fingerprinting:** Send probe chars (<>"'`;/\\) to see what's stripped/encoded.
Then: determine where filter runs (input/output), when (store/reflect), what triggers it.

**Polyglot XSS:** '"-->]]>*/</style></script>--><svg onload=alert(1)>
**SQLi Probe:** 'sleep(5)#"sleep(5)--`sleep(5) (tests all quote+comment combos)
"""


# ── Full Playbook Reference (available via get_playbook tool) ─────────

# Maps playbook section to its content (loaded lazily from file)
_PLAYBOOK_SECTIONS = {
    "encoding": "Encoding Ladder — 8-rung progressive encoding from raw to Base64",
    "case": "Case Transformations — lowercase/UPPER/MixedCase/alternating",
    "whitespace": "Whitespace Alternatives — space equivalents per context (HTML/SQL/Shell/JS)",
    "quotes": "Quote Alternatives — per-context quote equivalents and no-quote tricks",
    "comments": "Comment Injection — comment syntax + keyword fragmentation",
    "concatenation": "Concatenation & Fragmentation — string building + execution indirection",
    "null_bytes": "Null Byte & Boundary Abuse",
    "parser_differential": "Parser Differential Attacks — URL/HTML/SQL parser confusion",
    "js_equivalents": "JavaScript Execution Equivalents — eval alternatives, string-to-code",
    "ssti_equivalents": "Template Injection Equivalents — Jinja2 object traversal, bypass patterns",
    "sqli_equivalents": "SQL Injection Equivalents — comment/string/UNION/blind techniques",
    "cmdi_equivalents": "Command Injection Equivalents — separators, space bypass, keyword alternatives",
    "filter_fingerprinting": "Filter Fingerprinting Methodology — 3-step probe approach",
    "context_detection": "Context-Aware Mutation Selection — detecting injection context",
    "compound_mutations": "Compound Mutation Strategies — combining dimensions",
    "ssti_reasoning": "SSTI Reasoning — object graph traversal to os.popen()",
    "sqli_reasoning": "SQLi Reasoning — query structure, closing strategies, UNION requirements",
    "xss_reasoning": "XSS Reasoning — event handler enumeration, minimum viable payloads",
    "path_traversal": "Path Traversal Reasoning — normalization, traversal variations, wrapper bypass",
    "polyglot": "Polyglot & Building Blocks — multi-context payloads, component decomposition",
}

_full_playbook_cache: str | None = None


def get_full_playbook() -> str:
    """Load the full playbook from the Jinja2 file (cached)."""
    global _full_playbook_cache
    if _full_playbook_cache is not None:
        return _full_playbook_cache

    import os
    playbook_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
        "vulnerability_playbooks.jinja2",
    )
    try:
        with open(playbook_path) as f:
            content = f.read()
        # Strip Jinja2 raw tags
        content = content.replace("{% raw %}", "").replace("{% endraw %}", "")
        _full_playbook_cache = content
        return content
    except FileNotFoundError:
        _full_playbook_cache = "(playbook file not found)"
        return _full_playbook_cache


def get_playbook_section(section: str) -> str:
    """Get a specific section of the playbook by keyword match."""
    full = get_full_playbook()
    if "(not found)" in full:
        return full

    # Find the section by PART number or heading
    section_lower = section.lower()

    # Map section names to search patterns
    patterns = {
        "encoding": "Dimension 1: ENCODING",
        "case": "Dimension 2: CASE",
        "whitespace": "Dimension 3: WHITESPACE",
        "quotes": "Dimension 4: QUOTE",
        "comments": "Dimension 5: COMMENT",
        "concatenation": "Dimension 6: CONCATENATION",
        "null_bytes": "Dimension 7: NULL BYTE",
        "parser_differential": "PART 2: PARSER DIFFERENTIAL",
        "js_equivalents": "JavaScript Execution Equivalents",
        "ssti_equivalents": "Template Injection Equivalents",
        "sqli_equivalents": "SQL Injection Equivalents",
        "cmdi_equivalents": "Command Injection Equivalents",
        "filter_fingerprinting": "PART 4: FILTER FINGERPRINTING",
        "context_detection": "PART 5: CONTEXT-AWARE",
        "compound_mutations": "PART 6: COMPOUND",
        "ssti_reasoning": "SSTI: Object Traversal",
        "sqli_reasoning": "SQLi: Query Structure",
        "xss_reasoning": "XSS: Event Handler",
        "path_traversal": "Path Traversal: Path Normalization",
        "polyglot": "PART 8: CREATIVE PAYLOAD",
    }

    pattern = patterns.get(section_lower, section)

    # Find the section in the full text
    idx = full.find(pattern)
    if idx == -1:
        # Try case-insensitive search
        full_lower = full.lower()
        idx = full_lower.find(pattern.lower())

    if idx == -1:
        available = ", ".join(_PLAYBOOK_SECTIONS.keys())
        return f"Section '{section}' not found. Available: {available}"

    # Extract ~3000 chars from this point
    end_idx = min(idx + 3000, len(full))
    # Try to end at a section boundary
    next_section = full.find("\n---\n", idx + 100)
    if next_section != -1 and next_section < end_idx + 500:
        end_idx = next_section

    return full[idx:end_idx].strip()


def list_playbook_sections() -> dict[str, str]:
    """Return available playbook sections with descriptions."""
    return dict(_PLAYBOOK_SECTIONS)
