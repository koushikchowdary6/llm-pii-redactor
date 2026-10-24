"""Opaque HTTP header credentials must not leak into downstream LLM prompts."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from redactor import redact


@pytest.mark.parametrize("header", [
    "X-API-Key", "api-key", "X-Auth-Token", "X-Access-Token",
    "Cookie", "Set-Cookie",
])
def test_low_entropy_header_values_are_redacted(header):
    text = f"GET / HTTP/1.1\n{header}: aaaa\nAccept: text/plain"
    safe, findings = redact(text)
    assert safe == (
        f"GET / HTTP/1.1\n{header}: [REDACTED:SENSITIVE_HEADER]"
        "\nAccept: text/plain"
    )
    assert len(findings) == 1
    assert findings[0].kind == "SENSITIVE_HEADER"
    assert findings[0].value == "[REDACTED]"
    assert text[findings[0].start:findings[0].end] == "aaaa"


def test_cookie_value_with_multiple_secrets_is_redacted_as_one_unit():
    text = "Cookie: session=aaaa; csrf=bbbb\nUser-Agent: example"
    safe, findings = redact(text)
    assert safe == "Cookie: [REDACTED:SENSITIVE_HEADER]\nUser-Agent: example"
    assert [finding.kind for finding in findings] == ["SENSITIVE_HEADER"]


def test_non_sensitive_headers_and_prose_are_not_redacted():
    text = "Accept: text/plain\nX-Request-ID: test\nPlease review the X-API-Key header."
    safe, findings = redact(text)
    assert safe == text
    assert findings == []


def test_header_match_does_not_consume_next_line_when_value_missing():
    text = "X-API-Key: \nAccept: text/plain"
    safe, findings = redact(text)
    assert safe == text
    assert findings == []
