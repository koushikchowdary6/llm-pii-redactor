"""HTTP obs-fold must not leave credential continuations in LLM-bound text."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from redactor import redact


@pytest.mark.parametrize("header", [
    "Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie",
    "X-API-Key", "X-Auth-Token",
])
@pytest.mark.parametrize("newline", ["\n", "\r\n"])
def test_folded_credentials_are_redacted_as_one_unit(header, newline):
    text = (
        f"{header}: firstsecret{newline}"
        f"\tsecondsecret{newline}"
        f"  thirdsecret{newline}"
        "Accept: text/plain"
    )
    safe, findings = redact(text)
    assert "firstsecret" not in safe
    assert "secondsecret" not in safe
    assert "thirdsecret" not in safe
    assert safe.endswith("Accept: text/plain")
    assert len(findings) == 1
    assert findings[0].value == "[REDACTED]"
    if header in {"Authorization", "Proxy-Authorization"}:
        assert safe == "[REDACTED:AUTHORIZATION_CREDENTIAL]" + newline + "Accept: text/plain"
    else:
        assert safe == f"{header}: [REDACTED:SENSITIVE_HEADER]" + newline + "Accept: text/plain"


def test_blank_line_ends_header_continuation_scope():
    text = "Cookie: session=abc\r\n\tsecret=def\r\n\r\n  visible body"
    safe, findings = redact(text)
    assert safe == "Cookie: [REDACTED:SENSITIVE_HEADER]\r\n\r\n  visible body"
    assert len(findings) == 1


def test_indented_unrelated_header_is_not_considered_folded_without_sensitive_header():
    text = "Accept: text/plain\n  X-Request-ID: sample"
    safe, findings = redact(text)
    assert safe == text
    assert findings == []


def test_empty_sensitive_header_does_not_claim_following_line():
    text = "X-API-Key: \n\tshort\nAccept: text/plain"
    safe, findings = redact(text)
    assert safe == text
    assert findings == []
