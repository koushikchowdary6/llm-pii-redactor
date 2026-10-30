"""Cloud/AI-provider credential headers must be redacted even for short values."""

import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize("header", [
    "X-Goog-Api-Key", "x-goog-api-key", "X-Amz-Security-Token",
    "X-Functions-Key", "X-API-Token",
])
def test_provider_header_redacts_complete_opaque_value(header):
    value = "aaaa; session=bbbb"
    text = f"{header}: {value}\nAccept: text/plain"
    safe, findings = redact(text)
    assert safe == f"{header}: [REDACTED:SENSITIVE_HEADER]\nAccept: text/plain"
    assert len(findings) == 1
    assert findings[0].kind == "SENSITIVE_HEADER"
    assert findings[0].value == "[REDACTED]"
    assert text[findings[0].start:findings[0].end] == value


def test_provider_header_folded_continuation_is_not_leaked():
    text = "X-Goog-Api-Key: aaaa\r\n  bbbb\r\nAccept: application/json"
    safe, findings = redact(text)
    assert safe == "X-Goog-Api-Key: [REDACTED:SENSITIVE_HEADER]\r\nAccept: application/json"
    assert len(findings) == 1


def test_empty_provider_header_and_documentation_prose_remain_unchanged():
    text = "X-Goog-Api-Key: \nAccept: text/plain\nRead the X-Goog-Api-Key documentation."
    safe, findings = redact(text)
    assert safe == text
    assert findings == []
