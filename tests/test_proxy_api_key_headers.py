"""Proxy credential aliases and client secrets must not leak to LLM inputs."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redactor import redact


@pytest.mark.parametrize("header", [
    "X-Forwarded-API-Key",
    "x-original-api-key",
    "X-Forwarded-Access-Token",
    "X-Original-Access-Token",
    "X-API-Secret",
    "X-Client-Secret",
])
def test_short_opaque_proxy_credentials_are_fully_masked(header):
    original = f"{header}: aaaa; another=bbbb\nAccept: application/json"
    safe, findings = redact(original)

    assert safe == f"{header}: [REDACTED:SENSITIVE_HEADER]\nAccept: application/json"
    assert [finding.kind for finding in findings] == ["SENSITIVE_HEADER"]
    assert findings[0].value == "[REDACTED]"
    assert original[findings[0].start:findings[0].end] == "aaaa; another=bbbb"


def test_folded_proxy_api_key_does_not_leave_continuation_secret():
    source = "X-Forwarded-API-Key: aaaa\r\n  bbbb\r\nAccept: text/plain"
    safe, findings = redact(source)
    assert safe == "X-Forwarded-API-Key: [REDACTED:SENSITIVE_HEADER]\r\nAccept: text/plain"
    assert len(findings) == 1
    assert "aaaa" not in safe and "bbbb" not in safe


def test_empty_proxy_key_and_header_name_in_prose_are_not_secrets():
    source = "X-Original-API-Key: \nAccept: text/plain\nCheck the X-Client-Secret header."
    safe, findings = redact(source)
    assert safe == source
    assert findings == []
