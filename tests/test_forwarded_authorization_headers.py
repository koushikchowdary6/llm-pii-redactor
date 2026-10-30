"""Reverse-proxy authorization aliases must not leak short opaque credentials."""

import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize(
    "header",
    [
        "Authorization",
        "Proxy-Authorization",
        "X-Authorization",
        "X-Forwarded-Authorization",
        "X-Original-Authorization",
        "x-forwarded-authorization",
    ],
)
def test_opaque_authorization_headers_are_redacted_as_a_whole(header):
    source = f"{header}: Basic aaaa\nAccept: application/json"
    safe, findings = redact(source)

    assert safe == "[REDACTED:AUTHORIZATION_CREDENTIAL]\nAccept: application/json"
    assert [finding.kind for finding in findings] == ["AUTHORIZATION_CREDENTIAL"]
    assert findings[0].value == "[REDACTED]"


@pytest.mark.parametrize(
    "header",
    ["X-Forwarded-Authorization", "X-Original-Authorization"],
)
def test_folded_proxy_credentials_cannot_leak_continuation_lines(header):
    source = (
        f'{header}: Digest username="alice",\r\n'
        '  response="short-secret"\r\n'
        "Accept: text/plain"
    )
    safe, findings = redact(source)

    assert safe == "[REDACTED:AUTHORIZATION_CREDENTIAL]\r\nAccept: text/plain"
    assert len(findings) == 1
    assert "short-secret" not in safe


def test_bare_scheme_is_not_mistaken_for_a_credential():
    safe, findings = redact("X-Forwarded-Authorization: Bearer\nAccept: text/plain")
    assert safe == "X-Forwarded-Authorization: Bearer\nAccept: text/plain"
    assert findings == []
