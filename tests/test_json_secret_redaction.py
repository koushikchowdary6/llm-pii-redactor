"""JSON credential values must not leak into LLM-bound text."""

import json
import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize("key", [
    "api_key", "api-key", "access_token", "refresh_token", "id_token",
    "client_secret", "password", "passwd", "secret", "token",
    "authorization", "session_token", "webhook_secret", "API_KEY",
])
def test_short_json_credentials_are_redacted_without_entropy_requirement(key):
    source = json.dumps({"safe": "visible", key: "aaaa"})
    safe, findings = redact(source)
    assert json.loads(safe) == {"safe": "visible", key: "[REDACTED:JSON_SECRET]"}
    assert [f.kind for f in findings] == ["JSON_SECRET"]
    assert findings[0].value == "[REDACTED]"
    assert source[findings[0].start:findings[0].end] == "aaaa"


def test_json_string_with_escaped_quotes_and_backslashes_is_redacted_entirely():
    source = json.dumps({"api_key": 'ab"cd\\ef', "note": "keep this"})
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "api_key": "[REDACTED:JSON_SECRET]", "note": "keep this"
    }
    assert [f.kind for f in findings] == ["JSON_SECRET"]


def test_multiple_json_credentials_are_independently_redacted():
    source = '{"password":"1234","access_token":"xyz","note":"safe"}'
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "password": "[REDACTED:JSON_SECRET]",
        "access_token": "[REDACTED:JSON_SECRET]",
        "note": "safe",
    }
    assert [f.kind for f in findings] == ["JSON_SECRET", "JSON_SECRET"]


def test_json_credential_with_nested_provider_token_is_one_complete_finding():
    source = '{"api_key":"sk-' + "A" * 30 + ' extra"}'
    safe, findings = redact(source)
    assert safe == '{"api_key":"[REDACTED:JSON_SECRET]"}'
    assert [f.kind for f in findings] == ["JSON_SECRET"]


def test_empty_json_credentials_are_not_reported_as_leaks():
    source = '{"api_key":"","password":null,"note":"ok"}'
    safe, findings = redact(source)
    assert safe == source
    assert findings == []


def test_non_secret_json_fields_are_preserved():
    source = '{"api_key_hint":"demo","password_policy":"strong","role":"reader"}'
    safe, findings = redact(source)
    assert safe == source
    assert findings == []


def test_json_secret_nested_inside_cookie_header_is_claimed_once():
    source = 'Cookie: {"api_key":"aaaa"}\nAccept: application/json'
    safe, findings = redact(source)
    assert safe == 'Cookie: [REDACTED:SENSITIVE_HEADER]\nAccept: application/json'
    assert [f.kind for f in findings] == ["SENSITIVE_HEADER"]
