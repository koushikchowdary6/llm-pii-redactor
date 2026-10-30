"""Unquoted numeric JSON credentials must be redacted without invalid JSON."""

import json
import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize("raw", ["0", "1234", "-17", "12.75", "1e6", "-2.5E+4"])
def test_numeric_password_values_are_masked_as_valid_json(raw):
    source = '{"password": ' + raw + ', "note": 42}'
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "password": "[REDACTED:JSON_NUMERIC_SECRET]", "note": 42,
    }
    assert [f.kind for f in findings] == ["JSON_NUMERIC_SECRET"]
    assert findings[0].value == "[REDACTED]"
    assert source[findings[0].start:findings[0].end] == raw
    assert raw not in safe


def test_multiple_nested_numeric_credentials_are_masked():
    source = '{"config":{"api_key":1234,"token":0},"enabled":true}'
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "config": {
            "api_key": "[REDACTED:JSON_NUMERIC_SECRET]",
            "token": "[REDACTED:JSON_NUMERIC_SECRET]",
        },
        "enabled": True,
    }
    assert [f.kind for f in findings] == [
        "JSON_NUMERIC_SECRET", "JSON_NUMERIC_SECRET",
    ]


def test_custom_mask_is_escaped_as_json_string():
    source = '{"password": 1234}'
    safe, _ = redact(source, mask='masked "{kind}"')
    assert json.loads(safe) == {"password": 'masked "JSON_NUMERIC_SECRET"'}


def test_unrelated_numeric_json_and_empty_or_null_secrets_are_preserved():
    source = '{"count":1234,"password":null,"token":"","note":4.5}'
    safe, findings = redact(source)
    assert safe == source
    assert findings == []


@pytest.mark.parametrize("raw", ["1234xyz", "01", "1.2.3", "1e"])
def test_malformed_numeric_values_are_not_partially_redacted(raw):
    source = '{"password": ' + raw + '}'
    safe, findings = redact(source)
    assert safe == source
    assert findings == []


def test_numeric_secret_inside_cookie_is_one_header_redaction():
    source = 'Cookie: {"token": 1234}\nAccept: application/json'
    safe, findings = redact(source)
    assert safe == 'Cookie: [REDACTED:SENSITIVE_HEADER]\nAccept: application/json'
    assert [f.kind for f in findings] == ["SENSITIVE_HEADER"]
