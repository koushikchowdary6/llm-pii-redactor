"""Regression tests for short structured session and cookie credentials."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redactor import redact


@pytest.mark.parametrize("key", [
    "cookie", "set_cookie", "set-cookie", "proxy_authorization",
    "proxy-authorization", "x_amz_security_token", "x-amz-security-token",
])
def test_json_short_session_credentials_are_fully_redacted(key):
    source = json.dumps({"safe": "visible", key: "aaaa; sid=bbbb"})
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "safe": "visible", key: "[REDACTED:JSON_SECRET]",
    }
    assert [f.kind for f in findings] == ["JSON_SECRET"]
    assert findings[0].value == "[REDACTED]"
    assert source[findings[0].start:findings[0].end] == "aaaa; sid=bbbb"


@pytest.mark.parametrize("key", [
    "cookie", "set_cookie", "proxy_authorization", "x_amz_security_token",
])
def test_numeric_json_session_secrets_remain_valid_json(key):
    source = json.dumps({key: 1234, "safe": "keep"})
    safe, findings = redact(source)
    assert json.loads(safe) == {
        key: "[REDACTED:JSON_NUMERIC_SECRET]", "safe": "keep",
    }
    assert [f.kind for f in findings] == ["JSON_NUMERIC_SECRET"]


@pytest.mark.parametrize("key", [
    "set_cookie", "proxy_authorization", "x_amz_security_token",
])
def test_yaml_config_secrets_are_masked_without_neighbor_loss(key):
    source = f"service: example\n{key}: aaaa # rotate\nregion: us-west-2"
    safe, findings = redact(source)
    assert safe == (
        f"service: example\n{key}: [REDACTED:CONFIG_SECRET] # rotate\n"
        "region: us-west-2"
    )
    assert [f.kind for f in findings] == ["CONFIG_SECRET"]


def test_cookie_header_keeps_existing_full_header_precedence():
    source = "Cookie: sid=aaaa; csrf=bbbb\nAccept: application/json"
    safe, findings = redact(source)
    assert safe == "Cookie: [REDACTED:SENSITIVE_HEADER]\nAccept: application/json"
    assert [f.kind for f in findings] == ["SENSITIVE_HEADER"]


def test_nonsecret_similar_field_names_are_preserved():
    source = json.dumps({
        "cookie_policy": "visible", "proxy_authorization_hint": "visible",
        "x_amz_security_token_name": "visible",
    })
    safe, findings = redact(source)
    assert safe == source
    assert findings == []


def test_structured_metadata_keys_do_not_disable_entropy_value_detection():
    source = json.dumps({
        "x_amz_security_token_name": "plain",
        "payload": "aBcD1234+/qWeR5678_-tYuI9012",
    })
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "x_amz_security_token_name": "plain",
        "payload": "[REDACTED:HIGH_ENTROPY_SECRET]",
    }
    assert [f.kind for f in findings] == ["HIGH_ENTROPY_SECRET"]
