"""Regression tests for opaque HTTP authorization secrets in LLM prompts."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redactor import detect, redact


@pytest.mark.parametrize("header", [
    "Authorization: Bearer AAAAAAAAAAAA",
    "authorization: basic dXNlcjpwYXNz",
    "Proxy-Authorization: Token short_123",
    "  Authorization : Bearer a.b.c-123",
])
def test_opaque_authorization_header_is_redacted_completely(header):
    output, findings = redact(f"before\n{header}\nafter")
    assert output == "before\n[REDACTED:AUTHORIZATION_CREDENTIAL]\nafter"
    assert [f.kind for f in findings] == ["AUTHORIZATION_CREDENTIAL"]
    assert findings[0].value == "[REDACTED]"


def test_recognized_provider_key_preserves_specific_finding_type():
    token = "sk-" + "A" * 30
    output, findings = redact(f"Authorization: Bearer {token}")
    assert output == "Authorization: Bearer [REDACTED:OPENAI_API_KEY]"
    assert [f.kind for f in findings] == ["OPENAI_API_KEY"]


def test_header_name_in_prose_does_not_trigger_redaction():
    text = "Documentation mentions Authorization: Bearer demo as an example."
    assert detect(text) == []


def test_missing_header_value_does_not_consume_next_line():
    text = "Authorization: Bearer\nordinary text"
    assert redact(text)[0] == text


def test_multiple_opaque_headers_do_not_leak_values():
    text = "Authorization: Bearer secret_1\nProxy-Authorization: Basic dXNlcjpwYXNz"
    output, findings = redact(text)
    assert "secret_1" not in output
    assert "dXNlcjpwYXNz" not in output
    assert output.count("[REDACTED:AUTHORIZATION_CREDENTIAL]") == 2
    assert len(findings) == 2


@pytest.mark.parametrize("header", [
    'Authorization: Digest username="alice", realm="private", response="aaaa"',
    "Authorization: AWS4-HMAC-SHA256 Credential=demo/20261024/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=aaaa",
    "Proxy-Authorization: Custom low-entropy credential",
    "Authorization: Bearer opaque-token, extra=123",
    "Authorization: Bearer first second",
])
def test_other_schemes_and_multifield_credentials_do_not_leak(header):
    output, findings = redact(f"before\n{header}\nafter")
    assert output == "before\n[REDACTED:AUTHORIZATION_CREDENTIAL]\nafter"
    assert [f.kind for f in findings] == ["AUTHORIZATION_CREDENTIAL"]


def test_authorization_header_does_not_consume_following_lines():
    text = "Authorization: Digest username=alice, response=aaaa\nAccept: text/plain"
    output, findings = redact(text)
    assert output == "[REDACTED:AUTHORIZATION_CREDENTIAL]\nAccept: text/plain"
    assert len(findings) == 1


def test_provider_key_with_additional_header_parameters_is_fully_redacted():
    token = "sk-" + "A" * 30
    text = f"Authorization: Bearer {token}, extra=opaque"
    output, findings = redact(text)
    assert output == "[REDACTED:AUTHORIZATION_CREDENTIAL]"
    assert len(findings) == 1
