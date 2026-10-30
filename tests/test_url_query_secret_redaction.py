"""Regression tests for secret-bearing URL query parameters."""

import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize("parameter", [
    "sig", "api_key", "api-key", "access_token",
    "refresh_token", "client_secret", "token", "API_KEY",
    "password", "passwd", "secret", "signature",
    "X-Amz-Signature", "x-amz-security-token",
])
def test_sensitive_query_values_are_redacted_even_when_low_entropy(parameter):
    url = f"https://example.test/hook?page=1&{parameter}=aaaa&limit=10"
    redacted, findings = redact(url)

    assert redacted == (
        f"https://example.test/hook?page=1&{parameter}="
        "[REDACTED:URL_QUERY_SECRET]&limit=10"
    )
    assert len(findings) == 1
    assert findings[0].kind == "URL_QUERY_SECRET"
    assert findings[0].value == "[REDACTED]"
    assert url[findings[0].start:findings[0].end] == "aaaa"


def test_multiple_signed_url_values_are_redacted_independently():
    text = "https://example.test/run?sig=abc&access_token=xyz#section"
    redacted, findings = redact(text)
    assert redacted == (
        "https://example.test/run?sig=[REDACTED:URL_QUERY_SECRET]"
        "&access_token=[REDACTED:URL_QUERY_SECRET]#section"
    )
    assert [f.kind for f in findings] == ["URL_QUERY_SECRET", "URL_QUERY_SECRET"]


def test_non_sensitive_query_parameters_remain_unchanged():
    text = "https://example.test/search?page=1&sort=asc&limit=20"
    redacted, findings = redact(text)
    assert redacted == text
    assert findings == []


def test_secret_query_value_stops_at_text_delimiters():
    text = 'Webhook: "https://example.test/run?sig=abc", next step'
    redacted, _ = redact(text)
    assert redacted == (
        'Webhook: "https://example.test/run?sig=[REDACTED:URL_QUERY_SECRET]", next step'
    )


def test_query_secret_keys_are_exact_not_prefix_matches():
    url = (
        "https://example.test/docs?"
        "password_hint=demo&signature_version=v4&secret_name=sample"
    )
    redacted, findings = redact(url)
    assert redacted == url
    assert findings == []


def test_aws_presigned_url_signature_is_redacted_without_touching_scope():
    url = (
        "https://bucket.example.test/object?"
        "X-Amz-Algorithm=AWS4-HMAC-SHA256"
        "&X-Amz-Date=20261025T120000Z"
        "&X-Amz-Signature=aaaa"
    )
    redacted, findings = redact(url)
    assert "X-Amz-Algorithm=AWS4-HMAC-SHA256" in redacted
    assert "X-Amz-Date=20261025T120000Z" in redacted
    assert "X-Amz-Signature=[REDACTED:URL_QUERY_SECRET]" in redacted
    assert [f.kind for f in findings] == ["URL_QUERY_SECRET"]
