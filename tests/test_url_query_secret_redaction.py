"""Regression tests for secret-bearing URL query parameters."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from redactor import redact


@pytest.mark.parametrize("parameter", [
    "sig", "api_key", "api-key", "access_token",
    "refresh_token", "client_secret", "token", "API_KEY",
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
