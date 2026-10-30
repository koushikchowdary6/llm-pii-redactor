"""Regression tests for credentials in OAuth redirect URL fragments."""

import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize("key", ["access_token", "id_token", "refresh_token", "ACCESS_TOKEN"])
def test_first_oauth_fragment_field_is_redacted_even_when_low_entropy(key):
    url = f"https://client.example.test/callback#{key}=aaaa&state=public"
    redacted, findings = redact(url)

    assert redacted == (
        f"https://client.example.test/callback#{key}="
        "[REDACTED:URL_QUERY_SECRET]&state=public"
    )
    assert len(findings) == 1
    assert findings[0].kind == "URL_QUERY_SECRET"
    assert findings[0].value == "[REDACTED]"
    assert url[findings[0].start:findings[0].end] == "aaaa"


def test_multiple_oauth_fragment_secrets_are_redacted_without_hiding_metadata():
    url = (
        "https://client.example.test/callback#access_token=short"
        "&token_type=Bearer&id_token=bbbb&expires_in=3600"
    )
    redacted, findings = redact(url)

    assert redacted == (
        "https://client.example.test/callback#access_token=[REDACTED:URL_QUERY_SECRET]"
        "&token_type=Bearer&id_token=[REDACTED:URL_QUERY_SECRET]&expires_in=3600"
    )
    assert [f.kind for f in findings] == ["URL_QUERY_SECRET", "URL_QUERY_SECRET"]


def test_nonsecret_fragments_and_prefix_similar_keys_are_preserved():
    url = (
        "https://client.example.test/callback#section"
        "?token_hint=public&access_token_hint=public"
    )
    assert redact(url) == (url, [])


def test_id_token_in_regular_query_string_is_also_redacted():
    url = "https://client.example.test/callback?id_token=abc&state=xyz"
    redacted, findings = redact(url)
    assert redacted == (
        "https://client.example.test/callback?id_token=[REDACTED:URL_QUERY_SECRET]"
        "&state=xyz"
    )
    assert len(findings) == 1
