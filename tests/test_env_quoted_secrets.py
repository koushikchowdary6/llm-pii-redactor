"""Regression tests for quoted .env secrets and ordinary URL/form assignments."""

import sys
from pathlib import Path


from redactor import redact


def test_quoted_and_spaced_env_secrets_are_redacted_as_complete_values():
    text = (
        'API_KEY = "aaaa"\n'
        "CLIENT_SECRET = 'short secret'\n"
        'password = "p@ss word"\n'
        'ordinary = "visible"\n'
    )
    safe, findings = redact(text)
    assert safe == (
        "API_KEY = [REDACTED:URL_QUERY_SECRET]\n"
        "CLIENT_SECRET = [REDACTED:URL_QUERY_SECRET]\n"
        "password = [REDACTED:URL_QUERY_SECRET]\n"
        'ordinary = "visible"\n'
    )
    assert [f.kind for f in findings] == ["URL_QUERY_SECRET"] * 3
    assert all(f.value == "[REDACTED]" for f in findings)


def test_escaped_quotes_empty_assignments_and_url_parameters():
    text = (
        'token = "ab\\\"cd"\n'
        'TOKEN=\n'
        'token = ""\n'
        'not_token=public\n'
        'https://example.test/?access_token=xyz&mode=preview\n'
    )
    safe, findings = redact(text)
    assert 'token = [REDACTED:URL_QUERY_SECRET]\n' in safe
    assert 'TOKEN=\n' in safe
    assert 'token = ""\n' in safe
    assert 'not_token=public\n' in safe
    assert '?access_token=[REDACTED:URL_QUERY_SECRET]&mode=preview' in safe
    assert [f.kind for f in findings] == ["URL_QUERY_SECRET", "URL_QUERY_SECRET"]
