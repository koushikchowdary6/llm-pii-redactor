"""Quoted YAML credential keys must not bypass the pre-LLM redaction guard."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redactor import redact


@pytest.mark.parametrize(
    "line, expected",
    [
        ("'password': short", "'password': [REDACTED:CONFIG_SECRET]"),
        ('"api_key": short', '"api_key": [REDACTED:CONFIG_SECRET]'),
        ("  'client_secret': low entropy # rotation",
         "  'client_secret': [REDACTED:CONFIG_SECRET] # rotation"),
        ("'token': 'short secret'", "'token': [REDACTED:CONFIG_SECRET]"),
    ],
)
def test_quoted_yaml_secret_keys_are_redacted(line, expected):
    safe, findings = redact(line)
    assert safe == expected
    assert [f.kind for f in findings] == ["CONFIG_SECRET"]
    assert all(f.value == "[REDACTED]" for f in findings)


@pytest.mark.parametrize("indicator", ["|", ">-", "|2-"])
def test_quoted_yaml_keys_redact_entire_multiline_secret(indicator):
    source = (
        "service: billing\n"
        f"'password': {indicator}\n"
        "  first line\n"
        "  second line\n"
        "region: west\n"
    )
    safe, findings = redact(source)
    assert safe == (
        "service: billing\n"
        "'password': [REDACTED:CONFIG_SECRET]\n"
        "region: west\n"
    )
    assert [f.kind for f in findings] == ["CONFIG_SECRET"]


def test_quoted_nonsecret_keys_and_prose_are_unchanged():
    source = (
        "'region': west\n"
        '"enabled": true\n'
        "Please discuss 'password': short\n"
    )
    safe, findings = redact(source)
    assert safe == source
    assert findings == []
