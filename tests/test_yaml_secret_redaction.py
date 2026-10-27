"""YAML-style credentials must be masked before prompts leave the trust boundary."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redactor import redact


@pytest.mark.parametrize("line, expected", [
    ("password: aaaa", "password: [REDACTED:CONFIG_SECRET]"),
    ("  client_secret: \"short secret\" # explanation",
     "  client_secret: [REDACTED:CONFIG_SECRET] # explanation"),
    ("token: aaaa#bbbb", "token: [REDACTED:CONFIG_SECRET]"),
    ("API_KEY: alpha beta", "API_KEY: [REDACTED:CONFIG_SECRET]"),
    ("session_token: 'short secret'",
     "session_token: [REDACTED:CONFIG_SECRET]"),
    ("password: aaaa\\r", "password: [REDACTED:CONFIG_SECRET]\\r"),
])
def test_yaml_credentials_redact_complete_values(line, expected):
    safe, findings = redact(line)
    assert safe == expected
    assert [finding.kind for finding in findings] == ["CONFIG_SECRET"]
    assert findings[0].value == "[REDACTED]"


def test_yaml_secrets_do_not_consume_comments_or_neighboring_fields():
    text = (
        "service: payments\\n"
        "password: ab cd # rotation required\\n"
        "region: us-west-2\\n"
        "token: abc#def\\n"
    )
    safe, findings = redact(text)
    assert safe == (
        "service: payments\\n"
        "password: [REDACTED:CONFIG_SECRET] # rotation required\\n"
        "region: us-west-2\\n"
        "token: [REDACTED:CONFIG_SECRET]\\n"
    )
    assert [f.kind for f in findings] == ["CONFIG_SECRET", "CONFIG_SECRET"]


def test_non_secret_yaml_and_empty_values_remain_unchanged():
    text = (
        "region: us-west-2\\n"
        "password: \\n"
        'token: ""\\n'
        "Please discuss password: aaaa\\n"
    )
    safe, findings = redact(text)
    assert safe == text
    assert findings == []
