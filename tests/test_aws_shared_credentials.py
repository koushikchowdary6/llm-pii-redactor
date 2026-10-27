"""AWS shared credentials must not leak through generic config field names."""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from redactor import redact


@pytest.mark.parametrize("name", [
    "aws_secret_access_key", "aws_session_token", "aws_access_key_id",
    "AWS-SECRET-ACCESS-KEY",
])
def test_env_and_form_aws_credentials_redacted_even_when_low_entropy(name):
    text = f"{name}=aaaa\nnon_secret=keep"
    safe, findings = redact(text)
    assert safe == f"{name}=[REDACTED:URL_QUERY_SECRET]\nnon_secret=keep"
    assert len(findings) == 1
    assert findings[0].value == "[REDACTED]"


@pytest.mark.parametrize("name", [
    "aws_secret_access_key", "aws_session_token", "aws_access_key_id",
])
def test_yaml_aws_credentials_preserve_key_and_comment(name):
    safe, findings = redact(f"{name}: abcd # deployment secret\nregion: us-east-1")
    assert safe == (
        f"{name}: [REDACTED:CONFIG_SECRET] # deployment secret\n"
        "region: us-east-1"
    )
    assert len(findings) == 1


@pytest.mark.parametrize("name", [
    "aws_secret_access_key", "aws_session_token", "aws_access_key_id",
])
def test_json_aws_credentials_stay_valid_json(name):
    payload = json.dumps({name: "abcd", "region": "us-east-1"})
    safe, findings = redact(payload)
    parsed = json.loads(safe)
    assert parsed[name] == "[REDACTED:JSON_SECRET]"
    assert parsed["region"] == "us-east-1"
    assert len(findings) == 1


def test_noncredential_field_names_are_not_redacted():
    text = "aws_region=us-east-1\naws_account_id=123456789012"
    safe, findings = redact(text)
    assert safe == text
    assert findings == []
