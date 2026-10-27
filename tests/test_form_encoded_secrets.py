"""Secret assignments in form-encoded bodies must not bypass URL-only rules."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from redactor import redact


@pytest.mark.parametrize("key", [
    "access_token", "refresh_token", "client_secret", "password",
    "api_key", "sig", "X-Amz-Signature", "TOKEN",
])
def test_form_body_first_parameter_is_redacted(key):
    body = f"{key}=aaaa&grant_type=client_credentials"
    safe, findings = redact(body)
    assert safe == f"{key}=[REDACTED:URL_QUERY_SECRET]&grant_type=client_credentials"
    assert [f.kind for f in findings] == ["URL_QUERY_SECRET"]
    assert findings[0].value == "[REDACTED]"


def test_multiline_log_assignments_and_multiple_form_fields():
    text = "POST /token\nContent-Type: application/x-www-form-urlencoded\n\nclient_id=public&client_secret=aaaa&access_token=bbbb"
    safe, findings = redact(text)
    assert "client_id=public" in safe
    assert "client_secret=[REDACTED:URL_QUERY_SECRET]" in safe
    assert "access_token=[REDACTED:URL_QUERY_SECRET]" in safe
    assert "aaaa" not in safe and "bbbb" not in safe
    assert len(findings) == 2


def test_assignment_keys_must_not_match_inside_other_names():
    text = "prefix_access_token=demo password_hint=demo signature_version=v4"
    assert redact(text) == (text, [])


def test_short_secret_in_log_line_is_masked_without_entropy():
    safe, findings = redact("credentials: client_secret=aaaa next=public")
    assert safe == "credentials: client_secret=[REDACTED:URL_QUERY_SECRET] next=public"
    assert [f.kind for f in findings] == ["URL_QUERY_SECRET"]
