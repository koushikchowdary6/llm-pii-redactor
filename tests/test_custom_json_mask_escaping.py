"""Custom redaction masks must preserve the JSON string contract."""

import json
import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize("mask", [
    'hidden "quoted" \\ slash {kind}',
    "line one\nline two\ttab {kind}",
    "unicode snowman ☃ and emoji 😀 {kind}",
])
def test_custom_mask_escapes_json_string_and_numeric_secrets(mask):
    source = '{"password":"abcd","token":1234,"safe":"visible"}'
    safe, findings = redact(source, mask=mask)
    assert json.loads(safe) == {
        "password": mask.format(kind="JSON_SECRET"),
        "token": mask.format(kind="JSON_NUMERIC_SECRET"),
        "safe": "visible",
    }
    assert [f.kind for f in findings] == ["JSON_SECRET", "JSON_NUMERIC_SECRET"]
    assert all(f.value == "[REDACTED]" for f in findings)
    assert '"abcd"' not in safe
    assert '"token":1234' not in safe


def test_default_mask_still_preserves_json_and_unchanged_fields():
    source = json.dumps({"password": "secret-value", "count": 5, "enabled": True})
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "password": "[REDACTED:JSON_SECRET]",
        "count": 5,
        "enabled": True,
    }
    assert [f.kind for f in findings] == ["JSON_SECRET"]
