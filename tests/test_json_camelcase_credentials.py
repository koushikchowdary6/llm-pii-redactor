"""CamelCase credential keys must be redacted even for short, low-entropy values."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from redactor import redact


@pytest.mark.parametrize("key", [
    "apiKey", "accessToken", "refreshToken", "idToken", "clientSecret",
    "awsSecretAccessKey", "awsAccessKeyId", "awsSessionToken",
    "sessionToken", "webhookSecret", "proxyAuthorization", "xAmzSecurityToken",
])
@pytest.mark.parametrize("value, kind", [
    ("aaaa", "JSON_SECRET"),
    (1234, "JSON_NUMERIC_SECRET"),
])
def test_camelcase_credentials_redacted_as_complete_valid_json(key, value, kind):
    source = json.dumps({"config": {key: value}, "note": "safe"})
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "config": {key: f"[REDACTED:{kind}]"}, "note": "safe"
    }
    assert [finding.kind for finding in findings] == [kind]
    assert findings[0].value == "[REDACTED]"


def test_nested_short_camelcase_secrets_do_not_leak():
    source = json.dumps({
        "auth": {"clientSecret": "abcd", "accessToken": "1234"},
        "metadata": {"clientSecretHint": "keep", "apiKeyName": "visible"},
    })
    safe, findings = redact(source)
    assert json.loads(safe) == {
        "auth": {
            "clientSecret": "[REDACTED:JSON_SECRET]",
            "accessToken": "[REDACTED:JSON_SECRET]",
        },
        "metadata": {"clientSecretHint": "keep", "apiKeyName": "visible"},
    }
    assert len(findings) == 2


def test_custom_json_mask_remains_escaped_for_camelcase_keys():
    safe, findings = redact('{"clientSecret":"abc"}', mask='safe "{kind}"')
    assert json.loads(safe) == {"clientSecret": 'safe "JSON_SECRET"'}
    assert len(findings) == 1
