"""YAML literal/folded secret blocks must be redacted in full."""

import sys
from pathlib import Path

import pytest


from redactor import redact


@pytest.mark.parametrize("indicator", ["|", ">", "|-", ">+", "|2-", ">-2"])
def test_multiline_credential_blocks_are_fully_redacted(indicator):
    source = (
        "service: billing\n"
        f"password: {indicator}\n"
        "  short-secret\n"
        "  second secret line\n"
        "region: west\n"
    )
    safe, findings = redact(source)
    assert safe == (
        "service: billing\n"
        "password: [REDACTED:CONFIG_SECRET]\n"
        "region: west\n"
    )
    assert len(findings) == 1
    assert findings[0].kind == "CONFIG_SECRET"
    assert findings[0].value == "[REDACTED]"
    assert source[findings[0].start:findings[0].end].startswith(indicator)
    assert "second secret line" not in safe


def test_nested_yaml_block_and_blank_lines_do_not_leak():
    source = (
        "config:\n"
        "  token: |\n"
        "    line-one\n"
        "\n"
        "    token: nested secret\n"
        "  region: west\n"
        "enabled: true\n"
    )
    safe, findings = redact(source)
    assert safe == (
        "config:\n"
        "  token: [REDACTED:CONFIG_SECRET]\n"
        "  region: west\n"
        "enabled: true\n"
    )
    assert [f.kind for f in findings] == ["CONFIG_SECRET"]


def test_non_secret_multiline_yaml_is_preserved():
    source = "description: |\n  public project details\nregion: west\n"
    safe, findings = redact(source)
    assert safe == source
    assert findings == []


def test_secret_block_at_end_of_document_is_redacted():
    source = "password: >\n  line one\n  line two"
    safe, findings = redact(source)
    assert safe == "password: [REDACTED:CONFIG_SECRET]"
    assert len(findings) == 1
