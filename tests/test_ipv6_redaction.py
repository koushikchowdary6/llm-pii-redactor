"""IPv6 privacy regressions: validate addresses, avoid colon-text false positives."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from redactor import detect, redact


@pytest.mark.parametrize("literal", [
    "2001:db8::1",
    "2001:0db8:0000:0000:0000:ff00:0042:8329",
    "::1",
    "[2001:db8::1]",
    "::ffff:192.0.2.128",
    "fe80::1%eth0",
])
def test_ipv6_addresses_are_redacted_without_leaking_parts(literal):
    output, findings = redact(f"source={literal} end")
    assert literal not in output
    assert output == "source=[REDACTED:IPV6] end"
    assert [f.kind for f in findings] == ["IPV6"]
    assert all(f.value == "[REDACTED]" for f in findings)


@pytest.mark.parametrize("text", [
    "release v1:2:3",
    "ratio 12:30:45",
    "invalid 2001:db8::gggg",
    "not-an-ip 12345:67890:abcd",
])
def test_colon_separated_non_addresses_are_not_redacted_as_ipv6(text):
    assert not any(f.kind == "IPV6" for f in detect(text))


def test_ipv4_behavior_remains_unchanged():
    output, findings = redact("connect 192.0.2.42")
    assert output == "connect [REDACTED:IPV4]"
    assert [f.kind for f in findings] == ["IPV4"]
