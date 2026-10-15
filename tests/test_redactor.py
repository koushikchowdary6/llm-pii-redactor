import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from redactor import detect, redact, shannon_entropy, _luhn_ok


def _kinds(text):
    return {f.kind for f in detect(text)}


def test_email_detected_and_redacted():
    red, findings = redact("contact bob@example.org please")
    assert "bob@example.org" not in red
    assert "[REDACTED:EMAIL]" in red


def test_aws_key_detected():
    assert "AWS_ACCESS_KEY" in _kinds("key AKIAIOSFODNN7EXAMPLE here")


def test_ssn_detected():
    assert "SSN" in _kinds("ssn 123-45-6789")


def test_valid_credit_card_detected():
    assert "CREDIT_CARD" in _kinds("card 4111 1111 1111 1111")


def test_invalid_credit_card_rejected_by_luhn():
    # 4111...1112 fails the Luhn checksum, so it should NOT be flagged as a card.
    assert "CREDIT_CARD" not in _kinds("number 4111 1111 1111 1112")


def test_luhn_helper():
    assert _luhn_ok("4111111111111111")
    assert not _luhn_ok("4111111111111112")


def test_private_key_header_detected():
    assert "PRIVATE_KEY" in _kinds("-----BEGIN RSA PRIVATE KEY-----")


def test_jwt_detected():
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
    assert "JWT" in _kinds(f"token {jwt}")


def test_high_entropy_secret_detected():
    assert "HIGH_ENTROPY_SECRET" in _kinds("apikey sk-Abc123XyZ789Def456Ghi012Jkl")


def test_plain_english_word_not_flagged_as_secret():
    # An ordinary long word is low-entropy and must not be redacted.
    assert detect("internationalization is a long word") == []


def test_clean_text_yields_no_findings():
    red, findings = redact("The quick brown fox jumps over the lazy dog.")
    assert findings == []
    assert red == "The quick brown fox jumps over the lazy dog."


def test_entropy_monotonic():
    assert shannon_entropy("aaaa") < shannon_entropy("ab12XY")


def test_redaction_preserves_surrounding_text():
    red, _ = redact("start jane@x.com end")
    assert red.startswith("start ") and red.endswith(" end")


def test_complete_private_key_block_is_fully_redacted():
    key = (
        "-----BEGIN PRIVATE KEY-----\n"
        "abc123DEF456+/=\n"
        "\n"
        "xyz789GHI012+/=\n"
        "-----END PRIVATE KEY-----"
    )
    red, findings = redact(f"before {key} after")
    assert key not in red
    assert "[REDACTED:PRIVATE_KEY]" in red
    assert any(f.kind == "PRIVATE_KEY" for f in findings)


def test_incomplete_private_key_fails_closed_to_end_of_input():
    text = (
        "prefix -----BEGIN RSA PRIVATE KEY-----\n"
        "abc123DEF456+/=\n"
        "unterminated secret material"
    )
    red, findings = redact(text)
    assert "abc123DEF456" not in red
    assert "unterminated secret material" not in red
    assert red == "prefix [REDACTED:PRIVATE_KEY]"
    assert any(f.kind == "PRIVATE_KEY" for f in findings)


def test_adjacent_private_key_blocks_are_redacted_independently():
    first = (
        "-----BEGIN PRIVATE KEY-----\n"
        "abc123DEF456+/=\n"
        "-----END PRIVATE KEY-----"
    )
    second = (
        "-----BEGIN EC PRIVATE KEY-----\n"
        "xyz789GHI012+/=\n"
        "-----END EC PRIVATE KEY-----"
    )
    red, findings = redact(f"{first}\nseparator\n{second}")
    assert first not in red and second not in red
    assert red.count("[REDACTED:PRIVATE_KEY]") == 2
    assert sum(f.kind == "PRIVATE_KEY" for f in findings) == 2
