"""Large collections of independent PII spans must not trigger quadratic overlap scans."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from redactor import detect, redact


def test_many_short_independent_email_matches_are_all_redacted():
    # Thousands of small findings previously each scanned every claimed span.
    # The regression asserts exact output and metadata without a flaky wall
    # clock threshold; occupied-byte indexing keeps overlap work bounded.
    addresses = [f"user{i}@example.org" for i in range(3000)]
    source = "\n".join(addresses)
    sanitized, findings = redact(source)
    assert sanitized == "\n".join(["[REDACTED:EMAIL]"] * len(addresses))
    assert len(findings) == len(addresses)
    assert all(f.kind == "EMAIL" and f.value == "[REDACTED]" for f in findings)


def test_overlapping_header_and_secret_spans_still_mask_complete_values():
    source = "X-API-Key: aaaa@example.org\nContact bob@example.org"
    sanitized, findings = redact(source)
    assert sanitized == (
        "X-API-Key: [REDACTED:SENSITIVE_HEADER]\n"
        "Contact [REDACTED:EMAIL]"
    )
    assert [f.kind for f in findings] == ["SENSITIVE_HEADER", "EMAIL"]
    assert detect("No secrets in this sentence.") == []
