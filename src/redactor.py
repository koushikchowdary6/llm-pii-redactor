"""
llm-pii-redactor
----------------
Detect and redact sensitive data -- PII and secrets -- from text *before* it
is sent to an LLM (or logged, or shared). A practical AI-safety guardrail:
users routinely paste emails, API keys, and customer records into prompts,
and that data then leaves your trust boundary. This strips it first.

Two detector families:
  * Pattern detectors -- regexes for well-structured PII/secrets (email,
    phone, credit card w/ Luhn check, SSN, IPv4, AWS/OpenAI/Anthropic
    keys, GitHub tokens, JWTs, private keys).
  * Entropy detector -- flags high-entropy tokens that look like generic
    secrets (random API keys) even when they match no known pattern.

Pure standard library. Deterministic. No network, no LLM call needed to run.
"""
from __future__ import annotations

import argparse
import ipaddress
import math
import re
import sys
from dataclasses import dataclass

# --- Pattern detectors ---------------------------------------------------------

_PATTERNS: list[tuple[str, re.Pattern]] = [
    # Some applications use opaque bearer/basic credentials without a provider
    # prefix or enough entropy for generic detection. Redact the *whole* header
    # value (including scheme) so short or repetitive secrets cannot leak.
    # Only match actual header lines, not prose mentioning authorization.
    ("AUTHORIZATION_CREDENTIAL", re.compile(
        r"(?im)^[ \t]*(?:Proxy-)?Authorization[ \t]*:[ \t]*"
        r"(?:Bearer|Basic|Token)[ \t]+[A-Za-z0-9._~+/\-]+=*"
        r"(?![A-Za-z0-9._~+/\-])"
    )),
    # Signed webhook URLs and API requests often put low-entropy secrets in
    # query parameters. Match only the value, preserving the parameter name
    # and URL structure for safe troubleshooting after redaction.
    # Opaque credentials in common HTTP headers can be short or low entropy.
    # Redact the entire value, not just a token-looking substring. Restrict
    # matching to header lines so ordinary prose is unaffected.
    ("SENSITIVE_HEADER", re.compile(
        r"(?im)^[ \\t]*(?:X-API-Key|API-Key|X-Auth-Token|X-Access-Token|Cookie|Set-Cookie)"
        r"[ \\t]*:[ \\t]*(?P<value>[^\\r\\n]+)"
    )),
    ("URL_QUERY_SECRET", re.compile(
        r"""[?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|sig|token)=(?P<secret>[^&#\s"'<>),;]+)""",
        re.IGNORECASE,
    )),
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    # GitHub classic PAT/OAuth/app tokens and fine-grained PATs. Recognize
    # provider-specific prefixes even when a synthetic or low-entropy test
    # token would not pass the generic entropy heuristic.
    ("GITHUB_TOKEN", re.compile(
        r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{20,})\b"
    )),
    # Prefix-aware provider tokens are detected even when a synthetic token
    # has low entropy (e.g. repeated characters in a test fixture).
    ("ANTHROPIC_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b")),
    ("OPENAI_API_KEY", re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("PRIVATE_KEY", re.compile(
        # Match the complete block, including blank lines and nonstandard body
        # formatting. Do not cross into another BEGIN block while seeking END.
        # If the matching END is missing or malformed, fail closed: redact
        # from the private-key header to the next BEGIN marker or end of input.
        # This can intentionally over-redact trailing text after a broken key.
        r"-----BEGIN (?P<label>(?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY)-----"
        r"(?:(?!-----BEGIN ).)*?"
        r"-----END (?P=label)-----"
        r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        r"(?:(?!-----BEGIN ).)*?(?=-----BEGIN |\Z)",
        re.DOTALL,
    )),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")),
    ("SSN", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]*?){13,16}\b")),
    ("PHONE", re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b")),
    ("IPV4", re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")),
]

# Order matters: try the most specific patterns first so a JWT isn't partly
# eaten by a looser rule. CREDIT_CARD/PHONE are validated further below.
_ORDER = ["PRIVATE_KEY", "JWT", "AWS_ACCESS_KEY", "GITHUB_TOKEN", "ANTHROPIC_API_KEY",
          "OPENAI_API_KEY", "AUTHORIZATION_CREDENTIAL", "SENSITIVE_HEADER", "URL_QUERY_SECRET", "EMAIL", "SSN",
          "CREDIT_CARD", "PHONE", "IPV4"]
_PATTERN_MAP = dict(_PATTERNS)


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    start: int
    end: int


def _luhn_ok(number: str) -> bool:
    digits = [int(c) for c in number if c.isdigit()]
    if not 13 <= len(digits) <= 16:
        return False
    checksum, parity = 0, len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _find_high_entropy(text: str, min_len: int = 20, min_entropy: float = 3.5) -> list[Finding]:
    """Flag long, high-entropy tokens that look like generic secrets."""
    findings = []
    for m in re.finditer(r"\b[A-Za-z0-9+/_\-]{%d,}\b" % min_len, text):
        tok = m.group()
        # Skip tokens that are all letters or all digits -- likely words/ids.
        if tok.isalpha() or tok.isdigit():
            continue
        if shannon_entropy(tok) >= min_entropy:
            findings.append(Finding("HIGH_ENTROPY_SECRET", tok, m.start(), m.end()))
    return findings


# Candidate extraction deliberately requires validation with ipaddress: colon-
# separated identifiers are not necessarily addresses. Bracketed URL literals
# and scoped link-local addresses are supported.
_IPV6_CANDIDATES = re.compile(
    r"(?<![A-Za-z0-9_:.])"
    r"(?:\[[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?\]"
    r"|[0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?)"
    r"(?![A-Za-z0-9_:.])"
)


def _find_ipv6(text: str) -> list[Finding]:
    findings = []
    for match in _IPV6_CANDIDATES.finditer(text):
        raw = match.group()
        candidate = raw[1:-1] if raw.startswith("[") and raw.endswith("]") else raw
        if ":" not in candidate:
            continue
        try:
            ipaddress.IPv6Address(candidate)
        except ValueError:
            continue
        findings.append(Finding("IPV6", raw, match.start(), match.end()))
    return findings


def detect(text: str) -> list[Finding]:
    # Validate and claim complete IPv6 literals first. Otherwise the IPv4
    # pattern consumes the dotted tail of an IPv4-mapped IPv6 address and
    # leaks the surrounding IPv6 prefix into the redacted output.
    findings: list[Finding] = _find_ipv6(text)
    claimed: list[tuple[int, int]] = [(f.start, f.end) for f in findings]

    def overlaps(s: int, e: int) -> bool:
        return any(s < ce and cs < e for cs, ce in claimed)

    for kind in _ORDER:
        for m in _PATTERN_MAP[kind].finditer(text):
            # Query-parameter detectors redact only the value, not its name.
            # Other detectors continue to redact their entire match.
            if kind in ("URL_QUERY_SECRET", "SENSITIVE_HEADER"):
                s, e = m.span("secret" if kind == "URL_QUERY_SECRET" else "value")
                val = m.group("secret" if kind == "URL_QUERY_SECRET" else "value")
            else:
                s, e, val = m.start(), m.end(), m.group()
            if overlaps(s, e):
                continue
            if kind == "CREDIT_CARD" and not _luhn_ok(val):
                continue
            findings.append(Finding(kind, val, s, e))
            claimed.append((s, e))

    for f in _find_high_entropy(text):
        if not overlaps(f.start, f.end):
            findings.append(f)
            claimed.append((f.start, f.end))

    return sorted(findings, key=lambda f: f.start)


def redact(
    text: str, mask: str = "[REDACTED:{kind}]", *, include_values: bool = False
) -> tuple[str, list[Finding]]:
    """Redact text and return metadata without raw secrets by default.

    detect() exposes matching values for trusted local analysis, but callers
    often log the findings returned by redact(). Set include_values=True
    only when raw values are explicitly needed. Original offsets are retained.
    """
    findings = detect(text)
    out, last = [], 0
    for f in findings:
        out.append(text[last:f.start])
        out.append(mask.format(kind=f.kind))
        last = f.end
    out.append(text[last:])
    public_findings = (
        findings if include_values
        else [Finding(f.kind, "[REDACTED]", f.start, f.end) for f in findings]
    )
    return "".join(out), public_findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Redact PII/secrets from text before sending it to an LLM.")
    parser.add_argument("path", nargs="?", help="text file to redact; omit to read stdin")
    parser.add_argument("--report", action="store_true", help="also print a summary of what was redacted")
    args = parser.parse_args()

    text = open(args.path).read() if args.path else sys.stdin.read()
    redacted, findings = redact(text)
    sys.stdout.write(redacted)
    if args.report:
        counts: dict[str, int] = {}
        for f in findings:
            counts[f.kind] = counts.get(f.kind, 0) + 1
        sys.stderr.write("\n--- redaction report ---\n")
        for kind, n in sorted(counts.items()):
            sys.stderr.write(f"  {kind}: {n}\n")
        if not findings:
            sys.stderr.write("  (nothing sensitive found)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
