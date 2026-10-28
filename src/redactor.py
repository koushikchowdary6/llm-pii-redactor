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
import json
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
    # Legacy folded continuation lines belong to the same credential and
    # must not survive redaction as a separate line.
    ("AUTHORIZATION_CREDENTIAL", re.compile(
        r"(?im)^[ \t]*(?:Proxy-)?Authorization[ \t]*:[ \t]*"
        r"(?P<value>(?:[^\r\n \t][^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*|\r?\n[ \t]+[^\r\n \t][^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*))"
    )),
    # Opaque credentials in common HTTP and cloud/AI-provider headers can be short or low entropy.
    # Redact the entire value, not just a token-looking substring. Restrict
    # matching to header lines so ordinary prose is unaffected. Include
    # folded continuation lines in the value to prevent partial disclosure.
    ("SENSITIVE_HEADER", re.compile(
        r"(?im)^[ \t]*(?:X-API-Key|API-Key|X-API-Token|X-Auth-Token|X-Access-Token|X-Goog-Api-Key|X-Amz-Security-Token|X-Functions-Key|Cookie|Set-Cookie)"
        r"[ \t]*:[ \t]*(?P<value>(?:[^\r\n \t][^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*|\r?\n[ \t]+[^\r\n \t][^\r\n]*(?:\r?\n[ \t]+[^\r\n]*)*))"
    )),
    # Signed URLs, OAuth fragments, and form-encoded request bodies can
    # carry short credentials. A form body may start with access_token=...,
    # without a URL query delimiter. Also cover quoted or space-padded .env
    # assignments whose low-entropy values otherwise survive unchanged.
    # Reject partial key-name matches while preserving the assignment name.
    # Include quote delimiters in the redacted span to avoid leaking quoted
    # values with embedded spaces or escaped quotes.
    ("URL_QUERY_SECRET", re.compile(
        r"""(?<![A-Za-z0-9_.-])(?:aws[_-]?(?:secret[_-]?access[_-]?key|session[_-]?token|access[_-]?key[_-]?id)|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|x-amz-(?:signature|security-token)|password|passwd|secret|signature|sig|token)[ \t]*=[ \t]*(?P<secret>"(?:\\.|[^"\\\r\n])+"|'(?:\\.|[^'\\\r\n])+'|[^&#\s"'<>),;]+)""",
        re.IGNORECASE,
    )),
    # JSON credential fields often contain short, low-entropy values that
    # provider-token and entropy detectors miss. Match the *string contents*
    # so replacement preserves valid JSON and leaves the key inspectable.
    # Escaped quotes/backslashes are consumed as part of the same value.
    # YAML-style configuration commonly uses "password: value" instead of
    # .env "=" assignments. Short and low-entropy secrets must not escape
    # redaction just because they lack a provider prefix. Match only a
    # standalone credential key, preserving its indentation and key name.
    # Keep trailing YAML comments outside the secret span; an unquoted
    # value may contain spaces or a literal '#' without a preceding space.
    ("CONFIG_SECRET", re.compile(
        r"""^[ \t]*(?:aws[_-]?(?:secret[_-]?access[_-]?key|session[_-]?token|access[_-]?key[_-]?id)|api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|password|passwd|secret|signature|token|session[_-]?token|webhook[_-]?secret)[ \t]*:[ \t]*(?P<secret>"(?:\\.|[^"\\\r\n])+"|'(?:\\.|[^'\\\r\n])+'|[^ \t\r\n#"'][^\r\n]*?)(?=[ \t]+\#.*\r?$|[ \t]*\r?$)""",
        re.IGNORECASE | re.MULTILINE,
    )),
    ("JSON_SECRET", re.compile(
        r'"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|'
        r'client[_-]?secret|aws[_-]?(?:secret[_-]?access[_-]?key|session[_-]?token|access[_-]?key[_-]?id)|password|passwd|secret|token|authorization|'
        r'session[_-]?token|webhook[_-]?secret)"[ \t\r\n]*:[ \t\r\n]*'
        r'"(?P<value>(?:\\.|[^"\\])+)"',
        re.IGNORECASE,
    )),
    # JSON credentials sometimes arrive as unquoted numeric values (PINs,
    # numeric API tokens, legacy passwords). Preserve the JSON structure by
    # quoting the replacement in redact(); never expose the numeric value.
    # The trailing delimiter prevents matching a prefix of malformed JSON.
    ("JSON_NUMERIC_SECRET", re.compile(
        r'"(?:api[_-]?key|access[_-]?token|refresh[_-]?token|id[_-]?token|'
        r'client[_-]?secret|aws[_-]?(?:secret[_-]?access[_-]?key|session[_-]?token|access[_-]?key[_-]?id)|'
        r'password|passwd|secret|token|authorization|session[_-]?token|webhook[_-]?secret)"'
        r'[ \t\r\n]*:[ \t\r\n]*(?P<value>-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)'
        r'(?=[ \t\r\n]*[,}\]])',
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
          "OPENAI_API_KEY", "SENSITIVE_HEADER", "CONFIG_SECRET", "URL_QUERY_SECRET", "EMAIL", "SSN",
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
        # Query parameter names are metadata, not secret values. Preserve
        # them so a separately redacted credential value stays attributable.
        if (m.start() > 0 and text[m.start() - 1] in "?&"
                and text[m.end():m.end() + 1] == "="):
            continue
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
    # Claim complete sensitive header values before token/IP detectors.
    # Otherwise an IPv6 literal or provider key inside a Cookie header can
    # preempt the full-value match and leave the rest of the cookie exposed.
    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []
    # Header names are public metadata, not high-entropy secret values.
    # Preserve the header name even when its hyphenated spelling looks random.
    sensitive_header_name_spans: list[tuple[int, int]] = []

    def overlaps(s: int, e: int) -> bool:
        return any(s < ce and cs < e for cs, ce in claimed)

    for match in _PATTERN_MAP["SENSITIVE_HEADER"].finditer(text):
        start, end = match.span("value")
        sensitive_header_name_spans.append((match.start(), start))
        findings.append(Finding("SENSITIVE_HEADER", match.group("value"), start, end))
        claimed.append((start, end))

    # An Authorization header can carry Digest, AWS SigV4, or a custom
    # credential scheme. Redact the complete opaque header so commas,
    # whitespace and multiple credential fields cannot leave a tail exposed.
    # Preserve provider-specific finding kinds for a single known token.
    for match in _PATTERN_MAP["AUTHORIZATION_CREDENTIAL"].finditer(text):
        value = match.group("value").strip()
        parts = value.split()
        if len(parts) == 1 and parts[0].lower() in {"bearer", "basic", "token"}:
            continue  # A bare scheme is not a credential.
        if (len(parts) == 2 and parts[0].lower() in {"bearer", "basic", "token"}
                and any(_PATTERN_MAP[kind].fullmatch(parts[1]) for kind in (
                    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN",
                    "AWS_ACCESS_KEY", "JWT",
                ))):
            continue
        findings.append(Finding(
            "AUTHORIZATION_CREDENTIAL", match.group(), match.start(), match.end()
        ))
        claimed.append(match.span())

    # Claim JSON credential strings before IP/provider/entropy detectors.
    # Otherwise a nested email or token can consume only part of a value,
    # leaving surrounding credential bytes visible in the sanitized JSON.
    for kind in ("JSON_SECRET", "JSON_NUMERIC_SECRET"):
        for match in _PATTERN_MAP[kind].finditer(text):
            start, end = match.span("value")
            if not overlaps(start, end):
                findings.append(Finding(kind, match.group("value"), start, end))
                claimed.append((start, end))

    # Validate and claim complete IPv6 literals before the IPv4 pattern.
    for finding in _find_ipv6(text):
        if not overlaps(finding.start, finding.end):
            findings.append(finding)
            claimed.append((finding.start, finding.end))

    for kind in _ORDER:
        for m in _PATTERN_MAP[kind].finditer(text):
            # Query-parameter detectors redact only the value, not its name.
            # Other detectors continue to redact their entire match.
            if kind in ("URL_QUERY_SECRET", "CONFIG_SECRET", "SENSITIVE_HEADER"):
                field = "value" if kind == "SENSITIVE_HEADER" else "secret"
                s, e = m.span(field)
                val = m.group(field)
            else:
                s, e, val = m.start(), m.end(), m.group()
            if overlaps(s, e):
                continue
            if kind == "CREDIT_CARD" and not _luhn_ok(val):
                continue
            findings.append(Finding(kind, val, s, e))
            claimed.append((s, e))

    for f in _find_high_entropy(text):
        if (not overlaps(f.start, f.end)
                and not any(start <= f.start and f.end <= end
                            for start, end in sensitive_header_name_spans)):
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
        replacement = mask.format(kind=f.kind)
        # JSON numbers cannot be replaced with bare [REDACTED] text without
        # breaking the surrounding JSON document. Quote and escape the mask.
        if f.kind == "JSON_NUMERIC_SECRET":
            replacement = json.dumps(replacement)
        out.append(replacement)
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
