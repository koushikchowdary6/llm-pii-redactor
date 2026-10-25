# LLM PII / Secret Redactor 🕶️🤖

[![CI](https://github.com/koushikchowdary6/llm-pii-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/llm-pii-redactor/actions/workflows/ci.yml)

An **AI-safety guardrail** that detects and redacts sensitive data — PII and
secrets — from text **before it's sent to an LLM** (or logged, or shared).
People routinely paste emails, API keys, and customer records into prompts;
that data then leaves your trust boundary. This strips it first.

Pure Python standard library — deterministic, offline, no dependencies.

## What it catches

**Pattern detectors:** email, phone, US SSN, credit card (with a **Luhn
checksum** so fake 16-digit numbers aren't flagged), IPv4 and validated IPv6 literals (including bracketed and scoped forms), AWS access keys,
JWTs, GitHub classic/fine-grained access tokens, OpenAI (`sk-`, `sk-proj-`, `sk-svcacct-`) and Anthropic (`sk-ant-`) API key prefixes, and private-key blocks. HTTP `Authorization` and `Proxy-Authorization` headers are redacted as complete opaque credential lines, including Digest, AWS SigV4, custom schemes, and multi-field values that could otherwise leak a trailing secret. For a single recognized provider token under Bearer/Basic/Token, the more specific finding type is preserved. Bare scheme names without credentials are not redacted. Common credential-bearing `X-API-Key`, `API-Key`, `X-Auth-Token`, `X-Access-Token`, `Cookie`, and `Set-Cookie` header values are redacted as complete values, even when their contents are short, low-entropy, or contain multiple credentials. Non-sensitive headers are preserved.

**Entropy detector:** long, high-entropy tokens that *look* like secrets
(random API keys) even when they match no known pattern — while leaving
ordinary long words alone.

## Usage

```bash
# redact a file
python src/redactor.py notes.txt

# redact stdin, with a summary of what was removed
echo "email a@b.com, key AKIAIOSFODNN7EXAMPLE" | python src/redactor.py --report
```

```
email [REDACTED:EMAIL], key [REDACTED:AWS_ACCESS_KEY]
--- redaction report ---
  AWS_ACCESS_KEY: 1
  EMAIL: 1
```

Or use it as a library, e.g. in an LLM app's input pipeline:

```python
from redactor import redact
safe_text, findings = redact(user_input)
# send only safe_text to the model
# for audit telemetry, log only finding types/counts — never Finding.value
```

## Tests

```bash
PYTHONPATH=src python -m pytest tests/ -v
```

Tests cover detector behavior, GitHub/OpenAI/Anthropic token formats, Luhn validation, entropy-based secret detection,
clean-text pass-through, complete/incomplete PEM private-key handling, and
multiple adjacent key blocks.

## Where it fits

This is a companion to my
[prompt-injection-detector](https://github.com/koushikchowdary6/prompt-injection-detector):
one guards the *input* against malicious instructions, this guards it against
*data leakage*. Both are the kind of input-side controls a responsible LLM
application needs.

## ⚠️ Honesty about scope

Redaction is a strong safety net, not a guarantee. Regex + entropy detection
catches structured and obviously-random secrets, but can miss unusually
formatted data, short/unknown provider tokens, or context-dependent PII (a name in a sentence, an internal
project codename). Use it as one layer of defense-in-depth, tuned to your data,
not as a sole control.

## Author

Koushik Chowdary — [LinkedIn](https://linkedin.com/in/koushik-chowdary) · [GitHub](https://github.com/koushikchowdary6)


## Safe audit logging

`Finding.value` intentionally contains the original matched secret/PII so callers
can inspect a detection in memory. Do **not** write that value to application logs,
telemetry, traces, or analytics. Prefer aggregate metadata such as finding kinds
and counts:

```python
from collections import Counter

safe_text, findings = redact(user_input)
audit_counts = Counter(f.kind for f in findings)
```

This avoids turning the redaction layer itself into a secondary data-leak path.
