# LLM PII / Secret Redactor 🕶️🤖

[![CI](https://github.com/koushikchowdary6/llm-pii-redactor/actions/workflows/ci.yml/badge.svg)](https://github.com/koushikchowdary6/llm-pii-redactor/actions/workflows/ci.yml)

An **AI-safety guardrail** that detects and redacts sensitive data — PII and
secrets — from text **before it's sent to an LLM** (or logged, or shared).
People routinely paste emails, API keys, and customer records into prompts;
that data then leaves your trust boundary. This strips it first.

Pure Python standard library — deterministic, offline, no dependencies.

## What it catches

**Pattern detectors:** email, phone, US SSN, credit card (with a **Luhn
checksum** so fake 16-digit numbers aren't flagged), IPv4, AWS access keys,
JWTs, and private-key headers.

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
# send safe_text to the model; log `findings` for auditing
```

## Tests

```bash
PYTHONPATH=src python -m pytest tests/ -v
```

13 tests: each detector type, the Luhn check *rejecting* an invalid card, the
entropy detector catching a generic key but **not** flagging a plain English
word, and that clean text passes through untouched.

## Where it fits

This is a companion to my
[prompt-injection-detector](https://github.com/koushikchowdary6/prompt-injection-detector):
one guards the *input* against malicious instructions, this guards it against
*data leakage*. Both are the kind of input-side controls a responsible LLM
application needs.

## ⚠️ Honesty about scope

Redaction is a strong safety net, not a guarantee. Regex + entropy detection
catches structured and obviously-random secrets, but can miss unusually
formatted data or context-dependent PII (a name in a sentence, an internal
project codename). Use it as one layer of defense-in-depth, tuned to your data,
not as a sole control.

## Author

Koushik Chowdary — [LinkedIn](https://linkedin.com/in/koushik-chowdary) · [GitHub](https://github.com/koushikchowdary6)
