# Migration provenance

Snapshot migration from https://github.com/koushikchowdary6/llm-pii-redactor/tree/17b46b60cafb74021a1d8ca1388e5f792608ee03/projects/document-review.

The source tree identifier is 17b46b60cafb74021a1d8ca1388e5f792608ee03. Original commit history remains in the source repository; this standalone snapshot does not reattribute earlier work. Code was initially built with AI assistance and subsequently maintained in that repository. This migration preserves upstream copyright notices and does not claim the reference resume's employment or client work.

## File mapping

- `tests/test_authorization_header_redaction.py` → `tests/test_authorization_header_redaction.py`
- `tests/test_ai_provider_header_redaction.py` → `tests/test_ai_provider_header_redaction.py`
- `projects/document-review/review.py` → `review.py`
- `projects/document-review/examples/synthetic.txt` → `examples/synthetic.txt`
- `src/redactor.py` → `redactor.py`
- `tests/test_form_encoded_secrets.py` → `tests/test_form_encoded_secrets.py`
- `tests/test_aws_shared_credentials.py` → `tests/test_aws_shared_credentials.py`
- `tests/test_folded_header_redaction.py` → `tests/test_folded_header_redaction.py`
- `tests/test_quoted_yaml_secret_keys.py` → `tests/test_quoted_yaml_secret_keys.py`
- `tests/test_oauth_fragment_secrets.py` → `tests/test_oauth_fragment_secrets.py`
- `projects/document-review/.gitignore` → `.gitignore`
- `tests/test_env_quoted_secrets.py` → `tests/test_env_quoted_secrets.py`
- `tests/test_numeric_json_credentials.py` → `tests/test_numeric_json_credentials.py`
- `tests/test_proxy_api_key_headers.py` → `tests/test_proxy_api_key_headers.py`
- `tests/test_forwarded_authorization_headers.py` → `tests/test_forwarded_authorization_headers.py`
- `projects/document-review/decision.py` → `decision.py`
- `tests/test_ipv6_redaction.py` → `tests/test_ipv6_redaction.py`
- `projects/document-review/test_decision.py` → `test_decision.py`
- `tests/test_redactor.py` → `tests/test_redactor.py`
- `tests/test_structured_session_secrets.py` → `tests/test_structured_session_secrets.py`
- `tests/test_sensitive_header_redaction.py` → `tests/test_sensitive_header_redaction.py`
- `tests/test_yaml_secret_redaction.py` → `tests/test_yaml_secret_redaction.py`
- `projects/document-review/README.md` → `README.md`
- `tests/test_json_secret_redaction.py` → `tests/test_json_secret_redaction.py`
- `tests/test_url_query_secret_redaction.py` → `tests/test_url_query_secret_redaction.py`
- `tests/__init__.py` → `tests/__init__.py`
- `LICENSE` → `LICENSE`
- `tests/test_custom_json_mask_escaping.py` → `tests/test_custom_json_mask_escaping.py`
- `tests/test_yaml_block_secret_redaction.py` → `tests/test_yaml_block_secret_redaction.py`
- `tests/test_bounded_input.py` → `tests/test_bounded_input.py`
- `projects/document-review/test_review.py` → `test_review.py`

Changes at migration: root-level layout, standalone imports, README paths, CI, development dependencies and this provenance record. Implementation behavior is otherwise preserved.
