"""Oversized prompts must fail closed rather than yielding partially sanitized text."""
import io
import sys
from pathlib import Path

import pytest

import redactor


def test_library_rejects_oversized_input_before_detection(monkeypatch):
    monkeypatch.setattr(redactor, "MAX_INPUT_CHARS", 12)
    with pytest.raises(ValueError, match="input exceeds 12 characters"):
        redactor.detect("secret" + "x" * 7)
    with pytest.raises(ValueError, match="input exceeds 12 characters"):
        redactor.redact("secret" + "x" * 7)


def test_exact_limit_is_accepted(monkeypatch):
    monkeypatch.setattr(redactor, "MAX_INPUT_CHARS", 12)
    assert redactor.redact("hello world!")[0] == "hello world!"


@pytest.mark.parametrize("from_file", [False, True])
def test_cli_rejects_oversized_input_without_leaking_or_partial_output(
    monkeypatch, capsys, tmp_path, from_file
):
    monkeypatch.setattr(redactor, "MAX_INPUT_CHARS", 12)
    secret = "sensitive-value-that-must-not-appear"
    if from_file:
        path = tmp_path / "prompt.txt"
        path.write_text(secret, encoding="utf-8")
        argv = ["redactor.py", str(path), "--report"]
    else:
        monkeypatch.setattr(sys, "stdin", io.StringIO(secret))
        argv = ["redactor.py", "--report"]
    monkeypatch.setattr(sys, "argv", argv)
    with pytest.raises(SystemExit) as exc:
        redactor.main()
    assert exc.value.code == 2
    output = capsys.readouterr()
    assert output.out == ""
    assert secret not in output.err
    assert "input exceeds 12 characters" in output.err
