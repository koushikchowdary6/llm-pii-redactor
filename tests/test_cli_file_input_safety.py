"""CLI file input is an untrusted trust boundary for the LLM guardrail."""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import redactor  # noqa: E402


def _run_file(monkeypatch, capsys, path):
    monkeypatch.setattr(sys, "argv", ["redactor.py", str(path)])
    with pytest.raises(SystemExit) as exc:
        redactor.main()
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    return captured.err


def test_cli_rejects_symlink_without_exposing_target(monkeypatch, capsys, tmp_path):
    target = tmp_path / "private.txt"
    secret = "do-not-print-this-credential"
    target.write_text(secret, encoding="utf-8")
    link = tmp_path / "prompt.txt"
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    error = _run_file(monkeypatch, capsys, link)
    assert "regular file" in error
    assert secret not in error


def test_cli_rejects_directory(monkeypatch, capsys, tmp_path):
    assert "regular file" in _run_file(monkeypatch, capsys, tmp_path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_cli_rejects_fifo_without_hanging(monkeypatch, capsys, tmp_path):
    path = tmp_path / "prompt.pipe"
    os.mkfifo(path)
    assert "regular file" in _run_file(monkeypatch, capsys, path)


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs unavailable")
def test_cli_detects_fifo_swapped_after_lstat(monkeypatch, capsys, tmp_path):
    path = tmp_path / "prompt.txt"
    path.write_text("original", encoding="utf-8")
    real_open = os.open

    def replace_with_fifo(filename, flags, *args, **kwargs):
        path.unlink()
        os.mkfifo(path)
        assert flags & os.O_NONBLOCK
        return real_open(filename, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", replace_with_fifo)
    assert "regular file" in _run_file(monkeypatch, capsys, path)


def test_cli_accepts_exact_limit_of_four_byte_unicode(monkeypatch, capsys, tmp_path):
    monkeypatch.setattr(redactor, "MAX_INPUT_CHARS", 4)
    path = tmp_path / "unicode.txt"
    path.write_text("\U0001f600" * 4, encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redactor.py", str(path)])
    assert redactor.main() == 0
    captured = capsys.readouterr()
    assert captured.out == "\U0001f600" * 4
    assert captured.err == ""
