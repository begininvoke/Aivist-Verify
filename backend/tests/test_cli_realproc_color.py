# ==============================================================================
# Bug 1 (REAL PROCESS) — color must degrade to plain, never leak raw ANSI. Drives the ACTUAL
# `python run.py` and asserts on its captured stdout/stderr BYTES (the method that was missing when the
# in-process tests passed but PowerShell leaked). NOTE: a captured pipe is non-TTY ⇒ the CLI takes the
# plain path here; the Windows-console VT *rendering* can only be confirmed by a human on Windows.
# ==============================================================================
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.tests._cli_harness import run_cli, seed_target, VERIFY_SCRIPT

_ESC = b"\x1b["


def test_real_cli_emits_zero_raw_ansi_when_piped(tmp_path):
    seed_target(tmp_path)
    out, err, code = run_cli(VERIFY_SCRIPT, home=tmp_path)     # piped stdout -> non-VT -> plain path
    blob = out + err
    assert _ESC not in blob                                    # ZERO raw escape bytes in the real output
    assert b"Confirming on" in out                            # ...and it is real, non-trivial CLI output


def test_real_cli_plain_under_no_color(tmp_path):
    seed_target(tmp_path)
    out, err, code = run_cli(VERIFY_SCRIPT, home=tmp_path, env_extra={"NO_COLOR": "1"})
    assert _ESC not in (out + err)                             # NO_COLOR honored on the real process


def test_real_cli_can_emit_ansi_when_forced(tmp_path):
    seed_target(tmp_path)
    out, err, code = run_cli(VERIFY_SCRIPT, home=tmp_path, env_extra={"FORCE_COLOR": "1"})
    assert _ESC in (out + err)                                 # same real process CAN color -> painter works


# ------------------------------------------------------------------ strip-ALL-escapes fallback (unit)
def test_strip_ansi_removes_sequences():
    from backend.app.cli.confirm_render import _strip_ansi
    assert _strip_ansi("\x1b[31m\x1b[1mHACK\x1b[0m") == "HACK"


def test_render_tree_strips_escapes_embedded_in_content_when_plain():
    # An escape sequence arriving INSIDE captured content (a response body) must not survive plain render.
    from backend.app.cli.confirm_render import render_tree
    rec = {
        "shape": "read_semantic", "final_verdict": "verified", "guard_override": None,
        "method": "GET", "baseline_path": "/books/v1/x", "attack_path": "/books/v1/x",
        "evidence": {"attack": {
            "request": {"method": "GET", "url": "http://t/books/v1/x", "headers": {}},
            "response": {"status_code": 200, "content_length": 12, "body": "\x1b[31mSECRET\x1b[0m"}}},
    }
    out = render_tree(rec, color=False)
    assert "\x1b[" not in out                                  # embedded escape stripped in plain mode
