# ==============================================================================
# Bug C (real-path) — interactive `verify` on a SPEC-LESS selected target must build the op from the
# target's OWN fields and reach a verdict. Without the fix it does NOT crash: run_external_verify
# catches the empty --spec at external_verify.py:585-590 and returns exit 2 with "[NOT DATA] could not
# read --spec" — a graceful REFUSAL, so a spec-less target could never be verified from the console.
# The earlier tests never drove do_verify against a spec-less selected target, so they missed it.
# ==============================================================================
import os
import sys

from pydantic import SecretStr

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.app.core.config import settings
from backend.app.cli.console.controller import ConsoleController
from backend.app.cli.console import targets as tmod
from backend.tests.test_scan_run import _result


def _async_engine():
    async def eng(**kw):
        eng.calls.append(kw)
        return _result(ai_verdict="failed")
    eng.calls = []
    return eng


def test_spec_less_verify_builds_op_from_target_and_reaches_verdict(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "LLM_API_KEY", SecretStr("test-key"))
    monkeypatch.setattr(settings, "AI_DEEP_VERIFY_ENABLED", False)
    monkeypatch.setenv("TARGET_ATTACKER_TOKEN", "ATK-ENV")
    monkeypatch.setenv("TARGET_OWNER_TOKEN", "OWN-ENV")
    eng = _async_engine()
    lines = []
    it = iter(["", ""])   # assert-owner? blank, account-labels? blank
    c = ConsoleController(prompt=lambda *a: next(it, ""), secret_prompt=lambda *a: "",
                          echo=lambda *a: lines.append(" ".join(str(x) for x in a)),
                          config_path=str(tmp_path / "c.toml"), engine=eng)
    # a SPEC-LESS target (spec_path="") with the endpoint + ids filled in — exactly the director's case
    c.selected = tmod.Target(name="vampi", base_url="http://localhost:5000", spec_path="", method="GET",
                             path_template="/books/v1/{book_title}", id_location="path",
                             id_param="book_title", attacker_id="alicebook", victim_id="bobbook")
    c.do_verify()
    out = "\n".join(lines)

    assert "No such file or directory: ''" not in out           # not the empty-path FileNotFoundError text
    assert "[NOT DATA] could not read --spec" not in out         # and not the graceful empty-spec REFUSAL
    assert len(eng.calls) == 1                                  # the engine was actually reached
    # the op was built from the target's OWN fields (attacker id filled into the path), not a file
    assert eng.calls[0]["parsed_request"]["path"] == "/books/v1/alicebook"
    # a minimal spec was synthesized from the target's endpoint and handed to the engine as the catalog
    assert "GET /books/v1/{book_title}" in list(eng.calls[0].get("available_endpoints") or [])
    assert "exit 0" in out or "REFUTED" in out                  # a verdict was rendered end-to-end
