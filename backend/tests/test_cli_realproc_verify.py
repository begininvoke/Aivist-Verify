# ==============================================================================
# Bug 3 (REAL PROCESS) — interactive `verify` on a SPEC-LESS selected target must build the op from the
# target's own fields and reach the engine, NOT die on an empty --spec path. Drives the ACTUAL
# `python run.py` on a spec-less target and asserts on captured bytes. (A NOT-DATA from the dead-port
# target is expected here — that is the run reaching the engine, not the bug.)
# ==============================================================================
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.tests._cli_harness import run_cli, seed_target, VERIFY_SCRIPT


def test_real_cli_spec_less_verify_builds_op_and_reaches_engine(tmp_path):
    seed_target(tmp_path)                                       # spec_path="" (spec-less)
    out, err, code = run_cli(VERIFY_SCRIPT, home=tmp_path)
    blob = out + err

    assert b"No such file or directory: ''" not in blob        # the Bug-3 empty-path crash is GONE
    assert b"could not read --spec" not in blob
    # the op was built from the target's OWN fields (attacker id filled into the path template)
    assert b"GET /books/v1/bookTitle77" in blob
    # and it reached the engine: NOT DATA from the dead-port connection (expected / out of scope)
    assert b"NOT DATA" in blob
