# ==============================================================================
# Bug 2 (REAL PROCESS) — the interactive `verify` path must read attacker + owner + bystander from the
# environment (never a manual paste) when all three TARGET_*_TOKEN are set. Drives the ACTUAL
# `python run.py` and asserts on captured bytes (the in-process test alone was the gap). Red line: the
# raw token values must NOT appear (masked), and the run must complete cleanly (no getpass hang).
# ==============================================================================
import os
import sys

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, _REPO_ROOT)

from backend.tests._cli_harness import run_cli, seed_target, VERIFY_SCRIPT, ENV_TOKENS


def test_real_cli_verify_reads_all_three_tokens_from_env(tmp_path):
    seed_target(tmp_path)
    out, err, code = run_cli(VERIFY_SCRIPT, home=tmp_path)
    blob = out + err

    # every one of the three is picked up from the environment (masked confirmation), so NONE fell
    # through to a paste prompt — that message is echoed ONLY on an env read.
    for key in ("TARGET_ATTACKER_TOKEN", "TARGET_OWNER_TOKEN", "TARGET_BYSTANDER_TOKEN"):
        assert (b"from environment (" + key.encode() + b", masked)") in blob, key

    # the raw token VALUES never appear anywhere in the output (masked)
    for val in ENV_TOKENS.values():
        assert val.encode() not in blob

    # a clean exit proves getpass was never reached (env supplied all three; a fall-through would have
    # blocked on the console-reading getpass or shown a distinct hidden-input prompt).
    assert code == 0
