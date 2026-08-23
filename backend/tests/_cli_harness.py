# ==============================================================================
# Real-process CLI harness — spawns the ACTUAL `aivist` entry (`python run.py`), feeds it real stdin,
# and returns its captured stdout/stderr BYTES. This exists because the prior regressions passed
# in-process unit tests but broke on the real CLI: these helpers drive the real process instead.
#
# Isolation: USERPROFILE/HOME point at a tmp home so `branding.config_dir()` / `targets.targets_dir()`
# (both expanduser("~")-derived) land in tmp; a dummy GEMINI_API_KEY clears the API-key gate; all three
# TARGET_*_TOKEN are set so the env-first path is taken and getpass (which reads the console, not the
# stdin pipe) is never reached -> the piped run completes cleanly. The seeded target's base_url points at
# a dead port so the engine call fails fast (connection refused -> NOT DATA) with no real network/LLM use.
# ==============================================================================
from __future__ import annotations

import os
import sys
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple

_REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# A spec-less target mirroring the director's real 'vampi' (spec_path="" -> exercises the Bug-3 path).
# base_url is a dead port so `verify` reaches the engine then fails fast (connection refused = NOT DATA).
SPECLESS_TARGET_TOML = (
    'name = "vampi"\n'
    'base_url = "http://127.0.0.1:59999"\n'
    'spec_path = ""\n'
    'method = "GET"\n'
    'path_template = "/books/v1/{book_title}"\n'
    'id_location = "path"\n'
    'id_param = "book_title"\n'
    'attacker_id = "bookTitle77"\n'
    'victim_id = "bookTitle78"\n'
    'auth_spec_path = ""\n'
)

# The three env tokens set for every run so the env-first path is taken (never a paste / getpass).
ENV_TOKENS = {
    "TARGET_ATTACKER_TOKEN": "ATK-ENV-SECRET",
    "TARGET_OWNER_TOKEN": "OWN-ENV-SECRET",
    "TARGET_BYSTANDER_TOKEN": "BYST-ENV-SECRET",
}


def seed_target(home: Path, toml_text: str = SPECLESS_TARGET_TOML, name: str = "vampi") -> None:
    """Write a selectable target into the isolated home's targets dir (~/.<brand>/targets/<name>.toml).

    The brand segment is derived from `branding.BRAND_NAME` (the single source of truth the CLI's own
    `targets.targets_dir()` uses), NOT hardcoded — so a future rename cannot silently strand this harness
    the way the lanivist->aivist rename did."""
    from backend.app.cli.branding import BRAND_NAME
    tdir = Path(home) / ("." + BRAND_NAME) / "targets"
    tdir.mkdir(parents=True, exist_ok=True)
    (tdir / f"{name}.toml").write_text(toml_text, encoding="utf-8")


def run_cli(stdin_script: str, *, home: Path, env_extra: Optional[Dict[str, str]] = None,
            with_tokens: bool = True, timeout: float = 90.0) -> Tuple[bytes, bytes, int]:
    """Spawn the real `python run.py`, feed `stdin_script`, return (stdout_bytes, stderr_bytes, code)."""
    env = dict(os.environ)
    env["USERPROFILE"] = str(home)                 # Windows: expanduser("~") -> home
    env["HOME"] = str(home)                        # POSIX
    env.pop("HOMEDRIVE", None)
    env.pop("HOMEPATH", None)
    env.setdefault("GEMINI_API_KEY", "dummy-key")  # clears the API-key gate (no real key needed)
    env.pop("NO_COLOR", None)                      # let each test control color via env_extra
    env.pop("FORCE_COLOR", None)
    if with_tokens:
        env.update(ENV_TOKENS)
    if env_extra:
        env.update({k: str(v) for k, v in env_extra.items()})
    proc = subprocess.run(
        [sys.executable, "run.py"], cwd=_REPO_ROOT,
        input=stdin_script.encode("utf-8"), capture_output=True, timeout=timeout, env=env)
    return proc.stdout, proc.stderr, proc.returncode


# Drive: select the (only) saved target, run `verify`, answer its two clear-text prompts (assert-owner=No,
# account-labels=No), then quit. Extra blank lines are harmless empty REPL commands. No secret prompts are
# hit because all three tokens come from the environment.
VERIFY_SCRIPT = "targets\n1\nverify\n\n\n\n\nquit\n"
