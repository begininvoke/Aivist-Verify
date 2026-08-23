# Reproducing the access-control verifier's zero-false-positive evidence

The zero-false-positive claim rests on **three independently verifiable layers**. Each can
be checked on its own; together they mean the claim does not require trusting a transcript.

## Layer 1 — the targets and their independent ground truth (zero API key)

Two self-contained vulnerable labs, each with an **independent** ground-truth test suite
that proves — against the live target's real bytes, with **no involvement from the verifier
engine** — that every case labelled REAL is genuinely exploitable cross-account and every
case labelled SECURE genuinely resists that attack.

```bash
python -m pytest vulnerable_target/test_vulns.py -q     # 31 tests
python -m pytest depot_target/test_vulns.py -q          # 23 tests
```

These require **no Gemini key**. They are the oracle: the engine is graded against them,
never the reverse, and a label is never edited to make the engine agree.

## Layer 2 — the structured result artifacts (readable, diffable, no API key)

`scripts/measure/results/*.jsonl` — one JSON row per measured run: case id, ground truth,
shape, `ai_verdict_raw → final_verdict`, the exemption channel that fired, every anchor
result, owner-view similarity (read-semantic cases), and a per-row regression check against
the caseset's known-good baseline. Small and diffable, so a reviewer can read the evidence
directly:

- **`sweep_highN.jsonl` — CANONICAL.** The high-N zero-FP record (SAFE/control N=20, VULN
  N=10), 430 rows. **Every headline figure in this repo comes from this file.** If a number
  in `README.md` or `RESULTS.md` disagrees with what you compute, compute it against *this*
  file before concluding anything.
- `sweep_n1.jsonl` — the N=1 regression baseline across all 28 cases on both targets, 28 rows.
- `sweep_highN_d19.jsonl` — a **second, separate 430-row pass**, kept as the acceptance
  artifact for the **D19 promotion layer** (it adds the `owner_view_corroborated`,
  `promotion_channel` and `would_promote` columns that the D19 choke point is checked
  against). It is **not** an alternative source for the headline.

> **The two 430-row files do not yield the same headline number, and we would rather tell
> you than have you find it.** Counting rows where the model's raw verdict was `verified`
> but the final verdict was not: **`sweep_highN.jsonl` gives 79; `sweep_highN_d19.jsonl`
> gives 77.** They are two different measured passes, not two views of one pass. The model
> is sampled at `temperature=0.4` with no seed, so on borderline SAFE cases its raw verdict
> genuinely varies run to run — `X-EQUIV-SAFE` raw-said `verified` once in the canonical
> pass and zero times in the D19 pass; `X-MASS-SAFE-PRESENT` 19 times vs 17.
>
> What does **not** vary is the thing being claimed. In **both** files: SAFE/control runs
> reaching a final `verified` = **0**, VULN runs reaching `verified` = **130 / 130**,
> degraded rows = **0**. The headline "79" is a property of one measured pass; the zero is a
> property of the gate. Quote 79 only alongside `sweep_highN.jsonl`.

Inspect with any JSON tool, e.g.:

```bash
python - <<'PY'
import json, collections

# CANONICAL artifact. Every headline figure below comes from this exact path.
CANONICAL = "scripts/measure/results/sweep_highN.jsonl"
rows = [json.loads(l) for l in open(CANONICAL, encoding="utf-8") if l.strip()]

safe   = [r for r in rows if r["ground_truth"] in ("SECURE", "CONTROL")]
real   = [r for r in rows if r["ground_truth"] == "REAL"]
refused = [r for r in rows
           if r["ai_verdict_raw"] == "verified" and r["final_verdict"] != "verified"]

print("artifact                              :", CANONICAL)
print("usable runs                           :", len(rows), "  degraded:", sum(1 for r in rows if r["degraded"]))
print("SAFE/control runs -> final 'verified' :", len(safe), "->",
      sum(1 for r in safe if r["final_verdict"] == "verified"))
print("VULN runs         -> final 'verified' :", len(real), "->",
      sum(1 for r in real if r["final_verdict"] == "verified"))
print("model raw-said 'verified', gate refused:", len(refused))
print("  by channel:", dict(collections.Counter(r["guard_override"] for r in refused)))

# per-case raw -> final, as before
by = collections.defaultdict(collections.Counter)
for r in rows:
    by[r["case_id"]][f'{r["ai_verdict_raw"]}->{r["final_verdict"]}'] += 1
for cid, dist in by.items():
    print(cid, dict(dist))
PY
```

The first five lines reproduce the `RESULTS.md` headline table exactly: **430 usable, 0
degraded · 300 → 0 · 130 → 130 · 79 refused.** Point `CANONICAL` at
`sweep_highN_d19.jsonl` instead and the last figure becomes 77 — see the note above for why.

## Layer 3 — the measurement tool (re-runnable with the reader's own key)

`scripts/measure/verdict_measure.py` regenerates Layer 2 from Layer 1. It drives the **real**
`execute_deep_verification` against a fresh-seeded target and writes the structured artifact.
It needs the reader's **own `GEMINI_API_KEY`** (environment or `backend/.env`).

```bash
# the full high-N zero-FP pass — SAFE/control N=20, VULN N=10, both targets
python scripts/measure/verdict_measure.py \
    --caseset scripts/measure/casesets/vulnerable_target.json \
    --caseset scripts/measure/casesets/depot.json \
    --n-safe 20 --n-vuln 10 --out scripts/measure/results/sweep_highN.jsonl
```

**Run count vs. call count — budget for the second one.** The full pass is **430 runs**
(vulnerable_target 7×20 + 7×10 = 210; depot 8×20 + 6×10 = 220), and the N=1 sweep is
**28 runs**. A *run* is not a *call*: each run is one `execute_deep_verification`, which
issues **one** model call if the model delivers a verdict from the baseline+attack evidence
alone, and **two** if it requests a follow-up read-back (or the engine gathers one
deterministically) and then answers in turn 2.

Recounted from the committed artifacts' own `follow_up_performed` column:

| Pass | Runs | of which took a follow-up | **Model calls** |
|---|---|---|---|
| Full high-N pass (`sweep_highN.jsonl`) | 430 | 350 | **780** |
| N=1 sweep (`sweep_n1.jsonl`) | 28 | 23 | **51** |

So budget **≈ 780 calls** for the full pass and **≈ 51** for `--n 1` — roughly **1.8×** the
run count, not 1×. Worst case is 2× (every run taking a follow-up); a transient 503 can add
up to two more attempts per call on top (`max_attempts=3`, 503-only retry).

The tool prints the planned run count *and* the derived call range before it starts, and
flags any degraded/truncated run as **NOT DATA** (excluded from the claim) rather than
silently reporting a smaller N.

Runtime flags (`AI_DEEP_VERIFY_ENABLED`, `AI_DEEP_VERIFY_OWNER_AUTH`) are set in-process by
the tool; the committed config defaults stay off/unset.

## What is deliberately NOT committed

Full verbose per-run transcripts (raw model text, every HTTP body) are noise and stay
gitignored under `scripts/audit/`. Only the structured artifacts and curated transcripts are
committed. The evidence is the diffable JSONL, not a wall of prose.
