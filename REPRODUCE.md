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
# the full high-N zero-FP pass — SAFE/control N=20, VULN N=10, both targets.
# NOTE the --out path: your sweep goes to scripts/measure/repro/, NOT into
# scripts/measure/results/. That directory holds our committed artifacts and the
# documented procedure never writes into it — you are here to COMPARE against the
# baseline, not to replace it. scripts/measure/repro/ is gitignored, so a full
# reproduction leaves `git status` clean.
mkdir -p scripts/measure/repro
python scripts/measure/verdict_measure.py \
    --caseset scripts/measure/casesets/vulnerable_target.json \
    --caseset scripts/measure/casesets/depot.json \
    --n-safe 20 --n-vuln 10 --out scripts/measure/repro/sweep_repro.jsonl
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

### Compare your sweep against ours

**Your gated-down count will probably not be 79, and that is not a failure.** That number
counts how often the *model's raw opinion* asked to confirm a secure endpoint. The proposer
is sampled at `temperature=0.4` with no seed, so its error rate is stochastic: our own two
committed passes, same 28 cases and same N, produced **79** and **77**. Expect a number in
that neighbourhood, not that number.

**What must not differ is the invariant.** Whatever the proposer does, every SAFE/control run
must still end at a final verdict that is not `verified`, every VULN run must still reach
`verified`, and nothing may degrade. That is the claim being reproduced — *the gate is not
moved by the model* — and it is what this comparison checks:

```bash
python - scripts/measure/results/sweep_highN.jsonl scripts/measure/repro/sweep_repro.jsonl <<'PY'
import json, sys, collections

CANONICAL, REPRODUCTION = sys.argv[1], sys.argv[2]

def summarise(path):
    rows = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
    safe = [r for r in rows if r["ground_truth"] in ("SECURE", "CONTROL")]
    real = [r for r in rows if r["ground_truth"] == "REAL"]
    refused = [r for r in rows
               if r["ai_verdict_raw"] == "verified" and r["final_verdict"] != "verified"]
    return {
        "usable runs":              len(rows),
        "degraded":                 sum(1 for r in rows if r["degraded"]),
        "SAFE/control runs":        len(safe),
        "  -> final 'verified'":    sum(1 for r in safe if r["final_verdict"] == "verified"),
        "VULN runs":                len(real),
        "  -> final 'verified' ":   sum(1 for r in real if r["final_verdict"] == "verified"),
        "gated down (raw yes, final no)": len(refused),
    }, collections.Counter(r["guard_override"] for r in refused)

a, ca = summarise(CANONICAL)
b, cb = summarise(REPRODUCTION)

INVARIANT = {"usable runs", "degraded", "SAFE/control runs", "  -> final 'verified'",
             "VULN runs", "  -> final 'verified' "}

print(f"{'':34}{'canonical':>12}{'yours':>12}   ")
print("-" * 72)
for k in a:
    flag = ""
    if a[k] != b[k]:
        flag = "  <-- MUST NOT DIFFER" if k in INVARIANT else "  <-- expected to vary"
    print(f"{k:34}{a[k]:>12}{b[k]:>12}{flag}")
print("-" * 72)
print("gated-down by channel:")
for ch in sorted(set(ca) | set(cb)):
    print(f"  {str(ch):44}{ca.get(ch,0):>8}{cb.get(ch,0):>8}")
print()
bad = [k for k in INVARIANT if a[k] != b[k]]
print("INVARIANT HELD" if not bad else f"INVARIANT BROKEN on: {bad}")
PY
```

Here is that comparison run against **our own two committed passes** — `sweep_highN.jsonl`
as canonical and `sweep_highN_d19.jsonl` standing in for a reproduction. It is exactly the
shape your output should have:

```
                                     canonical       yours
------------------------------------------------------------------------
usable runs                                430         430
degraded                                     0           0
SAFE/control runs                          300         300
  -> final 'verified'                        0           0
VULN runs                                  130         130
  -> final 'verified'                      130         130
gated down (raw yes, final no)              79          77  <-- expected to vary
------------------------------------------------------------------------
gated-down by channel:
  cross_resource_readback_not_decisive              38      37
  owner_view_not_corroborated                       41      40

INVARIANT HELD
```

Two independent passes, two different proposer error rates, one identical invariant. If your
run prints `INVARIANT HELD`, you have reproduced the claim. If it prints `INVARIANT BROKEN`,
that is a real finding and we want to hear about it — open an issue with your
`sweep_repro.jsonl` attached.

Runtime flags (`AI_DEEP_VERIFY_ENABLED`, `AI_DEEP_VERIFY_OWNER_AUTH`) are set in-process by
the tool; the committed config defaults stay off/unset.

## What is deliberately NOT committed

Full verbose per-run transcripts (the model's parsed `reasoning` field, every HTTP body) are
noise and stay gitignored under `scripts/audit/`. Only the structured artifacts and curated
transcripts are committed. The evidence is the diffable JSONL, not a wall of prose.

To be exact about what those gitignored transcripts hold: they log the **parsed
`reasoning` string** the engine extracted from each completion, not the raw completion. The
verbatim model JSON is captured in memory (`DeepVerificationResult.turns_raw`) and is never
written to a file by any committed code path — grep the transcripts for `turns_raw` or for a
`{"decision"` blob and you get nothing. So **no committed or gitignored file in this repo
contains a raw model completion.** If you need one, `backend/scripts/deep_verify_live_check.py`
prints `turns_raw` to stdout on a live run.
