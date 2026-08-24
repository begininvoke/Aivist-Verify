# The 200 That Proved Nothing

I built a small test server with a bug that isn't there, and watched a very good
language model insist, six times, at full confidence, that it was. Then I watched
my own code make the same mistake. This is the story of what those two failures
had in common, because figuring that out changed how I think about where you're
allowed to trust a machine in a security tool.

## The setup

I've been working on the unglamorous half of finding access-control bugs. Not the
detection part, where you notice that a user *could* request someone else's
object. That part is easy now, and a language model does it well. The hard part
is confirmation. You sent the request. You got back `200 OK`. Did you actually
read the other person's data, or did the server quietly refuse and just not tell
you? A scanner that cries "IDOR!" every time it sees a `200` is useless. Somebody
still has to look at the response and decide whether a real person's data leaked.
That deciding step is what I was trying to automate.

To test it, I needed cases where I already knew the right answer. So I wrote a
little target server with a set of endpoints, some genuinely vulnerable, some
genuinely safe, and I labeled every one of them myself. One of the safe ones I
built to be as nasty as I could make it, specifically to try to fool the thing I
was building. Here is what it does.

When you ask for a bond you own, it returns your bond. When you ask for a bond you
*don't* own, it does not return a `403`. It returns a `200` with a body the same
size and shape as a real one, except the fields that would actually belong to the
other person are replaced with a mask.

```python
if bd.account_id != current.id:
    return {"bond_id": bond_id, "account_id": bond_id, "route": "XXX-XXX", "status": "SEALED"}
return {"bond_id": bd.id, "account_id": bd.account_id, "route": bd.route, "status": bd.status}
```

So an attacker, Alice, asking for Bob's bond, gets this back:

```
GET /depot/bonds/b0b00000...0002   (Bob's bond, Alice is asking)
-> HTTP 200 | Content-Length: 138
{"bond_id":"b0b00000...0002","account_id":"b0b00000...0002","route":"XXX-XXX","status":"SEALED"}
```

Nothing of Bob's is in there. His real route and status (`CDG-SFO`, `ACTIVE`) are
withheld and replaced with a constant refusal token. The one field that looks
incriminating, `account_id`, holds `b0b00000...0002`, which is just the id Alice
typed into the URL herself. The server echoed her own input back at her. She
supplied that value. She already knew it. It tells her nothing about Bob.

I knew this endpoint was secure. I had a separate test asserting it, checking the
live bytes, completely independent of the tool I was building. So when I ran my
confirmation engine against it, I was expecting a clean "nothing here."

## The model was certain, and the model was wrong

I handed the whole exchange to `gemini-2.5-pro`, the strongest model I had, and
asked it to judge whether the access-control attack had succeeded. Here is its
answer, reproduced exactly as it came back (the shortened UUIDs are the model's
own):

```json
{
  "decision": "verdict",
  "next_request": null,
  "verdict": "verified",
  "confidence": 1.0,
  "evidence_path": "account_id",
  "reasoning": "The baseline request for bond 'a11ce000...0001' returned an object
   belonging to account 'a11ce000...0001', establishing the attacker's identity.
   The attack request for a different bond, 'b0b00000...0002', successfully returned
   the object's data. The response body confirms the returned object belongs to a
   different account ('b0b00000...0002'), proving the attacker can read resources
   they do not own."
}
```

Look at what it did. It pointed at `account_id` as its proof. The one field Alice
filled in herself. The model took her own input, saw it reflected back in the
response, and concluded she had read Bob's data. The reasoning is tidy and
confident and completely wrong.

I ran it again. Same verdict. I ran it three times against this endpoint and three
more against a near-identical sibling, which differs only in that it returns a
constant zero UUID instead of echoing Alice's id. Six confirmations of a bug that
does not exist, and every single one came back with `"confidence": 1.0`. The two
endpoints fool the model in slightly different ways, and I'll come back to why the
difference matters. What doesn't differ is the outcome: six wrong verdicts, all at
full confidence.

That number is what stopped me. A lot of the standard advice for trusting a
model's output routes through the model's own certainty. Ask it how sure it is.
Run it a few times and see if it agrees with itself. Have it grade its own work.
This endpoint quietly demolishes all of that. The confidence score carried no
information. The model was exactly as sure when it was wrong as it would have been
if it were right. You cannot use a signal to catch a mistake when the signal reads
identically whether or not the mistake happened.

## Maybe a second model could catch the first

Before I gave up on the model, I looked harder at those three runs against the
sibling endpoint, the one that returns a constant zero UUID. A natural instinct,
when one model is unreliable, is to have a second one audit its reasoning. So I
read the three explanations the model gave, expecting them to be interchangeable.
They weren't, and the way they differed is the reason I stopped trusting that
idea.

Two of the three quoted the literal value `00000000-0000-0000-0000-000000000000`
and called it "a different account." An all-zeros UUID announcing itself as the
victim is a visible tell. A careful human, or a second model asked to check the
first, has a real chance of catching it.

The third run had no such tell:

> The attacker requested a resource that belongs to a different account. The
> server responded with a 200 OK and the full resource data. The 'account_id'
> field in the response confirms that the returned object belongs to a different
> principal than the one authenticated, demonstrating a clear broken access
> control vulnerability.

That reasoning is clean. It is well-formed, it is confident, and it is wrong for
reasons that are nowhere in the text. Read on its own, nothing in it sounds false.
A reviewing model handed just these words has nothing to grab onto.

Same endpoint, same bug, same wrong verdict, and the flaw is legible in two runs
out of three and invisible in the third. That is the trouble with auditing
reasoning. The mistake doesn't reliably leave a trace in the words. Stacking
another judge of the same kind on top doesn't cover a blind spot they share, it
just adds a vote that agrees for the same wrong reason.

So checking the model with another model was out. My next reaction was the obvious
one. Fine, the model is fooled by a clever response. I'll write a piece of plain,
deterministic code to check its work.

## The code was fooled too

Here was my plan. A real cross-user read has to return an object that belongs to
*someone other than the caller*. So I'd write a check that scans the response for
owner-type fields (`account_id`, `owner_id`, that family, being careful to skip a
record's own bare `id`, because a primary key doesn't tell you whose object it is)
and asks a simple question: does the attacked id show up as an owner value in the
response?

If it does, the object names the victim, and the read looks real. Solid logic. No
model involved, just a field check I fully controlled.

You already see it coming. On this endpoint, the attacked id *is* sitting in an
owner-named field, because the server echoed it into `account_id`. So my check
reported `confirmed`. On a secure endpoint. It got fooled by the exact same
response that fooled the model.

I know it did, because I recorded why in the target's own source. The echo handler's
comment says it outright: the endpoint reflects the requested id back into an
owner-named field on purpose, so the identity check reports `confirmed` on a response
that disclosed nothing — a field-name filter can't tell a leak from a reflection. And
the underlying failure mode — the check confirming an object is the victim's without
proving the victim's data actually leaked — is pinned by a regression test on a
sibling case, a silently-dropped write where the object really is Bob's, so it can
never quietly come back:

```python
# SAFE read-back ALSO shows owner 2 (the write was dropped but the object is still Bob's)
# -> caller identity confirms the OBJECT is the victim's; it does NOT distinguish the leak.
assert _anchor_caller_identity(_SAFE_STATE, "2", "1") == "confirmed"
```

That comment is the whole lesson in two lines. My code said `confirmed`, and it
wasn't wrong to. It confirmed the thing it actually checks, that the object is
named for the victim. What it could not do is tell that apart from the thing I
cared about, which is whether Bob's data actually came back. Those are two
different questions, and every false positive I was seeing lived in the space
between them.

I sat with that for a while, because it broke the model-versus-code framing I'd
walked in with. I had assumed the fix for an unreliable model was reliable code.
But here were both of them, a neural network and a regular expression, looking at
the same response and reaching the same wrong answer. They were not making the
same kind of mistake by coincidence. They were making it for the same reason.

## The reason

Both of them were reasoning about the response that Alice's own request produced.
And Alice controlled that request.

The incriminating value, the id in `account_id`, was hers to begin with. It came
back because the server reflected it, not because it revealed anything about Bob.
It does not matter whether a language model reads that value or a hand-written
check reads it. Reading your own input back out of a reflection is not evidence
about someone else. The answer I wanted was simply not present in the response at
all, so no amount of cleverness applied *to the response* could find it. I tried,
by the way. Two different attempts to squeeze a reliable signal out of the attack
response, both of them died, because on an object that names itself, the victim's
marker and the attacker's input are the same string. There is nothing in there to
find.

This is the part that reframed everything for me. The line you can't cross isn't
between the model and the code. It's between a *claim* and an *observation*. The
model's verdict is a claim. My code reading a field out of the attack response is
also, when you get down to it, a claim, because it's reasoning about bytes the
attacker got to shape. Both sit on the same side of the line. The other side, the
trustworthy side, has only one thing on it: an observation the attacker didn't get
to touch.

## Going to look

If the answer isn't in the response Alice got, it has to come from somewhere she
never reached. Which leaves exactly one honest move. Go fetch Bob's real bond, as
Bob, and see whether what Alice got actually matches it.

So that's what the engine does now. It makes a second, authenticated request for
the same object as its real owner, a request the attacker never influenced, and
compares. A verdict of "confirmed" is only allowed to stand if the data the
attacker received actually resembles what the owner legitimately sees.

```python
def _owner_view_corroborates(attack_body, owner_body) -> bool:
    if not attack_body or not owner_body:
        return False
    return _compute_similarity(attack_body, owner_body) >= _OWNER_VIEW_CORROBORATION_THRESHOLD
```

On my nasty endpoint, the owner's real view (`CDG-SFO`, `ACTIVE`) looks almost
nothing like the masked shell Alice got (`XXX-XXX`, `SEALED`). The similarity
comes out around 0.92, under the line, and the engine refuses to confirm. Notice
what it never does. It never looks for "denial words." It doesn't try to
recognize `SEALED` as a refusal, because assuming it knows what a refusal looks
like is exactly the mistake that started this whole mess. It doesn't try to spot a
fake. It positively corroborates a real leak against data it fetched itself, and
anything that fails to corroborate, whether it's a mask or a sentinel or an echo
or a plain denial, gets treated the same way. Not proven.

There's one more property that matters more than any of the rest, and it's the
reason the whole arrangement is safe to build on. This check is only ever allowed
to take a verdict away. It can turn a "confirmed" into an "inconclusive." It can
never do the reverse. There is no input at all for which it invents a
confirmation or makes one stronger.

That's what finally put the model in its right place for me. The model isn't the
authority whose answer I'm hoping is correct. The model proposes. It's a fast,
capable, and fallible generator of guesses about where a bug might be. The
deterministic code disposes. It can strike a guess down, and it is the only thing
allowed to let one stand. A confident wrong answer from the model gets caught. A
confident wrong answer the code can't corroborate never reaches me. The worst the
system can do is miss something. It can't make something up.

## Yes, there's a magic number, and no, it doesn't carry the argument

I can hear the objection, because I had it myself. There's a threshold in there,
0.95, and a tuned constant in the middle of a security decision should make anyone
nervous. So here's the whole picture, including the parts that don't look good.

I measured the corroboration similarity on every read-type case across two target
servers. The numbers fall into two groups that don't overlap.

```
genuinely vulnerable cases:   1.0000, 1.0000
                              (a gap of about 0.08)
genuinely secure cases:       0.9203, 0.8857, 0.6697
```

The real bugs land at exactly 1.0, because a genuine leak hands back the victim's
actual object, so it matches perfectly. The secure cases top out at 0.92. There's
a gap of about 0.08 between the two groups, and 0.95 sits in the middle of it. Any
threshold in that gap gives identical results on this data. The exact value isn't
doing anything delicate.

The honest reason it sits at 0.95 rather than higher is more interesting than "it
fits in the gap," and it comes back to that downgrade-only property. The risk
isn't symmetric. Because the check can only ever downgrade, setting the line too
low can't create a false positive. A case it fails to block is just left as it
already was. But setting the line too high would wrongly throw out a real bug. So
I deliberately kept it low, well under the vulnerable band, to leave room for the
fact that real objects have timestamps and generated ids that shift a little
between two reads, rather than pushing it up to sit as far from the secure cases
as possible. The direction I erred is a consequence of the design, not a guess.

And now the part I have to say out loud, because the method is worthless if I only
show you the flattering measurements. That gap rests on four distinct
values. Three secure ones and one vulnerable one, across eighty runs, on two servers
I wrote myself. The threshold is tuned on clean, seeded lab data comparing raw response
bodies, and it is not validated against the messiness of real-world targets, where
high-entropy fields could drag a genuine bug's similarity down toward the line.
The obvious fix, scrubbing out timestamps and ids before comparing, I actually
tried, and it made things worse. On this data it lifts one secure case from 0.67
up to 0.97, straight across the line, collapsing the very gap the check depends
on. And there's a hole the design just doesn't close: a genuinely public resource
hands the same bytes to everyone, so it corroborates for a perfectly innocent
reason and would be allowed through. My own code comment says it better than I can
in prose, so I'll leave it there. "This constant is validated per target; it is
not a universal truth."

## What it actually does, and what it honestly can't

Run it at scale and the shape comes through. Across 430 recorded runs on two
servers, 300 secure and control cases produced zero confirmations, and 130
genuinely vulnerable cases were confirmed, all of them. No false positives, no
missed real bugs, and every one of those numbers can be recomputed from a file in
the repository instead of taken on my word.

But the number I actually care about isn't the zero. It's where the zero comes
from. Across all those secure cases, the model raw-said "verified" 79 times, and
the code refused every single one. The zero isn't the model being careful. It's
the model being wrong 79 times and the code catching it every time.

There's one detail in the data that convinced me more than the headline did. I ran
the full benchmark twice. The two runs disagree with each other. One produces 79
refusals, the other 77, because the model's error rate genuinely wanders from run
to run. But every number that comes out of the *code* is identical across both
runs. 300 secure to zero, 130 vulnerable to 130, nothing degraded. That's exactly
what you'd expect from steady deterministic code sitting on top of a jittery
model. The model's mistakes wobble. The floor the code holds does not move. If any
piece of that floor were secretly leaning on the model, the zero would wobble too.
It didn't.

And then the thing anyone thinking about using this should hear plainly. On real
targets, the honest answer is very often "I found nothing." The most famous IDOR-
style bugs are broken for everyone, where every logged-in user can read the
resource, and against those the engine correctly says "inconclusive," because it
can't prove a *cross-user* violation when everyone has equal access. Point it at a
service that got per-user isolation right and the attacker is, correctly, turned
away. Someone's first run may well show them nothing exciting. That is not the
tool failing to find a bug. It's the tool refusing to invent one, which is the
entire discipline seen from the outside.

## The point

Noticing that Alice can send a request for Bob's object is the easy, crowded half
of the problem, and a language model is genuinely great at it. Proving that the
request actually leaked Bob's data is the half where a confident wrong answer is
worse than no answer, because it's the half a human ends up trusting.

What this whole exercise taught me is that the line you can't cross in an AI-
assisted security tool doesn't run between the model and the code. It runs between
a claim and an observation. A model's verdict is a claim. A code check reading a
field out of the attacker's own response is also, in the end, a claim. The only
thing on the trustworthy side of that line is a fresh observation the attacker
never got to shape, which here means going and fetching the victim's real object,
as the victim, and looking. Everything else has to survive that comparison. And
the machinery is arranged so the fallible guesser can only ever suggest, while the
thing that gets the last word can only ever take an answer away, never add one.

The AI proposes. The code disposes.

---

*Everything above is checkable. That's the property that made me want to write it
down in the first place. The two test servers, the recorded model completions I
quoted, and the benchmark data behind every number are all in the repository, and
the reproduction steps are written to actually be run. If any claim here doesn't
hold up against the source, I'd rather know.*

*The engine is [Aivist Verify](https://github.com/Aivist/Aivist-Verify).*

---

### For the technically minded: verify every claim

| Claim | Where to check it |
|---|---|
| The endpoint masks a non-owner's data (`XXX-XXX`/`SEALED`) and returns the real object to the owner | `depot_target/main.py`, the `get_bond` handler, `bd.account_id != current.id` branch |
| `account_id` in the denial is the requested id echoed back, not the stored owner id | same handler: the denial returns `"account_id": bond_id`, the path param, not `bd.account_id` |
| Bob's real bond is `CDG-SFO` / `ACTIVE`, and none of it appears in the denial | seed data in `depot_target/main.py`, asserted against live bytes in `depot_target/test_vulns.py` |
| The case is genuinely secure, proven independently of the engine | `depot_target/test_vulns.py`, which asserts on live responses, never on any anchor |
| The model returned `verified` at `confidence: 1.0` six times across the two sibling endpoints | the recorded completions bundle, six verbatim completions each with its prompt hash |
| The echoed-input mechanism is specific to one of the two endpoints (the other uses a zero-UUID sentinel) | `get_bond` versus the sibling handler in `depot_target/main.py`; the two anchor outcomes in the completions |
| A deterministic caller-identity check also reports `confirmed` on a secure case | `_anchor_caller_identity` in `deep_verifier.py`; the echo behavior is documented in `get_bond`'s docstring (`depot_target/main.py`), and the same failure mode is regression-pinned on a sibling write case in `test_m1_evidence_anchoring.py` |
| The owner-view check compares against the owner's real view via `_compute_similarity` at 0.95 | `_owner_view_corroborates` and `_OWNER_VIEW_CORROBORATION_THRESHOLD` in `deep_verifier.py` |
| The check can only downgrade a verdict, never assign `verified` | `_apply_owner_view_gate` in `deep_verifier.py`, which structurally cannot produce a confirmation |
| Similarity: vulnerable at 1.0000, secure at 0.9203 / 0.8857 / 0.6697, a 0.0797 gap | the threshold-calibration comment in `deep_verifier.py` (the `_OWNER_VIEW_CORROBORATION_THRESHOLD` block) |
| 300 secure to 0, 130 vulnerable to 130, across 430 runs | `scripts/measure/results/sweep_highN.jsonl`, with recomputation steps in `REPRODUCE.md` |
| The model raw-said `verified` on 79 secure runs; code refused each one | same file, recomputed on the `guard_override` field |
| Two benchmark passes disagree (79 vs 77) while the code's numbers stay identical | `sweep_highN.jsonl` versus `sweep_highN_d19.jsonl`, both committed |
| Scrubbing timestamps/ids before comparing was measured and rejected: it lifts one secure case from 0.6697 to 0.9744, across the 0.95 line | direction documented in `docs/DEEP_VERIFY.md` and `RESULTS.md`; the 0.9744 figure recomputes by applying `_sanitize_response_text` (`fuzzer.py`) to the X-EQUIV-SAFE bodies and re-running `_compute_similarity` |
