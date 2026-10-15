"""M3 calibration-suite tests: across several seeds the shadow grader must place
each of the nine archetypes in its expected band, agree with every expectation,
and — the anti-gaming guarantee — let ONLY a genuinely correct investigation (or a
defensible technically-correct alternative) reach the 95% bar. Guessing and
evidence padding must never reach it."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from siem import calibration as cal

SEEDS = ["cal-seed-01", "smoke", "seed-xyz", "alpha", "q1-2026"]

P = F = 0
def check(name, ok):
    global P, F
    print(("PASS " if ok else "FAIL ") + name); P += ok; F += (not ok)


def run():
    for seed in SEEDS:
        r = cal.run(seed)
        rows = {row["archetype"]: row for row in r["rows"]}
        anti = {a["probe"]: a for a in r["anti_gaming"]}

        # every archetype agrees with its expected band
        check(f"[{seed}] all archetypes agree with expected band",
              all(row["agree"] for row in r["rows"]))

        # ONLY fully_correct and technically_correct_alternative may pass the bar
        passers = {name for name, row in rows.items() if row["passes_bar"]}
        check(f"[{seed}] only correct/defensible-alternative pass the bar: {sorted(passers)}",
              passers <= {"fully_correct", "technically_correct_alternative"})
        check(f"[{seed}] fully_correct passes", rows["fully_correct"]["passes_bar"])

        # competence gaps stay below the bar
        for name in ("partially_correct", "missed_incidents", "false_positive",
                     "unsupported_fabricated_evidence", "correct_evidence_incorrect_conclusion",
                     "correct_conclusion_insufficient_evidence", "strong_analysis_weak_response"):
            check(f"[{seed}] {name} does NOT reach the bar", not rows[name]["passes_bar"])

        # specific review-flag expectations
        check(f"[{seed}] false_positive flags FALSE_INCIDENT_CLAIMED",
              "FALSE_INCIDENT_CLAIMED" in rows["false_positive"]["review_flags"])
        check(f"[{seed}] correct_evidence_incorrect_conclusion raises a citation review flag",
              "CITATION_REVIEW_FLAG" in rows["correct_evidence_incorrect_conclusion"]["review_flags"])

        # anti-gaming: neither probe reaches the bar; padding is flagged
        check(f"[{seed}] guessing_shotgun cannot reach the bar",
              not anti["guessing_shotgun"]["passes_bar"])
        check(f"[{seed}] evidence_padding cannot reach the bar",
              not anti["evidence_padding"]["passes_bar"])
        check(f"[{seed}] evidence_padding is flagged POSSIBLE_EVIDENCE_PADDING",
              "POSSIBLE_EVIDENCE_PADDING" in anti["evidence_padding"]["review_flags"])

    print(f"\n{P} passed, {F} failed")
    return F == 0


def test_calibration():
    assert run()


if __name__ == "__main__":
    sys.exit(0 if run() else 1)
