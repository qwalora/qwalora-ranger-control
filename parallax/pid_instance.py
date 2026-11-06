"""PX-D1 per-instance campaign derivation (cohort + candidate differentiation).

Every (cohort, candidate, attempt) already mints a distinct, signed GenerationContract (parallax.
contracts), so no two candidates share an instance and a submission can never be transferred. This
module turns that keyed identity into the concrete campaign arrangement the grader runs, so two
cohorts and two candidates measurably differ while ONE approved blueprint grades them all.

Keylessness: the PORTAL (which holds the MAC key) computes the two integer seeds and passes them in the
grader job; the GRADER derives the arrangement from those integers alone (no key on the grader).

Comparability: the adversarial attack family is kept whole for everyone (a defense is graded on
resisting the full preregistered family, so scores are comparable). Differentiation is in the ordering
now and, once the task/variant pools grow past the floors below, a per-cohort subset of the approved
pool - the selection is a pure function of the seeds, never an edit to the approved spec.
"""
from __future__ import annotations

import random
from typing import Any, List, Optional, Tuple

from siem.schema import keyed_mac
from .research import protocol as P

ASSESSMENT_ID = "PX-D1"
TASK_SUBSET_FLOOR = 5       # keep all tasks until the pool exceeds this (today there are 3)
VARIANT_SUBSET_FLOOR = 10   # keep the whole attack family until the pool exceeds this (today 6)


def _seed_int(label: bytes, text: str) -> int:
    return int(keyed_mac(label + text.encode("utf-8"))[:16], 16)


def instance_seed(cohort: str, candidate_key: str, attempt: int, assessment_id: str = ASSESSMENT_ID) -> int:
    """Per-(cohort, candidate, attempt) seed. Portal-side (keyed)."""
    return _seed_int(b"pxd1-instance\x1f", "%s\x1f%s\x1f%s\x1f%d" %
                     (assessment_id, cohort, candidate_key, int(attempt)))


def cohort_seed(cohort: str, assessment_id: str = ASSESSMENT_ID) -> int:
    """Per-cohort seed (shared by a cohort, distinct across cohorts). Portal-side (keyed)."""
    return _seed_int(b"pxd1-cohort\x1f", "%s\x1f%s" % (assessment_id, cohort))


def select(inst_seed: int, coh_seed: Optional[int], workload_id: str
           ) -> Tuple[List[Any], List[Any], int, str]:
    """Derive (tasks, variants, repetitions, protocol_version) from the integer seeds. Pure; keyless;
    deterministic. Grader-side."""
    advanced = str(workload_id).endswith("advanced")
    variants = list(P.ADVANCED_ATTACK_VARIANTS if advanced else P.ATTACK_VARIANTS)
    tasks = list(P.LEGIT_TASKS)

    # per-cohort subset of the approved pool, active only once the pool is large enough to keep the
    # measurement comparable (floors above). Until then every cohort sees the full pool.
    if coh_seed is not None:
        cr = random.Random(coh_seed)
        if len(tasks) > TASK_SUBSET_FLOOR:
            tasks = cr.sample(tasks, max(TASK_SUBSET_FLOOR, (len(tasks) * 2) // 3))
        if len(variants) > VARIANT_SUBSET_FLOOR:
            variants = cr.sample(variants, max(VARIANT_SUBSET_FLOOR, (len(variants) * 3) // 4))

    # per-instance ordering (anti-replay / makes each candidate's run distinct)
    r = random.Random(inst_seed)
    r.shuffle(tasks)
    r.shuffle(variants)

    reps = 2 if advanced else 1
    pv = P.ADVANCED_PROTOCOL_VERSION if advanced else P.PROTOCOL_VERSION
    return tasks, variants, reps, pv
