"""Board 2 enterprise SOC shadow grader (score_board2_enterprise).

SHADOW ONLY. This evaluator computes a richer, rubric-v2 composite for an
enterprise Board 2 case submission against the protected scenario truth. It is
NEVER wired to qualification: its output is stored on the case submission's
shadow fields and compared against the live `score_board2` path. It reads the
pass bar from program for the near-bar review trigger only, and it never writes
to any qualification state — not the board-result tables, the scored-objective
columns, or a candidate's earned rank.

Design principles (from the approved BOARD2_SOC_CONTRACT.md and the M3 brief):
  - Answer-free: every component is checked server-side against the hidden truth
    (incident membership by event_uid, techniques, verdicts) and against the
    candidate's OWN authorized index. Nothing is revealed to the candidate.
  - The three evidence properties stay distinct (see case_contract): reference
    validity, claim support, malicious-activity determination. Membership alone
    never grants credit; legitimate baseline/precursor/corroborating/exclusion
    evidence is credited on its merits.
  - Explicit scoring anchors + partial-credit rules + documented human-review
    triggers. The approved v2 weights are preserved exactly; v2 only decides how
    the 0..1 composite is composed, and the 95% bar arithmetic is untouched.
  - No second grading system: evidence verification reuses
    case_contract.verify_evidence and the real per-seed truth from enterprise.

The evaluator is a PURE function of (truth, submission, source lookups). It does
not read env, DB, or clocks.
"""
from __future__ import annotations

import program as _program  # PASS_BAR lives here; imported read-only
from . import case_contract as cc

ENTERPRISE_GRADER_VERSION = 1
RUBRIC_VERSION = cc.RUBRIC_VERSION  # 2
PASS_BAR = _program.PASS_BAR        # 95.0 — referenced for the near-bar trigger only

# Approved v2 weights (BOARD2_RUBRIC_V2.md). Sum to 100. SHADOW ONLY.
WEIGHTS = {
    "incident_identification": 30,
    "evidence_quality": 20,
    "attribution": 15,
    "detection_gap": 15,
    "timeline_correlation": 10,
    "judgment": 10,
}
assert sum(WEIGHTS.values()) == 100

# Human-review trigger codes raised by the grader (in addition to the per-citation
# flags that case_contract already raises).
TRIG_NEAR_BAR = "NEAR_PASS_BAR_REVIEW"
TRIG_CONFIDENT_INCOMPLETE = "CONFIDENT_BUT_INCOMPLETE"
TRIG_EVIDENCE_PADDING = "POSSIBLE_EVIDENCE_PADDING"
TRIG_INCONCLUSIVE_TP = "INCONCLUSIVE_ON_TRUE_POSITIVE"
TRIG_MISSED_DETECTION = "MISSED_DETECTION_GAP"
TRIG_CITATION_FLAG = "CITATION_REVIEW_FLAG"
TRIG_FALSE_INCIDENT = "FALSE_INCIDENT_CLAIMED"

_DETECTION_FAILURE_VERDICT = "true_positive_missed_by_detector"


# --- small helpers -----------------------------------------------------------
def _norm(s):
    return str(s or "").strip().casefold()


def _f1(precision, recall):
    return (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0


def _anchor(x, full=0.85, partial=0.4):
    return "full" if x >= full else ("partial" if x >= partial else "none")


def _source_lookup(truth, reader, candidate_index):
    """Build uid -> _source for every truth member event, read from the candidate's
    own index (the malicious events live there unlabeled). Truth-safe: no label is
    read, only the event body the candidate also sees."""
    out = {}
    for inc in truth.get("incidents", []):
        for uid in inc.get("event_uids", []):
            src = reader.get_source(candidate_index, uid) if reader else None
            if src is not None:
                out[uid] = src
    return out


def _dotted(src, path):
    cur = src
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return None
        cur = cur[part]
    return cur


def _incident_expected(inc, source_by_uid):
    """Derive the ground-truth attributes of one truth incident from its member
    event sources: identities, assets (hosts), datasets, and the true time order."""
    identities, assets, datasets = set(), set(), set()
    order = []  # (ts, uid)
    for uid in inc.get("event_uids", []):
        src = source_by_uid.get(uid)
        if not src:
            continue
        u = _dotted(src, "user.name")
        if u:
            identities.add(_norm(u))
        h = _dotted(src, "host.name") or _dotted(src, "host")
        if isinstance(h, dict):
            h = h.get("name")
        if h:
            assets.add(_norm(h))
        ds = _dotted(src, "event.dataset") or _dotted(src, "data_stream.dataset")
        if ds:
            datasets.add(_norm(ds))
        ts = _dotted(src, "@timestamp")
        if ts:
            order.append((str(ts), uid))
    if inc.get("primary_identity"):
        identities.add(_norm(inc["primary_identity"]))
    order.sort()
    return {"identities": identities, "assets": assets, "datasets": datasets,
            "true_order": [uid for _ts, uid in order]}


def _cited_members(incident, member_uids):
    """Distinct member event_uids this candidate incident cites (any role)."""
    out = set()
    for c in (incident.get("cited_evidence") or []):
        uid = str((c or {}).get("event_uid") or "")
        if uid in member_uids:
            out.add(uid)
    return out


# --- incident matching -------------------------------------------------------
def _match_incidents(submission, truth, member_uids):
    """Greedy one-to-one match of candidate CONFIRMED incidents to truth incidents
    by cited-member overlap. Returns (matches, false_incidents, missed_truth).

    matches: list of (cand_index_pos, truth_index_pos, overlap_uids)
    A candidate confirmed incident with zero member overlap is a FALSE incident
    (hurts precision). A truth incident matched by nobody is MISSED (hurts recall).
    Matching is answer-free: the candidate never learns the truth structure; the
    server infers correspondence from what they cited."""
    cand = [(i, inc) for i, inc in enumerate(submission.get("incidents") or [])
            if _norm(inc.get("disposition")) == "confirmed_incident"]
    truth_inc = list(enumerate(truth.get("incidents", [])))
    # score every candidate/truth pair by member-uid overlap
    pairs = []
    for ci, inc in cand:
        cm = _cited_members(inc, member_uids)
        for ti, tinc in truth_inc:
            tset = set(tinc.get("event_uids", []))
            overlap = cm & tset
            if overlap:
                pairs.append((len(overlap), ci, ti, overlap))
    pairs.sort(reverse=True)  # strongest overlap first
    used_c, used_t, matches = set(), set(), []
    for _n, ci, ti, overlap in pairs:
        if ci in used_c or ti in used_t:
            continue
        used_c.add(ci); used_t.add(ti)
        matches.append((ci, ti, overlap))
    false_incidents = [ci for ci, _inc in cand if ci not in used_c]
    missed_truth = [ti for ti, _t in truth_inc if ti not in used_t]
    return matches, false_incidents, missed_truth


# --- the grader --------------------------------------------------------------
def score_board2_enterprise(truth, submission, reader, candidate_index,
                            verification=None):
    """Compute the SHADOW enterprise composite for one submission.

    Returns a dict:
      {version, rubric_version, shadow: True, score (0..100), normalized (0..1),
       components: {name: {score, weight, applicable, points, anchor, notes}},
       review_flags: [...], matching: {...}}
    `score` NEVER drives qualification; callers store it in CaseSubmission.shadow_*.
    """
    if verification is None:
        verification = cc.verify_evidence(submission, reader, candidate_index, truth=truth)
    member_uids = cc._truth_member_uids(truth)
    source_by_uid = _source_lookup(truth, reader, candidate_index)
    matches, false_incidents, missed_truth = _match_incidents(submission, truth, member_uids)
    incidents = submission.get("incidents") or []
    truth_incidents = truth.get("incidents", [])
    review = []

    # per-incident verification lookup (by position in submission)
    vmap = {i: v for i, v in enumerate(verification.get("incidents", []))}

    # ---- component 1: incident identification (precision/recall F1) ---------
    n_truth = len(truth_incidents)
    n_conf = sum(1 for inc in incidents if _norm(inc.get("disposition")) == "confirmed_incident")
    recall = (len(matches) / n_truth) if n_truth else 1.0
    precision = (len(matches) / n_conf) if n_conf else (1.0 if n_truth == 0 else 0.0)
    c1 = _f1(precision, recall)
    if false_incidents:
        review.append(TRIG_FALSE_INCIDENT)
    if missed_truth and any((inc.get("confidence") or 0) >= 80
                            for inc in incidents
                            if _norm(inc.get("disposition")) == "confirmed_incident"):
        review.append(TRIG_CONFIDENT_INCOMPLETE)
    # inconclusive disposition over a real incident's events
    for i, inc in enumerate(incidents):
        if _norm(inc.get("disposition")) == "inconclusive" and _cited_members(inc, member_uids):
            review.append(TRIG_INCONCLUSIVE_TP); break

    # ---- component 2: evidence sufficiency + relevance ----------------------
    ev_scores = []
    padding_suspected = False
    for ci, ti, overlap in matches:
        tinc = truth_incidents[ti]
        chain = set(tinc.get("event_uids", []))
        coverage = (len(overlap) / len(chain)) if chain else 0.0
        vinc = vmap.get(ci, {})
        cites = vinc.get("citations", [])
        valid = [c for c in cites if c.get("reference_valid")]
        reproducibility = (len(valid) / len(cites)) if cites else 0.0
        rels = [c.get("relevance") for c in cites if c.get("relevance") is not None]
        relevance = (sum(rels) / len(rels)) if rels else 0.0
        # padding signal: a run of low-relevance citations inside one incident
        # (volume that does not advance the claim), regardless of how much real
        # evidence sits alongside it.
        low_rel = sum(1 for c in cites
                      if c.get("relevance") is not None and c["relevance"] < 0.5)
        if low_rel >= 4 or (len(cites) >= 5 and relevance < 0.5):
            padding_suspected = True
        ev_scores.append(0.5 * min(1.0, coverage) + 0.3 * relevance + 0.2 * reproducibility)
    c2 = (sum(ev_scores) / len(ev_scores)) if ev_scores else 0.0
    if padding_suspected:
        review.append(TRIG_EVIDENCE_PADDING)

    # ---- component 3: attribution (identity, assets, techniques) ------------
    at_scores = []
    for ci, ti, overlap in matches:
        inc = incidents[ci]
        tinc = truth_incidents[ti]
        exp = _incident_expected(tinc, source_by_uid)
        ident_ok = 1.0 if _norm(inc.get("primary_identity")) in exp["identities"] else 0.0
        cand_tech = {_norm(t) for t in (inc.get("attack_techniques") or [])}
        truth_tech = {_norm(t) for t in (tinc.get("techniques") or [])}
        tech_recall = (len(cand_tech & truth_tech) / len(truth_tech)) if truth_tech else 1.0
        cand_assets = {_norm(a) for a in (inc.get("affected_assets") or [])}
        asset_recall = (len(cand_assets & exp["assets"]) / len(exp["assets"])) if exp["assets"] else 1.0
        at_scores.append(0.4 * ident_ok + 0.4 * tech_recall + 0.2 * asset_recall)
    c3 = (sum(at_scores) / len(at_scores)) if at_scores else 0.0

    # ---- component 4: detection-gap finding (conditional) -------------------
    df_positions = [ti for ti, t in enumerate(truth_incidents)
                    if t.get("verdict") == _DETECTION_FAILURE_VERDICT]
    c4_applicable = bool(df_positions)
    c4 = 0.0
    if c4_applicable:
        best = 0.0
        for ti in df_positions:
            match = next((m for m in matches if m[1] == ti), None)
            if not match:
                continue
            ci = match[0]
            inc = incidents[ci]
            found = 0.5  # located the missed activity by matching it at all
            da = inc.get("detection_assessment") or {}
            named = bool(da.get("detector_should_have_fired")) and \
                bool(str(da.get("gap") or "").strip()) and \
                bool(str(da.get("proposed_detection") or "").strip())
            best = max(best, found + (0.5 if named else 0.0))
        c4 = best
        if best < 0.5:
            review.append(TRIG_MISSED_DETECTION)

    # ---- component 5: timeline & correlation --------------------------------
    tl_scores = []
    for ci, ti, overlap in matches:
        inc = incidents[ci]
        tinc = truth_incidents[ti]
        exp = _incident_expected(tinc, source_by_uid)
        true_order = exp["true_order"]
        rank = {uid: i for i, uid in enumerate(true_order)}
        tl = inc.get("timeline") or []
        seq = [str((e or {}).get("event_uid") or "") for e in tl]
        seq = [u for u in seq if u in rank]  # only member events with known truth order
        ordering = 0.0
        if len(seq) >= 2:
            pairs = list(zip(seq, seq[1:]))
            correct = sum(1 for a, b in pairs if rank[a] <= rank[b])
            ordering = correct / len(pairs)
        # cross-source linkage: cited members span >= 2 datasets
        cited_m = _cited_members(inc, member_uids)
        ds = {_norm(_dotted(source_by_uid.get(u, {}), "event.dataset")) for u in cited_m}
        ds.discard("")
        linkage = 1.0 if len(ds) >= 2 else (0.5 if len(ds) == 1 else 0.0)
        tl_scores.append(0.6 * ordering + 0.4 * linkage)
    c5 = (sum(tl_scores) / len(tl_scores)) if tl_scores else 0.0

    # ---- component 6: judgment under uncertainty ----------------------------
    # Brier-style calibration over all confirmed incidents: outcome 1 if matched a
    # real incident, else 0. Overconfident false leads and underconfident correct
    # calls both cost.
    matched_ci = {ci for ci, _ti, _ov in matches}
    briers = []
    for i, inc in enumerate(incidents):
        if _norm(inc.get("disposition")) != "confirmed_incident":
            continue
        conf = inc.get("confidence")
        if not isinstance(conf, (int, float)):
            conf = 50
        p = max(0.0, min(1.0, conf / 100.0))
        outcome = 1.0 if i in matched_ci else 0.0
        briers.append((p - outcome) ** 2)
    calibration = (1.0 - sum(briers) / len(briers)) if briers else 1.0
    limitations = 1.0 if str(submission.get("stated_limitations") or "").strip() else 0.0
    # response quality: did the candidate recommend a response for each confirmed
    # incident? ("technical judgment + response" in the rubric brief.)
    resp = [1.0 if (inc.get("response_recommendations") or []) else 0.0
            for inc in incidents if _norm(inc.get("disposition")) == "confirmed_incident"]
    response_quality = (sum(resp) / len(resp)) if resp else 1.0
    c6 = 0.5 * calibration + 0.2 * limitations + 0.3 * response_quality

    # propagate per-citation review flags up to the grader result
    for vinc in verification.get("incidents", []):
        for c in vinc.get("citations", []):
            if c.get("review_flag"):
                review.append(TRIG_CITATION_FLAG); break
        else:
            continue
        break

    components = {
        "incident_identification": _comp(c1, "incident_identification", True,
            f"precision={precision:.2f} recall={recall:.2f} "
            f"matched={len(matches)}/{n_truth} false={len(false_incidents)}"),
        "evidence_quality": _comp(c2, "evidence_quality", True,
            f"matched-incident mean of coverage/relevance/reproducibility over {len(ev_scores)}"),
        "attribution": _comp(c3, "attribution", True,
            f"identity/technique/asset recall over {len(at_scores)} matched"),
        "detection_gap": _comp(c4, "detection_gap", c4_applicable,
            "located missed activity + named gap/proposal" if c4_applicable
            else "no detection-failure scenario in this seed (excluded)"),
        "timeline_correlation": _comp(c5, "timeline_correlation", True,
            f"ordering + cross-source linkage over {len(tl_scores)} matched"),
        "judgment": _comp(c6, "judgment", True,
            f"calibration={calibration:.2f} limitations={'yes' if limitations else 'no'} "
            f"response={response_quality:.2f}"),
    }

    # composite over APPLICABLE components only (keeps 0..1 comparable when the
    # detection-gap scenario is absent). Weights themselves are never changed.
    num = sum(c["points"] for c in components.values() if c["applicable"])
    den = sum(c["weight"] for c in components.values() if c["applicable"])
    normalized = (num / den) if den else 0.0
    score = round(100.0 * normalized, 1)

    if 90.0 <= score < 97.0:
        review.append(TRIG_NEAR_BAR)

    # de-dup review flags, stable order
    seen, flags = set(), []
    for f in review:
        if f not in seen:
            seen.add(f); flags.append(f)

    return {
        "version": ENTERPRISE_GRADER_VERSION,
        "rubric_version": RUBRIC_VERSION,
        "shadow": True,
        "score": score,
        "normalized": round(normalized, 4),
        "components": components,
        "review_flags": flags,
        "matching": {
            "matched": [{"candidate_incident": ci, "truth_incident": ti,
                         "overlap": sorted(ov)} for ci, ti, ov in matches],
            "false_incidents": false_incidents,
            "missed_truth": missed_truth,
            "truth_incident_count": n_truth,
            "confirmed_claimed": n_conf,
        },
        "pass_bar_reference": PASS_BAR,
    }


def _comp(score01, name, applicable, notes):
    w = WEIGHTS[name]
    score01 = max(0.0, min(1.0, float(score01)))
    return {"score": round(score01, 4), "weight": w,
            "points": round(score01 * w, 4) if applicable else 0.0,
            "applicable": applicable, "anchor": _anchor(score01), "notes": notes}
