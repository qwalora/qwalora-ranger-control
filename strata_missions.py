"""S2 - STRATA board mission packages (approved, versioned, candidate-safe).

A mission package is the professional, case-style instruction set a candidate reads before working a
STRATA board. It explains the mission thoroughly WITHOUT teaching how to solve it: no exploitation
commands, no step-by-step solutions, no suggested attack paths, no query strings that would locate a
hidden incident, no expected answers, no private grading rules, no hidden evaluator truth, and no AI
coaching. All protected material (answer keys, evaluator configuration, scenario truth) lives only in
the Ranger backend; nothing here carries it.

Design:
  * One reusable 10-section structure across all boards, with genuinely board-specific content.
  * Each package is versioned and carries an explicit `approved` flag. Presence is never approval;
    an unapproved draft is not shown as approved.
  * Packages are cohort- and scenario-REFERENCE-READY: the board-level mission (enterprise, role,
    scope, objectives, deliverables) is stable, while the specific incident or vulnerability is left
    to the bound, approved scenario specification (scenario_ref / scenario_version). This lets a
    future cohort receive a materially different scenario (S3/S4) without changing these templates,
    and it never hard-codes the same incident into every cohort.
  * Environment availability is computed from REAL signals (the seeded dataset workspace for the blue
    boards, the live OpenSearch SOC for board 2, and the Ludus broker for the red boards). A mission
    package being documented NEVER implies the environment is available: boards 5 and 6 show the
    range as unavailable until a real GOAD deployment is approved and validated.

The ten sections (reused across boards):
  1 business_context      5 objectives           9  evaluation
  2 assigned_role         6 deliverables         10 support
  3 authorized_scope      7 evidence
  4 environment           8 submission
"""
from __future__ import annotations

import program as P

MISSION_CONTRACT_VERSION = 1
ORG = "Valyria Financial Group"
ORG_DESC = ("Valyria Financial Group is a fictional, synthetic financial-services enterprise used "
            "for assessment. All data, identities, and systems are synthetic and clearly tagged as "
            "such; no real organization or person is represented.")

# Environment kinds drive the availability model (not the documentation's existence).
ENV_DATASET = "dataset"   # per-candidate seeded analysis workspace (boards 1, 3, 4)
ENV_SIEM = "siem"         # live OpenSearch SOC, private (board 2)
ENV_RANGE = "range"       # isolated Ludus/GOAD range over WireGuard (boards 5, 6)


def _ref(title, publisher, note):
    return {"title": title, "publisher": publisher, "note": note}


# Common, board-agnostic professional references (candidate-safe; never an official solution).
_COMMON_REFS = [
    _ref("MITRE ATT&CK Enterprise Matrix", "MITRE",
         "Adversary tactics and techniques taxonomy used throughout STRATA. Reference for naming, "
         "not a checklist of what is present in your assessment."),
    _ref("NIST SP 800-61r2, Computer Security Incident Handling Guide", "NIST",
         "Incident-handling lifecycle and terminology. Background reference, not a solution."),
]

# scenario_ref -> workbench_scenarios entry where one already exists (board 1 reuses strata-soc-triage).
MISSIONS = {
    1: {1: {
        "approved": True,
        "title": "SOC alert triage",
        "environment_kind": ENV_DATASET,
        "required_evidence_types": ["triage_adjudication"],
        "scenario_ref": "strata-soc-triage", "scenario_version": 1,
        "business_context":
            f"{ORG} operates a 24x7 Security Operations Center. Overnight, the detection stack has "
            "raised a batch of alerts spanning authentication, endpoint, and network activity across "
            "the corporate estate. As the incoming analyst, you own the first-line adjudication of "
            "this queue. Some alerts reflect genuine malicious activity; many are routine operational "
            "noise. The business needs an accurate, defensible disposition of each alert so that real "
            "threats are escalated and analyst time is not wasted on false positives.",
        "assigned_role":
            "SOC Analyst (Tier 1 triage). You adjudicate alerts, assign severity, attribute technique "
            "where warranted, and record the indicators that justify each true-positive call.",
        "authorized_scope":
            "You are authorized to review every alert in your assigned queue and the raw signal that "
            "accompanies it. You work only within your own assigned dataset. You do not pivot into "
            "systems outside the provided evidence, and you do not act on behalf of any identity.",
        "environment":
            "Your investigation surface is a per-candidate seeded alert dataset delivered to your "
            "Ranger lab workspace. Download it from your board workspace; each alert carries an id, "
            "timestamp, host, signal, and the raw log line. The dataset is unique to you and to this "
            "attempt.",
        "objectives": [
            "Adjudicate each alert as a true positive or a false positive, with a defensible basis.",
            "Assign a severity consistent with the activity the alert represents.",
            "For each true positive, attribute the MITRE ATT&CK technique the raw signal supports.",
            "For each true positive, record the indicators of compromise a responder would pivot on.",
            "Keep false positives out of the escalation set."],
        "deliverables": [
            "A triage adjudication covering every alert id in your queue.",
            "Per alert: verdict (true_positive or false_positive) and severity.",
            "Per true positive: the ATT&CK technique id and the supporting indicators."],
        "evidence":
            "Your evidence is the raw signal already present in the dataset; cite the alert ids you "
            "rely on. There is no external evidence to acquire for this board. Your submission is the "
            "record of your adjudication and is preserved as submitted.",
        "submission":
            "Submit the completed triage adjudication through your board workspace. A submission is "
            "accepted when it covers the alert ids in your queue and is well formed. Severity and "
            "technique fields are required for true positives.",
        "evaluation":
            "Your adjudication is graded server-side against the dataset, objectively and "
            "answer-free. The STRATA objective standard is 95 percent. Grading rewards correct "
            "verdicts, correct severity, correct technique attribution on true positives, and the "
            "quality of the indicators you cite, and it penalizes escalating false positives. The "
            "specific scoring weights and the answer key are not disclosed.",
        "support":
            "If the dataset will not download or appears truncated, re-open your board workspace and "
            "retry the download; the dataset is regenerated deterministically and your attempt is "
            "preserved. A download or workspace fault is a technical-support matter. Which verdict an "
            "alert deserves is an investigation question and is not supported. Contact candidate "
            "support for access faults only.",
        "references": _COMMON_REFS,
    }},
    2: {1: {
        "approved": True,
        "title": "Enterprise SOC investigation",
        "environment_kind": ENV_SIEM,
        "required_evidence_types": ["event_reference"],
        "scenario_ref": None, "scenario_version": None,  # bound to the Board 2 case contract per cohort
        "business_context":
            f"{ORG} has engaged you to investigate suspected malicious activity inside its enterprise "
            "estate over a defined assessment window. The environment is a realistic financial-sector "
            "network: identities across trading, retail banking, finance, compliance, IT and HR; "
            "business applications; and segmented infrastructure, carrying heavy legitimate activity. "
            "Your job is to determine, with evidence, whether one or more security incidents occurred, "
            "and to scope and characterize anything you confirm.",
        "assigned_role":
            "SOC Investigator (enterprise case). You run the investigation end to end in a live SIEM, "
            "cite the events that support your conclusions, and deliver a defensible case.",
        "authorized_scope":
            "You are authorized to query and analyze only your own assigned index in the Ranger SIEM. "
            "You operate as yourself; cross-candidate data is not accessible and must not be sought. "
            "You investigate; you do not remediate production systems.",
        "environment":
            "Your investigation surface is a live OpenSearch SIEM with Dashboards, backed by a "
            "per-candidate index populated with the assessment telemetry. Access is granted on "
            "assignment through the Ranger SOC gateway using your authorized identity; you read your "
            "own index only. The SIEM is a private, operated service; it is not a seeded file "
            "download.",
        "objectives": [
            "Establish whether security incidents occurred within the assessment window.",
            "For each confirmed incident: disposition, severity, a calibrated confidence, the "
            "affected identities and systems, the ATT&CK techniques, and a reconstructed timeline.",
            "Separate genuine malicious activity from the legitimate operational baseline.",
            "Assess detection coverage and note gaps you can support with evidence."],
        "deliverables": [
            "A structured case per the Board 2 submission workspace: baseline summary and overall "
            "conclusion, plus one entry per incident.",
            "For each incident: dispositioned findings with cited evidence, where each citation is an "
            "event identifier plus the exact query that reproduces it in your own index."],
        "evidence":
            "Evidence is cited events from your own authorized index. Each citation must exist in "
            "your index and reproduce from the query you provide; a valid reference that does not "
            "support the claim earns nothing. Your cited evidence is verified server-side and "
            "preserved as an Ed25519-signed citation record. This is the established Board 2 "
            "signed-citation workflow and is unchanged.",
        "submission":
            "Submit through the Board 2 case workspace. Submission runs the established citation "
            "verification: every cited event must be real, in scope, and reproducible. A submitted "
            "case is immutable and its evidence record is signed.",
        "evaluation":
            "Your case is evaluated against the authorized dataset and by reviewer adjudication. The "
            "STRATA objective standard is 95 percent. Evidence integrity proves origin and "
            "tamper-evidence; it is not a measure of investigative correctness. The answer key and "
            "scoring internals are not disclosed.",
        "support":
            "If the SIEM is unreachable, your index is empty, or Dashboards will not load, that is a "
            "technical-support matter; re-launch your SOC session from your board workspace and "
            "retry. Whether a given event is malicious is an investigation question and is not "
            "supported. Report access faults to candidate support.",
        "references": _COMMON_REFS + [
            _ref("OpenSearch Dashboards Documentation", "OpenSearch Project",
                 "Reference for the query and visualization interface you will use. Not a solution."),
            _ref("The DFIR Report (public incident write-ups)", "The DFIR Report",
                 "Professional examples of evidence-led intrusion analysis. Background reading."),
        ],
    }},
    3: {1: {
        "approved": True,
        "title": "Detection engineering",
        "environment_kind": ENV_DATASET,
        "required_evidence_types": ["detection_ruleset"],
        "scenario_ref": None, "scenario_version": None,
        "business_context":
            f"The {ORG} detection engineering team needs reliable analytics for a set of adversary "
            "behaviors that its current stack covers poorly. You are given labeled examples of the "
            "behaviors to detect and a sample of normal activity that includes legitimate uses of the "
            "same tools. Your analytics must catch the malicious behavior wherever it appears, not "
            "just in the samples you were shown, and must not drown the SOC in false positives on "
            "legitimate activity.",
        "assigned_role":
            "Detection Engineer. You author detection rules that generalize to unseen variants of the "
            "target behaviors while staying quiet on benign activity.",
        "authorized_scope":
            "You are authorized to study the labeled malicious samples and the benign baseline "
            "provided in your workspace, and to author detection rules against the documented "
            "detectable fields. You work only within your own assigned materials.",
        "environment":
            "Your workspace provides a per-candidate set of labeled malicious samples (intel, "
            "deliberately labeled) and a benign baseline that includes near-miss legitimate activity. "
            "The list of fields a rule may match on is published in the workspace. Your rules are "
            "evaluated by the Ranger backend against a held-out corpus you never see.",
        "objectives": [
            "Author detection rules that identify each target behavior by its invariant tradecraft.",
            "Ensure every target technique is covered; partial coverage is penalized.",
            "Keep precision high: legitimate activity that merely resembles the behavior must not "
            "fire your rules.",
            "Prefer rules that generalize over rules that memorize a specific sample string."],
        "deliverables": [
            "A detection ruleset in the documented rule format (named rules with a detection block "
            "and condition).",
            "Each rule may declare the technique it targets for your own mapping."],
        "evidence":
            "Your deliverable is the ruleset itself; no external evidence is acquired. Validation "
            "metrics are returned to you (coverage, false positives, recall, precision, per-rule "
            "firing counts) so you can iterate. The held-out corpus is never exposed.",
        "submission":
            "Submit your ruleset through your board workspace. A submission is accepted when it is a "
            "well-formed list of rules; malformed rules are reported back with actionable errors and "
            "do not crash evaluation.",
        "evaluation":
            "Your ruleset is compiled and run against a seeded held-out corpus derived from the same "
            "assignment, and scored on macro-recall across the target techniques and precision "
            "against benign activity. The STRATA objective standard is 95 percent. A rule that "
            "matches everything, or that covers only some techniques, cannot reach the bar. The "
            "corpus contents and the exact scoring are not disclosed.",
        "support":
            "If the workspace will not load the samples or the rule format reference, that is a "
            "technical-support matter; retry from your board workspace. Whether a specific field or "
            "token distinguishes malicious from benign is an investigation question and is not "
            "supported.",
        "references": _COMMON_REFS + [
            _ref("Sigma: Generic Signature Format for SIEM Systems", "SigmaHQ",
                 "The rule-authoring model STRATA's evaluator is based on. Reference for the format."),
            _ref("MITRE ATT&CK Data Sources and Detection", "MITRE",
                 "How techniques map to observable data. Background for detection design."),
        ],
    }},
    4: {1: {
        "approved": True,
        "title": "Incident response and forensic reconstruction",
        "environment_kind": ENV_DATASET,
        "required_evidence_types": ["ir_report"],
        "scenario_ref": None, "scenario_version": None,
        "business_context":
            f"{ORG} has suffered a confirmed breach. The intrusion is over; you are the responder "
            "brought in to reconstruct what happened from the forensic evidence collected across the "
            "affected estate. Leadership needs an accurate incident report: where the attacker got in, "
            "how far they reached, in what order events unfolded, and what must be removed to evict "
            "them. The evidence is woven through a large volume of normal activity.",
        "assigned_role":
            "Incident Responder / Forensic Analyst. You scope the compromise, reconstruct the "
            "timeline, and identify the persistence that must be remediated.",
        "authorized_scope":
            "You are authorized to analyze the forensic evidence set provided for this incident in "
            "your workspace. You work only within your own assigned evidence; you do not touch live "
            "production systems.",
        "environment":
            "Your workspace provides a per-candidate multi-host forensic evidence set: events across "
            "the estate with id, timestamp, host, account, type, and detail, with the incident labels "
            "stripped. The data is unique to you and to this attempt.",
        "objectives": [
            "Identify patient zero (the initial-access host) and the initial-access technique.",
            "Scope the compromise: the full set of affected hosts and accounts.",
            "Reconstruct the incident timeline in the correct order.",
            "Identify the persistence mechanism that must be removed."],
        "deliverables": [
            "An incident report: patient zero, initial-access technique, affected hosts, affected "
            "accounts, the ordered timeline of incident events, and the persistence to remediate."],
        "evidence":
            "Your evidence is the forensic event set already provided; cite the event ids that "
            "support each conclusion, including the ordered ids that make up your timeline. Your "
            "report is preserved as submitted.",
        "submission":
            "Submit your incident report through your board workspace. A submission is accepted when "
            "it is well formed and addresses the required sections.",
        "evaluation":
            "Your report is graded server-side against the incident ground truth, answer-free: "
            "patient zero, initial access, affected-host and affected-account accuracy, timeline "
            "membership and ordering, and persistence identification. The STRATA objective standard "
            "is 95 percent. An out-of-order timeline and an incorrect scope are penalized. The ground "
            "truth and scoring weights are not disclosed.",
        "support":
            "If the evidence set will not load or appears incomplete, retry from your board "
            "workspace; the set is regenerated deterministically and your attempt is preserved. That "
            "is a technical-support matter. Which events belong to the incident is an investigation "
            "question and is not supported.",
        "references": _COMMON_REFS + [
            _ref("SANS Digital Forensics and Incident Response posters", "SANS Institute",
                 "Reference material on timeline reconstruction and artifacts. Background only."),
        ],
    }},
    5: {1: {
        "approved": True,
        "title": "Authorized Active Directory red-team assessment",
        "environment_kind": ENV_RANGE,
        "required_evidence_types": ["captured_flags"],
        "scenario_ref": None, "scenario_version": None,
        "business_context":
            f"{ORG} has authorized an offensive security assessment of an isolated replica of its "
            "Active Directory estate. You are the operator. The engagement measures whether a "
            "determined adversary could progress from no access to full domain compromise against a "
            "realistic Windows AD environment, and documents the path with proof of each objective "
            "reached.",
        "assigned_role":
            "Red Team Operator. You conduct the authorized assessment against your own isolated range "
            "and prove each objective by capturing the artifact placed behind it.",
        "authorized_scope":
            "You are authorized to attack ONLY your own assigned, isolated range, reachable solely "
            "over your issued WireGuard tunnel. The range is single-tenant and dedicated to you. You "
            "are not authorized to touch any other candidate's range, Ranger infrastructure, or any "
            "system outside your tunnel. Activity outside the authorized range is out of scope and "
            "prohibited.",
        "environment":
            "Your environment is a dedicated, isolated Game-of-Active-Directory range, reachable over "
            "a per-operator WireGuard tunnel. Proof of each objective is a unique flag planted in the "
            "range at a location reachable only by completing that objective; the flag is derived "
            "cryptographically for you and is useless to anyone else.",
        "objectives": [
            "Progress through the published engagement objectives, from domain enumeration and "
            "foothold to credential access, lateral movement, privilege escalation, and domain "
            "compromise.",
            "Each objective lists its name, the associated technique family, and its point value.",
            "Capture the flag behind each objective you complete."],
        "deliverables": [
            "The captured flags, one per objective completed, submitted against their objective ids."],
        "evidence":
            "Your proof of action is the captured flag for each objective. Flags are per-operator and "
            "non-transferable; a flag captured by another operator will not score for you. No written "
            "narrative is graded for this board.",
        "submission":
            "Submit captured flags through your board workspace, mapped to their objective ids. "
            "Scoring is points-weighted by objective. Guessed or fabricated flags do not score.",
        "evaluation":
            "The Ranger backend re-derives the expected flags for your assignment and scores your "
            "captures, points-weighted. The STRATA objective standard is 95 percent. Because each "
            "flag is a cryptographic proof of a specific action on your own range, the score reflects "
            "the objectives you genuinely completed; guessing cannot reach the bar. Objective credit "
            "is awarded only against a real, validated isolated range: a simulated or unvalidated "
            "environment records no credit, regardless of score, and board clearance also requires "
            "report approval.",
        "support":
            "Range provisioning, WireGuard connectivity, and flag retrieval faults are "
            "technical-support matters: check your tunnel and range status in your board workspace "
            "and retry. If your range is suspended to free capacity while you are away, your disks "
            "and progress are preserved; resume it from your board workspace to continue. How to "
            "complete an objective is the assessment itself and is not supported, and no hints, "
            "commands, or attack paths are provided.",
        "references": _COMMON_REFS + [
            _ref("Game of Active Directory (GOAD)", "Orange Cyberdefense",
                 "The open AD lab project this range is built on. Reference for the environment's "
                 "shape, not a solution to the assessment."),
            _ref("Active Directory Security (adsecurity.org)", "Sean Metcalf",
                 "Professional reference on AD attack surface and defense. Background only."),
        ],
    }},
    6: {1: {
        "approved": True,
        "title": "Capstone: multi-forest Active Directory compromise",
        "environment_kind": ENV_RANGE,
        "required_evidence_types": ["captured_flags"],
        "scenario_ref": None, "scenario_version": None,
        "business_context":
            f"The {ORG} capstone assessment raises the bar to a multi-domain forest with an external "
            "trust. You must demonstrate end-to-end mastery: compromise a child domain, abuse the "
            "trust to the forest root, establish forest-wide persistence, and pivot across the trust "
            "into a second forest. This is the culminating offensive assessment of the STRATA "
            "program.",
        "assigned_role":
            "Capstone Red Team Operator (Vanguard). You own the full engagement across a forest and "
            "its trusts and prove each escalation with its flag.",
        "authorized_scope":
            "You are authorized to attack ONLY your own assigned, isolated multi-forest range over "
            "your issued WireGuard tunnel. The range is single-tenant. No other candidate's range, no "
            "Ranger infrastructure, and nothing outside your tunnel is in scope.",
        "environment":
            "Your environment is a dedicated, isolated multi-forest GOAD range (a parent and child "
            "domain plus a trust to a second forest), reachable over a per-operator WireGuard tunnel. "
            "Each capstone objective is proven by a unique, cryptographically derived flag planted "
            "behind it; flags are distinct from every other board and non-transferable.",
        "objectives": [
            "Progress through the capstone objectives: forest and trust enumeration, foothold, ticket "
            "harvesting, child-domain compromise, cross-domain trust abuse, forest-root takeover, "
            "forest persistence, cross-forest pivot, and capture of the designated crown-jewel "
            "secret.",
            "Each objective lists its name, technique family, and point value.",
            "Capture the flag behind each objective you complete."],
        "deliverables": [
            "The captured flags, one per capstone objective completed, submitted against their "
            "objective ids."],
        "evidence":
            "Your proof of action is the captured flag per objective. Capstone flags carry a "
            "board-specific tag and are distinct from Board 5 flags, so no earlier capture transfers "
            "to the capstone.",
        "submission":
            "Submit captured flags through your board workspace, mapped to their objective ids. "
            "Unlike Board 5's flat points sum, the capstone is graded by a versioned capstone rubric: "
            "a set of MANDATORY end-to-end milestones (child-domain compromise, cross-domain trust "
            "abuse, forest-root takeover, forest persistence, cross-forest pivot, and crown-jewel "
            "capture) must ALL be demonstrated. Missing any mandatory milestone is a critical failure "
            "that caps your score below the pass bar regardless of points earned on other objectives. "
            "Guessed or fabricated flags do not score.",
        "evaluation":
            "The Ranger backend re-derives the capstone's expected flags and scores your captures "
            "under the versioned capstone rubric (points-weighted, with the mandatory-milestone "
            "critical-failure gate above). The STRATA objective standard is 95 percent. The capstone's "
            "distinct derivation and rubric ensure it measures capstone competency specifically, "
            "separate from Board 5. Objective credit is awarded only against a real, validated isolated "
            "range: a simulated or unvalidated environment records no credit, and clearance also "
            "requires report approval.",
        "support":
            "Range, tunnel, and flag faults are technical-support matters: check range status in your "
            "board workspace and retry. If your range is suspended to free capacity while you are "
            "away, your disks and progress are preserved; resume it from your board workspace. How to "
            "complete a capstone objective is the assessment itself and is not supported; no hints, "
            "commands, or attack paths are provided.",
        "references": _COMMON_REFS + [
            _ref("Game of Active Directory (GOAD)", "Orange Cyberdefense",
                 "The multi-forest lab project this capstone range extends. Reference only."),
            _ref("An ACE Up the Sleeve / AD trust research (public)", "SpecterOps and others",
                 "Professional research on AD trusts and delegation. Background, not a solution."),
        ],
    }},
}


# --- API ------------------------------------------------------------------------------------
def _versions(board):
    return MISSIONS.get(int(board), {})


def available_versions(board):
    return sorted(v for v, e in _versions(board).items() if e.get("approved") is True)


def latest_version(board):
    vs = available_versions(board)
    return vs[-1] if vs else None


def is_approved(board, version):
    e = _versions(board).get(int(version)) if version is not None else None
    return bool(e) and e.get("approved") is True


def get(board, version=None):
    """Return the approved, candidate-safe mission package for a board (latest approved version when
    version is None), enriched with identity and binding fields, or None when none is approved."""
    board = int(board)
    if version is None:
        version = latest_version(board)
    if version is None:
        return None
    e = _versions(board).get(int(version))
    if not e or e.get("approved") is not True:
        return None
    out = dict(e)
    out["board"] = board
    out["version"] = int(version)
    out["mission_contract_version"] = MISSION_CONTRACT_VERSION
    out["org"] = ORG
    out["org_disclaimer"] = ORG_DESC
    try:
        out["badge"] = P.badge_for(board)[1]
        out["role_title"] = P.ROLE_TITLES.get(P.role_of(board), out.get("assigned_role", ""))
        out["tier"] = P.tier_of(board)
    except Exception:  # noqa: BLE001 - program metadata is best-effort for display
        out.setdefault("badge", None)
        out.setdefault("role_title", out.get("assigned_role", ""))
        out.setdefault("tier", None)
    # pass_bar is quoted from program, never redefined here
    out["pass_bar"] = P.PASS_BAR
    return out


def for_binding(binding, *, broker_mod=None):
    """A scenario-BOUND mission package for a candidate's actual assignment.

    This is a CANDIDATE-FACING projection. It overlays only the cohort identity, the pinned scenario
    version and an OPAQUE, keyed scenario reference onto the generic, S2-approved board mission. It
    deliberately does NOT surface the variant id, the variant spec id, or the variant's own title and
    business_context, because the public variant library (siem/board_variants.py) authors those per
    incident type: the Board 2 variant titles and contexts name the incident-family composition
    (privileged-identity takeover, service-account exfiltration, stealth lateral movement) and, for
    the insider-exfil variant, the hidden detection gap ("whether current detections covered it").
    Disclosing them to the assigned candidate would reveal which scenario they were given before they
    investigate. The generic board mission already states the legitimate scope, role, deliverables and
    authorized investigation activities, so the brief stays professional and useful without that leak.
    The hidden incident family, truth, ground-truth ids, attack sequence and intended detection gaps
    are never stored on the binding and never surfaced here. Returns None when the board has no
    mission package. `binding` is a models.ScenarioBinding."""
    board = int(binding.board)
    pkg = get(board)
    if not pkg:
        return None
    out = dict(pkg)
    out["cohort"] = binding.cohort
    out["scenario_version"] = binding.spec_version
    # Opaque, keyed, non-invertible reference only. NEVER binding.spec_id / variant_id (which map to
    # the publicly readable incident-family composition), and NEVER the variant title/business_context.
    try:
        from siem import schema as _schema
        out["scenario_ref"] = _schema.case_ref(binding.github_id, board, binding.seed)
    except Exception:  # noqa: BLE001 - reference is best-effort display metadata
        out["scenario_ref"] = None
    out["scenario_bound"] = True
    return out


def environment_availability(board, *, broker_mod=None, siem_live=None):
    """Compute REAL environment availability for a board's mission. Documentation existing never
    implies availability. Returns {"available", "state", "message"}.

      dataset (boards 1,3,4): available to an authorized candidate (the seeded workspace).
      siem    (board 2): provisioned; candidate access is granted on assignment.
      range   (boards 5,6): available ONLY when the Ludus broker is live; mock mode = unavailable
              until a real GOAD range is approved, deployed, and validated.
    """
    pkg = get(board)
    kind = (pkg or {}).get("environment_kind")
    if kind == ENV_DATASET:
        return {"available": True, "state": "dataset_ready",
                "message": "Your seeded analysis workspace is available from your board workspace."}
    if kind == ENV_SIEM:
        return {"available": True, "state": "siem_on_assignment",
                "message": "The SOC environment is provisioned; access is granted on assignment "
                           "through the SOC gateway using your authorized identity."}
    if kind == ENV_RANGE:
        if broker_mod is None:
            try:
                import broker as broker_mod  # noqa: PLC0415
            except Exception:  # noqa: BLE001
                broker_mod = None
        live = bool(broker_mod and broker_mod.is_live())
        if live:
            return {"available": True, "state": "range_live",
                    "message": "Your isolated range can be deployed from your board workspace."}
        return {"available": False, "state": "range_unavailable",
                "message": "Live range access is not yet available. The isolated GOAD environment "
                           "for this board requires an approved and validated deployment before it "
                           "can be provisioned. Mission instructions are available for preparation; "
                           "the environment is not."}
    return {"available": False, "state": "unknown",
            "message": "No environment is defined for this board."}


def mission_index():
    """A discovery index of approved missions: one row per board with its latest approved version."""
    rows = []
    for board in sorted(MISSIONS):
        v = latest_version(board)
        if v is None:
            continue
        pkg = get(board, v)
        rows.append({"board": board, "version": v, "title": pkg["title"],
                     "role_title": pkg.get("role_title"), "badge": pkg.get("badge"),
                     "environment_kind": pkg["environment_kind"],
                     "tier": pkg.get("tier")})
    return rows
