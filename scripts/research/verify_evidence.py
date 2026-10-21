"""Read-only CLI for verifying PARALLAX campaign evidence and producing a sanitized export.

    python -m scripts.research.verify_evidence <evidence_dir> \
        [--trusted-keys trusted_keys.json] \
        [--signatures signatures.json] \
        [--plan plan.json] \
        [--commitments commitments.json] \
        [--export <dest_dir>] \
        [--report-out report.json] \
        [--require-eligible]

Inputs (all optional except the evidence dir):
  --trusted-keys   JSON array of {"kid","public_b64"[,"alg"]} the verifier EXPLICITLY trusts.
  --signatures     JSON object mapping evidence_hash -> {"signature_b64","kid"?}.
  --plan           JSON array of preregistered unit keys [repetition, condition, task_id, variant_id].
  --commitments    JSON object mapping evidence_hash -> {reproducible_content_sha256, config_identity_sha256, full_record_sha256?}.
  --export         Produce the sanitized export bundle into this (new/empty, non-symlink) directory.
  --report-out     Write the machine-readable verification report to this path.
  --require-eligible  Exit non-zero unless the result is scientifically ELIGIBLE (not merely complete).

This script performs NO network calls and writes only to the paths you name (report-out / export).
It never modifies the evidence directory. Exit code: 0 on overall PASS (and, with --require-eligible,
eligible), 1 otherwise, 2 on a refused/unsafe operation.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

# Allow running both as a module (-m scripts.research.verify_evidence) and as a file.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from parallax.research import evidence_verifier as V


def _load_json(path):
    if not path:
        return None
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="verify_evidence", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("evidence_dir")
    ap.add_argument("--trusted-keys")
    ap.add_argument("--signatures")
    ap.add_argument("--plan")
    ap.add_argument("--commitments")
    ap.add_argument("--expected-config-identity",
                    help="preregistered config_identity_sha256 every record must match")
    ap.add_argument("--export")
    ap.add_argument("--report-out")
    ap.add_argument("--require-eligible", action="store_true")
    args = ap.parse_args(argv)

    trusted = _load_json(args.trusted_keys)
    signatures = _load_json(args.signatures)
    plan = _load_json(args.plan)
    commitments = _load_json(args.commitments)

    report = V.verify_campaign(args.evidence_dir, trusted_keys=trusted, signatures=signatures,
                               expected_plan=plan, committed_commitments=commitments,
                               expected_config_identity=args.expected_config_identity)

    if args.report_out:
        with open(args.report_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, sort_keys=True, indent=2)

    v = report["verdicts"]
    print("overall:               %s" % report["overall"])
    print("integrity_ok:          %s" % v["integrity_ok"])
    print("campaign_complete:     %s" % v["campaign_complete"]["complete"])
    for r in v["campaign_complete"]["reasons"]:
        print("    - %s" % r)
    print("result_eligible:       %s" % v["result_eligible"]["eligible"])
    for r in v["result_eligible"]["reasons"]:
        print("    - %s" % r)
    print("signatures:            %s" % report["signatures"]["summary"])
    cc = report["config_consistency"]
    print("config_consistency:    distinct=%d homogeneous=%s matches_expected=%s"
          % (cc["distinct_configs"], cc["homogeneous"], cc["matches_expected"]))
    tb = report["trust_basis"]
    print("trust_basis:           independent_validation=%s (keys=%s plan=%s)"
          % (tb["independent_validation"], tb["trusted_keys_supplied"], tb["plan_supplied"]))
    print("committed_state:       %s" % report.get("committed_state"))
    if v["campaign_complete"].get("state_disagreement"):
        print("    ! %s" % v["campaign_complete"]["state_disagreement"])
    rec = report["reconciliation"]
    print("reconciliation:        planned=%s with_record=%s excluded=%s on_plan=%s unaccounted=%d double=%d"
          % (rec.get("planned"), rec.get("with_record"), rec.get("excluded"),
             rec.get("excluded_on_plan"), len(rec["unaccounted"]), len(rec["double_counted"])))

    if args.export:
        try:
            man = V.build_sanitized_export(args.evidence_dir, args.export, report=report,
                                           signatures=signatures, trusted_keys=trusted,
                                           expected_plan=plan, committed_commitments=commitments,
                                           expected_config_identity=args.expected_config_identity)
        except (V.UnsafeExportPath, V.RedactionFailure) as e:
            print("EXPORT REFUSED: %s" % e, file=sys.stderr)
            return 2
        print("export_dir:            %s" % man["export_dir"])
        print("records_redacted:      %d/%d" % (man["redaction_summary"]["records_redacted"],
                                                man["redaction_summary"]["records_total"]))
        print("signatures_preserved:  %d" % man["redaction_summary"]["signatures_preserved"])

    if report["overall"] != "PASS":
        return 1
    if args.require_eligible and not v["result_eligible"]["eligible"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
