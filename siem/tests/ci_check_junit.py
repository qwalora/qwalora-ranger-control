#!/usr/bin/env python3
"""STRATA S5.1 CI JUnit gate.

A green CI result must mean the real-OpenSearch integration tests actually EXECUTED and PASSED. This
gate fails the job (exit 1) when that is not true. It is mandatory and must not be bypassed.

Fails when:
  * the JUnit XML is missing or unparseable (suite not collected / readiness not confirmed);
  * zero tests ran;
  * any test was skipped (skips are correct for local dev, but NOT for this CI job);
  * any test failed or errored;
  * fewer than the expected minimum number of tests were collected (partial collection).

Usage: python siem/tests/ci_check_junit.py <junit.xml> [--min N]
Writes a short summary to stdout and, when present, to $GITHUB_STEP_SUMMARY.
"""
from __future__ import annotations

import os
import sys
import xml.etree.ElementTree as ET


def _summary(line: str):
    print(line)
    p = os.environ.get("GITHUB_STEP_SUMMARY")
    if p:
        try:
            with open(p, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:  # noqa: BLE001
            pass


def main(argv):
    path = argv[1] if len(argv) > 1 else "artifacts/real-opensearch.xml"
    minimum = 1
    if "--min" in argv:
        try:
            minimum = int(argv[argv.index("--min") + 1])
        except Exception:  # noqa: BLE001
            minimum = 1

    _summary("## STRATA S5.1 real-OpenSearch JUnit gate")
    if not os.path.exists(path):
        _summary(f"FAIL: JUnit report `{path}` is missing - the real-node suite did not run "
                 f"(OpenSearch readiness/authorization not confirmed).")
        return 1
    try:
        root = ET.parse(path).getroot()
    except Exception as e:  # noqa: BLE001
        _summary(f"FAIL: cannot parse JUnit report `{path}`: {e}")
        return 1

    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    tests = failures = errors = skipped = 0
    for s in suites:
        tests += int(s.get("tests", 0) or 0)
        failures += int(s.get("failures", 0) or 0)
        errors += int(s.get("errors", 0) or 0)
        skipped += int(s.get("skipped", 0) or 0)
    executed = tests - skipped
    passed = executed - failures - errors

    _summary(f"- collected: {tests}")
    _summary(f"- passed: {passed}")
    _summary(f"- failed: {failures}")
    _summary(f"- errored: {errors}")
    _summary(f"- skipped: {skipped}")

    problems = []
    if tests == 0:
        problems.append("zero tests ran")
    if tests < minimum:
        problems.append(f"only {tests} tests collected (expected at least {minimum})")
    if skipped > 0:
        problems.append(f"{skipped} test(s) skipped - real OpenSearch validation must not skip in CI")
    if failures > 0:
        problems.append(f"{failures} test(s) failed")
    if errors > 0:
        problems.append(f"{errors} test(s) errored")

    if problems:
        _summary("FAIL: " + "; ".join(problems) + ".")
        return 1
    _summary(f"PASS: {passed} real-OpenSearch test(s) executed and passed, 0 skipped.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
