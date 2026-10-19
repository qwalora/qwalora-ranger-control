#!/usr/bin/env python3
"""Build the Ranger candidate handbook from ONE markdown source into a navigable HTML page and a
downloadable PDF, so both outputs derive from a single version-controlled source.

Source:  docs/handbook/RANGER_CANDIDATE_HANDBOOK.md
Outputs: docs/handbook/dist/ranger-candidate-handbook.html   (navigable, standalone, with TOC)
         docs/handbook/dist/Qwalora-Ranger-Candidate-Handbook.pdf

LOCAL BUILD ONLY. Public publication to ranger.qwalora.com is a separate, authorization-gated
deployment of the qwalora-cyber-range repository (see docs/RELEASE_DOC_VALIDATION.md). A generated
PDF is NOT a published handbook.
"""
import datetime
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "docs", "handbook", "RANGER_CANDIDATE_HANDBOOK.md")
DIST = os.path.join(ROOT, "docs", "handbook", "dist")
HTML = os.path.join(DIST, "ranger-candidate-handbook.html")
PDF = os.path.join(DIST, "Qwalora-Ranger-Candidate-Handbook.pdf")


def _git_commit():
    try:
        return subprocess.check_output(["git", "-C", ROOT, "rev-parse", "--short", "HEAD"],
                                       stderr=subprocess.DEVNULL).decode().strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def build():
    if not os.path.exists(SRC):
        print("handbook source missing:", SRC)
        return 1
    os.makedirs(DIST, exist_ok=True)
    commit = _git_commit()
    built = datetime.datetime.now(datetime.timezone.utc).isoformat()
    meta = ["-M", "build-commit=" + commit, "-M", "build-timestamp=" + built,
            "-M", "title=Qwalora Ranger Candidate Handbook",
            # pagetitle sets the HTML <title>, which wkhtmltopdf records as the PDF Title metadata
            "-V", "pagetitle=Qwalora Ranger Candidate Handbook"]
    # navigable, self-contained HTML with a table of contents
    subprocess.check_call(["pandoc", SRC, "-s", "--toc", "--toc-depth=2", *meta, "-o", HTML])
    # downloadable PDF from the SAME source
    subprocess.check_call(["pandoc", SRC, "--toc", "--toc-depth=2",
                           "--pdf-engine=wkhtmltopdf", *meta, "-o", PDF])
    print("build-commit:   ", commit)
    print("build-timestamp:", built)
    print("HTML:", HTML, os.path.getsize(HTML), "bytes")
    print("PDF: ", PDF, os.path.getsize(PDF), "bytes")
    return 0


if __name__ == "__main__":
    sys.exit(build())
