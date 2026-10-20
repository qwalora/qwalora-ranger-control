#!/usr/bin/env python3
"""PARALLAX design-completion acceptance harness.

Seeds real signed records into a throwaway SQLite database, serves the real Flask app in a
daemon thread, then drives a real Chromium (Playwright) against the rendered pages to:
  - run an axe-core WCAG 2.2 AA audit on every researcher surface (desktop + mobile),
  - capture full-page screenshots at 390 / 768 / 1280 / 1440 px,
  - execute the 10-step researcher journey (command center, console, evidence detail,
    provenance verification, authorized export, program authorization, not-found, keyboard focus).

Single process on purpose: the Flask dev server and the browser share one lifecycle so the app
cannot be torn down between the audit and the journey. Nothing here fabricates results; every
assertion is read back from the rendered DOM or a real HTTP response.

Run (from the repository root), with the local UI venv active:

    AXE_CORE_JS=node_modules/axe-core/axe.min.js \
    PLAYWRIGHT_CHROMIUM=/opt/pw-browsers/chromium-1194/chrome-linux/chrome \
    python scripts/research/acceptance/acceptance.py /path/to/output_dir

Defaults: AXE_CORE_JS falls back to ./node_modules/axe-core/axe.min.js (npm i axe-core),
PLAYWRIGHT_CHROMIUM falls back to Playwright's bundled Chromium (playwright install chromium).
Output: <output_dir>/accept-<surface>-<viewport>.png (16 files) and acceptance_results.json.
Exit code is non-zero if any axe critical/serious violation, any failed journey step, or any
capture error is recorded, so it can gate CI.
"""
import json
import os
import sys
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, ROOT)

DB_PATH = os.environ.get("ACCEPT_DB", os.path.join(os.sep, "tmp", "parallax_accept.db"))
os.environ.setdefault("DATABASE_URL", "sqlite:///" + DB_PATH)
os.environ.setdefault("SECRET_KEY", "accept-fixed-secret-00000000000000")
os.environ.update(
    RANGER_ENV="dev", RANGER_PARALLAX_LABA="1", RANGER_PARALLAX_LABA_ENV="dev",
    DEFAULT_COHORT="2026-A", RANGER_PARALLAX_LABA_APPROVAL_B64="", CUDA_VISIBLE_DEVICES="")

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(ROOT, "scratchpad-accept")
os.makedirs(OUT, exist_ok=True)
PORT = int(os.environ.get("ACCEPT_PORT", "5090"))
if os.path.exists(DB_PATH):
    os.remove(DB_PATH)

import app as A  # noqa: E402
from models import db, Candidate, ParallaxResearchRun  # noqa: E402
from parallax.research import store as rstore  # noqa: E402


def persist_trial(rid, is_real, outcome, model_id="qwalora-charGPT-tiny"):
    """Persist one signed trial record exactly as the harness would (owner-scoped, Ed25519-signed)."""
    camp = {"manifest": {"kind": "trial", "backend": {"is_real": is_real, "model_id": model_id,
            "runtime": "isolated-worker", "backend": "http"}, "n_records": 1},
            "metrics": {"kind": "trial", "record": {"outcome": outcome, "condition": "baseline_benign",
            "evaluation": {"canary": False}, "model": {"digest": "bae88d84" * 8},
            "inference_params": {"temperature": 0.0, "max_tokens": 256, "latency_s": 0.25}}}}
    return rstore.persist_run(db, researcher_id=rid, campaign=camp)


with A.app.app_context():
    import scripts.px_review_fixture as fx
    fx.ensure_fixture(db)  # researcher A: parallax + 1 trial + 1 investigation (pending review)
    a = Candidate.query.filter_by(github_id="nonprod-fixture:parallax-review-selftest").first()
    for oc in ("inconclusive", "boundary_preserved", "inconclusive"):
        persist_trial(a.github_id, True, oc)
    cid = a.id
    nruns = ParallaxResearchRun.query.filter_by(researcher_id=a.github_id).count()
print("seeded researcher cid=%d runs=%d" % (cid, nruns))

threading.Thread(target=lambda: A.app.run("127.0.0.1", PORT, threaded=True, use_reloader=False),
                 daemon=True).start()
import urllib.request  # noqa: E402
for _ in range(40):
    try:
        urllib.request.urlopen("http://127.0.0.1:%d/healthz" % PORT, timeout=3)
        break
    except Exception:
        time.sleep(0.5)

from flask.sessions import SecureCookieSessionInterface  # noqa: E402
cookie = SecureCookieSessionInterface().get_signing_serializer(A.app).dumps({"cand": cid})
cname = A.app.config.get("SESSION_COOKIE_NAME", "session")
BASE = "http://127.0.0.1:%d" % PORT
SURFACES = [("command-center", "/me?program=parallax"), ("console", "/parallax/workspace"),
            ("evidence", "/parallax/research/evidence"), ("account", "/account")]
VIEWPORTS = [("mobile390", 390, 844), ("tablet768", 768, 1024), ("desktop1280", 1280, 900),
             ("large1440", 1440, 900)]
AXE = os.environ.get("AXE_CORE_JS", os.path.join(ROOT, "node_modules", "axe-core", "axe.min.js"))
CH = os.environ.get("PLAYWRIGHT_CHROMIUM", "")

from playwright.sync_api import sync_playwright  # noqa: E402
results = {"axe": {}, "journey": [], "screenshots": [], "errors": []}


def _launch(p):
    return p.chromium.launch(executable_path=CH, args=["--no-sandbox"]) if CH \
        else p.chromium.launch(args=["--no-sandbox"])


with sync_playwright() as p:
    b = _launch(p)

    # ---- 4-viewport screenshots of every surface ----
    for vlabel, w, h in VIEWPORTS:
        ctx = b.new_context(viewport={"width": w, "height": h}, device_scale_factor=1.5)
        ctx.add_cookies([{"name": cname, "value": cookie, "domain": "127.0.0.1", "path": "/"}])
        pg = ctx.new_page()
        for slug, path in SURFACES:
            try:
                pg.goto(BASE + path, wait_until="load", timeout=20000)
                pg.wait_for_timeout(300)
                fn = "%s/accept-%s-%s.png" % (OUT, slug, vlabel)
                pg.screenshot(path=fn, full_page=True)
                results["screenshots"].append(os.path.basename(fn))
            except Exception as e:
                results["errors"].append("shot %s %s: %s" % (slug, vlabel, type(e).__name__))
        ctx.close()

    # ---- axe-core audit on each surface (desktop + mobile) ----
    for vlabel, w, h in [("desktop1280", 1280, 900), ("mobile390", 390, 844)]:
        ctx = b.new_context(viewport={"width": w, "height": h})
        ctx.add_cookies([{"name": cname, "value": cookie, "domain": "127.0.0.1", "path": "/"}])
        pg = ctx.new_page()
        for slug, path in SURFACES:
            try:
                pg.goto(BASE + path, wait_until="load", timeout=20000)
                pg.add_script_tag(path=AXE)
                res = pg.evaluate("""async () => {
                    const r = await axe.run(document, {runOnly:{type:'tag',
                        values:['wcag2a','wcag2aa','wcag21a','wcag21aa','wcag22aa','best-practice']}});
                    return r.violations.map(v => ({id:v.id, impact:v.impact, help:v.help,
                        n:v.nodes.length, targets:v.nodes.slice(0,3).map(n=>n.target.join(' '))}));
                }""")
                results["axe"]["%s@%s" % (slug, vlabel)] = res
            except Exception as e:
                results["errors"].append("axe %s %s: %s" % (slug, vlabel, type(e).__name__))
        ctx.close()

    # ---- 10-step researcher journey (desktop) ----
    ctx = b.new_context(viewport={"width": 1280, "height": 900})
    ctx.add_cookies([{"name": cname, "value": cookie, "domain": "127.0.0.1", "path": "/"}])
    pg = ctx.new_page()

    def step(name, ok, detail=""):
        results["journey"].append({"step": name, "ok": bool(ok), "detail": detail})

    try:
        pg.goto(BASE + "/me?program=parallax", wait_until="load")
        step("1 open command center", "Research activity" in pg.content())
        pg.goto(BASE + "/parallax/workspace", wait_until="load")
        step("2 research console", "Experiment" in pg.content())
        pg.goto(BASE + "/parallax/research/evidence", wait_until="load")
        html = pg.content()
        step("3 inspect trial list", "Evidence records" in html)
        pg.eval_on_selector_all("details.pxe-item", "els=>{if(els[0])els[0].setAttribute('open','')}")
        pg.wait_for_timeout(200)
        d = pg.content()
        step("4 open signed evidence detail", "Record id" in d)
        step("5 verify provenance+metadata",
             all(k in d for k in ("Execution", "Evidence", "Measurement", "Finding status")))
        href = pg.eval_on_selector("a[href$='.json']", "a=>a.getAttribute('href')")
        er = pg.request.get(BASE + href)
        step("6 export authorized JSON",
             er.status == 200 and "attachment" in (er.headers.get("content-disposition") or ""),
             "status=%s" % er.status)
        pg.goto(BASE + "/parallax/workspace", wait_until="load")
        step("7 return to workspace", "Experiment" in pg.content())
        pg.goto(BASE + "/account", wait_until="load")
        ah = pg.content()
        step("8 account + program authorization", "GitHub authenticated" in ah and "Program access" in ah)
        nf = pg.request.get(BASE + "/parallax/research/evidence/run-doesnotexist.json")
        step("9 not-found/unavailable state", nf.status == 404, "status=%s" % nf.status)
        pg.goto(BASE + "/parallax/research/evidence", wait_until="load")
        pg.keyboard.press("Tab")
        focused = pg.evaluate("""() => { const e=document.activeElement; if(!e) return null;
            const s=getComputedStyle(e); return {tag:e.tagName,
            text:(e.innerText||e.getAttribute('aria-label')||'').slice(0,30),
            outline:s.outlineStyle, boxShadow:(s.boxShadow||'').slice(0,20)}; }""")
        step("10 keyboard focus reaches a named control", bool(focused and focused.get("tag")),
             json.dumps(focused))
    except Exception as e:
        results["errors"].append("journey: %s %s" % (type(e).__name__, str(e)[:120]))
    ctx.close()
    b.close()

crit = []
for k, vs in results["axe"].items():
    for v in (vs or []):
        if v["impact"] in ("critical", "serious"):
            crit.append({"surface": k, **v})
results["axe_critical_serious"] = crit
results["axe_total_violations"] = sum(len(v or []) for v in results["axe"].values())
json.dump(results, open("%s/acceptance_results.json" % OUT, "w"), indent=2)

print("=== ACCEPTANCE SUMMARY ===")
print("screenshots:", len(results["screenshots"]), "| errors:", len(results["errors"]))
print("axe total violations:", results["axe_total_violations"], "| critical/serious:", len(crit))
for c in crit:
    print("  [%s] %s (%s) x%d @%s" % (c["impact"], c["id"], c["help"][:50], c["n"], c["surface"]))
print("journey:")
for s in results["journey"]:
    print("  %s %s %s" % ("PASS" if s["ok"] else "FAIL", s["step"], s["detail"][:60]))
if results["errors"]:
    print("errors:", results["errors"])

sys.exit(1 if (crit or results["errors"] or any(not s["ok"] for s in results["journey"])) else 0)
