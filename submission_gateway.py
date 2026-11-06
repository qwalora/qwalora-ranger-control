"""Ranger /submit gateway: one-click, tamper-proof PARALLAX submission.

An AI-security candidate works in a PLATFORM-OWNED per-candidate repository
(qwalora-ranger/<cohort>-<slug>). When they click Submit, the SERVER does all of
the work with tokens the candidate never holds: it snapshots the repo at the exact
HEAD commit, computes a content digest, pins an immutable tag at that commit,
optionally records a Hugging Face model revision, builds and Ed25519-signs a
submission manifest, records the immutable reference, and enqueues a grading job.

Custody mirrors soc_gateway.py: every token (the platform GitHub org token, the
optional Hugging Face token, the signing key) lives in the portal process and is
injected into upstream requests only. It never reaches the browser, a URL, or
storage. The candidate cannot alter what was submitted: the signed manifest binds
the exact commit SHA and the snapshot digest, so grading reads a frozen artifact.

Grading runs in a SEPARATE low-privilege service (the grader), reached over Railway
private networking with a shared internal token. The grader holds no GitHub or HF
token: the portal hands it a digest-verified code snapshot plus a model endpoint,
and the grader runs parallax.research.harness against it. Isolation is by identity
and process boundary, not by per-candidate infrastructure.

Gating: the gateway is inert unless RANGER_SUBMISSION is enabled AND the platform
org token is configured. Candidate-facing routes additionally require an active
PARALLAX program membership. Internal grader routes require the shared grader token.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import abort, jsonify, request, session

import signing

# --- Configuration -----------------------------------------------------------
GH_API = "https://api.github.com"
HF_API = "https://huggingface.co/api"
ORG = os.environ.get("RANGER_SUBMISSION_ORG", "qwalora")
SIG_DOMAIN = "parallax.submission.v1"
GRADE_SIG_DOMAIN = "parallax.grade.v1"
# Hard cap on the code snapshot the portal will hand the grader inline. Code and
# configs are KB-MB; model weights never travel this path (they go to HF via LFS).
MAX_SNAPSHOT_BYTES = int(os.environ.get("RANGER_SUBMISSION_MAX_SNAPSHOT_BYTES", str(16 * 1024 * 1024)))
HTTP_TIMEOUT = int(os.environ.get("RANGER_SUBMISSION_HTTP_TIMEOUT", "30"))
_UA = "qwalora-ranger-submission"


def _enabled() -> bool:
    return str(os.environ.get("RANGER_SUBMISSION", "")).strip().lower() in ("1", "true", "yes", "on")


def _org_token() -> str:
    # Fine-grained PAT or GitHub App installation token scoped to the submission org
    # with Contents: read/write and Administration: write (repo create). Server-only.
    return os.environ["RANGER_GITHUB_ORG_TOKEN"]


def _hf_token():
    return os.environ.get("RANGER_HF_TOKEN") or None


def _grader_token() -> str:
    return os.environ.get("RANGER_GRADER_TOKEN", "")


def _log(event, **kv):
    safe = {k: v for k, v in kv.items() if k not in ("token", "authorization", "secret")}
    print(f"[submit-audit] {event} " + " ".join(f"{k}={v}" for k, v in safe.items()), flush=True)


def _utcnow():
    return _dt.datetime.now(_dt.timezone.utc)


# --- GitHub (server-side, token never leaves the process) --------------------
def _gh(method, path, token, body=None, accept="application/vnd.github+json", raw=False):
    url = GH_API + path
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Authorization": "Bearer " + token, "Accept": accept,
               "User-Agent": _UA, "X-GitHub-Api-Version": "2022-11-28"}
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        r = urllib.request.urlopen(req, timeout=HTTP_TIMEOUT)
        payload = r.read()
        return r.status, (payload if raw else json.loads(payload.decode() or "{}"))
    except urllib.error.HTTPError as e:
        payload = e.read()
        if raw:
            return e.code, payload
        try:
            return e.code, json.loads(payload.decode() or "{}")
        except Exception:  # noqa: BLE001
            return e.code, {"message": payload[:200].decode(errors="replace")}


def _slug(candidate) -> str:
    # Stable, filesystem/URL-safe per-candidate identity. Prefer the immutable
    # GitHub numeric id so a handle rename never forks a candidate's repo.
    base = str(candidate.github_id or candidate.handle or candidate.id)
    out = "".join(c if (c.isalnum() or c in "-_") else "-" for c in base).strip("-").lower()
    return out or ("cand-" + str(candidate.id))


def _repo_name(candidate, cohort) -> str:
    co = "".join(c if (c.isalnum() or c in "-_") else "-" for c in str(cohort)).strip("-").lower()
    return f"{co}-{_slug(candidate)}"


def _ensure_repo(candidate, cohort):
    """Idempotently ensure the platform-owned per-candidate repo exists. Returns
    (full_name, html_url, default_branch, created). The candidate is granted push
    access so they can work in it; Submit snapshots are server-pinned and immutable,
    so working access never lets them alter a recorded submission."""
    name = _repo_name(candidate, cohort)
    full = f"{ORG}/{name}"
    token = _org_token()
    code, info = _gh("GET", f"/repos/{full}", token)
    created = False
    if code == 404:
        code, info = _gh("POST", f"/orgs/{ORG}/repos", token, {
            "name": name, "private": True, "auto_init": True,
            "description": f"PARALLAX workspace for {candidate.handle} ({cohort})",
            "has_issues": False, "has_projects": False, "has_wiki": False})
        if code not in (200, 201):
            _log("repo_create_failed", repo=full, code=code, err=str(info.get("message"))[:160])
            abort(502)
        created = True
    elif code not in (200,):
        _log("repo_lookup_failed", repo=full, code=code)
        abort(502)
    # Grant the candidate push access to their own workspace (best-effort; the
    # submission record never depends on candidate repo permissions).
    login = candidate.handle
    if login:
        pc, _ = _gh("PUT", f"/repos/{full}/collaborators/{urllib.parse.quote(login)}",
                    token, {"permission": "push"})
        _log("collaborator_set", repo=full, login=login, code=pc)
    return full, info.get("html_url"), info.get("default_branch", "main"), created


def _head_commit(full, branch, token):
    code, ref = _gh("GET", f"/repos/{full}/git/ref/heads/{urllib.parse.quote(branch)}", token)
    if code != 200:
        return None
    return (ref.get("object") or {}).get("sha")


def _commit_meta(full, sha, token):
    code, c = _gh("GET", f"/repos/{full}/git/commits/{sha}", token)
    if code != 200:
        return None
    return {"commit_sha": sha, "tree_sha": (c.get("tree") or {}).get("sha"),
            "committed_at": ((c.get("committer") or {}).get("date"))}


def _pin_tag(full, sha, tag, token):
    """Create an immutable tag pointing at the exact submitted commit. If the tag
    already exists (idempotent resubmission of the same attempt) it is left as-is;
    a tag that points elsewhere is a conflict and fails closed."""
    code, existing = _gh("GET", f"/repos/{full}/git/ref/tags/{urllib.parse.quote(tag)}", token)
    if code == 200:
        cur = (existing.get("object") or {}).get("sha")
        return cur == sha  # idempotent only if it already points at this commit
    code, _ = _gh("POST", f"/repos/{full}/git/refs", token,
                  {"ref": f"refs/tags/{tag}", "sha": sha})
    return code in (200, 201)


def _snapshot_digest(full, sha, token):
    """Fetch the repo tarball at the exact commit and return (sha256_hex, bytes).
    This is the content digest the manifest binds and the grader re-verifies, so a
    later force-push to the tag can never swap what was graded. Fails closed above
    the size cap (code submissions are small; weights go to HF)."""
    code, payload = _gh("GET", f"/repos/{full}/tarball/{sha}", token,
                        accept="application/vnd.github+json", raw=True)
    if code not in (200,):
        return None, None
    if len(payload) > MAX_SNAPSHOT_BYTES:
        _log("snapshot_too_large", repo=full, bytes=len(payload), cap=MAX_SNAPSHOT_BYTES)
        return "TOO_LARGE", None
    return hashlib.sha256(payload).hexdigest(), payload


# --- Hugging Face (optional model-weights portfolio, server-side) ------------
def _hf_latest_revision(hf_repo):
    """Resolve the current commit of a model repo on the Hub. Read-only; the token
    is used only if the repo is private. Returns a revision sha or None."""
    token = _hf_token()
    headers = {"User-Agent": _UA}
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(f"{HF_API}/models/{urllib.parse.quote(hf_repo)}", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as r:
            return json.loads(r.read().decode() or "{}").get("sha")
    except Exception as e:  # noqa: BLE001
        _log("hf_resolve_failed", hf_repo=hf_repo, err=str(e)[:120])
        return None


# --- Registration ------------------------------------------------------------
def register(app, candidate_model, db, helpers=None):
    helpers = helpers or {}
    from models import ParallaxSubmission

    def _nonprod_ok():
        # Never serve candidate submission routes in a production-marked environment
        # unless explicitly asserted non-production, mirroring parallax_routes gating.
        for marker in ("RANGER_ENV", "APP_ENV", "ENVIRONMENT", "FLASK_ENV"):
            if os.environ.get(marker, "").strip().lower() in ("prod", "production"):
                return False
        return True

    def _parallax_active(cid):
        pa = helpers.get("program_active")
        if pa is not None:
            return pa(cid, "parallax")
        from models import ProgramMembership
        m = ProgramMembership.query.filter_by(candidate_id=cid, program="parallax").first()
        return bool(m and m.status == "active")

    def _candidate_or_401():
        cid = session.get("cand")
        if not cid:
            abort(401)
        c = candidate_model.query.get(cid)
        if not c or c.status != "active":
            abort(403)
        if not _parallax_active(c.id):
            abort(403)  # authenticated + active, but not entitled to PARALLAX
        return c

    def _gate():
        if not _enabled() or not os.environ.get("RANGER_GITHUB_ORG_TOKEN"):
            abort(404)
        if not _nonprod_ok():
            abort(404)

    def _require_grader():
        tok = _grader_token()
        supplied = request.headers.get("X-Grader-Token", "")
        if not tok or supplied != tok:
            _log("grader_auth_denied", path=request.path)
            abort(403)

    def _current_cohort(c):
        return c.cohort or os.environ.get("DEFAULT_COHORT", "2026-A")

    def _workload_id(c):
        # Which graded workload this submission targets. Parameterizes the grader's
        # attack family so each board can escalate difficulty (basic -> advanced
        # split-payload variants) without new code. Defaults by env; overridable
        # per request within the configured allowlist only.
        default = os.environ.get("RANGER_SUBMISSION_WORKLOAD", "parallax-pi-basic")
        req = (request.get_json(silent=True) or {}).get("workload_id")
        allow = {w.strip() for w in os.environ.get(
            "RANGER_SUBMISSION_WORKLOADS", default).split(",") if w.strip()}
        return req if (req in allow) else default

    # ---- Candidate: provision workspace -------------------------------------
    @app.post("/submit/start")
    def submit_start():
        _gate()
        c = _candidate_or_401()
        cohort = _current_cohort(c)
        full, html_url, branch, created = _ensure_repo(c, cohort)
        _log("workspace_ready", cand=c.id, repo=full, created=created)
        return jsonify(repo=full, url=html_url, branch=branch,
                       clone_url=f"https://github.com/{full}.git", created=created)

    # ---- Candidate: one-click submit ----------------------------------------
    @app.post("/submit")
    def submit_now():
        _gate()
        c = _candidate_or_401()
        cohort = _current_cohort(c)
        token = _org_token()
        full, html_url, branch, _ = _ensure_repo(c, cohort)

        sha = _head_commit(full, branch, token)
        if not sha:
            _log("submit_no_commit", cand=c.id, repo=full)
            return jsonify(error="your workspace has no commits to submit yet"), 409
        meta = _commit_meta(full, sha, token) or {"commit_sha": sha}

        # Attempt number: one more than the candidate's existing submissions here.
        prior = (ParallaxSubmission.query
                 .filter_by(candidate_id=c.id, repo=full)
                 .order_by(ParallaxSubmission.attempt.desc()).first())
        attempt = (prior.attempt + 1) if prior else 1
        # Idempotency: an unchanged HEAD since the last submission is a no-op.
        if prior and prior.commit_sha == sha and prior.status in ("submitted", "grading", "graded"):
            _log("submit_idempotent", cand=c.id, repo=full, sha=sha[:12], attempt=prior.attempt)
            return jsonify(_receipt(prior)), 200

        digest, snapshot = _snapshot_digest(full, sha, token)
        if digest == "TOO_LARGE":
            return jsonify(error="submission snapshot exceeds the size limit; keep model "
                                 "weights on Hugging Face, not in the code repo"), 413
        if not digest:
            _log("submit_snapshot_failed", cand=c.id, repo=full, sha=sha[:12])
            abort(502)

        tag = f"submit-a{attempt}-{sha[:12]}"
        if not _pin_tag(full, sha, tag, token):
            _log("submit_tag_conflict", cand=c.id, repo=full, tag=tag)
            return jsonify(error="could not pin an immutable tag for this submission"), 409

        # Optional model-weights portfolio reference (later boards).
        hf_repo = (request.get_json(silent=True) or {}).get("hf_repo") or None
        hf_rev = _hf_latest_revision(hf_repo) if hf_repo else None

        workload_id = _workload_id(c)
        manifest = {
            "schema": SIG_DOMAIN,
            "program": "parallax",
            "workload_id": workload_id,
            "cohort": cohort,
            "candidate_id": c.id,
            "candidate_handle": c.handle,
            "repo": full,
            "ref": f"refs/tags/{tag}",
            "tag": tag,
            "commit_sha": sha,
            "tree_sha": meta.get("tree_sha"),
            "content_digest_sha256": digest,
            "snapshot_bytes": len(snapshot) if snapshot else None,
            "hf_repo": hf_repo,
            "hf_revision": hf_rev,
            "attempt": attempt,
            "submitted_at": int(time.time()),
        }
        sig, kid = signing.sign_domain(SIG_DOMAIN, manifest)

        row = ParallaxSubmission(
            candidate_id=c.id, cohort=cohort, program="parallax", workload_id=workload_id,
            repo=full, attempt=attempt, status="submitted",
            commit_sha=sha, tree_sha=meta.get("tree_sha"), tag=tag,
            content_digest=digest, hf_repo=hf_repo, hf_revision=hf_rev,
            manifest=json.dumps(manifest, sort_keys=True), manifest_sig=sig, signing_kid=kid)
        # Keep the digest-verified snapshot for the grader to pull over private
        # networking; never exposed to the candidate, dropped once grading records.
        row.snapshot_b64 = base64.b64encode(snapshot).decode() if snapshot else None
        db.session.add(row)
        db.session.commit()
        _log("submitted", cand=c.id, repo=full, tag=tag, sha=sha[:12],
             digest=digest[:12], attempt=attempt, workload=workload_id, sub=row.id)
        return jsonify(_receipt(row)), 201

    def _receipt(row):
        return {
            "submission_id": row.id, "status": row.status, "attempt": row.attempt,
            "repo": row.repo, "tag": row.tag, "commit_sha": row.commit_sha,
            "content_digest_sha256": row.content_digest, "workload_id": row.workload_id,
            "hf_repo": row.hf_repo, "hf_revision": row.hf_revision,
            "manifest_sig": row.manifest_sig, "signing_kid": row.signing_kid,
            "public_key_b64": signing.public_key_b64(row.signing_kid),
            "score": row.score, "verify_url": f"/submit/verify/{row.id}",
        }

    # ---- Candidate: status --------------------------------------------------
    @app.get("/submit/status")
    def submit_status():
        _gate()
        c = _candidate_or_401()
        rows = (ParallaxSubmission.query.filter_by(candidate_id=c.id)
                .order_by(ParallaxSubmission.created_at.desc()).limit(50).all())
        return jsonify(submissions=[_receipt(r) for r in rows])

    # ---- Public: independent verification -----------------------------------
    @app.get("/submit/verify/<int:sub_id>")
    def submit_verify(sub_id):
        _gate()
        row = ParallaxSubmission.query.get(sub_id)
        if not row:
            abort(404)
        manifest = json.loads(row.manifest)
        ok = signing.verify_domain(SIG_DOMAIN, manifest, row.manifest_sig, kid=row.signing_kid)
        out = {"submission_id": row.id, "signature_valid": bool(ok),
               "repo": row.repo, "tag": row.tag, "commit_sha": row.commit_sha,
               "content_digest_sha256": row.content_digest, "signing_kid": row.signing_kid,
               "public_key_b64": signing.public_key_b64(row.signing_kid),
               "graded": row.status == "graded", "score": row.score}
        return jsonify(out)

    # ---- Internal (grader): claim next job ----------------------------------
    @app.get("/submit/internal/next")
    def submit_internal_next():
        if not _enabled():
            abort(404)
        _require_grader()
        # Atomically claim one pending submission for grading.
        row = (ParallaxSubmission.query
               .filter(ParallaxSubmission.status == "submitted")
               .order_by(ParallaxSubmission.created_at.asc()).first())
        if not row:
            return jsonify(job=None)
        row.status = "grading"
        row.grading_started_at = _utcnow()
        db.session.commit()
        job = {
            "submission_id": row.id, "workload_id": row.workload_id,
            "repo": row.repo, "commit_sha": row.commit_sha, "tag": row.tag,
            "content_digest_sha256": row.content_digest,
            "snapshot_b64": row.snapshot_b64,  # digest-verified by the grader
            "hf_repo": row.hf_repo, "hf_revision": row.hf_revision,
            "model_url": os.environ.get("RANGER_RESEARCH_MODEL_URL"),
            "model_id": os.environ.get("RANGER_RESEARCH_MODEL_ID"),
        }
        _log("job_claimed", sub=row.id, repo=row.repo, workload=row.workload_id)
        return jsonify(job=job)

    # ---- Internal (grader): post result -------------------------------------
    @app.post("/submit/internal/result")
    def submit_internal_result():
        if not _enabled():
            abort(404)
        _require_grader()
        body = request.get_json(silent=True) or {}
        sub_id = body.get("submission_id")
        row = ParallaxSubmission.query.get(sub_id) if sub_id else None
        if not row:
            abort(404)
        if body.get("status") == "failed":
            row.status = "failed"
            row.grade_detail = json.dumps({"error": str(body.get("error"))[:500]})
            row.graded_at = _utcnow()
            row.snapshot_b64 = None
            db.session.commit()
            _log("grade_failed", sub=row.id, err=str(body.get("error"))[:120])
            return jsonify(ok=True)

        metrics = body.get("metrics") or {}
        evidence = body.get("evidence") or {}
        score = body.get("score")
        # The portal is the authority for the graded record: it signs the final,
        # candidate-immutable grade over the submitted manifest + grader metrics, so
        # the grade is bound to exactly what was submitted and independently verifiable.
        graded = {
            "schema": GRADE_SIG_DOMAIN, "submission_id": row.id,
            "commit_sha": row.commit_sha, "content_digest_sha256": row.content_digest,
            "workload_id": row.workload_id, "manifest_sig": row.manifest_sig,
            "metrics": metrics, "score": score,
            "grader_version": body.get("grader_version"),
            "findings_available": metrics.get("findings_available"),
            "graded_at": int(time.time()),
        }
        gsig, gkid = signing.sign_domain(GRADE_SIG_DOMAIN, graded)
        row.status = "graded"
        row.score = float(score) if score is not None else None
        row.metrics = json.dumps(metrics, sort_keys=True)
        row.grade_detail = json.dumps({"evidence_index": evidence,
                                       "grader_version": body.get("grader_version")})
        row.grade_record = json.dumps(graded, sort_keys=True)
        row.grade_sig = gsig
        row.grade_kid = gkid
        row.graded_at = _utcnow()
        row.snapshot_b64 = None  # grading done; drop the transient snapshot
        db.session.commit()
        _log("graded", sub=row.id, score=row.score,
             findings=metrics.get("findings_available"), grader=body.get("grader_version"))
        return jsonify(ok=True)

    # Test-only candidate session bootstrap for submission validation. Disabled unless
    # RANGER_SUBMISSION_TEST_KEY is set (never in production). Mints a synthetic PARALLAX
    # candidate with an active membership and sets its session, so the full submit flow can
    # be validated without GitHub OAuth. It grants no real access: the candidate is synthetic
    # and the key is absent in production.
    _test_key = os.environ.get("RANGER_SUBMISSION_TEST_KEY")
    if _test_key:
        @app.get("/submit-test/login")
        def submit_test_login():
            if request.args.get("key") != _test_key:
                abort(404)
            from models import ProgramMembership
            handle = "parallax-submit-test"
            c = candidate_model.query.filter_by(handle=handle).first()
            if not c:
                c = candidate_model(handle=handle, github_id="parallax-submit-test",
                                    name="PARALLAX Submit Test (synthetic)",
                                    email="parallax-submit-test@synthetic.ranger.local",
                                    status="active",
                                    cohort=os.environ.get("DEFAULT_COHORT", "2026-A"))
                db.session.add(c)
                db.session.commit()
            elif c.status != "active":
                c.status = "active"
                db.session.commit()
            m = ProgramMembership.query.filter_by(candidate_id=c.id, program="parallax").first()
            if not m:
                db.session.add(ProgramMembership(candidate_id=c.id, program="parallax",
                                                 status="active", granted_by="system:submit-test"))
                db.session.commit()
            elif m.status != "active":
                m.status = "active"
                db.session.commit()
            session["cand"] = c.id
            # Mirror the portal's own _csrf_token(): the browser CSRF guard checks
            # X-CSRF-Token against session["csrf"], so mint/return that same token.
            _csrf = session.get("csrf")
            if not _csrf:
                import secrets as _secrets
                _csrf = _secrets.token_urlsafe(24)
                session["csrf"] = _csrf
            _log("test_login", cand=c.id, handle=handle)
            return jsonify(ok=True, cand=c.id, csrf=_csrf)

    _log("gateway_registered", org=ORG, enabled=_enabled(),
         grader_auth=bool(_grader_token()), max_snapshot=MAX_SNAPSHOT_BYTES)
