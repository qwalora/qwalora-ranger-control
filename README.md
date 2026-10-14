# Qwalora Ranger - control plane

Minimal Flask control plane for the Ranger cyber range: enrollment, written-report
review, roster service for `cohort-sync`, and a Ludus range broker (stubbed until
the range host is live). Runs on Railway with Postgres.

Objective grading is **not** here. It stays answer-free and program-side: the
program clones each repo, re-measures, and signs the cohort. This plane runs the
human surface around that spine.

## Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | - | landing |
| GET | `/healthz` | - | liveness + db check (Railway healthcheck) |
| GET | `/enroll` | - | enrollment form |
| POST | `/enroll` | - | create candidate, issue submission token, queue range |
| POST | `/reports` | `X-Candidate-Token` | submit a written report |
| GET | `/admin` | bearer / session | grading dashboard |
| POST | `/admin/reports/<id>` | bearer / session | approve / reject a report |
| GET | `/roster.json?cohort=` | bearer | roster in the shape `cohort-sync` consumes |

## Environment variables

| Var | Required | Notes |
|---|---|---|
| `DATABASE_URL` | yes | set to `${{Postgres.DATABASE_URL}}` on Railway |
| `ADMIN_TOKEN` | yes | admin login + bearer auth; generate a strong one |
| `SECRET_KEY` | yes | Flask session signing |
| `DEFAULT_COHORT` | no | defaults to `2026-A` |
| `LUDUS_API_URL` | no | set when the Hetzner/Ludus box is live; broker goes from stubbed to live |
| `LUDUS_API_KEY` | no | Ludus admin API key (set alongside the URL) |

## Deploy on Railway

1. Push this repo to GitHub (`qwalora/qwalora-ranger-portal`).
2. In the `qwalora-ranger` Railway project: New → GitHub Repo → authorize Railway's
   GitHub app → pick this repo. Nixpacks builds it from `requirements.txt` + `Procfile`.
3. Set the env vars above. `DATABASE_URL` references the Postgres service.
4. Generate a domain, then point `portal.qwalora.com` at it via CNAME.

`/healthz` returns `{"status":"ok","db":true}` once Postgres is wired.

## Local run

    pip install -r requirements.txt
    ADMIN_TOKEN=dev SECRET_KEY=dev python app.py
    # http://127.0.0.1:8080  (falls back to sqlite when DATABASE_URL is unset)

## Wiring Ludus later

`broker.py::queue_range` is the single integration point. Until `LUDUS_API_URL`
is set, enrollment parks a `RangeRequest` in `queued`. Set the two Ludus vars and
fill the live `POST` to drain the queue into real per-candidate ranges.
