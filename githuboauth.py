"""GitHub OAuth: sign-in and identity assurance for Qwalora Ranger.

GitHub is the only way in, so we know a candidate is a real person and can
detect returning rangers by their immutable numeric id. We also enforce an
identity bar before letting someone enroll:

  - a verified email on the GitHub account
  - two-factor authentication enabled (REQUIRE_2FA, default on)
  - a minimum account age (MIN_ACCOUNT_AGE_DAYS, default 30)

Config (set on the service):
  GITHUB_OAUTH_CLIENT_ID, GITHUB_OAUTH_CLIENT_SECRET   the registered OAuth app
  PORTAL_BASE_URL         e.g. https://portal.qwalora.com (for the exact callback)
  REVIEWER_GITHUB_IDS     comma-separated numeric ids allowed as reviewers
  REQUIRE_2FA=0           to relax the 2FA requirement
  MIN_ACCOUNT_AGE_DAYS    integer, default 30

HTTP uses the standard library so there is no extra dependency. The three
network functions are isolated so tests can substitute them.
"""
import datetime as _dt
import json
import os
import urllib.parse
import urllib.request

AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API = "https://api.github.com"
SCOPE = "read:user user:email"
_TIMEOUT = 15


def enabled():
    return bool(os.environ.get("GITHUB_OAUTH_CLIENT_ID")
                and os.environ.get("GITHUB_OAUTH_CLIENT_SECRET"))


def base_url():
    return (os.environ.get("PORTAL_BASE_URL") or "https://portal.qwalora.com").rstrip("/")


def redirect_uri():
    return base_url() + "/auth/github/callback"


def authorize_url(state):
    q = urllib.parse.urlencode({
        "client_id": os.environ["GITHUB_OAUTH_CLIENT_ID"],
        "redirect_uri": redirect_uri(),
        "scope": SCOPE, "state": state, "allow_signup": "true"})
    return AUTHORIZE_URL + "?" + q


# --- network (isolated for tests) -------------------------------------------
def exchange_code(code):
    data = urllib.parse.urlencode({
        "client_id": os.environ["GITHUB_OAUTH_CLIENT_ID"],
        "client_secret": os.environ["GITHUB_OAUTH_CLIENT_SECRET"],
        "code": code, "redirect_uri": redirect_uri()}).encode()
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST",
                                 headers={"Accept": "application/json",
                                          "User-Agent": "qwalora-ranger"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
        return json.loads(r.read().decode() or "{}").get("access_token")


def _api_get(path, token):
    req = urllib.request.Request(API + path, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "User-Agent": "qwalora-ranger"})
    with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
        return json.loads(r.read().decode() or "{}")


def get_user(token):
    return _api_get("/user", token)


def get_emails(token):
    return _api_get("/user/emails", token)


# --- identity checks --------------------------------------------------------
def primary_verified_email(emails):
    for e in emails or []:
        if e.get("primary") and e.get("verified"):
            return e.get("email")
    for e in emails or []:
        if e.get("verified"):
            return e.get("email")
    return None


def account_age_days(user):
    created = user.get("created_at")
    if not created:
        return 0
    try:
        dt = _dt.datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        return (_dt.datetime.now(_dt.timezone.utc) - dt).days
    except ValueError:
        return 0


def identity_ok(user, emails):
    """Return (ok, reason, email). Enforces the enrollment identity bar."""
    require_2fa = os.environ.get("REQUIRE_2FA", "1") != "0"
    min_age = int(os.environ.get("MIN_ACCOUNT_AGE_DAYS", "30"))
    email = primary_verified_email(emails)
    if not email:
        return (False, "a verified email on your GitHub account is required", None)
    if require_2fa and not user.get("two_factor_authentication"):
        return (False, "two-factor authentication must be enabled on your GitHub account", None)
    if account_age_days(user) < min_age:
        return (False, f"your GitHub account must be at least {min_age} days old", None)
    return (True, "", email)


def reviewer_ids():
    return {x.strip() for x in os.environ.get("REVIEWER_GITHUB_IDS", "").split(",") if x.strip()}
