"""Deployment-time production secret gate (run in CI / pre-deploy, NOT at app runtime).

The application-level guard in create_app() fails closed only when secure mode is declared. Because
secure mode is opt-in, a production deployment that simply omits the marker would run in lenient mode
with predictable/ephemeral credentials. This preflight closes that gap: it REQUIRES the explicit
force flag RANGER_REQUIRE_SECURE_SECRETS=1 for a production target and then validates the full secret
contract exactly as the app will at boot. Wire it as a required step in the production deploy
pipeline, with the production environment variables injected, so a deploy cannot proceed without it.

Usage (with the production environment variables present in the step's environment):
    python scripts/preflight_prod_secrets.py
Exit codes: 0 = OK to deploy; 2 = force flag missing; 3 = secret/signing contract not satisfied.
It reads only environment variable names and never prints a secret value.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import prodconfig  # noqa: E402
import signing  # noqa: E402


def main():
    if not prodconfig._truthy(os.environ.get(prodconfig.FORCE_FLAG)):
        print("FAIL: %s=1 must be explicitly set for a production deployment. The application guard "
              "alone is not sufficient because secure mode is opt-in; this gate makes the flag "
              "mandatory at deploy time." % prodconfig.FORCE_FLAG)
        return 2
    try:
        prodconfig.require_secret_key()   # SECRET_KEY present, long enough, not placeholder, entropy ok
        signing.assert_signing_ready()    # exactly one signing source, well-formed, active key present
    except prodconfig.InsecureConfigError as e:
        print("FAIL: %s" % e)             # message names the variable, never its value
        return 3
    print("OK: production secret configuration present and valid "
          "(force flag set; SECRET_KEY and signing key validated).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
